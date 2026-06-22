use crate::AppState;
use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        State,
    },
    http::StatusCode,
    response::IntoResponse,
};
use axum_extra::extract::CookieJar;
use chrono::{DateTime, Utc};
use futures::sink::SinkExt;
use futures::stream::StreamExt;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc};
use futures::TryFutureExt;
use tokio::sync::{broadcast, Mutex};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

// Type aliases
pub type SharedState = Arc<Mutex<HashMap<String, Connection>>>;
pub type SessionStore = Arc<Mutex<HashMap<String, Session>>>;

// Session data
#[derive(Debug, Clone)]
pub struct Session {
    pub user_id: Uuid,
    pub username: String,
    pub created_at: DateTime<Utc>,
}

// Connection info
#[derive(Debug, Clone)]
pub struct Connection {
    pub username: String,
    pub user_id: Uuid,
    pub tx: broadcast::Sender<String>,
}

// E2E Encrypted Message types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ChatMessage {
    UserJoined {
        username: String,
        user_id: Uuid,
        timestamp: DateTime<Utc>,
    },
    UserLeft {
        username: String,
        user_id: Uuid,
        timestamp: DateTime<Utc>,
    },
    // Encrypted message for specific recipients
    EncryptedMessage {
        sender_id: Uuid,
        sender_username: String,
        encrypted_content: String, // Base64 encoded encrypted message
        recipients: Vec<Uuid>,
        timestamp: DateTime<Utc>,
        message_id: String,
        room: Option<String>, // 'global' or 'dm' (optional for backward compat)
        ttl_seconds: Option<i64>,
    },
    // Key exchange messages
    KeyExchange {
        from_user_id: Uuid,
        to_user_id: Uuid,
        encrypted_key: String, // Encrypted symmetric key
        key_id: String,
        scope: Option<String>, // 'global' or 'dm'
    },
    SystemMessage {
        content: String,
        timestamp: DateTime<Utc>,
    },
    // Request public keys for users
    RequestPublicKeys {
        user_ids: Vec<Uuid>,
        request_id: String,
    },
    // Response with public keys
    PublicKeysResponse {
        keys: Vec<PublicKeyInfo>,
        request_id: String,
    },
    // Initial presence sync to a newly connected client
    OnlineUsers {
        users: Vec<UserInfo>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyInfo {
    pub user_id: Uuid,
    pub username: String,
    pub public_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserInfo {
    pub user_id: Uuid,
    pub username: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedMessageContent {
    pub content: String,
    pub iv: String, // Initialization vector for AES
    pub key_id: String, // ID of the symmetric key used
}

// WebSocket handler with authentication
pub async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<impl IntoResponse, StatusCode> {
    // Extract session from cookie
    let session_id = jar
        .get("session_id")
        .map(|c| c.value().to_string())
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let session = {
        let sessions = state.sessions.lock().await;
        sessions
            .get(&session_id)
            .cloned()
            .ok_or(StatusCode::UNAUTHORIZED)?
    };

    info!(
        "WebSocket upgrade request from authenticated user: {}",
        session.username
    );

    Ok(ws.on_upgrade(move |socket| handle_socket(socket, state, session)))
}


async fn send_recent_history(
    state: &AppState,
    to_user_id: Uuid,
    tx: &broadcast::Sender<String>,
) -> Result<(), sqlx::Error> {
    // Select last 50 messages: all global + DMs where user is sender or recipient
    let rows = sqlx::query!(
        r#"SELECT m.id, m.sender_id, u.name as sender_name, m.encrypted_content, m.recipients, m.created_at, m.room, m.expires_at
           FROM messages m
           JOIN users u ON u.id = m.sender_id
           WHERE (m.room = 'global' OR m.sender_id = $1 OR $1 = ANY(m.recipients))
             AND m.expires_at > NOW()
           ORDER BY m.created_at DESC
           LIMIT 50"#,
        to_user_id
    )
        .fetch_all(&state.db_pool)
        .await?;

    for row in rows.into_iter().rev() {
        // Recipients and sender_name are already non-optional types from sqlx
        let recips: Vec<Uuid> = row.recipients;
        let sender_name: String = row.sender_name;

        let msg = ChatMessage::EncryptedMessage {
            sender_id: row.sender_id,
            sender_username: sender_name,
            encrypted_content: row.encrypted_content,
            recipients: recips,
            timestamp: row.created_at,
            message_id: row.id,
            room: Some(row.room),
            ttl_seconds: Some((row.expires_at - Utc::now()).num_seconds().max(0)),
        };

        if let Ok(json) = serde_json::to_string(&msg) {
            let _ = tx.send(json);
        }
    }
    Ok(())
}

pub async fn handle_socket(socket: WebSocket, state: AppState, session: Session) {
    let username = session.username.clone();
    let user_id = session.user_id;
    let connection_id = Uuid::new_v4().to_string();

    info!(
        "New WebSocket connection from: {} (User ID: {})",
        username, user_id
    );

    let (tx, mut rx) = broadcast::channel::<String>(100);

    // Add connection to state
    {
        let mut connections = state.connections.lock().await;
        connections.insert(
            connection_id.clone(),
            Connection {
                username: username.clone(),
                user_id,
                tx: tx.clone(),
            },
        );
    }

    // Send initial list of currently online users to this connection
    {
        let connections = state.connections.lock().await;
        let users: Vec<UserInfo> = connections
            .iter()
            .filter_map(|(cid, c)| {
                if cid == &connection_id { return None; }
                Some(UserInfo { user_id: c.user_id, username: c.username.clone() })
            })
            .collect();
        let init_msg = ChatMessage::OnlineUsers { users };
        if let Ok(json) = serde_json::to_string(&init_msg) {
            let _ = tx.send(json);
        }
    }

    // Broadcast user joined message
    broadcast_message(
        &state,
        None, // Send to all connections
        ChatMessage::UserJoined {
            username: username.clone(),
            user_id,
            timestamp: Utc::now(),
        },
    )
        .await;

    let (mut sender, mut receiver) = socket.split();
    let state_clone = Arc::new(state.clone());

    {
        let state_for_history = state_clone.clone();
        let tx_for_history = tx.clone();
        let to_user_id = user_id;
        tokio::spawn(async move {
            // small delay to allow other clients to broadcast presence
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
            // Deliver pending DM keys first so history can decrypt
            if let Err(e) = send_pending_dm_keys(&state_for_history, to_user_id, &tx_for_history).await {
                warn!("Failed to send pending DM keys: {:?}", e);
            }
            // Then send recent history
            if let Err(e) = send_recent_history(&state_for_history, to_user_id, &tx_for_history).await {
                warn!("Failed to send history: {:?}", e);
            }
        });
    }

    // Message receiving task
    let mut recv_task = tokio::spawn({
        let username = username.clone();
        let user_id = user_id;
        let connection_id = connection_id.clone();
        let state = state_clone.clone();

        async move {
            while let Some(Ok(msg)) = receiver.next().await {
                match msg {
                    Message::Text(text) => {
                        debug!("Received message from {}: {}", username, text);

                        // Parse the incoming message
                        match serde_json::from_str::<ChatMessage>(&text) {
                            Ok(chat_message) => {
                                handle_chat_message(
                                    &state,
                                    &connection_id,
                                    user_id,
                                    &username,
                                    chat_message,
                                )
                                    .await;
                            }
                            Err(e) => {
                                warn!("Failed to parse message from {}: {}", username, e);
                            }
                        }
                    }
                    Message::Ping(data) => {
                        debug!("Received ping from {}", username);
                        // Echo pong back (handled automatically by axum)
                    }
                    Message::Pong(_) => {
                        debug!("Received pong from {}", username);
                    }
                    Message::Close(_) => {
                        info!("Close message received from {}", username);
                        break;
                    }
                    _ => {
                        debug!("Received unsupported message type from {}", username);
                    }
                }
            }
        }
    });

    // Message sending task
    let mut send_task = tokio::spawn(async move {
        while let Ok(msg) = rx.recv().await {
            if sender.send(Message::Text(msg)).await.is_err() {
                warn!("Failed to send message, connection likely closed");
                break;
            }
        }
    });

    // Wait for either task to complete
    tokio::select! {
        _ = (&mut recv_task) => {
            send_task.abort();
        }
        _ = (&mut send_task) => {
            recv_task.abort();
        }
    };

    // Cleanup
    {
        let mut connections = state.connections.lock().await;
        connections.remove(&connection_id);
    }

    // Broadcast user left message
    broadcast_message(
        &state,
        None,
        ChatMessage::UserLeft {
            username: username.clone(),
            user_id,
            timestamp: Utc::now(),
        },
    )
        .await;

    info!("WebSocket connection closed for {}", username);
}

async fn handle_chat_message(
    state: &AppState,
    sender_connection_id: &str,
    sender_user_id: Uuid,
    sender_username: &str,
    message: ChatMessage,
) {
    match message {
        ChatMessage::EncryptedMessage {
            ref encrypted_content,
            ref recipients,
            timestamp,
            ref message_id,
            ref room,
            ttl_seconds: message_ttl,
            ..
        } => {
            // Determine room with backward-compat default
            let inferred_room = room
                .clone()
                .unwrap_or_else(|| if recipients.len() > 1 { "global" } else { "dm" }.to_string());
            info!(
                "Received EncryptedMessage id={} room={} recipients={} from {}",
                message_id,
                inferred_room,
                recipients.len(),
                sender_username
            );
            // Resolve TTL: prefer message-provided value, fallback to user's default in DB
            let effective_ttl = if let Some(v) = message_ttl { v } else {
                match sqlx::query!(
                    r#"SELECT COALESCE(default_ttl_seconds, 86400) AS ttl FROM users WHERE id = $1"#,
                    sender_user_id
                )
                .fetch_one(&state.db_pool)
                .await
                {
                    Ok(r) => r.ttl.unwrap_or(86400) as i64,
                    Err(_) => 86400,
                }
            };
            // Forward encrypted message to specified recipients
            forward_encrypted_message(
                state,
                sender_connection_id,
                sender_user_id,
                sender_username,
                encrypted_content.clone(),
                recipients.clone(),
                timestamp,
                message_id.clone(),
                inferred_room,
                effective_ttl,
            )
                .await;
        }
        ChatMessage::RequestPublicKeys { ref user_ids, ref request_id } => {
            // Handle public key request
            handle_public_keys_request(state, sender_user_id, user_ids.clone(), request_id.clone()).await;
        }
        ChatMessage::KeyExchange { ref to_user_id, ref encrypted_key, ref key_id, .. } => {
            // Forward key exchange to specific user
            forward_to_user(state, sender_user_id, *to_user_id, message.clone()).await;
            // If recipient is offline, persist for later delivery
            if !user_is_online(state, *to_user_id).await {
                let _ = sqlx::query!(
                    r#"INSERT INTO dm_key_exchanges (from_user_id, to_user_id, encrypted_key, key_id, delivered)
                       VALUES ($1, $2, $3, $4, FALSE)"#,
                    sender_user_id,
                    *to_user_id,
                    encrypted_key,
                    key_id
                )
                .execute(&state.db_pool)
                .await;
            }
        }
        _ => {
            // Broadcast other message types to all users
            broadcast_message(state, None, message).await;
        }
    }
}

async fn forward_encrypted_message(
    state: &AppState,
    sender_connection_id: &str,
    sender_user_id: Uuid,
    sender_username: &str,
    encrypted_content: String,
    mut recipients: Vec<Uuid>,
    timestamp: DateTime<Utc>,
    message_id: String,
    room: String,
    ttl_seconds: i64,
) {
    // Persist message
    {
        let expires_at = timestamp + chrono::Duration::seconds(ttl_seconds);
        let _ = sqlx::query!(
            r#"INSERT INTO messages (id, sender_id, encrypted_content, recipients, created_at, room, expires_at)
               VALUES ($1, $2, $3, $4, $5, $6, $7)
               ON CONFLICT (id) DO NOTHING"#,
            message_id,
            sender_user_id,
            encrypted_content,
            &recipients[..],
            timestamp,
            room,
            expires_at
        )
        .execute(&state.db_pool)
        .await;
    }

    let connections = state.connections.lock().await;

    // Fallback: if recipients is empty, treat as broadcast to all except sender (helps if client didn't yet have presence)
    let broadcast_all = recipients.is_empty();

    let mut delivered = 0usize;
    for (conn_id, conn) in connections.iter() {
        let should_send = if broadcast_all {
            conn_id != sender_connection_id
        } else {
            conn_id != sender_connection_id && recipients.contains(&conn.user_id)
        };
        if should_send {
            if broadcast_all {
                recipients.push(conn.user_id);
            }
            let forward_msg = ChatMessage::EncryptedMessage {
                sender_id: sender_user_id,
                sender_username: sender_username.to_string(),
                encrypted_content: encrypted_content.clone(),
                recipients: recipients.clone(),
                timestamp,
                message_id: message_id.clone(),
                room: Some(room.clone()),
                ttl_seconds: Some(ttl_seconds),
            };

            if let Ok(json) = serde_json::to_string(&forward_msg) {
                let _ = conn.tx.send(json);
                delivered += 1;
            }
        }
    }
    info!(
        "Forwarded EncryptedMessage id={} room={} delivered_to={}",
        message_id,
        room,
        delivered
    );
}

async fn forward_to_user(
    state: &AppState,
    from_user_id: Uuid,
    to_user_id: Uuid,
    message: ChatMessage,
) {
    let connections = state.connections.lock().await;

    for (_, conn) in connections.iter() {
        if conn.user_id == to_user_id {
            if let Ok(json) = serde_json::to_string(&message) {
                let _ = conn.tx.send(json);
                break;
            }
        }
    }
}

async fn handle_public_keys_request(
    state: &AppState,
    requester_id: Uuid,
    user_ids: Vec<Uuid>,
    request_id: String,
) {
    match crate::auth::get_public_keys(&state.db_pool, &user_ids).await {
        Ok(public_keys) => {
            let response = ChatMessage::PublicKeysResponse {
                keys: public_keys
                    .into_iter()
                    .filter_map(|pk| {
                        pk.public_key.map(|pub_key| PublicKeyInfo {
                            user_id: pk.user_id,
                            username: pk.username,
                            public_key: pub_key,
                        })
                    })
                    .collect(),
                request_id,
            };

            // Send response back to requester
            let connections = state.connections.lock().await;
            for (_, conn) in connections.iter() {
                if conn.user_id == requester_id {
                    if let Ok(json) = serde_json::to_string(&response) {
                        let _ = conn.tx.send(json);
                    }
                    break;
                }
            }
        }
        Err(e) => {
            error!("Failed to fetch public keys: {:?}", e);
        }
    }
}

async fn broadcast_message(state: &AppState, exclude_connection_id: Option<&String>, message: ChatMessage) {
    if let Ok(json) = serde_json::to_string(&message) {
        let connections = state.connections.lock().await;
        for (conn_id, conn) in connections.iter() {
            if Some(conn_id) != exclude_connection_id {
                let _ = conn.tx.send(json.clone());
            }
        }
    }
}

async fn user_is_online(state: &AppState, user_id: Uuid) -> bool {
    let connections = state.connections.lock().await;
    connections.values().any(|c| c.user_id == user_id)
}

async fn send_pending_dm_keys(
    state: &AppState,
    to_user_id: Uuid,
    tx: &broadcast::Sender<String>,
) -> Result<(), sqlx::Error> {
    let rows = sqlx::query!(
        r#"SELECT id, from_user_id, to_user_id, encrypted_key, key_id
           FROM dm_key_exchanges
           WHERE to_user_id = $1 AND delivered = FALSE
           ORDER BY created_at ASC"#,
        to_user_id
    )
        .fetch_all(&state.db_pool)
        .await?;

    let mut delivered_ids: Vec<Uuid> = Vec::new();  // Changed from Vec<i32> to Vec<Uuid>
    for row in rows {
        let msg = ChatMessage::KeyExchange {
            from_user_id: row.from_user_id,
            to_user_id: row.to_user_id,
            encrypted_key: row.encrypted_key,
            key_id: row.key_id,
            scope: Some("dm".to_string()),
        };
        if let Ok(json) = serde_json::to_string(&msg) {
            let _ = tx.send(json);
            delivered_ids.push(row.id);  // Now this will work since both are Uuid
        }
    }

    if !delivered_ids.is_empty() {
        // Mark as delivered
        let _ = sqlx::query!(
            r#"UPDATE dm_key_exchanges SET delivered = TRUE WHERE id = ANY($1)"#,
            &delivered_ids[..]
        )
            .execute(&state.db_pool)
            .await?;
    }
    Ok(())
}
