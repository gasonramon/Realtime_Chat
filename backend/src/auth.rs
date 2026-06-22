pub mod two_fa;
use crate::{AppState, Session};
use argon2::password_hash::{rand_core::OsRng, PasswordHash, SaltString};
use argon2::{Argon2, PasswordHasher, PasswordVerifier};
use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use axum_extra::extract::CookieJar;
use dotenv::dotenv;
use serde::{Deserialize, Serialize};
use sqlx::postgres::PgPoolOptions;
use std::env;
use tracing::{error, info, warn};
use uuid::Uuid;
use chrono::{Utc, Duration as ChronoDuration};
use lettre::{
    message::header::ContentType,
    transport::smtp::authentication::Credentials,
    transport::smtp::client::{Tls, TlsParameters},
    Message, SmtpTransport, Transport,
};

#[derive(Clone, Debug)]
pub struct User {
    pub id: Uuid,
    pub name: String,
    pub email: String,
    pub password_hash: String,
    pub public_key: Option<String>,
    pub default_ttl_seconds: Option<i32>,
}

// Database connection
pub async fn connect_to_db() -> Result<sqlx::PgPool, Box<dyn std::error::Error>> {
    dotenv().ok();
    let database_url = env::var("DATABASE_URL")?;
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await?;
    Ok(pool)
}

// User registration
pub async fn register_user(
    pool: &sqlx::PgPool,
    name: &str,
    email: &str,
    password: &str,
    public_key: Option<&str>,
) -> Result<User, sqlx::Error> {
    let user_id = Uuid::new_v4();
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| sqlx::Error::Protocol(format!("hash error: {}", e).into()))?
        .to_string();

    let row = sqlx::query!(
        r#"INSERT INTO users (id, name, email, password_hash, public_key)
           VALUES ($1, $2, $3, $4, $5)
           RETURNING id, name, email, password_hash, public_key, default_ttl_seconds"#,
        user_id,
        name,
        email,
        password_hash,
        public_key
    )
        .fetch_one(pool)
        .await?;

    Ok(User {
        id: row.id,
        name: row.name,
        email: row.email,
        password_hash: row.password_hash,
        public_key: row.public_key,
        default_ttl_seconds: Some(row.default_ttl_seconds),
    })
}

// User authentication
pub async fn authenticate_user(
    pool: &sqlx::PgPool,
    name: &str,
    password: &str,
) -> Result<User, AuthError> {
    let user = sqlx::query_as!(
        User,
        r#"SELECT id, name, email, password_hash, public_key, default_ttl_seconds FROM users WHERE name = $1"#,
        name
    )
        .fetch_optional(pool)
        .await
        .map_err(|_| AuthError::DatabaseError)?
        .ok_or(AuthError::InvalidCredentials)?;

    let parsed_hash =
        PasswordHash::new(&user.password_hash).map_err(|_| AuthError::HashError)?;

    Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .map_err(|_| AuthError::InvalidCredentials)?;

    Ok(user)
}

// Get user by ID
pub async fn get_user_by_id(pool: &sqlx::PgPool, user_id: Uuid) -> Result<User, sqlx::Error> {
    sqlx::query_as!(
        User,
        r#"SELECT id, name, email, password_hash, public_key, default_ttl_seconds FROM users WHERE id = $1"#,
        user_id
    )
        .fetch_one(pool)
        .await
}

// Update user's public key
pub async fn update_public_key(
    pool: &sqlx::PgPool,
    user_id: Uuid,
    public_key: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        r#"UPDATE users SET public_key = $1 WHERE id = $2"#,
        public_key,
        user_id
    )
        .execute(pool)
        .await?;
    Ok(())
}

// Get public keys for multiple users (for E2EE key exchange)
pub async fn get_public_keys(
    pool: &sqlx::PgPool,
    user_ids: &[Uuid],
) -> Result<Vec<PublicKeyInfo>, sqlx::Error> {
    let records = sqlx::query!(
        r#"SELECT id, name, public_key FROM users WHERE id = ANY($1)"#,
        user_ids
    )
        .fetch_all(pool)
        .await?;

    Ok(records
        .into_iter()
        .map(|r| PublicKeyInfo {
            user_id: r.id,
            username: r.name,
            public_key: r.public_key,
        })
        .collect())
}

// Error types
#[derive(Debug)]
pub enum AuthError {
    InvalidCredentials,
    DatabaseError,
    HashError,
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthError::InvalidCredentials => write!(f, "Invalid email or password"),
            AuthError::DatabaseError => write!(f, "Database error occurred"),
            AuthError::HashError => write!(f, "Password hash error"),
        }
    }
}

impl std::error::Error for AuthError {}

// HTTP Request/Response types
#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub name: String,
    pub email: String,
    pub password: String,
    pub public_key: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub name: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct UpdatePublicKeyRequest {
    pub public_key: String,
}

#[derive(Debug, Serialize)]
pub struct AuthResponse {
    pub success: bool,
    pub message: String,
    pub user: Option<UserResponse>,
    pub requires_2fa: Option<bool>,
    pub temp_session_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct UserResponse {
    pub id: Uuid,
    pub name: String,
    pub email: String,
    pub public_key: Option<String>,
    pub default_ttl_seconds: Option<i32>,
}

#[derive(Debug, Serialize)]
pub struct UserSummary {
    pub id: Uuid,
    pub name: String,
    pub public_key: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct PublicKeyInfo {
    pub user_id: Uuid,
    pub username: String,
    pub public_key: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SettingsResponse {
    pub default_ttl_seconds: i32,
}

#[derive(Debug, Deserialize)]
pub struct UpdateSettingsRequest {
    pub default_ttl_seconds: i32,
}

// Password reset DTOs
#[derive(Debug, Deserialize)]
pub struct ForgotPasswordRequest { pub email: String }

#[derive(Debug, Deserialize)]
pub struct ResetPasswordRequest { pub token: String, pub new_password: String }

// HTTP Handlers
pub async fn register_handler(
    State(state): State<AppState>,
    Json(payload): Json<RegisterRequest>,
) -> Result<(StatusCode, Json<AuthResponse>), (StatusCode, Json<AuthResponse>)> {
    match register_user(
        &state.db_pool,
        &payload.name,
        &payload.email,
        &payload.password,
        payload.public_key.as_deref(),
    )
        .await
    {
        Ok(user) => {
            info!("New user registered: {} ({}) - ID: {}", user.name, user.email, user.id);
            Ok((
                StatusCode::CREATED,
                Json(AuthResponse {
                    success: true,
                    message: "User registered successfully".to_string(),
                    user: Some(UserResponse {
                        id: user.id,
                        name: user.name,
                        email: user.email,
                        public_key: user.public_key,
                        default_ttl_seconds: user.default_ttl_seconds,
                    }),
                    requires_2fa: None,
                    temp_session_id: None,
                }),
            ))
        }
        Err(e) => {
            error!("Registration error: {:?}", e);
            Err((
                StatusCode::BAD_REQUEST,
                Json(AuthResponse {
                    success: false,
                    message: "Registration failed. Email may already be in use.".to_string(),
                    user: None,
                    requires_2fa: None,
                    temp_session_id: None,
                }),
            ))
        }
    }
}

pub async fn login_handler(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(payload): Json<LoginRequest>,
) -> Result<(CookieJar, Json<AuthResponse>), (StatusCode, Json<AuthResponse>)> {
    match authenticate_user(&state.db_pool, &payload.name, &payload.password).await {
        Ok(user) => {
            // 2FA is always enabled - generate and send OTP
            let otp_code = crate::auth::two_fa::generate_otp();
            let otp_entry = crate::auth::two_fa::OtpEntry::new(otp_code.clone());

            // Store OTP
            {
                let mut otp_store = state.otp_store.lock().await;
                otp_store.insert(user.id, otp_entry);
            }

            // Send OTP email
            if let Err(e) = crate::auth::two_fa::send_otp_email(&user.email, &user.name, &otp_code).await {
                error!("Failed to send OTP email: {:?}", e);
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(AuthResponse {
                        success: false,
                        message: "Failed to send verification code".to_string(),
                        user: None,
                        requires_2fa: Some(true),
                        temp_session_id: None,
                    }),
                ));
            }

            // Create temporary session
            let temp_session_id = Uuid::new_v4().to_string();
            let temp_session = Session {
                user_id: user.id,
                username: user.name.clone(),
                created_at: Utc::now(),
            };

            {
                let mut temp_sessions = state.temp_sessions.lock().await;
                temp_sessions.insert(temp_session_id.clone(), temp_session);
            }

            info!(
                "2FA OTP sent to user {} (ID: {})",
                user.name, user.id
            );

            // Return response indicating 2FA is required
            Ok((
                jar,
                Json(AuthResponse {
                    success: true,
                    message: "Verification code sent to your email".to_string(),
                    user: None,
                    requires_2fa: Some(true),
                    temp_session_id: Some(temp_session_id),
                }),
            ))
        }
        Err(e) => {
            warn!("Login failed: {}", e);
            Err((
                StatusCode::UNAUTHORIZED,
                Json(AuthResponse {
                    success: false,
                    message: "Invalid credentials".to_string(),
                    user: None,
                    requires_2fa: None,
                    temp_session_id: None,
                }),
            ))
        }
    }
}

pub async fn logout_handler(
    State(state): State<AppState>,
    jar: CookieJar,
) -> (CookieJar, Json<serde_json::Value>) {
    if let Some(cookie) = jar.get("session_id") {
        let session_id = cookie.value();
        let mut sessions = state.sessions.lock().await;
        if let Some(session) = sessions.remove(session_id) {
            info!("User {} (ID: {}) logged out", session.username, session.user_id);
        }
    }

    // Clear cookie
    let jar = jar.remove(axum_extra::extract::cookie::Cookie::named("session_id"));

    (
        jar,
        Json(serde_json::json!({
            "success": true,
            "message": "Logged out successfully"
        })),
    )
}

pub async fn me_handler(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<Json<UserResponse>, StatusCode> {
    let session_id = jar
        .get("session_id")
        .map(|c| c.value())
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let sessions = state.sessions.lock().await;
    let session = sessions.get(session_id).ok_or(StatusCode::UNAUTHORIZED)?;

    match get_user_by_id(&state.db_pool, session.user_id).await {
        Ok(user) => Ok(Json(UserResponse {
            id: user.id,
            name: user.name,
            email: user.email,
            public_key: user.public_key,
            default_ttl_seconds: user.default_ttl_seconds,
        })),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

pub async fn update_public_key_handler(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(payload): Json<UpdatePublicKeyRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let session_id = jar
        .get("session_id")
        .map(|c| c.value())
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let sessions = state.sessions.lock().await;
    let session = sessions.get(session_id).ok_or(StatusCode::UNAUTHORIZED)?;

    match update_public_key(&state.db_pool, session.user_id, &payload.public_key).await {
        Ok(_) => {
            info!("Public key updated for user {}", session.username);
            Ok(Json(serde_json::json!({
                "success": true,
                "message": "Public key updated successfully"
            })))
        }
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

pub async fn get_public_keys_handler(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(user_ids): Json<Vec<Uuid>>,
) -> Result<Json<Vec<PublicKeyInfo>>, StatusCode> {
    // Verify user is authenticated
    let session_id = jar
        .get("session_id")
        .map(|c| c.value())
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let sessions = state.sessions.lock().await;
    sessions.get(session_id).ok_or(StatusCode::UNAUTHORIZED)?;

    match get_public_keys(&state.db_pool, &user_ids).await {
        Ok(keys) => Ok(Json(keys)),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

// List all users (for DM directory)
pub async fn list_users_handler(
    State(state): State<AppState>,
) -> Result<Json<Vec<UserSummary>>, StatusCode> {
    let rows = sqlx::query!(
        r#"SELECT id, name, public_key FROM users ORDER BY name ASC"#
    )
    .fetch_all(&state.db_pool)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let list = rows
        .into_iter()
        .map(|r| UserSummary { id: r.id, name: r.name, public_key: r.public_key })
        .collect();
    Ok(Json(list))
}

// Settings handlers
pub async fn get_settings_handler(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<Json<SettingsResponse>, StatusCode> {
    let session_id = jar
        .get("session_id")
        .map(|c| c.value())
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let sessions = state.sessions.lock().await;
    let session = sessions.get(session_id).ok_or(StatusCode::UNAUTHORIZED)?;

    let row = sqlx::query!(
        r#"SELECT COALESCE(default_ttl_seconds, 86400) AS ttl FROM users WHERE id = $1"#,
        session.user_id
    )
    .fetch_one(&state.db_pool)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(SettingsResponse { default_ttl_seconds: row.ttl.unwrap_or(86400) }))
}

pub async fn update_settings_handler(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(payload): Json<UpdateSettingsRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let session_id = jar
        .get("session_id")
        .map(|c| c.value())
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let sessions = state.sessions.lock().await;
    let session = sessions.get(session_id).ok_or(StatusCode::UNAUTHORIZED)?;

    let ttl = payload.default_ttl_seconds.max(60); // minimum 60s
    sqlx::query!(
        r#"UPDATE users SET default_ttl_seconds = $1 WHERE id = $2"#,
        ttl,
        session.user_id
    )
    .execute(&state.db_pool)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(serde_json::json!({ "success": true, "default_ttl_seconds": ttl })))
}

// --- Password reset ---
async fn send_reset_email(to_email: &str, to_name: &str, link_url: &str) -> Result<(), Box<dyn std::error::Error>> {
    let smtp_host = env::var("SMTP_HOST")?;
    let smtp_port: u16 = env::var("SMTP_PORT")?.parse()?;
    let smtp_user = env::var("SMTP_USER")?;
    let smtp_pass = env::var("SMTP_PASS")?;
    let from_email = env::var("FROM_EMAIL")?;
    let from_name = env::var("FROM_NAME").unwrap_or_else(|_| "Realtime Chat".to_string());
    let smtp_mode = env::var("SMTP_MODE").unwrap_or_else(|_| "starttls".to_string());
    let accept_invalid = env::var("SMTP_ACCEPT_INVALID_CERTS").map(|v| v.eq_ignore_ascii_case("true") || v == "1").unwrap_or(false);

    let email = Message::builder()
        .from(format!("{} <{}>", from_name, from_email).parse()?)
        .to(format!("{} <{}>", to_name, to_email).parse()?)
        .subject("Password Reset Request")
        .header(ContentType::TEXT_PLAIN)
        .body(format!(
            "Hello {},\n\nWe received a request to reset your password.\n\nClick the link to set a new password (valid for 30 minutes):\n{}\n\nIf you did not request this, you can ignore this email.",
            to_name, link_url
        ))?;

    let creds = Credentials::new(smtp_user, smtp_pass);
    let tls_params = TlsParameters::builder(smtp_host.clone())
        .dangerous_accept_invalid_certs(accept_invalid)
        .build()?;
    let mailer = match smtp_mode.as_str() {
        "wrapper" | "smtps" => SmtpTransport::relay(&smtp_host)?.port(smtp_port).tls(Tls::Wrapper(tls_params)).credentials(creds).build(),
        "insecure" | "plain" => SmtpTransport::builder_dangerous(&smtp_host).port(smtp_port).credentials(creds).build(),
        _ => SmtpTransport::relay(&smtp_host)?.port(smtp_port).tls(Tls::Required(tls_params)).credentials(creds).build(),
    };
    mailer.send(&email)?;
    Ok(())
}

pub async fn forgot_password_handler(
    State(state): State<AppState>,
    Json(payload): Json<ForgotPasswordRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    // Find user by email (do not leak existence)
    let user = sqlx::query!(r#"SELECT id, name FROM users WHERE email = $1"#, payload.email)
        .fetch_optional(&state.db_pool)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"success": false}))))?;

    if let Some(u) = user {
        let token = Uuid::new_v4().to_string();
        let expires_at = Utc::now() + ChronoDuration::minutes(30);
        let _ = sqlx::query!(
            r#"INSERT INTO password_reset_tokens (token, user_id, expires_at, used) VALUES ($1, $2, $3, FALSE)"#,
            token,
            u.id,
            expires_at
        )
        .execute(&state.db_pool)
        .await;

        let frontend = env::var("FRONTEND_URL").unwrap_or_else(|_| "http://localhost:4200".to_string());
        let link = format!("{}/reset?token={}", frontend.trim_end_matches('/'), token);
        if let Err(e) = send_reset_email(&payload.email, &u.name, &link).await {
            error!("Failed to send reset email: {:?}", e);
        }
        info!("Password reset token issued for user {}", u.id);
    }

    Ok(Json(serde_json::json!({"success": true})))
}

pub async fn reset_password_handler(
    State(state): State<AppState>,
    Json(payload): Json<ResetPasswordRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    // Lookup token
    let rec = sqlx::query!(
        r#"SELECT user_id, expires_at, used FROM password_reset_tokens WHERE token = $1"#,
        payload.token
    )
    .fetch_optional(&state.db_pool)
    .await
    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"success": false}))))?;

    let rec = match rec { Some(r) => r, None => return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({"success": false, "message": "Invalid token"})))) };
    if rec.used || rec.expires_at < Utc::now() {
        return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({"success": false, "message": "Token expired"}))));
    }

    // Hash new password
    let salt = SaltString::generate(&mut OsRng);
    let password_hash = Argon2::default()
        .hash_password(payload.new_password.as_bytes(), &salt)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"success": false}))))?
        .to_string();

    // Update user and mark token used
    let mut tx = state.db_pool.begin().await.map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"success": false}))))?;
    sqlx::query!(r#"UPDATE users SET password_hash = $1 WHERE id = $2"#, password_hash, rec.user_id)
        .execute(&mut *tx)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"success": false}))))?;
    sqlx::query!(r#"UPDATE password_reset_tokens SET used = TRUE WHERE token = $1"#, payload.token)
        .execute(&mut *tx)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"success": false}))))?;
    tx.commit().await.map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"success": false}))))?;

    Ok(Json(serde_json::json!({"success": true})))
}
