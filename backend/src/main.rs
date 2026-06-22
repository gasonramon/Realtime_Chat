mod auth;
mod room;
use crate::auth::two_fa;

use axum::{
    routing::{get, post},
    Router,
};
use crate::room::socket;
use std::{collections::HashMap, sync::Arc};
use tokio::sync::Mutex;
use tower_http::cors::CorsLayer;
use http::header::{AUTHORIZATION, CONTENT_TYPE};
use http::Method;
use tracing::info;
use tokio::time::{sleep, Duration};

pub use room::socket::{Connection, SharedState, SessionStore, Session};
pub use two_fa::{OtpStore, OtpEntry};

// Temporary session for 2FA flow
pub type TempSessionStore = Arc<Mutex<HashMap<String, Session>>>;

#[derive(Clone)]
pub struct AppState {
    pub connections: SharedState,
    pub sessions: SessionStore,
    pub temp_sessions: TempSessionStore,
    pub otp_store: OtpStore,
    pub db_pool: sqlx::PgPool,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let db_pool = auth::connect_to_db()
        .await
        .expect("Failed to connect to database");

    let app_state = AppState {
        connections: Arc::new(Mutex::new(HashMap::new())),
        sessions: Arc::new(Mutex::new(HashMap::new())),
        temp_sessions: Arc::new(Mutex::new(HashMap::new())),
        otp_store: Arc::new(Mutex::new(HashMap::new())),
        db_pool,
    };


    {
        let pool = app_state.db_pool.clone();
        tokio::spawn(async move {
            loop {
                let _ = sqlx::query!(
                    "DELETE FROM messages WHERE expires_at < NOW()"
                )
                .execute(&pool)
                .await;
                println!("Removed expired messages");
                sleep(Duration::from_secs(3600)).await;

            }
        });
    }

    // Configure CORS to allow credentials
    let cors = CorsLayer::new()
        .allow_origin("http://localhost:4200".parse::<http::HeaderValue>().unwrap())
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE, Method::OPTIONS])
        .allow_headers([AUTHORIZATION, CONTENT_TYPE])
        .allow_credentials(true);

    let app = Router::new()
        .route("/ws", get(socket::ws_handler))
        .route("/api/register", post(auth::register_handler))
        .route("/api/login", post(auth::login_handler))
        .route("/api/logout", post(auth::logout_handler))
        .route("/api/me", get(auth::me_handler))
        .route("/api/users", get(auth::list_users_handler))
        .route("/api/public-keys", post(auth::get_public_keys_handler))
        .route("/api/update-public-key", post(auth::update_public_key_handler))
        .route("/api/settings", get(auth::get_settings_handler).post(auth::update_settings_handler))
        .route("/api/password/forgot", post(auth::forgot_password_handler))
        .route("/api/password/reset", post(auth::reset_password_handler))
        .route("/api/2fa/verify", post(two_fa::verify_otp_handler))

        .layer(cors)
        .with_state(app_state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000")
        .await
        .unwrap();

    info!("Server listening on http://0.0.0.0:3000");
    info!("WebSocket endpoint: ws://localhost:3000/ws");
    info!("API endpoints:");
    info!("  POST /api/register");
    info!("  POST /api/login");
    info!("  POST /api/logout");
    info!("  GET  /api/me");
    info!("  POST /api/public-keys");
    info!("  POST /api/update-public-key");
    info!("  POST /api/2fa/verify");

    axum::serve(listener, app).await.unwrap();
}


