use crate::{AppState, Session};
use axum::{extract::State, http::StatusCode, Json};
use axum_extra::extract::CookieJar;
use chrono::{DateTime, Duration, Utc};
use lettre::{
    message::header::ContentType, transport::smtp::authentication::Credentials,
    transport::smtp::client::{Tls, TlsParameters}, Message, SmtpTransport, Transport,
};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{error, info};
use uuid::Uuid;

// OTP storage
pub type OtpStore = Arc<Mutex<HashMap<Uuid, OtpEntry>>>;

#[derive(Clone, Debug)]
pub struct OtpEntry {
    pub code: String,
    pub expires_at: DateTime<Utc>,
    pub attempts: u32,
}

impl OtpEntry {
    pub fn new(code: String) -> Self {
        Self {
            code,
            expires_at: Utc::now() + Duration::minutes(10),
            attempts: 0,
        }
    }

    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    pub fn is_locked(&self) -> bool {
        self.attempts >= 3
    }
}

// Generate a 6-digit OTP
pub fn generate_otp() -> String {
    let mut rng = rand::thread_rng();
    format!("{:06}", rng.gen_range(0..1000000))
}

// Send OTP via email
pub async fn send_otp_email(
    to_email: &str,
    to_name: &str,
    otp_code: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let smtp_host = env::var("SMTP_HOST")?;
    let smtp_port: u16 = env::var("SMTP_PORT")?.parse()?;
    let smtp_user = env::var("SMTP_USER")?;
    let smtp_pass = env::var("SMTP_PASS")?;
    let from_email = env::var("FROM_EMAIL")?;
    let from_name = env::var("FROM_NAME").unwrap_or_else(|_| "Realtime Chat".to_string());
    // Optional configuration to help with various SMTP providers and Windows TLS issues
    let smtp_mode = env::var("SMTP_MODE").unwrap_or_else(|_| "starttls".to_string()); // starttls | wrapper | insecure
    let accept_invalid = env::var("SMTP_ACCEPT_INVALID_CERTS")
        .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
        .unwrap_or(false);

    let email = Message::builder()
        .from(format!("{} <{}>", from_name, from_email).parse()?)
        .to(format!("{} <{}>", to_name, to_email).parse()?)
        .subject("Your Login Verification Code")
        .header(ContentType::TEXT_PLAIN)
        .body(format!(
            "Hello {},\n\n\
            Your verification code is: {}\n\n\
            This code will expire in 10 minutes.\n\
            If you didn't request this code, please ignore this email.\n\n\
            Best regards,\n\
            Code Exploration Real Time Chat Team",
            to_name, otp_code
        ))?;

    let creds = Credentials::new(smtp_user, smtp_pass);

    // Build TLS parameters (optionally allow invalid certs for dev/self-signed endpoints)
    let tls_params = TlsParameters::builder(smtp_host.clone())
        .dangerous_accept_invalid_certs(accept_invalid)
        .build()?;

    // Select transport based on mode
    let mailer = match smtp_mode.as_str() {
        // Implicit TLS (SMTPS), typically port 465
        "wrapper" | "smtps" => {
            SmtpTransport::relay(&smtp_host)?
                .port(smtp_port)
                .tls(Tls::Wrapper(tls_params))
                .credentials(creds)
                .build()
        }
        // No TLS (for local dev tools like smtp4dev/MailHog); do not use in production
        "insecure" | "plain" => SmtpTransport::builder_dangerous(&smtp_host)
            .port(smtp_port)
            .credentials(creds)
            .build(),
        // Default STARTTLS (usually port 587)
        _ => SmtpTransport::relay(&smtp_host)?
            .port(smtp_port)
            .tls(Tls::Required(tls_params))
            .credentials(creds)
            .build(),
    };

    mailer.send(&email)?;

    Ok(())
}

// Request/Response types
#[derive(Debug, Deserialize)]
pub struct VerifyOtpRequest {
    pub otp_code: String,
    pub temp_session_id: String,
}

#[derive(Debug, Serialize)]
pub struct TwoFaResponse {
    pub success: bool,
    pub message: String,
    pub requires_otp: Option<bool>,
    pub temp_session_id: Option<String>,
}

// HTTP Handlers
pub async fn verify_otp_handler(
    State(state): State<AppState>,
    Json(payload): Json<VerifyOtpRequest>,
) -> Result<(CookieJar, Json<TwoFaResponse>), (StatusCode, Json<TwoFaResponse>)> {
    let temp_sessions = state.temp_sessions.lock().await;
    let temp_session = temp_sessions
        .get(&payload.temp_session_id)
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(TwoFaResponse {
                    success: false,
                    message: "Invalid or expired session".to_string(),
                    requires_otp: None,
                    temp_session_id: None,
                }),
            )
        })?;

    // Clone needed data before dropping lock
    let user_id = temp_session.user_id;
    let username = temp_session.username.clone();
    drop(temp_sessions);

    // Get the OTP entry
    let mut otp_store = state.otp_store.lock().await;
    let otp_entry = otp_store.get_mut(&user_id).ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(TwoFaResponse {
                success: false,
                message: "No OTP found. Please request a new one.".to_string(),
                requires_otp: None,
                temp_session_id: None,
            }),
        )
    })?;

    // Check if OTP is expired
    if otp_entry.is_expired() {
        otp_store.remove(&user_id);
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(TwoFaResponse {
                success: false,
                message: "OTP has expired. Please request a new one.".to_string(),
                requires_otp: None,
                temp_session_id: None,
            }),
        ));
    }

    // Check if account is locked due to too many attempts
    if otp_entry.is_locked() {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            Json(TwoFaResponse {
                success: false,
                message: "Too many failed attempts. Please request a new OTP.".to_string(),
                requires_otp: None,
                temp_session_id: None,
            }),
        ));
    }

    // Verify OTP code
    if otp_entry.code != payload.otp_code {
        otp_entry.attempts += 1;
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(TwoFaResponse {
                success: false,
                message: format!(
                    "Invalid OTP code. {} attempts remaining.",
                    3 - otp_entry.attempts
                ),
                requires_otp: None,
                temp_session_id: None,
            }),
        ));
    }

    // OTP is valid - create actual session
    let session_id = Uuid::new_v4().to_string();
    let session = Session {
        user_id,
        username: username.clone(),
        created_at: Utc::now(),
    };

    // Clean up OTP
    otp_store.remove(&user_id);
    drop(otp_store);

    // Store the actual session
    let mut sessions = state.sessions.lock().await;
    sessions.insert(session_id.clone(), session);
    drop(sessions);

    // Clean up temp session
    let mut temp_sessions = state.temp_sessions.lock().await;
    temp_sessions.remove(&payload.temp_session_id);

    // Create secure cookie
    let cookie = format!(
        "session_id={}; HttpOnly; SameSite=Lax; Path=/; Max-Age=86400",
        session_id
    );
    let jar = CookieJar::new();
    let jar = jar.add(axum_extra::extract::cookie::Cookie::parse(cookie).unwrap());

    info!(
        "User {} (ID: {}) completed 2FA verification",
        username, user_id
    );

    Ok((
        jar,
        Json(TwoFaResponse {
            success: true,
            message: "Login successful".to_string(),
            requires_otp: None,
            temp_session_id: None,
        }),
    ))
}
