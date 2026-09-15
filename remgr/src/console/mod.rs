//! Web console: axum router, session auth, service control API.

use std::sync::Arc;

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::json;

use crate::modules::ServiceModule;
use crate::state::AppState;

const COOKIE: &str = "remgr_session";

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/api/login", post(login))
        .route("/api/logout", post(logout))
        .route("/api/status", get(status))
        .route("/api/config/:service", get(get_config).put(put_config))
        .route("/api/service/:service/:action", post(service_action))
        .route("/api/logs", get(logs))
        .route("/api/ws/logs", get(ws_logs))
        .route("/api/system/certs/generate", post(certs_generate))
        .route("/api/system/certs/upload", post(certs_upload))
        .route("/api/console/password", post(change_password))
        .layer(middleware::from_fn_with_state(state.clone(), auth_mw))
        .with_state(state)
}

// ---------------------------------------------------------------- assets

const INDEX_HTML: &str = include_str!("assets/index.html");

async fn index() -> Response {
    (
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        INDEX_HTML,
    )
        .into_response()
}

// ---------------------------------------------------------------- auth

fn new_session(state: &AppState) -> String {
    use rand::RngCore;
    let mut buf = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut buf);
    let token: String = buf.iter().map(|b| format!("{b:02x}")).collect();
    let expiry = now_unix() + state.config_blocking().console.session_ttl;
    state.sessions.lock().unwrap().insert(token.clone(), expiry);
    token
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn session_ok(state: &AppState, headers: &HeaderMap) -> bool {
    let cookie = headers
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let token = cookie
        .split(';')
        .filter_map(|c| c.trim().strip_prefix(&format!("{COOKIE}=")))
        .next()
        .unwrap_or("");
    if token.is_empty() {
        return false;
    }
    let mut sessions = state.sessions.lock().unwrap();
    match sessions.get(token) {
        Some(&expiry) if expiry > now_unix() => true,
        Some(_) => {
            sessions.remove(token);
            false
        }
        None => false,
    }
}

async fn auth_mw(
    State(state): State<Arc<AppState>>,
    req: axum::extract::Request,
    next: Next,
) -> Response {
    let path = req.uri().path();
    let public = path == "/" || path == "/api/login";
    if public {
        return next.run(req).await;
    }
    if !session_ok(&state, req.headers()) {
        return (StatusCode::UNAUTHORIZED, Json(json!({"error": "unauthorized"}))).into_response();
    }
    // CSRF: mutating requests must carry a custom header (cannot be sent
    // cross-origin without CORS, which this server never offers).
    if matches!(*req.method(), axum::http::Method::POST | axum::http::Method::PUT | axum::http::Method::DELETE) {
        if req.headers().get("x-remgr-csrf").is_none() {
            return (StatusCode::FORBIDDEN, Json(json!({"error": "missing csrf header"}))).into_response();
        }
    }
    next.run(req).await
}

#[derive(serde::Deserialize)]
struct LoginReq {
    password: String,
}

async fn login(State(state): State<Arc<AppState>>, Json(req): Json<LoginReq>) -> Response {
    let hash = state.config_blocking().console.password_hash;
    let ok = PasswordHash::new(&hash)
        .map(|parsed| Argon2::default().verify_password(req.password.as_bytes(), &parsed).is_ok())
        .unwrap_or(false);
    if !ok {
        return (StatusCode::UNAUTHORIZED, Json(json!({"error": "invalid password"}))).into_response();
    }
    let token = new_session(&state);
    let cookie = format!("{COOKIE}={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={}", state.config_blocking().console.session_ttl);
    (
        StatusCode::OK,
        [(header::SET_COOKIE, HeaderValue::from_str(&cookie).unwrap())],
        Json(json!({"ok": true})),
    )
        .into_response()
}

async fn logout(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let cookie = headers.get(header::COOKIE).and_then(|v| v.to_str().ok()).unwrap_or("");
    if let Some(token) = cookie.split(';').filter_map(|c| c.trim().strip_prefix(&format!("{COOKIE}="))).next() {
        state.sessions.lock().unwrap().remove(token);
    }
    let cookie = format!("{COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0");
    (
        StatusCode::OK,
        [(header::SET_COOKIE, HeaderValue::from_str(&cookie).unwrap())],
        Json(json!({"ok": true})),
    )
        .into_response()
}

#[derive(serde::Deserialize)]
struct PasswordChange {
    old: String,
    new: String,
}

async fn change_password(State(state): State<Arc<AppState>>, Json(req): Json<PasswordChange>) -> Response {
    let hash = state.config_blocking().console.password_hash;
    let ok = PasswordHash::new(&hash)
        .map(|parsed| Argon2::default().verify_password(req.old.as_bytes(), &parsed).is_ok())
        .unwrap_or(false);
    if !ok {
        return (StatusCode::UNAUTHORIZED, Json(json!({"error": "invalid old password"}))).into_response();
    }
    if req.new.len() < 8 {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "new password too short (min 8)"}))).into_response();
    }
    let salt = SaltString::generate(&mut rand::rngs::OsRng);
    let new_hash = match Argon2::default().hash_password(req.new.as_bytes(), &salt) {
        Ok(h) => h.to_string(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))).into_response(),
    };
    {
        let mut cfg = state.config.write().await;
        cfg.console.password_hash = new_hash;
        if let Err(e) = cfg.save() {
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))).into_response();
        }
    }
    Json(json!({"ok": true})).into_response()
}

// ---------------------------------------------------------------- status / logs

async fn status(State(state): State<Arc<AppState>>) -> Response {
    let cfg = state.config.read().await.clone();
    let services = serde_json::json!({
        "easytier": state.easytier.status().await,
        "stun_turn": state.stun_turn.status().await,
        "rustdesk": state.rustdesk.status().await,
        "frps": state.frps.status().await,
    });
    Json(json!({
        "version": env!("CARGO_PKG_VERSION"),
        "os": std::env::consts::OS,
        "uptime_s": state.started_at.elapsed().as_secs(),
        "console": {
            "port": cfg.console.port,
            "tls": cfg.console.tls,
            "password_set": !cfg.console.password_hash.is_empty(),
        },
        "services": services,
    }))
    .into_response()
}

#[derive(serde::Deserialize)]
struct LogsQuery {
    #[serde(default = "default_log_n")]
    n: usize,
}
fn default_log_n() -> usize { 300 }

async fn logs(State(state): State<Arc<AppState>>, Query(q): Query<LogsQuery>) -> Response {
    let n = q.n.clamp(1, 1000);
    Json(json!({ "lines": state.logs.snapshot(n) })).into_response()
}

async fn ws_logs(State(state): State<Arc<AppState>>, ws: WebSocketUpgrade) -> Response {
    ws.on_upgrade(move |socket| handle_log_ws(socket, state))
}

async fn handle_log_ws(socket: WebSocket, state: Arc<AppState>) {
    use futures_util::{SinkExt, StreamExt};
    let (mut sender, mut receiver) = socket.split();
    let mut rx = state.logs.subscribe();
    let send_task = tokio::spawn(async move {
        loop {
            match rx.recv().await {
                Ok(line) => {
                    if sender.send(Message::Text(line)).await.is_err() {
                        break;
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(_) => break,
            }
        }
    });
    let recv_task = tokio::spawn(async move {
        while let Some(Ok(Message::Text(_))) = receiver.next().await {
            // ignore client messages
        }
    });
    tokio::select! {
        _ = send_task => {},
        _ = recv_task => {},
    }
}

// ---------------------------------------------------------------- config

async fn get_config(State(state): State<Arc<AppState>>, Path(service): Path<String>) -> Response {
    let cfg = state.config.read().await;
    let value = match service.as_str() {
        "easytier" => serde_json::to_value(&cfg.easytier).ok(),
        "stun_turn" => serde_json::to_value(&cfg.stun_turn).ok(),
        "rustdesk" => serde_json::to_value(&cfg.rustdesk).ok(),
        "frps" => serde_json::to_value(&cfg.frps).ok(),
        "console" => {
            let base = serde_json::to_value(&cfg.console).unwrap_or(serde_json::Value::Null);
            let mut v = match base {
                serde_json::Value::Object(m) => m,
                _ => serde_json::Map::new(),
            };
            v.remove("password_hash");
            v.insert("password_set".into(), json!(!cfg.console.password_hash.is_empty()));
            Some(serde_json::Value::Object(v))
        }
        _ => None,
    };
    match value {
        Some(v) => Json(v).into_response(),
        None => api_error(StatusCode::NOT_FOUND, "unknown service"),
    }
}

async fn put_config(
    State(state): State<Arc<AppState>>,
    Path(service): Path<String>,
    Json(value): Json<serde_json::Value>,
) -> Response {
    let module = match state.module(&service) {
        Some(m) => m,
        None if service == "console" => {
            return api_error(StatusCode::NOT_FOUND, "console config is read-only here; use /api/console/password");
        }
        None => return api_error(StatusCode::NOT_FOUND, "unknown service"),
    };

    let mut new_cfg = state.config_blocking();
    let result: anyhow::Result<()> = (|| {
        match service.as_str() {
            "easytier" => new_cfg.easytier = serde_json::from_value(value)?,
            "stun_turn" => new_cfg.stun_turn = serde_json::from_value(value)?,
            "rustdesk" => new_cfg.rustdesk = serde_json::from_value(value)?,
            "frps" => new_cfg.frps = serde_json::from_value(value)?,
            _ => anyhow::bail!("unknown service"),
        }
        new_cfg.save()?;
        Ok(())
    })();

    if let Err(e) = result {
        return api_error(StatusCode::BAD_REQUEST, &e.to_string());
    }
    *state.config.write().await = new_cfg;

    match module.apply_config().await {
        Ok(()) => Json(json!({"ok": true})).into_response(),
        Err(e) => api_error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

async fn service_action(
    State(state): State<Arc<AppState>>,
    Path((service, action)): Path<(String, String)>,
) -> Response {
    let Some(module) = state.module(&service) else {
        return api_error(StatusCode::NOT_FOUND, "unknown service");
    };
    let result = match action.as_str() {
        "start" => module.start().await,
        "stop" => module.stop().await,
        "restart" => {
            module.stop().await.ok();
            module.start().await
        }
        _ => return api_error(StatusCode::BAD_REQUEST, "unknown action"),
    };
    match result {
        Ok(()) => {
            // persist the enabled flag per action for convenience
            if action == "start" || action == "stop" {
                let enabled = action == "start";
                let mut cfg = state.config_blocking();
                match service.as_str() {
                    "easytier" => cfg.easytier.enabled = enabled,
                    "stun_turn" => cfg.stun_turn.enabled = enabled,
                    "rustdesk" => cfg.rustdesk.enabled = enabled,
                    "frps" => cfg.frps.enabled = enabled,
                    _ => {}
                }
                let _ = cfg.save();
            }
            Json(json!({"ok": true})).into_response()
        }
        Err(e) => api_error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

// ---------------------------------------------------------------- certs

#[derive(serde::Deserialize)]
struct CertGenReq {
    service: String,
    domain: String,
    #[serde(default = "default_days")]
    days: u32,
}
fn default_days() -> u32 { 825 }

async fn certs_generate(State(state): State<Arc<AppState>>, Json(req): Json<CertGenReq>) -> Response {
    let dir = state.cert_dir();
    match crate::certs::generate_service_cert(&dir, &req.service, &req.domain, req.days) {
        Ok((cert_path, key_path)) => Json(json!({
            "ok": true,
            "cert_path": cert_path.display().to_string(),
            "key_path": key_path.display().to_string(),
        }))
        .into_response(),
        Err(e) => api_error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

#[derive(serde::Deserialize)]
struct CertUploadReq {
    service: String,
    cert_pem: String,
    key_pem: String,
}

async fn certs_upload(State(state): State<Arc<AppState>>, Json(req): Json<CertUploadReq>) -> Response {
    let dir = state.cert_dir();
    match crate::certs::write_service_cert(&dir, &req.service, &req.cert_pem, &req.key_pem) {
        Ok((cert_path, key_path)) => Json(json!({
            "ok": true,
            "cert_path": cert_path.display().to_string(),
            "key_path": key_path.display().to_string(),
        }))
        .into_response(),
        Err(e) => api_error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

// ---------------------------------------------------------------- helpers

fn api_error(code: StatusCode, msg: &str) -> Response {
    (code, Json(json!({"error": msg}))).into_response()
}
