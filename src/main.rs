// ReMgr - Relay Manager
// All-in-one relay server manager supporting EasyTier, STUN/TURN, RustDesk, and Frps

use anyhow::Result;
use axum::{
    Router,
    routing::{get, post, put, delete},
    http::StatusCode,
    Json,
    Extension,
    middleware,
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;

mod config;
mod easytier_server;
mod stun_turn_server;
mod rustdesk_relay;
mod frps_server;
mod web_console;
mod system;

pub use config::Config;
pub use easytier_server::EasyTierCenter;
pub use stun_turn_server::StunTurnServer;
pub use rustdesk_relay::RustDeskRelay;
pub use frps_server::FrpsServer;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceStatus {
    pub name: String,
    pub running: bool,
    pub port: Option<u16>,
    pub config: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagerState {
    pub easytier: ServiceStatus,
    pub stun_turn: ServiceStatus,
    pub rustdesk_hbbr: ServiceStatus,
    pub rustdesk_hbbs: ServiceStatus,
    pub frps: ServiceStatus,
}

pub type SharedState = Arc<RwLock<ManagerState>>;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    std::env::set_var("RUST_LOG", "info");
    tracing_subscriber::fmt::init();
    
    #[cfg(target_os = "openbsd")]
    {
        system::init_system_security()?;
    }
    
    // Load configuration
    let config = Config::load()?;
    tracing::info!("Configuration loaded from {:?}", config.config_path);
    
    // Initialize state
    let state: SharedState = Arc::new(RwLock::new(ManagerState {
        easytier: ServiceStatus {
            name: "easytier".to_string(),
            running: false,
            port: Some(config.easytier.config_port),
            config: None,
        },
        stun_turn: ServiceStatus {
            name: "stun_turn".to_string(),
            running: false,
            port: Some(config.stun_turn.stun_port),
            config: None,
        },
        rustdesk_hbbr: ServiceStatus {
            name: "rustdesk_hbbr".to_string(),
            running: false,
            port: Some(config.rustdesk.relay_port),
            config: None,
        },
        rustdesk_hbbs: ServiceStatus {
            name: "rustdesk_hbbs".to_string(),
            running: false,
            port: Some(config.rustdesk.broker_port),
            config: None,
        },
        frps: ServiceStatus {
            name: "frps".to_string(),
            running: false,
            port: Some(config.frps.server_port),
            config: None,
        },
    }));
    
    // Build web console routes
    let app = Router::new()
        .route("/api/v1/status", get(get_status))
        .route("/api/v1/easytier/config", get(get_easytier_config).post(set_easytier_config))
        .route("/api/v1/easytier/start", post(start_easytier))
        .route("/api/v1/easytier/stop", post(stop_easytier))
        .route("/api/v1/stun-turn/config", get(get_stun_turn_config).put(set_stun_turn_config))
        .route("/api/v1/stun-turn/start", post(start_stun_turn))
        .route("/api/v1/stun-turn/stop", post(stop_stun_turn))
        .route("/api/v1/rustdesk/config", get(get_rustdesk_config).put(set_rustdesk_config))
        .route("/api/v1/rustdesk/hbbr/start", post(start_rustdesk_hbbr))
        .route("/api/v1/rustdesk/hbbs/start", post(start_rustdesk_hbbs))
        .route("/api/v1/frps/config", get(get_frps_config).put(set_frps_config))
        .route("/api/v1/frps/start", post(start_frps))
        .route("/api/v1/frps/stop", post(stop_frps))
        .route("/api/v1/login", post(login))
        .route("/api/v1/auth/verify", get(verify_auth))
        .route("/ws/events", web_console::websocket_handler)
        .fallback(web_console::serve_webui)
        .layer(middleware::from_fn(web_console::auth_middleware))
        .layer(Extension(state));
    
    let addr = SocketAddr::from(([0, 0, 0, 0], config.web_port));
    tracing::info!("ReMgr starting on {}", addr);
    
    #[cfg(target_os = "openbsd")]
    {
        system::apply_pledge_unveil()?;
    }
    
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    
    Ok(())
}

// API handlers
async fn get_status(Extension(state): Extension<SharedState>) -> Json<ManagerState> {
    state.read().await.clone()
}

async fn get_easytier_config(Extension(state): Extension<SharedState>) -> Result<Json<easytier_server::Config>, StatusCode> {
    let st = state.read().await;
    if let Some(config) = &st.easytier.config {
        serde_json::from_value(config.clone()).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

async fn set_easytier_config(
    Extension(state): Extension<SharedState>,
    Json(config): Json<easytier_server::Config>,
) -> Result<StatusCode, StatusCode> {
    let mut st = state.write().await;
    st.easytier.config = Some(serde_json::to_value(config).map_err(|_| StatusCode::BAD_REQUEST)?);
    Ok(StatusCode::OK)
}

async fn start_easytier(Extension(state): Extension<SharedState>) -> Result<Json<bool>, StatusCode> {
    let st = state.read().await;
    if st.easytier.running {
        return Ok(Json(false));
    }
    drop(st);
    
    // TODO: Start easytier via FFI
    let mut st = state.write().await;
    st.easytier.running = true;
    Ok(Json(true))
}

async fn stop_easytier(Extension(state): Extension<SharedState>) -> Result<Json<bool>, StatusCode> {
    let mut st = state.write().await;
    st.easytier.running = false;
    Ok(Json(true))
}

async fn get_stun_turn_config(Extension(state): Extension<SharedState>) -> Result<Json<stun_turn_server::Config>, StatusCode> {
    let st = state.read().await;
    if let Some(config) = &st.stun_turn.config {
        serde_json::from_value(config.clone()).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

async fn set_stun_turn_config(
    Extension(state): Extension<SharedState>,
    Json(config): Json<stun_turn_server::Config>,
) -> Result<StatusCode, StatusCode> {
    let mut st = state.write().await;
    st.stun_turn.config = Some(serde_json::to_value(config).map_err(|_| StatusCode::BAD_REQUEST)?);
    Ok(StatusCode::OK)
}

async fn start_stun_turn(Extension(state): Extension<SharedState>) -> Result<Json<bool>, StatusCode> {
    let mut st = state.write().await;
    st.stun_turn.running = true;
    Ok(Json(true))
}

async fn stop_stun_turn(Extension(state): Extension<SharedState>) -> Result<Json<bool>, StatusCode> {
    let mut st = state.write().await;
    st.stun_turn.running = false;
    Ok(Json(true))
}

async fn get_rustdesk_config(Extension(state): Extension<SharedState>) -> Result<Json<rustdesk_relay::Config>, StatusCode> {
    let st = state.read().await;
    if let Some(config) = &st.rustdesk_hbbr.config {
        serde_json::from_value(config.clone()).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

async fn set_rustdesk_config(
    Extension(state): Extension<SharedState>,
    Json(config): Json<rustdesk_relay::Config>,
) -> Result<StatusCode, StatusCode> {
    let mut st = state.write().await;
    st.rustdesk_hbbr.config = Some(serde_json::to_value(config).map_err(|_| StatusCode::BAD_REQUEST)?);
    Ok(StatusCode::OK)
}

async fn start_rustdesk_hbbr(Extension(state): Extension<SharedState>) -> Result<Json<bool>, StatusCode> {
    let mut st = state.write().await;
    st.rustdesk_hbbr.running = true;
    Ok(Json(true))
}

async fn start_rustdesk_hbbs(Extension(state): Extension<SharedState>) -> Result<Json<bool>, StatusCode> {
    let mut st = state.write().await;
    st.rustdesk_hbbs.running = true;
    Ok(Json(true))
}

async fn get_frps_config(Extension(state): Extension<SharedState>) -> Result<Json<frps_server::Config>, StatusCode> {
    let st = state.read().await;
    if let Some(config) = &st.frps.config {
        serde_json::from_value(config.clone()).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

async fn set_frps_config(
    Extension(state): Extension<SharedState>,
    Json(config): Json<frps_server::Config>,
) -> Result<StatusCode, StatusCode> {
    let mut st = state.write().await;
    st.frps.config = Some(serde_json::to_value(config).map_err(|_| StatusCode::BAD_REQUEST)?);
    Ok(StatusCode::OK)
}

async fn start_frps(Extension(state): Extension<SharedState>) -> Result<Json<bool>, StatusCode> {
    let mut st = state.write().await;
    st.frps.running = true;
    Ok(Json(true))
}

async fn stop_frps(Extension(state): Extension<SharedState>) -> Result<Json<bool>, StatusCode> {
    let mut st = state.write().await;
    st.frps.running = false;
    Ok(Json(true))
}

async fn login() -> Result<Json<bool>, StatusCode> {
    Ok(Json(true))
}

async fn verify_auth() -> Result<Json<bool>, StatusCode> {
    Ok(Json(true))
}