// ReMgr - Relay Manager
// All-in-one relay server manager supporting EasyTier, STUN/TURN, RustDesk, and Frps

use anyhow::Result;
use axum::{
    Router,
    routing::{get, post},
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
mod ssl_cert;

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

#[derive(Debug, Clone, Serialize)]
pub struct ManagerState {
    pub easytier: ServiceStatus,
    pub stun_turn: ServiceStatus,
    pub rustdesk_hbbr: ServiceStatus,
    pub rustdesk_hbbs: ServiceStatus,
    pub frps: ServiceStatus,
    pub web_port: u16,
    pub cert_dir: String,
    pub default_domain: String,
    // 服务实例
    #[serde(skip)]
    pub easytier_instance: Arc<RwLock<EasyTierCenter>>,
    #[serde(skip)]
    pub stun_turn_instance: Arc<RwLock<StunTurnServer>>,
    #[serde(skip)]
    pub rustdesk_hbbr_instance: Arc<RwLock<RustDeskRelay>>,
    #[serde(skip)]
    pub rustdesk_hbbs_instance: Arc<RwLock<RustDeskRelay>>,
    #[serde(skip)]
    pub frps_instance: Arc<RwLock<FrpsServer>>,
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

    // Initialize service instances (wrapped in Arc<RwLock<>> for shared state)
    let easytier_instance = Arc::new(RwLock::new(EasyTierCenter::new(easytier_server::Config::default())));
    let stun_turn_instance = Arc::new(RwLock::new(StunTurnServer::new(stun_turn_server::Config::default())));
    let rustdesk_hbbr_instance = Arc::new(RwLock::new(RustDeskRelay::new(rustdesk_relay::Config::default())));
    let rustdesk_hbbs_instance = Arc::new(RwLock::new(RustDeskRelay::new(rustdesk_relay::Config::default())));
    let frps_instance = Arc::new(RwLock::new(FrpsServer::new(frps_server::Config::default())));

    // Initialize state
    let state: SharedState = Arc::new(RwLock::new(ManagerState {
        easytier: ServiceStatus {
            name: "easytier".to_string(),
            running: false,
            port: Some(config.easytier.config_port),
            config: Some(serde_json::to_value(easytier_server::Config {
                enabled: config.easytier.enabled,
                config_port: config.easytier.config_port,
                api_port: config.easytier.api_port,
                db_path: config.easytier.db_path.to_string_lossy().to_string(),
                log_dir: config.easytier.log_dir.to_string_lossy().to_string(),
                domains: config.easytier.domains.clone(),
                ssl_cert: config.easytier.ssl_cert.as_ref().map(|p| p.to_string_lossy().to_string()),
                ssl_key: config.easytier.ssl_key.as_ref().map(|p| p.to_string_lossy().to_string()),
                network_name: None,
                network_secret: None,
            })?),
        },
        stun_turn: ServiceStatus {
            name: "stun_turn".to_string(),
            running: false,
            port: Some(config.stun_turn.stun_port),
            config: Some(serde_json::to_value(stun_turn_server::Config {
                enabled: config.stun_turn.enabled,
                stun_port: config.stun_turn.stun_port,
                turn_port: config.stun_turn.turn_port,
                tls_port: config.stun_turn.tls_port,
                domain: config.stun_turn.domain.clone(),
                ssl_cert: config.stun_turn.ssl_cert.to_string_lossy().to_string(),
                ssl_key: config.stun_turn.ssl_key.to_string_lossy().to_string(),
                min_port: config.stun_turn.min_port,
                max_port: config.stun_turn.max_port,
                users: config.stun_turn.users.clone(),
                log_file: config.stun_turn.log_file.to_string_lossy().to_string(),
                relay_ip: config.stun_turn.relay_ip.clone(),
            })?),
        },
        rustdesk_hbbr: ServiceStatus {
            name: "rustdesk_hbbr".to_string(),
            running: false,
            port: Some(config.rustdesk.relay_port),
            config: Some(serde_json::to_value(rustdesk_relay::Config {
                enabled: config.rustdesk.enabled,
                relay_port: config.rustdesk.relay_port,
                broker_port: config.rustdesk.broker_port,
                key_path: config.rustdesk.key_path.to_string_lossy().to_string(),
                db_path: config.rustdesk.db_path.to_string_lossy().to_string(),
                token_expiry: config.rustdesk.token_expiry,
                max_connections: config.rustdesk.max_connections,
                bandwidth_limit: config.rustdesk.bandwidth_limit,
            })?),
        },
        rustdesk_hbbs: ServiceStatus {
            name: "rustdesk_hbbs".to_string(),
            running: false,
            port: Some(config.rustdesk.broker_port),
            config: Some(serde_json::to_value(rustdesk_relay::Config {
                enabled: config.rustdesk.enabled,
                relay_port: config.rustdesk.relay_port,
                broker_port: config.rustdesk.broker_port,
                key_path: config.rustdesk.key_path.to_string_lossy().to_string(),
                db_path: config.rustdesk.db_path.to_string_lossy().to_string(),
                token_expiry: config.rustdesk.token_expiry,
                max_connections: config.rustdesk.max_connections,
                bandwidth_limit: config.rustdesk.bandwidth_limit,
            })?),
        },
        frps: ServiceStatus {
            name: "frps".to_string(),
            running: false,
            port: Some(config.frps.server_port),
            config: Some(serde_json::to_value(frps_server::Config {
                enabled: config.frps.enabled,
                server_port: config.frps.server_port,
                dashboard_port: config.frps.dashboard_port,
                vhost_http_port: config.frps.vhost_http_port,
                vhost_https_port: config.frps.vhost_https_port,
                token: config.frps.token.clone(),
                dashboard_user: config.frps.dashboard_user.clone(),
                dashboard_pwd: config.frps.dashboard_pwd.clone(),
                max_pool_count: config.frps.max_pool_count,
                sub_modules_per_pool: config.frps.sub_modules_per_pool,
                tcp_mux: config.frps.tcp_mux,
                allow_local_routes: config.frps.allow_local_routes,
                bind_addr: config.frps.bind_addr.clone(),
            })?),
        },
        web_port: config.web_port,
        cert_dir: "/etc/remgr/ssl".to_string(),
        default_domain: config.stun_turn.domain.clone(),
        easytier_instance,
        stun_turn_instance,
        rustdesk_hbbr_instance,
        rustdesk_hbbs_instance,
        frps_instance,
    }));

    // Build web console routes
    let app = Router::new()
        .route("/api/v1/status", get(get_status))
        .route("/api/v1/easytier/config", get(get_easytier_config).post(set_easytier_config).put(set_easytier_config))
        .route("/api/v1/easytier/start", post(start_easytier))
        .route("/api/v1/easytier/stop", post(stop_easytier))
        .route("/api/v1/stun-turn/config", get(get_stun_turn_config).put(set_stun_turn_config))
        .route("/api/v1/stun-turn/start", post(start_stun_turn))
        .route("/api/v1/stun-turn/stop", post(stop_stun_turn))
        .route("/api/v1/rustdesk/config", get(get_rustdesk_config).put(set_rustdesk_config))
        .route("/api/v1/rustdesk/hbbr/start", post(start_rustdesk_hbbr))
        .route("/api/v1/rustdesk/hbbs/start", post(start_rustdesk_hbbs))
        .route("/api/v1/rustdesk/stop", post(stop_rustdesk))
        .route("/api/v1/frps/config", get(get_frps_config).put(set_frps_config))
        .route("/api/v1/frps/start", post(start_frps))
        .route("/api/v1/frps/stop", post(stop_frps))
        .route("/api/v1/system/config", get(get_system_config))
        .route("/api/v1/system/generate-cert", post(generate_cert))
        .route("/api/v1/login", post(login))
        .route("/api/v1/auth/verify", get(verify_auth))
        .route("/ws/events", get(web_console::websocket_handler))
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

// Status - returns current state
async fn get_status(Extension(state): Extension<SharedState>) -> Json<ManagerState> {
    Json(state.read().await.clone())
}

// EasyTier config handlers
async fn get_easytier_config(Extension(state): Extension<SharedState>) -> Json<easytier_server::Config> {
    let st = state.read().await;
    let cfg: easytier_server::Config = st.easytier.config.as_ref()
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();
    Json(cfg)
}

async fn set_easytier_config(
    Extension(state): Extension<SharedState>,
    Json(config): Json<easytier_server::Config>,
) -> Result<StatusCode, StatusCode> {
    let mut st = state.write().await;
    st.easytier.config = Some(serde_json::to_value(config).map_err(|_| StatusCode::BAD_REQUEST)?);
    log::info!("EasyTier config updated");
    Ok(StatusCode::OK)
}

async fn start_easytier(Extension(state): Extension<SharedState>) -> Json<bool> {
    let mut st = state.write().await;
    if st.easytier.running {
        return Json(false);
    }
    st.easytier.running = true;
    let inst = st.easytier_instance.read().await;
    inst.start().await.map_err(|_| ()).unwrap_or(());
    Json(true)
}

async fn stop_easytier(Extension(state): Extension<SharedState>) -> Json<bool> {
    let mut st = state.write().await;
    st.easytier.running = false;
    let inst = st.easytier_instance.read().await;
    inst.stop().await.ok();
    Json(true)
}

// STUN/TURN config handlers
async fn get_stun_turn_config(Extension(state): Extension<SharedState>) -> Json<stun_turn_server::Config> {
    let st = state.read().await;
    let cfg = st.stun_turn.config.as_ref()
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();
    Json(cfg)
}

async fn set_stun_turn_config(
    Extension(state): Extension<SharedState>,
    Json(config): Json<stun_turn_server::Config>,
) -> Result<StatusCode, StatusCode> {
    let mut st = state.write().await;
    st.stun_turn.config = Some(serde_json::to_value(config).map_err(|_| StatusCode::BAD_REQUEST)?);
    log::info!("STUN/TURN config updated");
    Ok(StatusCode::OK)
}

async fn start_stun_turn(Extension(state): Extension<SharedState>) -> Json<bool> {
    let mut st = state.write().await;
    if st.stun_turn.running {
        return Json(false);
    }
    st.stun_turn.running = true;
    let mut inst = st.stun_turn_instance.write().await;
    inst.start().await.ok();
    Json(true)
}

async fn stop_stun_turn(Extension(state): Extension<SharedState>) -> Json<bool> {
    let mut st = state.write().await;
    st.stun_turn.running = false;
    let mut inst = st.stun_turn_instance.write().await;
    inst.stop().await.ok();
    Json(true)
}

// RustDesk config handlers
async fn get_rustdesk_config(Extension(state): Extension<SharedState>) -> Json<rustdesk_relay::Config> {
    let st = state.read().await;
    let cfg = st.rustdesk_hbbr.config.as_ref()
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();
    Json(cfg)
}

async fn set_rustdesk_config(
    Extension(state): Extension<SharedState>,
    Json(config): Json<rustdesk_relay::Config>,
) -> Result<StatusCode, StatusCode> {
    let mut st = state.write().await;
    st.rustdesk_hbbr.config = Some(serde_json::to_value(config).map_err(|_| StatusCode::BAD_REQUEST)?);
    st.rustdesk_hbbs.config = st.rustdesk_hbbr.config.clone();
    log::info!("RustDesk config updated");
    Ok(StatusCode::OK)
}

async fn start_rustdesk_hbbr(Extension(state): Extension<SharedState>) -> Json<bool> {
    let mut st = state.write().await;
    if st.rustdesk_hbbr.running {
        return Json(false);
    }
    st.rustdesk_hbbr.running = true;
    let mut inst = st.rustdesk_hbbr_instance.write().await;
    inst.start_relay().await.ok();
    Json(true)
}

async fn start_rustdesk_hbbs(Extension(state): Extension<SharedState>) -> Json<bool> {
    let mut st = state.write().await;
    if st.rustdesk_hbbs.running {
        return Json(false);
    }
    st.rustdesk_hbbs.running = true;
    let mut inst = st.rustdesk_hbbs_instance.write().await;
    inst.start_broker().await.ok();
    Json(true)
}

async fn stop_rustdesk(Extension(state): Extension<SharedState>) -> Json<bool> {
    let mut st = state.write().await;
    st.rustdesk_hbbr.running = false;
    st.rustdesk_hbbs.running = false;
    let mut inst = st.rustdesk_hbbr_instance.write().await;
    inst.stop().await.ok();
    Json(true)
}

// Frps config handlers
async fn get_frps_config(Extension(state): Extension<SharedState>) -> Json<frps_server::Config> {
    let st = state.read().await;
    let cfg = st.frps.config.as_ref()
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();
    Json(cfg)
}

async fn set_frps_config(
    Extension(state): Extension<SharedState>,
    Json(config): Json<frps_server::Config>,
) -> Result<StatusCode, StatusCode> {
    let mut st = state.write().await;
    st.frps.config = Some(serde_json::to_value(config).map_err(|_| StatusCode::BAD_REQUEST)?);
    log::info!("Frps config updated");
    Ok(StatusCode::OK)
}

async fn start_frps(Extension(state): Extension<SharedState>) -> Json<bool> {
    let mut st = state.write().await;
    if st.frps.running {
        return Json(false);
    }
    st.frps.running = true;
    let mut inst = st.frps_instance.write().await;
    inst.start().await.ok();
    Json(true)
}

async fn stop_frps(Extension(state): Extension<SharedState>) -> Json<bool> {
    let mut st = state.write().await;
    st.frps.running = false;
    let mut inst = st.frps_instance.write().await;
    inst.stop().await.ok();
    Json(true)
}

// System config handlers - for web_port, SSL certs, etc.
#[derive(serde::Deserialize)]
struct CertRequest {
    domain: Option<String>,
    base_dir: Option<String>,
}

async fn get_system_config(Extension(state): Extension<SharedState>) -> Json<serde_json::Value> {
    let st = state.read().await.clone();
    let cert_file = std::path::Path::new(&st.cert_dir).join(ssl_cert::DEFAULT_CERT_FILE);
    let cert_exists = cert_file.exists();
    Json(serde_json::json!({
        "web_port": st.web_port,
        "cert_dir": st.cert_dir,
        "default_domain": st.default_domain,
        "cert_present": cert_exists,
        "ssl_curve": "P-384"
    }))
}

async fn generate_cert(Json(req): Json<CertRequest>) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let domain = req.domain.unwrap_or_else(|| "remgr.local".to_string());
    let base_dir = req.base_dir
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("/etc/remgr/ssl"));
    match ssl_cert::generate_all_service_certs(&base_dir, &domain) {
        Ok(list) => {
            let out: Vec<_> = list.into_iter().map(|(svc, c)| {
                serde_json::json!({
                    "service": svc,
                    "cert_path": c.cert_path.display().to_string(),
                    "key_path": c.key_path.display().to_string(),
                    "cert_exists": c.cert_path.exists(),
                    "key_exists": c.key_path.exists()
                })
            }).collect();
            Ok(Json(serde_json::json!({"status": "ok", "certs": out})))
        }
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
    }
}

// Auth handlers
async fn login() -> Json<bool> {
    Json(true)
}

async fn verify_auth() -> Json<bool> {
    Json(true)
}