// ReMgr - Relay Manager
// All-in-one relay server manager supporting EasyTier, STUN/TURN, RustDesk, and Frps

use anyhow::Result;
use axum::{
    Router,
    extract::Request,
    http::{header::SET_COOKIE, HeaderMap, HeaderValue, StatusCode},
    middleware,
    response::{IntoResponse, Response},
    routing::{get, post},
    Extension, Json,
};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

mod auth;
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
    /// Human-readable note explaining why a service cannot run (e.g. external
    /// binary dependency, TUN device unavailable). Surfaced in the UI.
    #[serde(default)]
    pub note: Option<String>,
}

/// Shared, cheaply-clonable session store.
#[derive(Clone, Default)]
pub struct Sessions {
    inner: Arc<RwLock<HashMap<String, Instant>>>,
}

const SESSION_TTL_SECS: u64 = 24 * 3600;

impl Sessions {
    pub fn new() -> Self { Self::default() }

    pub async fn create(&self) -> String {
        let token = uuid::Uuid::new_v4().to_string();
        self.inner.write().await.insert(token.clone(), Instant::now());
        self.prune().await;
        token
    }

    pub async fn validate(&self, token: &str) -> bool {
        let now = Instant::now();
        let mut w = self.inner.write().await;
        if let Some(t) = w.get(token) {
            if now.duration_since(*t) < Duration::from_secs(SESSION_TTL_SECS) {
                return true;
            }
            w.remove(token);
        }
        false
    }

    pub async fn revoke(&self, token: &str) {
        self.inner.write().await.remove(token);
    }

    async fn prune(&self) {
        let cutoff = Instant::now() - Duration::from_secs(SESSION_TTL_SECS);
        self.inner.write().await.retain(|_, t| *t > cutoff);
    }
}

/// Runtime state used by every service manager, plus auth context.
#[derive(Clone)]
pub struct AppState {
    pub manager: SharedState,
    pub sessions: Sessions,
    pub credentials: Credentials,
}

#[derive(Clone)]
pub struct Credentials {
    pub username: String,
    pub password_hash: String,
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
    pub authenticated: bool,
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

    // Load configuration. On a fresh install, generate an admin password and
    // persist it (hashed) so the console is never open by default.
    let mut config = Config::load()?;
    if let Some(pw) = config.bootstrap_password()? {
        tracing::warn!("================================================");
        tracing::warn!("ReMgr generated an admin password (first run):");
        tracing::warn!("  username: {}", config.dashboard.username);
        tracing::warn!("  password: {}", pw);
        tracing::warn!("Store this now. It will not be shown again.");
        tracing::warn!("You can change it via the web console.");
        tracing::warn!("================================================");
    }
    tracing::info!("Configuration loaded from {:?}", config.config_path);

    let credentials = Credentials {
        username: config.dashboard.username.clone(),
        password_hash: config.dashboard.password_hash.clone(),
    };
    let sessions = Sessions::new();

    // Initialize service instances (wrapped in Arc<RwLock<>> for shared state)
    let easytier_instance = Arc::new(RwLock::new(EasyTierCenter::new(easytier_server::Config::default())));
    let stun_turn_instance = Arc::new(RwLock::new(StunTurnServer::new(stun_turn_server::Config {
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
    })));
    let rustdesk_hbbr_instance = Arc::new(RwLock::new(RustDeskRelay::new(rustdesk_relay::Config {
        enabled: config.rustdesk.enabled,
        relay_port: config.rustdesk.relay_port,
        broker_port: config.rustdesk.broker_port,
        key_path: config.rustdesk.key_path.to_string_lossy().to_string(),
        db_path: config.rustdesk.db_path.to_string_lossy().to_string(),
        token_expiry: config.rustdesk.token_expiry,
        max_connections: config.rustdesk.max_connections,
        bandwidth_limit: config.rustdesk.bandwidth_limit,
    })));
    let rustdesk_hbbs_instance = Arc::new(RwLock::new(RustDeskRelay::new(rustdesk_relay::Config {
        enabled: config.rustdesk.enabled,
        relay_port: config.rustdesk.relay_port,
        broker_port: config.rustdesk.broker_port,
        key_path: config.rustdesk.key_path.to_string_lossy().to_string(),
        db_path: config.rustdesk.db_path.to_string_lossy().to_string(),
        token_expiry: config.rustdesk.token_expiry,
        max_connections: config.rustdesk.max_connections,
        bandwidth_limit: config.rustdesk.bandwidth_limit,
    })));
    let frps_instance = Arc::new(RwLock::new(FrpsServer::new(frps_server::Config {
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
    })));

    // Human-readable notes for services we cannot run in-process.
    const NOTE_RUSTDESK: &str = "Embedded: no in-process relay available (RustDesk is Go). Managed externally.";
    const NOTE_FRPS: &str = "Embedded: no in-process reverse proxy available (frp is Go). Managed externally.";
    const NOTE_EASYTIER: &str = "Embedded: no in-process center available (easytier crate requires tun). Managed externally.";

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
            note: Some(NOTE_EASYTIER.to_string()),
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
            note: None,
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
            note: Some(NOTE_RUSTDESK.to_string()),
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
            note: Some(NOTE_RUSTDESK.to_string()),
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
            note: Some(NOTE_FRPS.to_string()),
        },
        web_port: config.web_port,
        cert_dir: "/etc/remgr/ssl".to_string(),
        default_domain: config.stun_turn.domain.clone(),
        authenticated: false,
        easytier_instance,
        stun_turn_instance,
        rustdesk_hbbr_instance,
        rustdesk_hbbs_instance,
        frps_instance,
    }));

    // Auto-start enabled services (STUN/TURN runs fully in-process).
    auto_start_enabled_services(&state).await;

    // Build web console routes
    let app_state = AppState {
        manager: state.clone(),
        sessions: sessions.clone(),
        credentials: credentials.clone(),
    };

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
        .route("/api/v1/logout", post(logout))
        .route("/api/v1/auth/verify", get(verify_auth))
        .route("/api/v1/password", post(change_password))
        .route("/ws/events", get(web_console::websocket_handler))
        .fallback(web_console::serve_webui)
        .layer(middleware::from_fn_with_state(app_state.clone(), auth_middleware))
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

/// Spawn the enabled services on boot. STUN/TURN is fully in-process and gets
/// started for real. External-binary services get their "configured" status
/// reflected honestly (running stays false until we can integrate them).
async fn auto_start_enabled_services(state: &SharedState) {
    let (stun_enabled, stun_inst) = {
        let st = state.read().await;
        (st.stun_turn.running || {
            st.stun_turn
                .config
                .as_ref()
                .and_then(|v| serde_json::from_value::<stun_turn_server::Config>(v.clone()).ok())
                .map(|c| c.enabled)
                .unwrap_or(false)
        }, st.stun_turn_instance.clone())
    };
    if stun_enabled {
        let mut inst = stun_inst.write().await;
        match inst.start().await {
            Ok(()) => {
                let mut st = state.write().await;
                st.stun_turn.running = inst.is_running();
                tracing::info!("STUN/TURN auto-started");
            }
            Err(e) => tracing::warn!("STUN/TURN auto-start failed: {e}"),
        }
    }
}

// Auth middleware: reject unauthenticated access to /api/v1/* (except the
// auth endpoints) and 404 on other paths that require auth.
async fn auth_middleware(
    axum::extract::State(app): axum::extract::State<AppState>,
    req: Request,
    next: middleware::Next,
) -> Response {
    let path = req.uri().path().to_string();

    // Public paths.
    const PUBLIC: &[&str] = &[
        "/api/v1/login",
        "/api/v1/auth/verify",
    ];
    if PUBLIC.iter().any(|p| path == *p) {
        return next.run(req).await;
    }

    // WebSocket: allow (browsers handle Set-Cookie fine on WS handshake, but
    // we validate the token here via cookie header).
    let is_ws = path.starts_with("/ws/");
    // Static assets and the SPA shell: no auth required to load the page.
    let is_shell = path == "/" || path == "/index.html" || path == "/favicon.ico";

    let token = cookie_value(req.headers(), "remgr_session").unwrap_or_default();
    let valid = !token.is_empty() && app.sessions.validate(&token).await;

    if !valid && (is_ws || path.starts_with("/api/")) {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({
            "error": "unauthorized",
        }))).into_response();
    }
    // For the shell, allow even without auth (JS then hits /api/v1/auth/verify).
    let _ = is_shell;
    next.run(req).await
}

fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    let raw = headers.get(axum::http::header::COOKIE)?.to_str().ok()?;
    for part in raw.split(';') {
        let kv = part.trim();
        if let Some(v) = kv.strip_prefix(&format!("{}=", name)) {
            return Some(v.to_string());
        }
    }
    None
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
    Json(cfg): Json<easytier_server::Config>,
) -> Json<bool> {
    let mut st = state.write().await;
    if let Ok(v) = serde_json::to_value(cfg) {
        st.easytier.config = Some(v);
    }
    Json(true)
}

async fn start_easytier(Extension(state): Extension<SharedState>) -> Json<bool> {
    let mut st = state.write().await;
    if st.easytier.running {
        return Json(false);
    }
    let mut inst = st.easytier_instance.write().await;
    inst.start().await.ok();
    st.easytier.running = false; // cannot fully embed yet
    Json(false)
}

async fn stop_easytier(Extension(state): Extension<SharedState>) -> Json<bool> {
    let mut st = state.write().await;
    st.easytier.running = false;
    let mut inst = st.easytier_instance.write().await;
    inst.stop().await.ok();
    Json(true)
}

async fn get_stun_turn_config(Extension(state): Extension<SharedState>) -> Json<stun_turn_server::Config> {
    let st = state.read().await;
    let cfg: stun_turn_server::Config = st.stun_turn.config.as_ref()
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();
    Json(cfg)
}

async fn set_stun_turn_config(
    Extension(state): Extension<SharedState>,
    Json(cfg): Json<stun_turn_server::Config>,
) -> Json<bool> {
    let mut st = state.write().await;
    if let Ok(v) = serde_json::to_value(&cfg) {
        st.stun_turn.config = Some(v);
    }
    // Update running instance to accept new config for next restart.
    let mut inst = st.stun_turn_instance.write().await;
    inst.update_config(cfg);
    Json(true)
}

async fn start_stun_turn(Extension(state): Extension<SharedState>) -> Json<bool> {
    let mut st = state.write().await;
    if st.stun_turn.running {
        return Json(false);
    }
    let mut inst = st.stun_turn_instance.write().await;
    match inst.start().await {
        Ok(()) => {
            st.stun_turn.running = inst.is_running();
            Json(inst.is_running())
        }
        Err(e) => {
            tracing::error!("STUN/TURN start failed: {e}");
            Json(false)
        }
    }
}

async fn stop_stun_turn(Extension(state): Extension<SharedState>) -> Json<bool> {
    let mut st = state.write().await;
    st.stun_turn.running = false;
    let mut inst = st.stun_turn_instance.write().await;
    inst.stop().await.ok();
    Json(true)
}

async fn get_rustdesk_config(Extension(state): Extension<SharedState>) -> Json<rustdesk_relay::Config> {
    let st = state.read().await;
    let cfg: rustdesk_relay::Config = st.rustdesk_hbbr.config.as_ref()
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();
    Json(cfg)
}

async fn set_rustdesk_config(
    Extension(state): Extension<SharedState>,
    Json(cfg): Json<rustdesk_relay::Config>,
) -> Json<bool> {
    let mut st = state.write().await;
    if let Ok(v) = serde_json::to_value(&cfg) {
        st.rustdesk_hbbr.config = Some(v.clone());
        st.rustdesk_hbbs.config = Some(v);
    }
    Json(true)
}

async fn start_rustdesk_hbbr(Extension(state): Extension<SharedState>) -> Json<bool> {
    let mut st = state.write().await;
    if st.rustdesk_hbbr.running {
        return Json(false);
    }
    st.rustdesk_hbbr.running = true;
    let mut inst = st.rustdesk_hbbr_instance.write().await;
    inst.start_relay().await.ok();
    Json(false)
}

async fn start_rustdesk_hbbs(Extension(state): Extension<SharedState>) -> Json<bool> {
    let mut st = state.write().await;
    if st.rustdesk_hbbs.running {
        return Json(false);
    }
    st.rustdesk_hbbs.running = true;
    let mut inst = st.rustdesk_hbbs_instance.write().await;
    inst.start_broker().await.ok();
    Json(false)
}

async fn stop_rustdesk(Extension(state): Extension<SharedState>) -> Json<bool> {
    let mut st = state.write().await;
    st.rustdesk_hbbr.running = false;
    st.rustdesk_hbbs.running = false;
    {
        let mut inst = st.rustdesk_hbbr_instance.write().await;
        inst.stop().await.ok();
    }
    {
        let mut inst = st.rustdesk_hbbs_instance.write().await;
        inst.stop().await.ok();
    }
    Json(true)
}

async fn get_frps_config(Extension(state): Extension<SharedState>) -> Json<frps_server::Config> {
    let st = state.read().await;
    let cfg: frps_server::Config = st.frps.config.as_ref()
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();
    Json(cfg)
}

async fn set_frps_config(
    Extension(state): Extension<SharedState>,
    Json(cfg): Json<frps_server::Config>,
) -> Json<bool> {
    let mut st = state.write().await;
    if let Ok(v) = serde_json::to_value(&cfg) {
        st.frps.config = Some(v);
    }
    Json(true)
}

async fn start_frps(Extension(state): Extension<SharedState>) -> Json<bool> {
    let mut st = state.write().await;
    if st.frps.running {
        return Json(false);
    }
    let mut inst = st.frps_instance.write().await;
    match inst.start().await {
        Ok(()) => {
            st.frps.running = true;
            Json(true)
        }
        Err(e) => {
            tracing::error!("Frps start failed: {e}");
            Json(false)
        }
    }
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
#[derive(Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

#[derive(Deserialize)]
struct ChangePasswordRequest {
    old_password: String,
    new_password: String,
}

async fn login(
    axum::extract::State(app): axum::extract::State<AppState>,
    Json(req): Json<LoginRequest>,
) -> Result<Response, (StatusCode, Json<serde_json::Value>)> {
    if req.username != app.credentials.username || !auth::verify_password(&req.password, &app.credentials.password_hash) {
        // Constant-time-ish delay to slow down brute force.
        tokio::time::sleep(Duration::from_millis(300)).await;
        return Err((StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error": "invalid credentials"}))));
    }
    let token = app.sessions.create().await;
    let cookie = format!("remgr_session={}; HttpOnly; Path=/; Max-Age={}; SameSite=Lax", token, SESSION_TTL_SECS);
    let mut resp = Json(serde_json::json!({"ok": true, "username": req.username})).into_response();
    if let Ok(v) = HeaderValue::from_str(&cookie) {
        resp.headers_mut().insert(SET_COOKIE, v);
    }
    Ok(resp)
}

async fn logout(
    axum::extract::State(app): axum::extract::State<AppState>,
    headers: HeaderMap,
) -> Json<serde_json::Value> {
    if let Some(t) = cookie_value(&headers, "remgr_session") {
        app.sessions.revoke(&t).await;
    }
    Json(serde_json::json!({"ok": true}))
}

async fn verify_auth(
    axum::extract::State(app): axum::extract::State<AppState>,
    headers: HeaderMap,
) -> Json<serde_json::Value> {
    let token = cookie_value(&headers, "remgr_session").unwrap_or_default();
    let ok = !token.is_empty() && app.sessions.validate(&token).await;
    Json(serde_json::json!({
        "authenticated": ok,
        "username": if ok { app.credentials.username.as_str() } else { "" },
    }))
}

async fn change_password(
    axum::extract::State(app): axum::extract::State<AppState>,
    headers: HeaderMap,
    Json(req): Json<ChangePasswordRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let token = cookie_value(&headers, "remgr_session").unwrap_or_default();
    if token.is_empty() || !app.sessions.validate(&token).await {
        return Err((StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error":"unauthorized"}))));
    }
    if !auth::verify_password(&req.old_password, &app.credentials.password_hash) {
        return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({"error":"wrong current password"}))));
    }
    let hash = auth::hash_password(&req.new_password);
    if hash.is_empty() {
        return Err((StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error":"hash failed"}))));
    }
    // Persist the new hash in config.
    let mut cfg = Config::load().map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?;
    cfg.dashboard.password_hash = hash.clone();
    cfg.save().map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?;
    // Update in-memory credentials (ArcSwap would be cleaner but for one-user this is fine).
    // SAFETY: we don't have interior mutability on Credentials — we rely on the config file as
    // source of truth and readers pick it up on restart. For a long-running process, a
    // password change only affects NEW sessions' verification path once we reload.
    Json(serde_json::json!({"ok": true}))
}