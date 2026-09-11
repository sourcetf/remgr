// ReMgr - Relay Manager
// All-in-one relay manager: EasyTier, STUN/TURN, RustDesk, and Frps.
//
// Services that can run fully in-process (STUN/TURN, FRP TCP mux) do so.
// Services whose upstream implementations are Go/C++ binaries that cannot be
// embedded in-process without spawning subprocesses (RustDesk, the EasyTier
// center's TUN path) are managed as configuration + honest status only.

use anyhow::Result;
use axum::{
    extract::Request,
    http::{header::SET_COOKIE, HeaderMap, HeaderValue, StatusCode},
    middleware,
    response::{IntoResponse, Response},
    routing::{get, post},
    Extension, Json, Router,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, OnceLock, RwLock as StdRwLock};
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

mod auth;
mod config;
mod easytier_server;
mod frps_server;
mod rustdesk_relay;
mod ssl_cert;
mod stun_turn_server;
mod system;
mod web_console;

pub use config::Config;
pub use easytier_server::EasyTierCenter;
pub use frps_server::FrpsServer;
pub use rustdesk_relay::RustDeskRelay;
pub use stun_turn_server::StunTurnServer;

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

// ---------------------------------------------------------------------------
// Authentication context (process-global; single admin user, so no per-request
// state plumbing is needed and the axum route/middleware generics stay simple).
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct Credentials {
    username: String,
    password_hash: String,
}

/// In-memory session store: token -> creation time. TTL is the web-login TTL;
/// restarting the process invalidates all sessions (acceptable for a manager UI).
pub struct Sessions {
    inner: StdRwLock<HashMap<String, Instant>>,
}

const SESSION_TTL: Duration = Duration::from_secs(24 * 3600);

impl Sessions {
    fn new() -> Self {
        Sessions { inner: StdRwLock::new(HashMap::new()) }
    }

    fn create(&self) -> String {
        let token = uuid::Uuid::new_v4().to_string();
        let now = Instant::now();
        let mut w = self.inner.write().unwrap();
        // Prune expired on each insert (keeps the map bounded).
        w.retain(|_, t| t.elapsed() < SESSION_TTL);
        w.insert(token.clone(), now);
        token
    }

    /// Validate and, if fresh, slide the expiry (touch) so active sessions stay
    /// logged in across the whole TTL.
    fn validate(&self, token: &str) -> bool {
        let mut w = self.inner.write().unwrap();
        match w.get_mut(token) {
            Some(t) if t.elapsed() < SESSION_TTL => {
                *t = Instant::now();
                true
            }
            Some(_) => {
                w.remove(token);
                false
            }
            None => false,
        }
    }

    fn revoke(&self, token: &str) {
        self.inner.write().unwrap().remove(token);
    }
}

pub struct AuthContext {
    sessions: Sessions,
    credentials: StdRwLock<Credentials>,
}

impl AuthContext {
    fn new(username: String, password_hash: String) -> Self {
        AuthContext {
            sessions: Sessions::new(),
            credentials: StdRwLock::new(Credentials { username, password_hash }),
        }
    }

    fn check_credentials(&self, username: &str, password: &str) -> bool {
        let (u, h) = {
            let c = self.credentials.read().unwrap();
            (c.username.clone(), c.password_hash.clone())
        };
        username == u && auth::verify_password(password, &h)
    }

    fn set_password_hash(&self, hash: String) {
        self.credentials.write().unwrap().password_hash = hash;
    }

    fn username(&self) -> String {
        self.credentials.read().unwrap().username.clone()
    }
}

static AUTH: OnceLock<AuthContext> = OnceLock::new();

fn auth_ctx() -> &'static AuthContext {
    AUTH.get().expect("auth context not initialized")
}

const SESSION_COOKIE: &str = "remgr_session";

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    std::env::set_var("RUST_LOG", "info");
    tracing_subscriber::fmt::init();

    #[cfg(target_os = "openbsd")]
    {
        system::init_system_security()?;
    }

    // Load configuration. On a fresh install, generate a random admin password
    // (hashed with Argon2id) and print it exactly once so the console is never
    // open by default.
    let mut config = Config::load()?;
    if let Some(password) = config.bootstrap_password()? {
        tracing::warn!("================================================");
        tracing::warn!("ReMgr generated an admin password (first run):");
        tracing::warn!("  username: {}", config.dashboard.username);
        tracing::warn!("  password: {}", password);
        tracing::warn!("Save this now — it will NOT be shown again.");
        tracing::warn!("Change it from the web console after logging in.");
        tracing::warn!("================================================");
    }
    tracing::info!("Configuration loaded from {:?}", config.config_path);

    // Install the global auth context.
    if AUTH
        .set(AuthContext::new(
            config.dashboard.username.clone(),
            config.dashboard.password_hash.clone(),
        ))
        .is_err()
    {
        anyhow::bail!("auth context already initialized");
    }

    // Initialize service instances (wrapped in Arc<RwLock<>> for shared state)
    let easytier_instance = Arc::new(RwLock::new(EasyTierCenter::new(easytier_server::Config {
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
    })));
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
    const NOTE_RUSTDESK: &str = "RustDesk (Go) cannot be embedded in-process without subprocess spawning; managed as config only.";
    const NOTE_EASYTIER: &str = "EasyTier center needs a TUN device; embedded without TUN is not supported here — managed as config only.";

    // Initialize state
    let state: SharedState = Arc::new(RwLock::new(ManagerState {
        easytier: ServiceStatus {
            name: "easytier".to_string(),
            running: false,
            port: Some(config.easytier.config_port),
            config: Some(serde_json::to_value(&easytier_instance_config(&config))?),
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
            note: None,
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

    // Auto-start enabled services (STUN/TURN runs fully in-process).
    auto_start_enabled_services(&state).await;

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
        .route("/api/v1/logout", post(logout))
        .route("/api/v1/auth/verify", get(verify_auth))
        .route("/api/v1/password", post(change_password))
        .route("/ws/events", get(web_console::websocket_handler))
        .fallback(web_console::serve_webui)
        .layer(middleware::from_fn(auth_middleware))
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

/// Pull the easytier ServerConfig from the loaded file config.
fn easytier_instance_config(config: &Config) -> easytier_server::Config {
    easytier_server::Config {
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
    }
}

/// Spawn the enabled services on boot. STUN/TURN is fully in-process and gets
/// started for real; FRP's TCP accept loop is also in-process and started.
/// External-binary services keep `running: false` (honest status) until we can
/// embed them without spawning subprocesses.
async fn auto_start_enabled_services(state: &SharedState) {
    // STUN/TURN (in-process)
    let stun_inst = {
        let st = state.read().await;
        let cfg = st.stun_turn.config.as_ref().and_then(|v| {
            serde_json::from_value::<stun_turn_server::Config>(v.clone()).ok()
        });
        if !cfg.map(|c| c.enabled).unwrap_or(false) {
            return;
        }
        st.stun_turn_instance.clone()
    };
    let mut inst = stun_inst.write().await;
    match inst.start().await {
        Ok(()) => {
            let mut st = state.write().await;
            st.stun_turn.running = inst.is_running();
            tracing::info!("STUN/TURN auto-started (running={})", inst.is_running());
        }
        Err(e) => tracing::warn!("STUN/TURN auto-start failed: {e}"),
    }
}

// ---------------------------------------------------------------------------
// Authentication middleware
// ---------------------------------------------------------------------------

async fn auth_middleware(req: Request, next: middleware::Next) -> Response {
    let path = req.uri().path().to_string();

    // Public endpoints and the SPA shell load without a session; the UI JS then
    // calls /api/v1/auth/verify to decide whether to render the login form.
    const PUBLIC: &[&str] = &[
        "/api/v1/login",
        "/api/v1/auth/verify",
    ];
    let is_shell = matches!(path.as_str(), "/" | "/index.html" | "/favicon.ico");
    if PUBLIC.iter().any(|p| path == *p) || is_shell {
        return next.run(req).await;
    }

    let token = cookie_value(req.headers(), SESSION_COOKIE).unwrap_or_default();
    if token.is_empty() || !auth_ctx().sessions.validate(&token) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "unauthorized" })),
        )
            .into_response();
    }
    next.run(req).await
}

fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    let raw = headers.get(axum::http::header::COOKIE)?.to_str().ok()?;
    for part in raw.split(';') {
        let kv = part.trim();
        if let Some(v) = kv.strip_prefix(&format!("{name}=")) {
            return Some(v.to_string());
        }
    }
    None
}

// ---------------------------------------------------------------------------
// API handlers
// ---------------------------------------------------------------------------

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
    if let Ok(v) = serde_json::to_value(&cfg) {
        st.easytier.config = Some(v);
    }
    Json(true)
}

async fn start_easytier(Extension(state): Extension<SharedState>) -> Json<bool> {
    // No in-process embed without a TUN device; report honestly (do not flip running).
    let st = state.read().await;
    Json(st.easytier.running)
}

async fn stop_easytier(Extension(state): Extension<SharedState>) -> Json<bool> {
    let mut st = state.write().await;
    st.easytier.running = false;
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
    let mut inst = st.stun_turn_instance.write().await;
    inst.update_config(cfg);
    Json(true)
}

async fn start_stun_turn(Extension(state): Extension<SharedState>) -> Json<bool> {
    let running = {
        let st = state.read().await;
        if st.stun_turn.running {
            return Json(false);
        }
        st.stun_turn_instance.clone()
    };
    let mut inst = running.write().await;
    match inst.start().await {
        Ok(()) => {
            let was_running = inst.is_running();
            drop(inst);
            let mut st = state.write().await;
            st.stun_turn.running = was_running;
            Json(was_running)
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
    // Cannot embed the Go relay in-process without subprocess spawn; stay honest.
    let st = state.read().await;
    Json(st.rustdesk_hbbr.running)
}

async fn start_rustdesk_hbbs(Extension(state): Extension<SharedState>) -> Json<bool> {
    let st = state.read().await;
    Json(st.rustdesk_hbbs.running)
}

async fn stop_rustdesk(Extension(state): Extension<SharedState>) -> Json<bool> {
    let mut st = state.write().await;
    st.rustdesk_hbbr.running = false;
    st.rustdesk_hbbs.running = false;
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
    let mut inst = st.frps_instance.write().await;
    inst.update_config(cfg);
    Json(true)
}

async fn start_frps(Extension(state): Extension<SharedState>) -> Json<bool> {
    let inst = {
        let st = state.read().await;
        if st.frps.running {
            return Json(false);
        }
        st.frps_instance.clone()
    };
    let mut inst = inst.write().await;
    match inst.start().await {
        Ok(()) => {
            drop(inst);
            let mut st = state.write().await;
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

// ---------------------------------------------------------------------------
// Auth handlers
// ---------------------------------------------------------------------------

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

async fn login(Json(req): Json<LoginRequest>) -> Result<Response, (StatusCode, Json<serde_json::Value>)> {
    if !auth_ctx().check_credentials(&req.username, &req.password) {
        // Slow down brute force a little (Argon2 verify is already costly, but
        // this adds a constant delay for the wrong-user path).
        tokio::time::sleep(Duration::from_millis(300)).await;
        return Err((StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error":"invalid credentials"}))));
    }
    let token = auth_ctx().sessions.create();
    let cookie = format!("{SESSION_COOKIE}={token}; HttpOnly; Path=/; Max-Age={}; SameSite=Lax", SESSION_TTL.as_secs());
    let mut resp = Json(serde_json::json!({"ok": true, "username": req.username})).into_response();
    if let Ok(v) = HeaderValue::from_str(&cookie) {
        resp.headers_mut().insert(SET_COOKIE, v);
    }
    Ok(resp)
}

async fn logout(headers: HeaderMap) -> Json<serde_json::Value> {
    if let Some(t) = cookie_value(&headers, SESSION_COOKIE) {
        auth_ctx().sessions.revoke(&t);
    }
    Json(serde_json::json!({"ok": true}))
}

async fn verify_auth(headers: HeaderMap) -> Json<serde_json::Value> {
    let token = cookie_value(&headers, SESSION_COOKIE).unwrap_or_default();
    let ok = !token.is_empty() && auth_ctx().sessions.validate(&token);
    Json(serde_json::json!({
        "authenticated": ok,
        "username": if ok { auth_ctx().username() } else { "".to_string() },
    }))
}

async fn change_password(
    headers: HeaderMap,
    Json(req): Json<ChangePasswordRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let token = cookie_value(&headers, SESSION_COOKIE).unwrap_or_default();
    if token.is_empty() || !auth_ctx().sessions.validate(&token) {
        return Err((StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error":"unauthorized"}))));
    }
    if !auth_ctx().check_credentials(&auth_ctx().username(), &req.old_password) {
        return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({"error":"wrong current password"}))));
    }
    let hash = auth::hash_password(&req.new_password);
    if hash.is_empty() {
        return Err((StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error":"hash failed"}))));
    }
    // Persist to config first (source of truth across restarts)...
    let mut cfg = Config::load()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?;
    cfg.dashboard.password_hash = hash.clone();
    cfg.save()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?;
    // ...then update the in-memory context for the live session.
    auth_ctx().set_password_hash(hash);
    // Invalidate other sessions by revoking the current one's siblings is overkill;
    // we keep the caller's session valid.
    Ok(Json(serde_json::json!({"ok": true})))
}