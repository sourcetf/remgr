//! Web console: axum router, session auth, service control API.

use std::sync::Arc;

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get, post};
use axum::{Json, Router};
use serde_json::json;

use crate::modules::ServiceModule;
use crate::state::{AppState, PreparedConsole};

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
        .route("/api/console/apply", post(console_apply))
        // the embedded easytier-web REST API, same-origin under /et
        .route("/et", any(easytier_web_proxy))
        .route("/et/", any(easytier_web_proxy))
        .route("/et/*path", any(easytier_web_proxy))
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

// ---------------------------------------------------------------- /et proxy

/// Reverse-proxy `/et/*` to the embedded easytier-web REST API, so the
/// EasyTier dashboard is reachable same-origin from the console.
///
/// The API binds to `api_addr:api_port` (loopback by default) and authenticates
/// with its own session cookie, which is scoped to `/et` on the way back.
async fn easytier_web_proxy(
    State(state): State<Arc<AppState>>,
    req: axum::extract::Request,
) -> Response {
    let cfg = state.config_blocking().easytier;
    let upstream = format!("http://{}:{}/", cfg.api_addr, cfg.api_port);

    // strip the /et prefix; the upstream router serves /api/v1/... at its root
    let path = req.uri().path().strip_prefix("/et").unwrap_or("");
    let query = req
        .uri()
        .query()
        .map(|q| format!("?{q}"))
        .unwrap_or_default();
    let url = format!("{upstream}{}{query}", path.trim_start_matches('/'));

    let method = reqwest::Method::from_bytes(req.method().as_str().as_bytes())
        .unwrap_or(reqwest::Method::GET);

    let mut outbound = state.et_http.request(method, &url);

    // forward the client's headers, dropping hop-by-hop and Host (reqwest
    // sets its own from the URL)
    for (name, value) in req.headers() {
        let n = name.as_str();
        if n.eq_ignore_ascii_case("host")
            || n.eq_ignore_ascii_case("connection")
            || n.eq_ignore_ascii_case("content-length")
            || n.eq_ignore_ascii_case("accept-encoding")
        {
            continue;
        }
        outbound = outbound.header(name, value);
    }

    let body = match axum::body::to_bytes(req.into_body(), 8 * 1024 * 1024).await {
        Ok(b) => b,
        Err(e) => {
            return api_error(StatusCode::BAD_REQUEST, &format!("read request body: {e}"));
        }
    };
    if !body.is_empty() {
        outbound = outbound.body(body);
    }

    // A connect timeout alone is not enough: a wedged but connected upstream
    // would hold the browser request open indefinitely, so cap the whole exchange.
    let resp = match tokio::time::timeout(std::time::Duration::from_secs(30), outbound.send()).await {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => {
            return api_error(
                StatusCode::BAD_GATEWAY,
                &format!("easytier-web API unreachable at {upstream}: {e}"),
            );
        }
        Err(_) => {
            return api_error(
                StatusCode::GATEWAY_TIMEOUT,
                &format!("easytier-web API at {upstream} did not answer within 30s"),
            );
        }
    };

    let status = StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let mut headers = HeaderMap::new();
    for (name, value) in resp.headers() {
        let n = name.as_str();
        if n.eq_ignore_ascii_case("connection")
            || n.eq_ignore_ascii_case("transfer-encoding")
            || n.eq_ignore_ascii_case("content-encoding")
            || n.eq_ignore_ascii_case("content-length")
        {
            continue;
        }
        if n.eq_ignore_ascii_case("set-cookie") {
            // scope the upstream session cookie to the /et prefix
            if let Ok(v) = value.to_str() {
                let scoped = scope_cookie_to_et(v);
                if let Ok(hv) = HeaderValue::from_str(&scoped) {
                    headers.append(header::SET_COOKIE, hv);
                }
            }
            continue;
        }
        headers.append(name.clone(), value.clone());
    }

    let bytes = match resp.bytes().await {
        Ok(b) => b,
        Err(e) => {
            return api_error(
                StatusCode::BAD_GATEWAY,
                &format!("read upstream response: {e}"),
            );
        }
    };

    (status, headers, bytes).into_response()
}

/// Rewrite a `Set-Cookie` so the upstream session only travels under `/et`.
fn scope_cookie_to_et(raw: &str) -> String {
    let mut parts: Vec<String> = raw
        .split(';')
        .map(|p| p.trim().to_string())
        .filter(|p| {
            let lower = p.to_ascii_lowercase();
            !lower.starts_with("domain=") && !lower.starts_with("path=")
        })
        .collect();
    parts.push("Path=/et".to_string());
    parts.join("; ")
}

// ---------------------------------------------------------------- auth

/// The session table is a plain std mutex: a panic while it is held would poison
/// it and fail every subsequent request, so recover the guard rather than
/// unwrapping.
fn sessions_lock(
    state: &AppState,
) -> std::sync::MutexGuard<'_, std::collections::HashMap<String, u64>> {
    state.sessions.lock().unwrap_or_else(|e| e.into_inner())
}

fn new_session(state: &AppState) -> String {
    use rand::RngCore;
    let mut buf = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut buf);
    let token: String = buf.iter().map(|b| format!("{b:02x}")).collect();
    let expiry = now_unix() + state.config_blocking().console.session_ttl;
    let mut sessions = sessions_lock(state);
    // Drop the expired entries instead of letting the table grow with every
    // login for the lifetime of the process.
    let now = now_unix();
    sessions.retain(|_, exp| *exp > now);
    sessions.insert(token.clone(), expiry);
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
    let mut sessions = sessions_lock(state);
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
    // cross-origin without CORS, which this server never offers). The /et
    // proxy is exempt: it forwards to the easytier-web API, which enforces
    // its own session cookie on every call.
    if !path.starts_with("/et")
        && matches!(*req.method(), axum::http::Method::POST | axum::http::Method::PUT | axum::http::Method::DELETE)
    {
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
        sessions_lock(&state).remove(token);
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

// ---------------------------------------------------------------- console server

/// Rebind the console with the settings currently saved in the config.
///
/// The new socket is prepared — port bound, TLS material loaded — *before* the
/// running console is asked to stop, so a taken port or an unreadable
/// certificate leaves the current console serving and reports the error to the
/// caller instead of cutting off the session that asked for the change.
async fn console_apply(State(state): State<Arc<AppState>>) -> Response {
    let cfg = state.config_blocking().console;
    match prepare_console(&cfg).await {
        Ok(prepared) => {
            *state.console_pending.lock().unwrap() = Some(prepared);
            if let Some(tx) = state.console_stop.lock().unwrap().take() {
                let _ = tx.send(());
            }
            Json(json!({
                "ok": true,
                "note": "console is rebinding; reload the page if the port or scheme changed",
            }))
            .into_response()
        }
        Err(e) => api_error(
            StatusCode::BAD_REQUEST,
            &format!("cannot apply console settings: {e:#}"),
        ),
    }
}

/// Bind the console listening socket and, when TLS is enabled, load its key pair.
pub async fn prepare_console(cfg: &crate::config::ConsoleConfig) -> anyhow::Result<PreparedConsole> {
    let addr: std::net::SocketAddr = format!("0.0.0.0:{}", cfg.port).parse()?;
    let listener = std::net::TcpListener::bind(addr).map_err(|e| anyhow::anyhow!("bind {addr}: {e}"))?;
    listener.set_nonblocking(true)?;
    if cfg.tls {
        let tls = axum_server::tls_rustls::RustlsConfig::from_pem_file(&cfg.tls_cert, &cfg.tls_key)
            .await
            .map_err(|e| {
                anyhow::anyhow!(
                    "load TLS certificate {} and key {}: {e}",
                    cfg.tls_cert,
                    cfg.tls_key
                )
            })?;
        return Ok(PreparedConsole::Tls(listener, tls));
    }
    Ok(PreparedConsole::Plain(listener))
}

/// Serve the console until the process exits, rebinding whenever
/// [`console_apply`] hands over a freshly prepared listener.
///
/// A configuration that cannot be served at all (unreadable certificate, port
/// taken) must not take the service down — the console then serves plain HTTP
/// on the configured port so the operator can still reach it and fix the cause.
pub async fn serve_console(state: Arc<AppState>) -> anyhow::Result<()> {
    loop {
        let cfg = state.config_blocking().console;
        let prepared = match state.console_pending.lock().unwrap().take() {
            Some(p) => p,
            None => match prepare_console(&cfg).await {
                Ok(p) => p,
                Err(e) => {
                    tracing::error!("console settings unusable: {e:#}");
                    let mut fallback = cfg.clone();
                    fallback.tls = false;
                    match prepare_console(&fallback).await {
                        Ok(p) => {
                            tracing::warn!(
                                "console serving plain HTTP on :{} — correct the settings, then apply again",
                                cfg.port
                            );
                            p
                        }
                        Err(e2) => {
                            tracing::error!("console cannot listen: {e2:#}; retrying in 5s");
                            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                            continue;
                        }
                    }
                }
            },
        };

        let app = router(state.clone());
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        *state.console_stop.lock().unwrap() = Some(tx);

        match prepared {
            PreparedConsole::Plain(listener) => {
                let listener = tokio::net::TcpListener::from_std(listener)?;
                let local = listener.local_addr().map(|a| a.to_string()).unwrap_or_default();
                tracing::info!("console listening on http://{local}");
                if let Err(e) = axum::serve(listener, app)
                    .with_graceful_shutdown(async move {
                        let _ = rx.await;
                    })
                    .await
                {
                    tracing::error!("console http server stopped: {e}");
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                }
            }
            PreparedConsole::Tls(listener, tls) => {
                let handle = axum_server::Handle::new();
                let shutdown_handle = handle.clone();
                tokio::spawn(async move {
                    let _ = rx.await;
                    shutdown_handle.graceful_shutdown(Some(std::time::Duration::from_secs(3)));
                });
                let local = listener.local_addr().map(|a| a.to_string()).unwrap_or_default();
                tracing::info!("console listening on https://{local}");
                if let Err(e) = axum_server::from_tcp_rustls(listener, tls)
                    .handle(handle)
                    .serve(app.into_make_service())
                    .await
                {
                    tracing::error!("console https server stopped: {e}");
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                }
            }
        }
    }
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
    /// read the on-disk log (history across restarts) instead of the ring buffer
    #[serde(default)]
    file: Option<u8>,
}
fn default_log_n() -> usize { 300 }

async fn logs(State(state): State<Arc<AppState>>, Query(q): Query<LogsQuery>) -> Response {
    let n = q.n.clamp(1, 20000);
    if q.file.is_some() {
        match read_log_file(n) {
            Ok(lines) => return Json(json!({ "lines": lines, "source": "file" })).into_response(),
            Err(e) => {
                return api_error(StatusCode::NOT_FOUND, &format!("no log file: {e}"));
            }
        }
    }
    Json(json!({ "lines": state.logs.snapshot(n), "source": "memory" })).into_response()
}

/// Tail the persisted log. The ring buffer covers the running process only, so a
/// restart otherwise wipes the history an operator needs to read afterwards.
fn read_log_file(n: usize) -> anyhow::Result<Vec<String>> {
    // one generation back is enough: remgr.log.1 is the previous file
    for path in ["/var/log/remgr/remgr.log", "/var/log/remgr/remgr.log.1"] {
        match std::fs::read_to_string(path) {
            Ok(text) => {
                let lines: Vec<&str> = text.lines().collect();
                let skip = lines.len().saturating_sub(n);
                return Ok(lines[skip..].iter().map(|l| l.to_string()).collect());
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => anyhow::bail!("{path}: {e}"),
        }
    }
    anyhow::bail!("no log file written yet")
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
    let send_abort = send_task.abort_handle();
    let recv_abort = recv_task.abort_handle();
    tokio::select! {
        _ = send_task => {},
        _ = recv_task => {},
    }
    // The select drops the losing handle without stopping its task: without this
    // the writer (or reader) survives until the next log line, leaking one task
    // per browser reconnect.
    send_abort.abort();
    recv_abort.abort();
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
    // The console's own settings are not a service module: they are persisted
    // here and only take effect when the listener is rebound, which the caller
    // triggers with POST /api/console/apply.
    if service == "console" {
        let mut new_cfg = state.config_blocking();
        let mut console: crate::config::ConsoleConfig = match serde_json::from_value(value) {
            Ok(c) => c,
            Err(e) => return api_error(StatusCode::BAD_REQUEST, &e.to_string()),
        };
        // The password has its own endpoint; never let it be cleared here.
        console.password_hash = new_cfg.console.password_hash.clone();
        if console.port == 0 {
            return api_error(StatusCode::BAD_REQUEST, "console port must not be 0");
        }
        if console.session_ttl == 0 {
            return api_error(StatusCode::BAD_REQUEST, "session_ttl must not be 0");
        }
        if console.tls && (console.tls_cert.is_empty() || console.tls_key.is_empty()) {
            return api_error(
                StatusCode::BAD_REQUEST,
                "TLS needs both a certificate and a key path",
            );
        }
        new_cfg.console = console;
        if let Err(e) = new_cfg.save() {
            return api_error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string());
        }
        *state.config.write().await = new_cfg;
        return Json(json!({
            "ok": true,
            "restart_required": true,
            "note": "saved; POST /api/console/apply rebinds the console with these settings",
        }))
        .into_response();
    }

    let module = match state.module(&service) {
        Some(m) => m,
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
            // Persist the enabled flag per action for convenience — and write the
            // same value back into memory, otherwise the file and what
            // /api/status reports disagree until the next restart.
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
                if let Err(e) = cfg.save() {
                    tracing::warn!("could not persist the enabled flag for {service}: {e:#}");
                }
                *state.config.write().await = cfg;
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
        Ok((cert_path, key_path)) => {
            let cert_path = cert_path.display().to_string();
            let key_path = key_path.display().to_string();
            let configured = point_service_at_cert(&state, &req.service, &cert_path, &key_path).await;
            Json(json!({
                "ok": true,
                "cert_path": cert_path,
                "key_path": key_path,
                "configured": configured,
            }))
            .into_response()
        }
        Err(e) => api_error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

/// Point a service's configuration at a certificate that was just written, and
/// restart it so the new pair is in effect. Without this the generated files sit
/// on disk while `cert_path` still names something else — the operator would have
/// to retype the paths the server already knows.
async fn point_service_at_cert(
    state: &Arc<AppState>,
    service: &str,
    cert_path: &str,
    key_path: &str,
) -> Vec<&'static str> {
    let mut cfg = state.config_blocking();
    let (module, updated): (&str, Vec<&'static str>) = match service {
        "turn" | "stun_turn" => {
            cfg.stun_turn.cert_path = cert_path.to_string();
            cfg.stun_turn.key_path = key_path.to_string();
            ("stun_turn", vec!["stun_turn.cert_path", "stun_turn.key_path"])
        }
        "frps" => {
            cfg.frps.tls_cert_path = Some(cert_path.to_string());
            cfg.frps.tls_key_path = Some(key_path.to_string());
            ("frps", vec!["frps.tls_cert_path", "frps.tls_key_path"])
        }
        "console" => {
            // Applied by POST /api/console/apply, not by a module restart.
            cfg.console.tls_cert = cert_path.to_string();
            cfg.console.tls_key = key_path.to_string();
            ("", vec!["console.tls_cert", "console.tls_key"])
        }
        _ => ("", Vec::new()),
    };
    if updated.is_empty() {
        return updated;
    }
    if let Err(e) = cfg.save() {
        tracing::warn!("certs: could not persist paths for {service}: {e:#}");
        return Vec::new();
    }
    *state.config.write().await = cfg;

    if !module.is_empty() {
        if let Some(m) = state.module(module) {
            if let Err(e) = m.apply_config().await {
                tracing::warn!("certs: {module} restart after certificate change failed: {e:#}");
            }
        }
    }
    updated
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
        Ok((cert_path, key_path)) => {
            let cert_path = cert_path.display().to_string();
            let key_path = key_path.display().to_string();
            let configured = point_service_at_cert(&state, &req.service, &cert_path, &key_path).await;
            Json(json!({
                "ok": true,
                "cert_path": cert_path,
                "key_path": key_path,
                "configured": configured,
            }))
            .into_response()
        }
        Err(e) => api_error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

// ---------------------------------------------------------------- helpers

fn api_error(code: StatusCode, msg: &str) -> Response {
    (code, Json(json!({"error": msg}))).into_response()
}
