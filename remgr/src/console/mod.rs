//! Web console: axum router, session auth, service control API.

use std::sync::Arc;

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get, post};
use axum::{Json, Router};
use serde_json::json;

use crate::modules::ServiceModule;
use crate::secure;
use crate::state::{AppState, PreparedConsole};

const COOKIE: &str = "remgr_session";
/// Shortest password the console accepts. The install default ("admin") has to
/// pass, so this is a floor against empty/silly values, not a strength policy.
const MIN_PASSWORD_LEN: usize = 4;

// ---------------------------------------------------------------- password hashing
//
// Argon2id, the Password Hashing Competition winner and OWASP's first choice:
// hybrid (the first half of the first pass is data-independent, so it resists
// side channels; the rest is data-dependent, so it resists GPU/ASIC search) and
// memory-hard with tunable cost. yescrypt is a fine algorithm too, but it has no
// RustCrypto-grade implementation (only thin ports of unknown quality), and
// OpenBSD — the only platform this ships on — does not use it anywhere, so
// adopting it would add an unaudited crypto dependency for no security gain.
//
// Parameters measured on the target (one core, 2 GiB): 64 MiB x 3 passes costs
// ~240 ms per login here, which is above every configuration OWASP recommends.
// `p = 1` because the box has a single core — more lanes would only ask for
// parallelism the CPU cannot provide (and Argon2 requires m to be a multiple of p).
const HASH_MEM_KIB: u32 = 65536; // 64 MiB
const HASH_PASSES: u32 = 3;
const HASH_LANES: u32 = 1;

/// The one place the hashing parameters are defined. Verification reads the cost
/// parameters from each stored PHC string, so raising these later does not
/// invalidate existing hashes — they keep working until the password is changed.
pub fn password_hasher() -> Argon2<'static> {
    let params = Params::new(HASH_MEM_KIB, HASH_PASSES, HASH_LANES, None)
        .unwrap_or_else(|_| Params::default());
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

/// Hash a password for storage (`$argon2id$v=19$m=65536,t=3,p=1$…`).
pub fn hash_password(password: &str) -> anyhow::Result<String> {
    let salt = SaltString::generate(&mut rand::rngs::OsRng);
    Ok(password_hasher()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("hash password: {e}"))?
        .to_string())
}

/// Verify a password against a stored PHC string. Any malformed or empty hash
/// simply fails (never panics).
pub fn verify_password(password: &str, hash: &str) -> bool {
    PasswordHash::new(hash)
        .map(|parsed| password_hasher().verify_password(password.as_bytes(), &parsed).is_ok())
        .unwrap_or(false)
}

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
        if n.eq_ignore_ascii_case("cookie") {
            // The upstream needs its own session cookie, but the console's
            // session token is Path=/ and would travel with it: never hand a
            // full console session to whatever `api_addr` points at.
            if let Some(scoped) = drop_console_cookie(value) {
                outbound = outbound.header(header::COOKIE, scoped);
            }
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
    let mut resp = match tokio::time::timeout(std::time::Duration::from_secs(30), outbound.send()).await {
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

    let bytes = match read_capped(&mut resp, MAX_ET_RESPONSE).await {
        Ok(b) => b,
        Err(e) => {
            return api_error(StatusCode::BAD_GATEWAY, &format!("read upstream response: {e}"));
        }
    };

    (status, headers, bytes).into_response()
}

/// Largest upstream body the proxy will buffer. The response used to be read
/// with `resp.bytes()`, which holds whatever the upstream sends in memory: a
/// large (or hostile) `api_addr` target could exhaust the process.
const MAX_ET_RESPONSE: usize = 16 * 1024 * 1024;

async fn read_capped(resp: &mut reqwest::Response, cap: usize) -> anyhow::Result<axum::body::Bytes> {
    let mut out: Vec<u8> = Vec::new();
    loop {
        match resp.chunk().await {
            Ok(Some(chunk)) => {
                if out.len().saturating_add(chunk.len()) > cap {
                    anyhow::bail!("upstream response exceeds {} bytes", cap);
                }
                out.extend_from_slice(&chunk);
            }
            Ok(None) => break,
            Err(e) => anyhow::bail!("{e}"),
        }
    }
    Ok(axum::body::Bytes::from(out))
}

/// Remove the console's own session from a forwarded `Cookie` header, keeping
/// everything else (the upstream's session lives under `/et` and must pass).
fn drop_console_cookie(raw: &HeaderValue) -> Option<HeaderValue> {
    let text = raw.to_str().ok()?;
    let kept: Vec<&str> = text
        .split(';')
        .map(|c| c.trim())
        .filter(|c| !c.is_empty() && !c.starts_with(&format!("{COOKIE}=")))
        .collect();
    if kept.is_empty() {
        return None;
    }
    HeaderValue::from_str(&kept.join("; ")).ok()
}

/// Rewrite a `Set-Cookie` so the upstream session only travels under `/et`.
/// A missing SameSite is filled in as Lax: the proxy is cross-site reachable
/// (it is exempt from the console's CSRF header rule), so the browser must not
/// attach the upstream session to a request another site initiated.
fn scope_cookie_to_et(raw: &str) -> String {
    let mut same_site = false;
    let mut parts: Vec<String> = raw
        .split(';')
        .map(|p| p.trim().to_string())
        .filter(|p| {
            let lower = p.to_ascii_lowercase();
            if lower.starts_with("samesite=") {
                same_site = true;
            }
            !lower.starts_with("domain=") && !lower.starts_with("path=")
        })
        .collect();
    if !same_site {
        parts.push("SameSite=Lax".to_string());
    }
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

/// The same for the console-control mutexes: a poisoned lock must not be able to
/// take the console's listener down.
fn lock_or_recover<T>(m: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Read-modify-write the shared configuration and persist it, all while holding
/// the write lock. Every handler used to clone a snapshot, mutate it, save and
/// store it back, so two concurrent requests (a service PUT and a console PUT,
/// or a module saving a generated key) silently overwrote each other's section
/// in memory *and* on disk. `edit` works on a copy and only commits once both it
/// and the save succeeded, so a failed save cannot leave the two disagreeing.
async fn edit_config<F>(state: &AppState, edit: F) -> anyhow::Result<()>
where
    F: FnOnce(&mut crate::config::Config) -> anyhow::Result<()>,
{
    let mut guard = state.config.write().await;
    let mut staged = guard.clone();
    edit(&mut staged)?;
    staged.save()?;
    *guard = staged;
    Ok(())
}

/// The scheme the console is actually serving, which is what the session cookie
/// has to agree with (`Secure` over plain HTTP locks the operator out).
fn serving_tls(state: &AppState) -> bool {
    *lock_or_recover(&state.console_serving_tls)
}

/// Session cookie for the given token. `Secure` is only added when the listener
/// really is TLS: if the console fell back to plain HTTP because the configured
/// certificate is unreadable, a Secure cookie would never be stored and the
/// console would be unreachable.
fn session_cookie(state: &AppState, token: &str, max_age: u64) -> String {
    let secure = if serving_tls(state) { "; Secure" } else { "" };
    format!("{COOKIE}={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age}{secure}")
}

fn new_session(state: &AppState) -> String {
    use rand::RngCore;
    let mut buf = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut buf);
    let token: String = buf.iter().map(|b| format!("{b:02x}")).collect();
    // saturating: a session_ttl near u64::MAX would otherwise wrap and hand back
    // a token that is already expired
    let expiry = now_unix().saturating_add(state.config_blocking().console.session_ttl);
    let mut sessions = sessions_lock(state);
    // Drop the expired entries instead of letting the table grow with every
    // login for the lifetime of the process.
    let now = now_unix();
    sessions.retain(|_, exp| *exp > now);
    sessions.insert(token.clone(), expiry);
    token
}

/// The session token this request carries, if any.
fn request_token(headers: &HeaderMap) -> Option<String> {
    let cookie = headers
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    cookie
        .split(';')
        .filter_map(|c| c.trim().strip_prefix(&format!("{COOKIE}=")))
        .next()
        .filter(|t| !t.is_empty())
        .map(|t| t.to_string())
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn session_ok(state: &AppState, headers: &HeaderMap) -> bool {
    let Some(token) = request_token(headers) else {
        return false;
    };
    let mut sessions = sessions_lock(state);
    match sessions.get(&token) {
        Some(&expiry) if expiry > now_unix() => true,
        Some(_) => {
            sessions.remove(&token);
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
    /// Empty is accepted as "the configured user name": the console used to be
    /// password-only, and a page cached before this change sends no user name.
    /// Nothing is weakened by that — the user name is not a secret and the
    /// password still has to be correct.
    #[serde(default)]
    username: String,
    password: String,
}

/// Failed logins allowed per window before further *wrong* passwords are refused.
const LOGIN_MAX_FAILURES: u32 = 10;
/// Length of that window, in seconds.
const LOGIN_FAILURE_WINDOW: u64 = 300;

/// Throttle failed console logins.
///
/// The console is meant to be reachable from the network and ships a short
/// default password, so guesses have to cost something. The password is verified
/// *before* this is consulted, and a correct one always succeeds (and clears the
/// counter) — so this can never lock an operator out of their own console, it
/// only refuses further wrong passwords once the window is saturated.
///
/// Counted globally rather than per source address: the TLS listener (the
/// default) is served by axum-server, which does not pass the peer address into
/// the request, so a per-IP table would silently degrade to this anyway. Say the
/// word if you want per-IP throttling; it needs the peer address plumbed through
/// the TLS serve path.
fn login_throttled(state: &AppState) -> Option<Response> {
    let now = now_unix();
    let mut window = lock_or_recover(&state.login_failures);
    // The window is a single (count, start) pair; drop it once it has expired so
    // the count cannot accumulate across windows.
    if now.saturating_sub(window.1) >= LOGIN_FAILURE_WINDOW {
        *window = (0, now);
    }
    let (count, start) = *window;
    if count < LOGIN_MAX_FAILURES {
        return None;
    }
    let retry_after = LOGIN_FAILURE_WINDOW.saturating_sub(now.saturating_sub(start)).max(1);
    tracing::warn!(
        "console: {count} failed logins in this window — refusing further attempts for {retry_after}s"
    );
    Some(
        (
            StatusCode::TOO_MANY_REQUESTS,
            [(header::RETRY_AFTER, HeaderValue::from_str(&retry_after.to_string()).unwrap())],
            Json(json!({
                "error": format!(
                    "too many failed login attempts — wait {retry_after}s (the correct password is always accepted)"
                )
            })),
        )
            .into_response(),
    )
}

fn note_login_failure(state: &AppState) {
    let now = now_unix();
    let mut window = lock_or_recover(&state.login_failures);
    if now.saturating_sub(window.1) >= LOGIN_FAILURE_WINDOW {
        *window = (1, now);
    } else {
        window.0 = window.0.saturating_add(1);
    }
}

fn clear_login_failures(state: &AppState) {
    *lock_or_recover(&state.login_failures) = (0, now_unix());
}

async fn login(State(state): State<Arc<AppState>>, Json(req): Json<LoginReq>) -> Response {
    let console = state.config_blocking().console;

    // Bounded hashing: Argon2id allocates 64 MiB per verification, so letting an
    // unbounded number of concurrent requests hash would be a memory-exhaustion
    // vector on this box (one core, 2 GiB). The permit is held for the duration
    // of the hashing; a caller that cannot get one within a few seconds is told to
    // try again rather than piling up.
    let _permit = match tokio::time::timeout(
        std::time::Duration::from_secs(5),
        state.password_hashes.acquire(),
    )
    .await
    {
        Ok(Ok(p)) => p,
        _ => {
            return api_error(StatusCode::SERVICE_UNAVAILABLE, "login is busy, try again shortly");
        }
    };

    // The password is always verified against the configured hash, even when the
    // username is wrong, so a rejected attempt costs the same as an accepted one
    // (no timing oracle telling an attacker which half was wrong). A username the
    // operator has not set is rejected outright.
    let password_ok = verify_password(&req.password, &console.password_hash);
    // An empty user name means "the configured one" (see LoginReq).
    let username_ok = req.username.trim().is_empty() || req.username.trim() == console.username;
    if !(password_ok && username_ok) {
        note_login_failure(&state);
        if let Some(refused) = login_throttled(&state) {
            return refused;
        }
        // One message for both halves: which credential was wrong is not disclosed.
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "invalid username or password"})),
        )
            .into_response();
    }
    clear_login_failures(&state);
    let token = new_session(&state);
    let cookie = session_cookie(&state, &token, console.session_ttl);
    (
        StatusCode::OK,
        [(header::SET_COOKIE, HeaderValue::from_str(&cookie).unwrap())],
        Json(json!({"ok": true})),
    )
        .into_response()
}

async fn logout(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Some(token) = request_token(&headers) {
        sessions_lock(&state).remove(&token);
    }
    let cookie = session_cookie(&state, "", 0);
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

async fn change_password(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<PasswordChange>,
) -> Response {
    let hash = state.config_blocking().console.password_hash;
    // Same bounded, same-parameters path as login.
    let old_ok = {
        let _permit = match tokio::time::timeout(
            std::time::Duration::from_secs(5),
            state.password_hashes.acquire(),
        )
        .await
        {
            Ok(Ok(p)) => p,
            _ => {
                return api_error(StatusCode::SERVICE_UNAVAILABLE, "busy, try again shortly");
            }
        };
        verify_password(&req.old, &hash)
    };
    if !old_ok {
        return (StatusCode::UNAUTHORIZED, Json(json!({"error": "invalid old password"}))).into_response();
    }
    if req.new.trim().len() < MIN_PASSWORD_LEN {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": format!("new password too short (min {MIN_PASSWORD_LEN})")})),
        )
            .into_response();
    }
    let new_hash = match hash_password(&req.new) {
        Ok(h) => h,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))).into_response(),
    };
    if let Err(e) = edit_config(&state, |cfg| {
        cfg.console.password_hash = new_hash;
        Ok(())
    })
    .await
    {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))).into_response();
    }
    // The password just changed: every other session was authenticated against
    // the old one and must not outlive it. The caller keeps its own token so the
    // change does not log the operator out of the page they are on.
    let keep = request_token(&headers);
    sessions_lock(&state).retain(|token, _| Some(token) == keep.as_ref());
    Json(json!({"ok": true, "other_sessions_ended": true})).into_response()
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
            *lock_or_recover(&state.console_pending) = Some(prepared);
            if let Some(tx) = lock_or_recover(&state.console_stop).take() {
                let _ = tx.send(());
            }
            Json(json!({
                "ok": true,
                "note": "console is rebinding; reload the page if the port or scheme changed",
            }))
            .into_response()
        }
        Err(e) if is_addr_in_use(&e) && *lock_or_recover(&state.console_serving_port) == Some(cfg.port) => {
            // Switching the scheme on the port the console is already serving:
            // the old listener holds it, so nothing can be bound up front. Ask the
            // serve loop to stop; it re-prepares from the (already saved) config,
            // so the same settings — with the new scheme — come back up. That also
            // means a failure here cannot strand the console: the loop falls back
            // to the settings that last worked.
            if let Some(tx) = lock_or_recover(&state.console_stop).take() {
                let _ = tx.send(());
            }
            Json(json!({
                "ok": true,
                "note": "same port: the console is briefly unavailable while it changes scheme; reload in a moment",
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
    // keep the io::Error intact (downcast_ref in the caller distinguishes "port
    // taken" — possibly by our own listener — from anything else)
    let listener = std::net::TcpListener::bind(addr)
        .map_err(|e| anyhow::Error::new(e).context(format!("bind {addr}")))?;
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

/// Was this failure the kernel refusing our bind because the address is taken?
fn is_addr_in_use(e: &anyhow::Error) -> bool {
    e.chain()
        .filter_map(|c| c.downcast_ref::<std::io::Error>())
        .any(|io| io.kind() == std::io::ErrorKind::AddrInUse)
}

/// Serve the console until the process exits, rebinding whenever
/// [`console_apply`] hands over a freshly prepared listener.
///
/// A configuration that cannot be served at all (unreadable certificate, port
/// taken) must not take the service down — the console then serves plain HTTP
/// on the configured port so the operator can still reach it and fix the cause.
pub async fn serve_console(state: Arc<AppState>) -> anyhow::Result<()> {
    // The settings that last bound successfully. They are the final fallback, so
    // a configuration that cannot listen (port stolen, certificate broken) can
    // never take the console away entirely.
    let mut last_good: Option<crate::config::ConsoleConfig> = None;
    loop {
        let cfg = state.config_blocking().console;
        let prepared = match lock_or_recover(&state.console_pending).take() {
            Some(p) => Some(p),
            None => {
                let mut chosen = None;
                match prepare_console(&cfg).await {
                    Ok(p) => {
                        last_good = Some(cfg.clone());
                        chosen = Some(p);
                    }
                    Err(e) => {
                        tracing::error!("console settings unusable: {e:#}");
                        // TLS material missing/corrupt: serve plain HTTP on the
                        // requested port rather than not serving at all.
                        let mut plain = cfg.clone();
                        plain.tls = false;
                        match prepare_console(&plain).await {
                            Ok(p) => {
                                tracing::warn!(
                                    "console serving plain HTTP on :{} — correct the settings, then apply again",
                                    cfg.port
                                );
                                chosen = Some(p);
                            }
                            Err(e2) => {
                                tracing::error!("console cannot listen with the new settings: {e2:#}");
                            }
                        }
                    }
                }
                if chosen.is_none() {
                    // Last resort: whatever worked before this change.
                    if let Some(good) = last_good.clone() {
                        match prepare_console(&good).await {
                            Ok(p) => {
                                tracing::error!(
                                    "console restored on :{} with the previous settings — \
                                     the new ones could not be applied",
                                    good.port
                                );
                                chosen = Some(p);
                            }
                            Err(e3) => {
                                tracing::error!("previous settings no longer bind either: {e3:#}");
                            }
                        }
                    }
                }
                chosen
            }
        };

        let Some(prepared) = prepared else {
            tracing::error!("console cannot listen at all; retrying in 5s");
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            continue;
        };

        let app = router(state.clone());
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        *lock_or_recover(&state.console_stop) = Some(tx);

        match prepared {
            PreparedConsole::Plain(listener) => {
                let listener = tokio::net::TcpListener::from_std(listener)?;
                let local = listener.local_addr().map(|a| a.to_string()).unwrap_or_default();
                let port = local.rsplit(':').next().and_then(|p| p.parse().ok());
                let mut serving_port = lock_or_recover(&state.console_serving_port);
                *serving_port = port;
                drop(serving_port);
                *lock_or_recover(&state.console_serving_tls) = false;
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
                let port = local.rsplit(':').next().and_then(|p| p.parse().ok());
                let mut serving_port = lock_or_recover(&state.console_serving_port);
                *serving_port = port;
                drop(serving_port);
                *lock_or_recover(&state.console_serving_tls) = true;
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
        "frpc": state.frpc.status().await,
    });
    Json(json!({
        "version": env!("CARGO_PKG_VERSION"),
        "os": std::env::consts::OS,
        "uptime_s": state.started_at.elapsed().as_secs(),
        "console": {
            "port": cfg.console.port,
            "tls": cfg.console.tls,
            // the scheme the listener actually came up with: a configured
            // certificate that cannot be read makes the console fall back to
            // plain HTTP, and that must be visible rather than a `tls: true`
            // that only describes the file
            "tls_active": serving_tls(&state),
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
        "frpc" => serde_json::to_value(&cfg.frpc).ok(),
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
    // A PUT replaces the whole section: every field the body omits is filled in
    // with its default (all the config structs are `#[serde(default)]`). An empty
    // object therefore means "reset this section to defaults", which is never what
    // a caller intends — a mistyped curl would silently wipe the token,
    // credentials and paths. Refuse it; the console always sends the full section.
    if matches!(&value, serde_json::Value::Object(m) if m.is_empty()) {
        return api_error(
            StatusCode::BAD_REQUEST,
            "empty body: PUT replaces the whole section, send the complete config",
        );
    }
    // The console's own settings are not a service module: they are persisted
    // here and only take effect when the listener is rebound, which the caller
    // triggers with POST /api/console/apply.
    if service == "console" {
        let console: crate::config::ConsoleConfig = match serde_json::from_value(value) {
            Ok(c) => c,
            Err(e) => return api_error(StatusCode::BAD_REQUEST, &e.to_string()),
        };
        if console.port == 0 {
            return api_error(StatusCode::BAD_REQUEST, "console port must not be 0");
        }
        // An empty user name would make login accept any user name, leaving only
        // the password as a check — refuse it rather than degrade silently.
        if console.username.trim().is_empty() {
            return api_error(StatusCode::BAD_REQUEST, "console username must not be empty");
        }
        if console.session_ttl == 0 {
            return api_error(StatusCode::BAD_REQUEST, "session_ttl must not be 0");
        }
        if console.tls && (console.tls_cert.trim().is_empty() || console.tls_key.trim().is_empty()) {
            return api_error(
                StatusCode::BAD_REQUEST,
                "TLS needs both a certificate and a key path",
            );
        }
        if console.tls {
            // A certificate the sandbox cannot see loads only at bind time, and
            // the serve loop then falls back to *plain HTTP* — a silent downgrade
            // the operator would have to notice from `/api/status`. Reject it
            // here instead, where the message can say exactly which tree is
            // readable.
            for (what, path) in [("tls_cert", &console.tls_cert), ("tls_key", &console.tls_key)] {
                if !path.starts_with('/') || path.contains("..") {
                    return api_error(
                        StatusCode::BAD_REQUEST,
                        &format!("{what} must be an absolute path"),
                    );
                }
                if !secure::path_is_visible(path) {
                    return api_error(
                        StatusCode::BAD_REQUEST,
                        &format!(
                            "{what} is outside the sandbox's readable trees ({}) — \
                             put the certificate under /etc/remgr/ssl",
                            secure::VISIBLE_ROOTS.join(", ")
                        ),
                    );
                }
            }
        }
        let result = edit_config(&state, |cfg| {
            let mut console = console;
            // The password has its own endpoint; never let it be cleared here.
            console.password_hash = cfg.console.password_hash.clone();
            cfg.console = console;
            Ok(())
        })
        .await;
        if let Err(e) = result {
            return api_error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string());
        }
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

    let result = edit_config(&state, move |cfg| {
        match service.as_str() {
            "easytier" => {
                let parsed: crate::config::EasyTierConfig = serde_json::from_value(value)?;
                // every other section feeds a socket bind; this one is also the
                // target the console's /et proxy connects to, so it has to be an
                // IP literal — anything else is a value the module refuses to
                // start with and the proxy would treat as another host
                parsed.api_addr.parse::<std::net::IpAddr>().map_err(|_| {
                    anyhow::anyhow!(
                        "api_addr must be an IP address (the console proxies /et to it): {:?}",
                        parsed.api_addr
                    )
                })?;
                cfg.easytier = parsed;
            }
            "stun_turn" => cfg.stun_turn = serde_json::from_value(value)?,
            "rustdesk" => cfg.rustdesk = serde_json::from_value(value)?,
            "frps" => cfg.frps = serde_json::from_value(value)?,
            "frpc" => cfg.frpc = serde_json::from_value(value)?,
            _ => anyhow::bail!("unknown service"),
        }
        Ok(())
    })
    .await;

    if let Err(e) = result {
        return api_error(StatusCode::BAD_REQUEST, &e.to_string());
    }

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
    // Start is only possible while the module is enabled, and a stop persists
    // enabled=false — so "start" has to clear that flag *before* calling into the
    // module, otherwise the button would fail with "module is disabled" and a
    // stopped service could never be started again from the console.
    if action == "start" || action == "restart" {
        if let Err(e) = set_enabled(&state, &service, true).await {
            tracing::warn!("could not persist the enabled flag for {service}: {e:#}");
        }
    }
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
                if let Err(e) = set_enabled(&state, &service, action == "start").await {
                    tracing::warn!("could not persist the enabled flag for {service}: {e:#}");
                }
            }
            Json(json!({"ok": true})).into_response()
        }
        Err(e) => api_error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

/// Persist a service's `enabled` flag (and keep memory and file in step).
async fn set_enabled(state: &AppState, service: &str, enabled: bool) -> anyhow::Result<()> {
    let known = {
        // hold the write lock only for the flag itself, never across the save
        let mut cfg = state.config.write().await;
        set_enabled_flag(&mut *cfg, service, enabled)
    };
    if !known {
        return Ok(()); // not a service this console knows about
    }
    state.save_config().await
}

/// Set a service's `enabled` flag in the given config snapshot.
/// Returns whether the service is one this console knows about.
fn set_enabled_flag(cfg: &mut crate::config::Config, service: &str, enabled: bool) -> bool {
    match service {
        "easytier" => cfg.easytier.enabled = enabled,
        "stun_turn" => cfg.stun_turn.enabled = enabled,
        "rustdesk" => cfg.rustdesk.enabled = enabled,
        "frps" => cfg.frps.enabled = enabled,
        "frpc" => cfg.frpc.enabled = enabled,
        _ => return false,
    }
    true
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
    // reject bad input as bad input: the generator itself would only report a
    // generic failure (and a silly `days` used to abort the request task)
    if !crate::certs::valid_service_name(&req.service) {
        return api_error(StatusCode::BAD_REQUEST, "invalid service name");
    }
    if req.domain.trim().is_empty() {
        return api_error(StatusCode::BAD_REQUEST, "domain must not be empty");
    }
    if req.days == 0 || req.days > crate::certs::MAX_CERT_DAYS {
        return api_error(
            StatusCode::BAD_REQUEST,
            &format!("days must be between 1 and {}", crate::certs::MAX_CERT_DAYS),
        );
    }
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
    let (module, updated): (&str, Vec<&'static str>) = match service {
        "turn" | "stun_turn" => ("stun_turn", vec!["stun_turn.cert_path", "stun_turn.key_path"]),
        "frps" => ("frps", vec!["frps.tls_cert_path", "frps.tls_key_path"]),
        // Applied by POST /api/console/apply, not by a module restart.
        "console" => ("", vec!["console.tls_cert", "console.tls_key"]),
        _ => ("", Vec::new()),
    };
    if updated.is_empty() {
        return updated;
    }
    if let Err(e) = edit_config(state, |cfg| {
        match service {
            "turn" | "stun_turn" => {
                cfg.stun_turn.cert_path = cert_path.to_string();
                cfg.stun_turn.key_path = key_path.to_string();
            }
            "frps" => {
                cfg.frps.tls_cert_path = Some(cert_path.to_string());
                cfg.frps.tls_key_path = Some(key_path.to_string());
            }
            "console" => {
                cfg.console.tls_cert = cert_path.to_string();
                cfg.console.tls_key = key_path.to_string();
            }
            _ => {}
        }
        Ok(())
    })
    .await
    {
        tracing::warn!("certs: could not persist paths for {service}: {e:#}");
        return Vec::new();
    }

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
    if !crate::certs::valid_service_name(&req.service) {
        return api_error(StatusCode::BAD_REQUEST, "invalid service name");
    }
    if !req.cert_pem.contains("BEGIN CERTIFICATE") || !req.key_pem.contains("PRIVATE KEY") {
        return api_error(
            StatusCode::BAD_REQUEST,
            "cert_pem and key_pem must be PEM-encoded certificate and private key blocks",
        );
    }
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
