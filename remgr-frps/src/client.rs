//! frp **client** ("frpc") — the outbound half of the fatedier/frp V1 wire
//! protocol whose server half lives in `server.rs`. With this module ReMgr can
//! *use* an upstream frp tunnel as well as offer one: log in to a real
//! fatedier/frp server (or another ReMgr, or anything speaking the same wire
//! protocol), authenticate with a token and expose local services as tcp/udp
//! proxies on the upstream's ports.
//!
//! Implemented protocol surface (mirrors what frpc 0.71.0 actually puts on the
//! wire — verified against `client/{connector,control,control_session}.go` and
//! `client/proxy/{tcp,udp}.go` of the v0.71.0 source):
//! - one TCP connection per control session; with `transport.tls` the first byte
//!   `0x17` (frp's custom marker) precedes the TLS handshake, and the upstream's
//!   certificate is accepted as-is unless `trusted_ca_file` names a CA bundle
//! - `Login` in the clear → `LoginResp`; everything after that on the control
//!   connection runs through the golib AES-128-CFB stream keyed by the token
//!   (`crypto.rs`), including when the token is empty — frp derives the key from
//!   the token unconditionally, so an empty token is a key, not "no crypto"
//! - `privilege_key = hex(md5(token || timestamp))` on `Login` and `NewWorkConn`
//!   (frpc always sets it, even for an empty token)
//! - `transport.tcpMux` (default): the connection is a yamux session, the client
//!   opens the control stream first and one stream per work connection. Liveness
//!   is left to the yamux keepalive — frpc sets `heartbeatInterval = -1` when
//!   tcp_mux is on, so no application heartbeat is sent
//! - no tcp_mux: every work connection is its own TCP connection whose first
//!   frame is `NewWorkConn`; work connections are never encrypted. Here frpc
//!   does send `Ping` every 30s and expects a `Pong` within 90s, which is
//!   reproduced (an upstream that ignores pings is still fine: only the
//!   heartbeat *timeout* tears the session down, and frp's own server answers)
//! - work connections: `NewWorkConn` → `StartWorkConn` → raw bytes (tcp) or
//!   `UDPPacket` frames (udp); the udp path keeps the stream framed and sends a
//!   bare `Ping` every 30s, exactly like frpc
//! - one `net.DialUDP`-style socket per *user* address on the udp path, with
//!   frp's 30s idle expiry
//!
//! Deliberately not implemented (rejected with a clear error instead of failing
//! silently): the http/https/tcpmux/stcp/xtcp proxy types, `use_encryption`,
//! `use_compression`, wire protocol v2, QUIC/KCP/websocket transports and
//! `ConnectServerLocalIP`/proxy-protocol options.
//!
//! Failure policy: no `panic!`/`exit` on anything that comes from the network.
//! A session that ends for any reason is reported in [`FrpcStatus::last_error`]
//! and retried with exponential backoff; the console shows the state of every
//! proxy, including the reason the upstream rejected it.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::Poll;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use rustls::pki_types::ServerName;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{mpsc, oneshot, watch, Mutex as AsyncMutex, RwLock};
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tokio_util::sync::CancellationToken;

use crate::crypto::CryptoStream;
use crate::msg::{self, Message};
use crate::server::BoxDuplex;

/// Advertised to the upstream in `Login`. Above 0.51 on purpose: frp removed
/// the application heartbeat for newer clients, and `server.rs` only enforces
/// its idle-control monitor for versions below that (see
/// `client_sends_heartbeats`), so claiming 0.71 keeps both this client and
/// ReMgr's own server on the same, heartbeat-free path.
const FRPC_VERSION: &str = "0.71.0";

/// frp's `transport.heartbeatInterval` for the non-mux case (30s), and the
/// timeout frpc then applies to the Pong (90s).
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);
const HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(90);
/// frpc's own cadence for the udp work-connection keepalive ping.
const UDP_KEEPALIVE: Duration = Duration::from_secs(30);
/// frp closes a per-user udp socket that saw no traffic for 30s (`Forwarder`).
const UDP_USER_IDLE: Duration = Duration::from_secs(30);
/// How long a `NewProxy` may stay unanswered before it is reported as failed.
/// The session keeps running: an upstream that answered for some proxies and
/// not others is better reported than torn down, and a restart would only
/// repeat it.
const PROXY_RESPONSE_TIMEOUT: Duration = Duration::from_secs(20);
const INITIAL_BACKOFF: Duration = Duration::from_secs(1);
const MAX_BACKOFF: Duration = Duration::from_secs(30);
/// Backoff floor after a rejected login: a wrong token will not start working,
/// so there is no point hammering the upstream once a second.
const AUTH_FAILED_BACKOFF: Duration = Duration::from_secs(30);
const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);
/// Local connections are opened per work connection; the timeout only bounds
/// a hung local service.
const LOCAL_DIAL_TIMEOUT: Duration = Duration::from_secs(10);
/// Cap on per-user udp sockets held by one udp work connection, so a hostile or
/// broken upstream cannot make the client allocate unboundedly. Stateless UDP
/// flows recover by opening a new socket on the next datagram.
const MAX_UDP_USER_SESSIONS: usize = 512;
/// Cap on udp user sockets across the whole client. Each one is an fd and a
/// task, and the *upstream* decides how many appear: it forwards a datagram for
/// whatever source address reaches the public udp port, and those are trivially
/// spoofed. Beyond this the datagram is dropped (UDP is lossy by nature).
const MAX_UDP_USER_SOCKETS: u64 = 1024;
/// Sanity bound on `pool_count`: the upstream is asked to pre-issue this many
/// work connections, and every one of them becomes a stream and a task here.
const MAX_POOL_COUNT: u32 = 1000;
/// Cap on work connections this client will serve at once. frps asks for one
/// per user connection (plus its pool), so this only ever bites a hostile or
/// broken upstream flooding `ReqWorkConn`: past the yamux stream limit (512 per
/// session, control stream included) the mux driver could not open another
/// stream anyway, and the excess is dropped here instead of piling up as tasks.
const MAX_WORK_CONNS: usize = 500;

fn now_secs() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as i64
}

/// `host:port` for dialing or displaying: a bare IPv6 literal has to be
/// bracketed (`[::1]:7000`), or the resolver reads `::1:7000` as a hostname and
/// every connection through that proxy fails. `server_addr` may equally be a
/// name or an address, which is why the brackets are added here and not by the
/// caller.
fn host_port(host: &str, port: u16) -> String {
    let host = host.trim();
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

fn d_true() -> bool {
    true
}
fn d_server_port() -> u16 {
    7000
}
fn d_connect_timeout() -> u64 {
    10
}
/// frp's `transport.poolCount` default.
fn d_pool_count() -> u32 {
    5
}
fn d_proxy_type() -> String {
    "tcp".into()
}
fn d_local_ip() -> String {
    "127.0.0.1".into()
}

// ---------------------------------------------------------------- config

/// One local service to publish on the upstream.
///
/// Deserializes from either a table (`{"name":…,"proxy_type":…}`) or a single
/// line (`"web tcp 127.0.0.1 8080 7001"` / `"web,udp,127.0.0.1,5353,5353"`),
/// so the console can offer a plain textarea and TOML/JSON can use tables.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct FrpcProxyConfig {
    pub name: String,
    #[serde(rename = "type")]
    pub proxy_type: String,
    pub local_ip: String,
    pub local_port: u16,
    pub remote_port: u16,
}

impl FrpcProxyConfig {
    /// `127.0.0.1:8080` — the address the local service is dialed on. An IPv6
    /// literal keeps the brackets frp's own config uses (`[::1]:8080`): without
    /// them `::1:8080` is not a valid socket address and the dial fails.
    pub fn local_addr(&self) -> String {
        host_port(&self.local_ip, self.local_port)
    }

    /// Parse `name [tcp|udp] [local_ip] local_port remote_port`; commas may be
    /// used instead of spaces. A field that is not a number is taken as
    /// `local_ip`, a leading `tcp`/`udp` as the type, everything else must be a
    /// port — anything else is an error rather than a silent guess. Public
    /// because it is also the console's proxy-line syntax and the probe's.
    pub fn parse_line(s: &str) -> std::result::Result<Self, String> {
        let parts: Vec<&str> = s
            .split(|c: char| c.is_whitespace() || c == ',')
            .filter(|p| !p.is_empty())
            .collect();
        let Some(name) = parts.first() else {
            return Err("empty proxy definition".into());
        };
        let mut p = FrpcProxyConfig {
            name: name.to_string(),
            proxy_type: d_proxy_type(),
            local_ip: d_local_ip(),
            local_port: 0,
            remote_port: 0,
        };
        let mut ports: Vec<u16> = Vec::new();
        let mut ip_seen = false;
        for tok in &parts[1..] {
            if tok.eq_ignore_ascii_case("tcp") || tok.eq_ignore_ascii_case("udp") {
                p.proxy_type = tok.to_ascii_lowercase();
            } else if let Ok(n) = tok.parse::<u16>() {
                ports.push(n);
            } else if let Ok(n) = tok.parse::<i64>() {
                // all digits but unusable as a port (70000, -1, …): a typo that
                // would otherwise be taken for an address and dialed as one
                return Err(format!("proxy {:?}: port {n} is out of range (0-65535)", p.name));
            } else if !ip_seen {
                p.local_ip = (*tok).to_string();
                ip_seen = true;
            } else {
                // A second address (or any other word) is a typo, not a value
                // to guess about: silently ignoring it turns "…127.0.0.1 8080
                // 7001 typo" into a proxy dialing the host "typo".
                return Err(format!(
                    "proxy {:?}: unexpected field {:?} \
                     (name [tcp|udp] [local_ip] local_port remote_port)",
                    p.name, tok
                ));
            }
        }
        if ports.len() > 2 {
            return Err(format!(
                "proxy {:?} has {} port values, expected local_port and remote_port",
                p.name,
                ports.len()
            ));
        }
        if ports.len() < 2 {
            return Err(format!(
                "proxy {:?} needs local_port and remote_port (got {} port value(s))",
                p.name,
                ports.len()
            ));
        }
        p.local_port = ports[0];
        p.remote_port = ports[1];
        Ok(p)
    }
}

impl<'de> Deserialize<'de> for FrpcProxyConfig {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(default)]
        struct Fields {
            name: String,
            #[serde(rename = "type")]
            proxy_type: String,
            local_ip: String,
            local_port: u16,
            remote_port: u16,
        }
        impl Default for Fields {
            fn default() -> Self {
                Self {
                    name: String::new(),
                    proxy_type: d_proxy_type(),
                    local_ip: d_local_ip(),
                    local_port: 0,
                    remote_port: 0,
                }
            }
        }
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Repr {
            Line(String),
            Fields(Fields),
        }
        match Repr::deserialize(d)? {
            Repr::Line(s) => FrpcProxyConfig::parse_line(&s).map_err(serde::de::Error::custom),
            Repr::Fields(f) => Ok(FrpcProxyConfig {
                name: f.name,
                proxy_type: f.proxy_type,
                local_ip: f.local_ip,
                local_port: f.local_port,
                remote_port: f.remote_port,
            }),
        }
    }
}

/// Upstream connection settings plus the proxies to publish.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FrpcConfig {
    /// Off by default: unlike the server modules a client has no useful default
    /// upstream, and auto-starting one that points nowhere would only produce a
    /// startup error on every boot.
    #[serde(default)]
    pub enabled: bool,
    /// upstream frps host name or IP
    #[serde(default)]
    pub server_addr: String,
    #[serde(default = "d_server_port")]
    pub server_port: u16,
    /// shared secret; must equal the upstream's `auth.token`
    #[serde(default)]
    pub token: String,
    /// `transport.tls.enable`
    #[serde(default)]
    pub tls: bool,
    /// PEM bundle used to verify the upstream certificate. Empty (the default)
    /// means "accept any certificate", which is what a self-signed upstream
    /// needs — frp's own default is a self-signed certificate.
    #[serde(default)]
    pub trusted_ca_file: Option<String>,
    /// `transport.tls.serverName`; empty uses `server_addr` (ignored as SNI
    /// when `server_addr` is an IP address).
    #[serde(default)]
    pub server_name: String,
    /// `transport.tcpMux`
    ///
    /// Off means the legacy transport where every work connection is its own TCP
    /// connection. Measured against frp 0.71.0: an frps of 0.52 or newer *always*
    /// multiplexes (its `transport.tcpMux` is gone) and answers the plain
    /// protocol with `yamux: Invalid protocol version: 111` — 111 being the `o`
    /// of the Login frame it just read. ReMgr's own frps behaves the same way
    /// while its `tcp_mux` is on, so with this off the upstream has to be an
    /// older frps or a ReMgr server configured with `tcp_mux` off as well.
    #[serde(default = "d_true")]
    pub tcp_mux: bool,
    /// seconds to reach the upstream and to finish TLS + login
    #[serde(default = "d_connect_timeout")]
    pub connect_timeout: u64,
    /// work connections the upstream is asked to keep warm (`transport.poolCount`)
    #[serde(default = "d_pool_count")]
    pub pool_count: u32,
    #[serde(default)]
    pub proxies: Vec<FrpcProxyConfig>,
}

impl Default for FrpcConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            server_addr: String::new(),
            server_port: d_server_port(),
            token: String::new(),
            tls: false,
            trusted_ca_file: None,
            server_name: String::new(),
            tcp_mux: true,
            connect_timeout: d_connect_timeout(),
            pool_count: d_pool_count(),
            proxies: Vec::new(),
        }
    }
}

impl FrpcConfig {
    /// Everything the console should surface before the client is even started.
    pub fn validate(&self) -> Result<()> {
        if self.server_addr.trim().is_empty() {
            bail!("frpc: server_addr is empty — set the upstream frp server address");
        }
        if self.server_port == 0 {
            bail!("frpc: server_port must not be 0");
        }
        if self.connect_timeout == 0 {
            bail!("frpc: connect_timeout must not be 0");
        }
        // The upstream pre-issues one work connection per pooled slot. A real
        // frps does not clamp this the way ReMgr's own does, so an absurd value
        // would have the upstream (and this client, which then has to open that
        // many streams) allocate until something gives.
        if self.pool_count > MAX_POOL_COUNT {
            bail!(
                "frpc: pool_count {} is out of range (0-{})",
                self.pool_count,
                MAX_POOL_COUNT
            );
        }
        let mut seen: Vec<&str> = Vec::new();
        for (i, p) in self.proxies.iter().enumerate() {
            if p.name.trim().is_empty() {
                bail!("frpc: proxy #{} has no name", i + 1);
            }
            if seen.contains(&p.name.as_str()) {
                bail!("frpc: duplicate proxy name {:?}", p.name);
            }
            seen.push(p.name.as_str());
            match p.proxy_type.as_str() {
                "tcp" | "udp" => {}
                other => bail!(
                    "frpc: proxy {:?} has type {:?}; only tcp and udp are implemented \
                     (http/https/tcpmux/stcp/xtcp are not)",
                    p.name,
                    other
                ),
            }
            if p.local_ip.trim().is_empty() {
                bail!("frpc: proxy {:?} has no local_ip", p.name);
            }
            if p.local_port == 0 {
                bail!("frpc: proxy {:?} has no local_port", p.name);
            }
            if p.remote_port == 0 {
                bail!("frpc: proxy {:?} has no remote_port", p.name);
            }
            // A proxy whose local service is the upstream's own listener (or its
            // own published port on the upstream host) forwards user traffic
            // straight back into itself: reject the literals that can be seen
            // without resolving names.
            if same_host(&p.local_ip, &self.server_addr) && p.local_port == self.server_port {
                bail!(
                    "frpc: proxy {:?} forwards to {:?}, the upstream's own control port — \
                     it would loop back into the tunnel",
                    p.name,
                    host_port(&p.local_ip, p.local_port)
                );
            }
            if same_host(&p.local_ip, &self.server_addr) && p.local_port == p.remote_port {
                bail!(
                    "frpc: proxy {:?} forwards to {:?}, its own published port on the \
                     upstream — it would loop back into the tunnel",
                    p.name,
                    host_port(&p.local_ip, p.local_port)
                );
            }
        }
        Ok(())
    }
}

/// Do two configured hosts name the same machine? Only the forms that can be
/// compared without resolving — an exact match, and the loopback spellings —
/// because resolving here would turn a validation into a name lookup.
fn same_host(a: &str, b: &str) -> bool {
    let (a, b) = (a.trim(), b.trim());
    if a.eq_ignore_ascii_case(b) {
        return true;
    }
    fn loopback(h: &str) -> bool {
        h.eq_ignore_ascii_case("localhost")
            || h.trim_start_matches('[').trim_end_matches(']').parse::<std::net::IpAddr>().map(|ip| ip.is_loopback()).unwrap_or(false)
    }
    loopback(a) && loopback(b)
}

// ---------------------------------------------------------------- status

#[derive(Debug, Clone, Serialize)]
pub struct ProxyStatus {
    pub name: String,
    #[serde(rename = "type")]
    pub proxy_type: String,
    /// `idle` (no session yet) · `waiting` (registered upstream, no answer yet)
    /// · `running` · `error`
    pub state: String,
    pub local_addr: String,
    pub remote_port: u16,
    /// what the upstream answered in `NewProxyResp` (empty until it did)
    pub remote_addr: String,
    /// why this proxy is not running (upstream error, or a timeout)
    pub error: String,
    pub conns_total: u64,
    /// received from the upstream and delivered to the local service
    pub bytes_in: u64,
    /// read from the local service and sent upstream
    pub bytes_out: u64,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct FrpcStatus {
    /// the module is started (it may still be reconnecting)
    pub running: bool,
    /// the control connection is logged in and carrying the current config
    pub connected: bool,
    pub upstream: String,
    pub run_id: String,
    pub tcp_mux: bool,
    pub tls: bool,
    pub token_set: bool,
    /// seconds since the current session logged in (0 while disconnected)
    pub session_uptime_secs: u64,
    pub total_logins: u64,
    pub total_work_conns: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    /// last session-level failure; empty while healthy
    pub last_error: String,
    pub proxies: Vec<ProxyStatus>,
}

/// Per-proxy runtime state, kept across config edits so the console's counters
/// survive a save that did not change the proxy itself.
struct ProxyRuntime {
    cfg: FrpcProxyConfig,
    meta: Mutex<ProxyMeta>,
    conns_total: AtomicU64,
    bytes_in: Arc<AtomicU64>,
    bytes_out: Arc<AtomicU64>,
}

#[derive(Default)]
struct ProxyMeta {
    state: String,
    remote_addr: String,
    error: String,
}

impl ProxyRuntime {
    fn new(cfg: FrpcProxyConfig) -> Self {
        Self {
            cfg,
            meta: Mutex::new(ProxyMeta { state: "idle".into(), ..Default::default() }),
            conns_total: AtomicU64::new(0),
            bytes_in: Arc::new(AtomicU64::new(0)),
            bytes_out: Arc::new(AtomicU64::new(0)),
        }
    }

    fn set(&self, state: &str, remote_addr: Option<String>, error: String) {
        let mut m = self.meta.lock().unwrap_or_else(|e| e.into_inner());
        m.state = state.to_string();
        m.error = error;
        if let Some(a) = remote_addr {
            m.remote_addr = a;
        }
    }

    fn snapshot(&self) -> ProxyStatus {
        let m = self.meta.lock().unwrap_or_else(|e| e.into_inner());
        ProxyStatus {
            name: self.cfg.name.clone(),
            proxy_type: self.cfg.proxy_type.clone(),
            state: m.state.clone(),
            local_addr: self.cfg.local_addr(),
            remote_port: self.cfg.remote_port,
            remote_addr: m.remote_addr.clone(),
            error: m.error.clone(),
            conns_total: self.conns_total.load(Ordering::Relaxed),
            bytes_in: self.bytes_in.load(Ordering::Relaxed),
            bytes_out: self.bytes_out.load(Ordering::Relaxed),
        }
    }
}

/// A byte counter that feeds both the proxy's own total and the client-wide one.
#[derive(Clone)]
struct ByteCounter {
    proxy: Arc<AtomicU64>,
    total: Arc<AtomicU64>,
}

impl ByteCounter {
    fn add(&self, n: usize) {
        self.proxy.fetch_add(n as u64, Ordering::Relaxed);
        self.total.fetch_add(n as u64, Ordering::Relaxed);
    }
}

/// State shared by the supervisor, every session and every work connection.
struct Shared {
    /// live configuration; edited by `update_config`, sampled at session start
    cfg: RwLock<FrpcConfig>,
    /// session-scoped status, written by the supervisor
    status: Mutex<StatusRaw>,
    /// proxies of the running session (rebuilt when the config changes)
    proxies: Mutex<Arc<HashMap<String, Arc<ProxyRuntime>>>>,
    bytes_in: Arc<AtomicU64>,
    bytes_out: Arc<AtomicU64>,
    total_logins: AtomicU64,
    total_work_conns: AtomicU64,
    /// run_id handed back by the upstream: frpc re-sends it on every reconnect
    /// so the upstream replaces the stale control instead of keeping both.
    last_run_id: Mutex<String>,
    /// Watch channel used to tell a live session that the config changed.
    cfg_tx: watch::Sender<u64>,
    cfg_gen: AtomicU64,
    /// Permits for work connections in flight, so a `ReqWorkConn` flood cannot
    /// grow tasks (and yamux streams) without bound — see `MAX_WORK_CONNS`.
    work_permits: Arc<tokio::sync::Semaphore>,
    /// udp user sockets currently open (see `MAX_UDP_USER_SOCKETS`).
    udp_user_sockets: Arc<AtomicU64>,
}

#[derive(Default)]
struct StatusRaw {
    running: bool,
    connected: bool,
    session_started: Option<Instant>,
    /// non-empty when the last session ended with an error
    last_error: String,
}

impl Shared {
    fn new(cfg: FrpcConfig) -> Arc<Self> {
        let (cfg_tx, _rx) = watch::channel(0u64);
        let shared = Arc::new(Self {
            cfg: RwLock::new(cfg.clone()),
            status: Mutex::new(StatusRaw::default()),
            proxies: Mutex::new(Arc::new(HashMap::new())),
            bytes_in: Arc::new(AtomicU64::new(0)),
            bytes_out: Arc::new(AtomicU64::new(0)),
            total_logins: AtomicU64::new(0),
            total_work_conns: AtomicU64::new(0),
            last_run_id: Mutex::new(String::new()),
            cfg_tx,
            cfg_gen: AtomicU64::new(0),
            work_permits: Arc::new(tokio::sync::Semaphore::new(MAX_WORK_CONNS)),
            udp_user_sockets: Arc::new(AtomicU64::new(0)),
        });
        shared.rebuild_proxies(&cfg);
        shared
    }

    /// Rebuild the proxy registry from `cfg`, carrying the counters of proxies
    /// whose definition did not change (a console save must not reset the
    /// traffic figures of an untouched proxy). The caller passes the config in
    /// because `tokio::sync::RwLock` has no blocking read outside a runtime.
    fn rebuild_proxies(&self, cfg: &FrpcConfig) {
        let previous = self.proxies.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let mut map = HashMap::new();
        for p in &cfg.proxies {
            let keep = previous
                .get(&p.name)
                .filter(|old| {
                    old.cfg.proxy_type == p.proxy_type
                        && old.cfg.local_ip == p.local_ip
                        && old.cfg.local_port == p.local_port
                        && old.cfg.remote_port == p.remote_port
                })
                .cloned();
            match keep {
                Some(rt) => {
                    map.insert(p.name.clone(), rt);
                }
                None => {
                    map.insert(p.name.clone(), Arc::new(ProxyRuntime::new(p.clone())));
                }
            }
        }
        *self.proxies.lock().unwrap_or_else(|e| e.into_inner()) = Arc::new(map);
    }

    fn proxies(&self) -> Arc<HashMap<String, Arc<ProxyRuntime>>> {
        self.proxies.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    fn set_error(&self, e: String) {
        let mut st = self.status.lock().unwrap_or_else(|e| e.into_inner());
        st.last_error = e;
    }

    fn set_connected(&self, connected: bool, run_id: &str) {
        let mut st = self.status.lock().unwrap_or_else(|e| e.into_inner());
        st.connected = connected;
        st.session_started = if connected { Some(Instant::now()) } else { None };
        if connected && !run_id.is_empty() {
            *self.last_run_id.lock().unwrap_or_else(|e| e.into_inner()) = run_id.to_string();
        }
    }

    fn previous_run_id(&self) -> String {
        self.last_run_id.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    fn mark_all_proxies_idle(&self) {
        for rt in self.proxies().values() {
            rt.set("idle", None, String::new());
        }
    }
}

// ---------------------------------------------------------------- mux session

/// A yamux session with a driver task, so work connections can be opened from
/// any task while `Connection::poll_next_inbound` keeps the session pumping.
///
/// rust-yamux 0.13 has no keepalive of its own (its `Config` has no such knob):
/// frp's Go side pings every `tcpMuxKeepaliveInterval` (30s) and answers pings,
/// and rust-yamux answers the pings it receives — which is what keeps a session
/// with a real frps alive. Two ReMgr endpoints rely on TCP keepalive instead.
struct MuxSession {
    open_tx: mpsc::Sender<OpenReq>,
    token: CancellationToken,
    join: AsyncMutex<Option<tokio::task::JoinHandle<()>>>,
}

type OpenReq = oneshot::Sender<Result<yamux::Stream>>;
type MuxConn = yamux::Connection<tokio_util::compat::Compat<BoxDuplex>>;

impl MuxSession {
    fn start(io: BoxDuplex, token: CancellationToken) -> Self {
        let (open_tx, open_rx) = mpsc::channel::<OpenReq>(16);
        let driver_token = token.clone();
        let join = tokio::spawn(async move {
            let conn = yamux::Connection::new(io.compat(), yamux::Config::default(), yamux::Mode::Client);
            mux_driver(conn, open_rx, driver_token).await;
        });
        Self { open_tx, token, join: AsyncMutex::new(Some(join)) }
    }

    async fn open(&self) -> Result<yamux::Stream> {
        let (tx, rx) = oneshot::channel();
        self.open_tx
            .send(tx)
            .await
            .map_err(|_| anyhow!("the yamux session is closed"))?;
        match rx.await {
            Ok(r) => r,
            Err(_) => Err(anyhow!("the yamux session closed before opening the stream")),
        }
    }

    /// Stop the driver and wait for it, so the underlying connection is really
    /// gone before the next reconnect dials a fresh one.
    async fn close(&self) {
        self.token.cancel();
        let mut join = self.join.lock().await;
        if let Some(j) = join.take() {
            let _ = tokio::time::timeout(SHUTDOWN_GRACE, j).await;
        }
    }
}

/// Owns the `yamux::Connection`: opens requested streams and keeps draining
/// inbound frames (without that, window updates for open streams would never be
/// processed and every transfer would stall).
async fn mux_driver(
    mut conn: MuxConn,
    mut open_rx: mpsc::Receiver<OpenReq>,
    token: CancellationToken,
) {
    let mut pending: Vec<OpenReq> = Vec::new();
    loop {
        // Serve everything that can be served right now.
        while !pending.is_empty() {
            match poll_open_now(&mut conn).await {
                Poll::Ready(Ok(stream)) => {
                    if let Some(req) = pending.pop() {
                        let _ = req.send(Ok(stream));
                    }
                }
                Poll::Ready(Err(e)) => {
                    // A stream-level failure — in practice the yamux stream
                    // limit, which is per connection, not fatal to it — must not
                    // end the session: the control stream is still usable, so
                    // fail what is queued and go back to serving it. (Ending the
                    // session here made a `ReqWorkConn` flood tear the tunnel
                    // down and reconnect, over and over.)
                    for req in pending.drain(..) {
                        let _ = req.send(Err(anyhow!("yamux open failed: {e}")));
                    }
                    break;
                }
                // Only reachable with the stream limit hit; retried below.
                Poll::Pending => break,
            }
        }

        tokio::select! {
            _ = token.cancelled() => break,
            req = open_rx.recv() => match req {
                Some(r) => pending.push(r),
                None => break,
            },
            retry = tokio::time::sleep(Duration::from_millis(200)), if !pending.is_empty() => {
                let _ = retry;
            }
            inbound = futures_util::future::poll_fn(|cx| conn.poll_next_inbound(cx)) => {
                match inbound {
                    Some(Ok(stream)) => {
                        // frps never opens streams towards an frpc in V1; if one
                        // appears, dropping it resets it instead of leaking it.
                        tracing::debug!("frpc: unexpected inbound yamux stream, resetting it");
                        drop(stream);
                    }
                    Some(Err(e)) => {
                        tracing::debug!("frpc: yamux session error: {e}");
                        break;
                    }
                    None => break,
                }
            }
        }
    }
    for req in pending.drain(..) {
        let _ = req.send(Err(anyhow!("the yamux session is closed")));
    }
}

/// Is this one of the type bytes frp defines?
///
/// Used to tell "a message this client has no variant for, but the protocol
/// defines" (skip it, the stream is still in sync) from "a byte frp does not
/// define at all" (the stream is out of sync — end the session). The server
/// half keeps the same distinction in its own reader.
fn is_known_frame_type(tb: u8) -> bool {
    matches!(
        tb,
        msg::TYPE_LOGIN
            | msg::TYPE_LOGIN_RESP
            | msg::TYPE_NEW_PROXY
            | msg::TYPE_NEW_PROXY_RESP
            | msg::TYPE_CLOSE_PROXY
            | msg::TYPE_NEW_WORK_CONN
            | msg::TYPE_REQ_WORK_CONN
            | msg::TYPE_START_WORK_CONN
            | msg::TYPE_NEW_VISITOR_CONN
            | msg::TYPE_NEW_VISITOR_CONN_RESP
            | msg::TYPE_PING
            | msg::TYPE_PONG
            | msg::TYPE_UDP_PACKET
    )
}

/// Poll for a new outbound stream without awaiting it: the caller needs the
/// `Pending` case to keep draining the connection instead of blocking on it.
fn poll_open_now(
    conn: &mut MuxConn,
) -> impl std::future::Future<Output = Poll<std::result::Result<yamux::Stream, yamux::ConnectionError>>> + '_ {
    futures_util::future::poll_fn(|cx| Poll::Ready(conn.poll_new_outbound(cx)))
}

// ---------------------------------------------------------------- client

struct RunHandle {
    token: CancellationToken,
    join: tokio::task::JoinHandle<()>,
}

/// An frp client. Cheap to hold: every session lives in a tokio task tree, and
/// the struct itself only owns configuration and counters.
pub struct FrpcClient {
    shared: Arc<Shared>,
    run: AsyncMutex<Option<RunHandle>>,
}

impl FrpcClient {
    pub fn new(cfg: FrpcConfig) -> Self {
        Self { shared: Shared::new(cfg), run: AsyncMutex::new(None) }
    }

    /// Validate and adopt a new configuration. If a session is live it is
    /// ended so the supervisor reconnects with the new settings; unchanged
    /// proxies keep their counters and their traffic only pauses for the
    /// reconnect (this is also what `apply_config` in the console path does).
    ///
    /// Re-sending the configuration the client already has — which is what the
    /// console's `start` and every `apply_config` do — is *not* a change: it
    /// must not bounce a live session or reset its uptime.
    pub async fn update_config(&self, cfg: FrpcConfig) {
        if *self.shared.cfg.read().await == cfg {
            return;
        }
        // Rebuild the proxy registry before publishing the new config: a session
        // that picks the config up immediately must find every proxy in it.
        self.shared.rebuild_proxies(&cfg);
        *self.shared.cfg.write().await = cfg;
        let gen = self.shared.cfg_gen.fetch_add(1, Ordering::Relaxed) + 1;
        // Only reaches a receiver while a supervisor is running; a send error
        // simply means "nobody to notify".
        let _ = self.shared.cfg_tx.send(gen);
    }

    pub async fn config(&self) -> FrpcConfig {
        self.shared.cfg.read().await.clone()
    }

    /// Start supervising. Idempotent: starting a running client is a no-op.
    /// Fails before spawning anything if the configuration cannot work, so the
    /// console's "start" shows the reason immediately.
    pub async fn start(&self) -> Result<()> {
        let mut run = self.run.lock().await;
        // A supervisor that ended by itself (a configuration it could not use)
        // leaves its handle behind. Without this check `start` would report
        // success while nothing was running, and neither the console's Start
        // button nor `restart_if_running` could ever bring the client back.
        if run.as_ref().is_some_and(|h| h.join.is_finished()) {
            *run = None;
        }
        if run.is_some() {
            return Ok(());
        }
        let cfg = self.shared.cfg.read().await.clone();
        cfg.validate()?;

        {
            let mut st = self.shared.status.lock().unwrap_or_else(|e| e.into_inner());
            st.running = true;
            st.connected = false;
            st.session_started = None;
            st.last_error = String::new();
        }
        self.shared.mark_all_proxies_idle();

        let token = CancellationToken::new();
        let shared = self.shared.clone();
        let join = tokio::spawn(supervise(shared, token.clone()));
        *run = Some(RunHandle { token, join });
        if !cfg.tcp_mux {
            // Not fatal (an old frps, or ReMgr's own server with tcp_mux off,
            // still works), but the failure it produces otherwise is the bare
            // "early eof", which says nothing about the cause.
            tracing::warn!(
                "frpc: tcp_mux is off — frp 0.52 and newer multiplex every connection, so this \
                 only works against an older frps or a ReMgr server with tcp_mux off"
            );
        }
        tracing::info!(
            "frpc: started (upstream {} tcp_mux={} tls={} proxies={})",
            host_port(&cfg.server_addr, cfg.server_port),
            cfg.tcp_mux,
            cfg.tls,
            cfg.proxies.len()
        );
        Ok(())
    }

    /// Stop and wait for the session to be torn down (bounded: a hung network
    /// call must not hold the console, and the task is cancel-aware anyway).
    ///
    /// The run lock stays held until the supervisor is gone, so a `stop` racing
    /// a `start` (the console's restart, or two browser tabs) cannot leave a
    /// second supervisor and a second session next to the one still tearing
    /// down — the old session's teardown would report the new one as down.
    pub async fn stop(&self) -> Result<()> {
        let mut run = self.run.lock().await;
        if let Some(h) = run.take() {
            h.token.cancel();
            if tokio::time::timeout(SHUTDOWN_GRACE, h.join).await.is_err() {
                tracing::warn!("frpc: shutdown took longer than {}s, continuing without it", SHUTDOWN_GRACE.as_secs());
            }
        }
        self.shared.set_connected(false, "");
        self.shared.mark_all_proxies_idle();
        {
            let mut st = self.shared.status.lock().unwrap_or_else(|e| e.into_inner());
            st.running = false;
            st.connected = false;
            st.session_started = None;
        }
        tracing::info!("frpc: stopped");
        Ok(())
    }

    pub async fn is_running(&self) -> bool {
        self.shared.status.lock().unwrap_or_else(|e| e.into_inner()).running
    }

    pub async fn status(&self) -> FrpcStatus {
        let cfg = self.shared.cfg.read().await.clone();
        let (running, connected, uptime, last_error) = {
            let st = self.shared.status.lock().unwrap_or_else(|e| e.into_inner());
            (
                st.running,
                st.connected,
                st.session_started.map(|t| t.elapsed().as_secs()).unwrap_or(0),
                st.last_error.clone(),
            )
        };
        let mut proxies: Vec<ProxyStatus> = self.shared.proxies().values().map(|p| p.snapshot()).collect();
        proxies.sort_by(|a, b| a.name.cmp(&b.name));
        FrpcStatus {
            running,
            connected,
            upstream: host_port(&cfg.server_addr, cfg.server_port),
            run_id: self.shared.previous_run_id(),
            tcp_mux: cfg.tcp_mux,
            tls: cfg.tls,
            token_set: !cfg.token.is_empty(),
            session_uptime_secs: uptime,
            total_logins: self.shared.total_logins.load(Ordering::Relaxed),
            total_work_conns: self.shared.total_work_conns.load(Ordering::Relaxed),
            bytes_in: self.shared.bytes_in.load(Ordering::Relaxed),
            bytes_out: self.shared.bytes_out.load(Ordering::Relaxed),
            last_error,
            proxies,
        }
    }
}

// ---------------------------------------------------------------- supervisor

/// Reconnect loop. Every session failure is recorded and retried with
/// exponential backoff; a configuration change interrupts the wait so an
/// operator's edit takes effect immediately.
async fn supervise(shared: Arc<Shared>, token: CancellationToken) {
    let mut cfg_rx = shared.cfg_tx.subscribe();
    let mut backoff = INITIAL_BACKOFF;
    loop {
        if token.is_cancelled() {
            break;
        }
        let cfg = shared.cfg.read().await.clone();
        // A configuration that cannot be used at all (no upstream, a bad proxy
        // list) would fail identically on every attempt: report it once and stop
        // supervising instead of spinning in the backoff loop. `running` goes
        // back to false so the console shows a stopped module carrying the
        // reason, and a later `start()` revalidates.
        if let Err(e) = cfg.validate() {
            let msg = format!("{e:#}");
            tracing::error!("frpc: {msg}; not connecting");
            shared.set_error(msg);
            shared.status.lock().unwrap_or_else(|e| e.into_inner()).running = false;
            break;
        }

        shared.mark_all_proxies_idle();
        shared.set_connected(false, "");
        // Mark the current generation as seen *before* the session's receiver is
        // cloned from this one: otherwise a clone inherits an unseen generation
        // and its first `changed()` returns immediately, which would restart the
        // session in a tight loop.
        let _ = cfg_rx.borrow_and_update();
        let upstream = host_port(&cfg.server_addr, cfg.server_port);
        let started = Instant::now();
        let outcome = tokio::select! {
            _ = token.cancelled() => break,
            r = run_session(shared.clone(), Arc::new(cfg), token.clone(), cfg_rx.clone()) => r,
        };

        shared.set_connected(false, "");
        match outcome {
            Ok(()) => {
                // Only reached when the session was cancelled (handled by the
                // loop's head) or when the configuration changed: reconnect now,
                // without a backoff penalty for the operator's edit.
                if token.is_cancelled() {
                    break;
                }
                backoff = INITIAL_BACKOFF;
                continue;
            }
            Err(e) => {
                let msg = format!("{e:#}");
                let auth_failed = is_auth_failure(&msg);
                tracing::warn!("frpc: session to {upstream} ended: {msg}");
                shared.set_error(msg);
                // A session that was up for a while proves the path works, so
                // restart the backoff at the low end; a login rejected for a bad
                // token will not improve in one second, so hold it long.
                backoff = if auth_failed {
                    AUTH_FAILED_BACKOFF
                } else if started.elapsed() < Duration::from_secs(30) {
                    (backoff * 2).min(MAX_BACKOFF)
                } else {
                    INITIAL_BACKOFF
                };
            }
        }

        tokio::select! {
            _ = token.cancelled() => break,
            _ = tokio::time::sleep(backoff) => {}
            _ = cfg_rx.changed() => {}
        }
    }
    // A cancelled token means the run was stopped from outside: `stop()` owns
    // the reported state from here on, and a `start` racing its grace period
    // may already have a newer session up. Writing "disconnected" here would
    // report that new session as down.
    if !token.is_cancelled() {
        shared.set_connected(false, "");
        shared.mark_all_proxies_idle();
    }
}

/// Does this session error look like "the upstream refused our token"?
fn is_auth_failure(msg: &str) -> bool {
    let m = msg.to_ascii_lowercase();
    m.contains("authentication failed") || m.contains("auth failed") || m.contains("token")
}

// ---------------------------------------------------------------- session

/// One live control connection plus everything derived from it.
struct Session {
    shared: Arc<Shared>,
    cfg: Arc<FrpcConfig>,
    run_id: String,
    /// cancelled when the session ends; every task it spawned watches it
    token: CancellationToken,
    mux: Option<MuxSession>,
    proxies: Arc<HashMap<String, Arc<ProxyRuntime>>>,
}

impl Session {
    /// Open the I/O for one work connection: a yamux stream, or a fresh
    /// (optionally TLS) TCP connection when tcp_mux is off.
    async fn open_io(&self) -> Result<BoxDuplex> {
        match &self.mux {
            Some(mux) => {
                let timeout = Duration::from_secs(self.cfg.connect_timeout.max(1));
                let stream = tokio::time::timeout(timeout, mux.open())
                    .await
                    .map_err(|_| anyhow!("timed out opening a work stream on the mux session"))??;
                Ok(Box::new(stream.compat()))
            }
            None => connect_upstream(&self.cfg).await,
        }
    }
}

/// Run one control session to completion. `Ok(())` means "stopped on purpose"
/// (cancelled or reconfigured); every other ending is an error to report and
/// retry.
async fn run_session(
    shared: Arc<Shared>,
    cfg: Arc<FrpcConfig>,
    token: CancellationToken,
    mut cfg_rx: watch::Receiver<u64>,
) -> Result<()> {
    let session_token = token.child_token();
    let result = run_session_inner(shared, cfg, session_token.clone(), &mut cfg_rx).await;
    // The mux driver and every work connection task watch this token; cancelling
    // it here covers the error paths too.
    session_token.cancel();
    result
}

async fn run_session_inner(
    shared: Arc<Shared>,
    cfg: Arc<FrpcConfig>,
    token: CancellationToken,
    cfg_rx: &mut watch::Receiver<u64>,
) -> Result<()> {
    // ---- connect + login
    let mut control = connect_upstream(&cfg).await?;
    let mut mux = None;
    if cfg.tcp_mux {
        let session = MuxSession::start(control, token.clone());
        // The stream speaks futures-io (yamux's own traits); `compat` turns it
        // back into the tokio traits the rest of this file uses.
        control = Box::new(
            tokio::time::timeout(Duration::from_secs(cfg.connect_timeout.max(1)), session.open())
                .await
                .map_err(|_| anyhow!("timed out opening the control stream"))??
                .compat(),
        );
        mux = Some(session);
    }

    let ts = now_secs();
    let login = msg::Login {
        version: FRPC_VERSION.into(),
        // No libc dependency here, and frp only shows this in its own UI: take
        // the environment's value when there is one, otherwise leave it out.
        hostname: std::env::var("HOSTNAME").unwrap_or_default(),
        os: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        privilege_key: msg::auth_key(&cfg.token, ts),
        timestamp: ts,
        // Re-send the run_id the upstream gave us, so it replaces the control
        // connection this one follows (frpc does the same).
        run_id: shared.previous_run_id(),
        // the wire type is Go's `int` (see msg.rs); the config keeps it unsigned
        pool_count: cfg.pool_count as i64,
        ..Default::default()
    };
    msg::write_msg(&mut control, &login, msg::TYPE_LOGIN).await?;

    let login_timeout = Duration::from_secs(cfg.connect_timeout.max(1));
    let (tb, body) = tokio::time::timeout(login_timeout, msg::read_frame(&mut control))
        .await
        .map_err(|_| anyhow!("timed out waiting for LoginResp"))?
        .with_context(|| {
            // With tcp_mux off the far side may have wrapped the connection in
            // yamux anyway — frp 0.52 and newer always do — and then this read
            // fails with an EOF or a nonsense length instead of anything that
            // names the cause.
            if cfg.tcp_mux {
                "reading LoginResp".to_string()
            } else {
                "reading LoginResp with tcp_mux off (frp servers 0.52 and newer always multiplex; \
                 the upstream has to be an older frps or a ReMgr server with tcp_mux off)"
                    .to_string()
            }
        })?;
    if tb != msg::TYPE_LOGIN_RESP {
        bail!("first message from the upstream is not LoginResp (type {tb:#04x})");
    }
    let resp: msg::LoginResp = serde_json::from_slice(&body).context("parsing LoginResp")?;
    if !resp.error.is_empty() {
        // frp's server words a bad token "authentication failed"; keep the
        // upstream's own text so the console shows exactly what it said.
        bail!("upstream rejected the login: {}", resp.error);
    }
    let run_id = resp.run_id.clone();
    shared.total_logins.fetch_add(1, Ordering::Relaxed);
    shared.set_connected(true, &run_id);
    tracing::info!(
        "frpc: logged in to {}:{} run_id={run_id} (upstream version {})",
        cfg.server_addr,
        cfg.server_port,
        if resp.version.is_empty() { "?" } else { &resp.version }
    );

    // Everything after LoginResp is encrypted with the token-derived key — frp
    // derives it unconditionally, so this happens for an empty token too.
    let io = CryptoStream::new(control, cfg.token.as_bytes());
    let (rd, wr) = tokio::io::split(io);
    let wr = Arc::new(AsyncMutex::new(wr));

    let (ev_tx, mut ev_rx) = mpsc::channel::<Message>(128);
    let reader_token = token.clone();
    let reader = tokio::spawn(control_reader(rd, ev_tx, reader_token));

    let session = Arc::new(Session {
        shared: shared.clone(),
        cfg: cfg.clone(),
        run_id: run_id.clone(),
        token: token.clone(),
        mux,
        proxies: shared.proxies(),
    });

    // ---- register every proxy
    let mut pending: HashMap<String, Instant> = HashMap::new();
    let deadline = Instant::now() + PROXY_RESPONSE_TIMEOUT;
    for p in &cfg.proxies {
        if let Some(rt) = session.proxies.get(&p.name) {
            rt.set("waiting", None, String::new());
        }
        let np = msg::NewProxy {
            proxy_name: p.name.clone(),
            proxy_type: p.proxy_type.clone(),
            remote_port: p.remote_port as i64,
            ..Default::default()
        };
        if let Err(e) = send_control(&wr, &np, msg::TYPE_NEW_PROXY).await {
            bail!("sending NewProxy for {} failed: {e:#}", p.name);
        }
        pending.insert(p.name.clone(), deadline);
    }

    // ---- control loop
    let mut heartbeat = tokio::time::interval(HEARTBEAT_INTERVAL);
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // First tick fires immediately; skip it so a fresh session does not ping
    // before it has anything to say.
    heartbeat.tick().await;
    let mut last_pong = Instant::now();

    let result = loop {
        // Wake up for the oldest unanswered NewProxy even when nothing else
        // happens on the control connection.
        let register_deadline = pending
            .values()
            .min()
            .copied()
            .unwrap_or_else(|| Instant::now() + Duration::from_secs(3600));

        tokio::select! {
            _ = token.cancelled() => break Ok(()),
            _ = cfg_rx.changed() => {
                tracing::info!("frpc: configuration changed, reconnecting");
                break Ok(());
            }
            ev = ev_rx.recv() => match ev {
                // The reader task ends when the control connection dies, which
                // is the trigger for the supervisor's reconnect.
                None => break Err(anyhow!("the upstream closed the control connection")),
                Some(Message::NewProxyResp(r)) => {
                    pending.remove(&r.proxy_name);
                    let Some(rt) = session.proxies.get(&r.proxy_name) else {
                        tracing::debug!("frpc: NewProxyResp for unknown proxy {}", r.proxy_name);
                        continue;
                    };
                    if r.error.is_empty() {
                        tracing::info!("frpc: proxy {} is up on the upstream at {}", r.proxy_name, r.remote_addr);
                        rt.set("running", Some(r.remote_addr.clone()), String::new());
                    } else {
                        tracing::error!("frpc: proxy {} rejected by the upstream: {}", r.proxy_name, r.error);
                        rt.set("error", None, r.error.clone());
                    }
                }
                Some(Message::ReqWorkConn(_)) => {
                    shared.total_work_conns.fetch_add(1, Ordering::Relaxed);
                    let session = session.clone();
                    // One permit per work connection in flight: an upstream that
                    // floods ReqWorkConn (or a user connection for every datagram
                    // of a spoofed udp flood) would otherwise spawn an unbounded
                    // number of tasks, each holding a yamux stream or a TCP
                    // connection. Excess requests are dropped, not queued: a real
                    // frps asks for a work conn per user connection and keeps a
                    // pool of a few, so this only ever truncates a flood.
                    match shared.work_permits.clone().try_acquire_owned() {
                        Ok(permit) => {
                            tokio::spawn(async move {
                                let _permit = permit;
                                if let Err(e) = serve_work_conn(session).await {
                                    tracing::debug!("frpc: work connection ended: {e:#}");
                                }
                            });
                        }
                        Err(_) => tracing::debug!(
                            "frpc: ignoring ReqWorkConn, {} work connections already in flight",
                            MAX_WORK_CONNS
                        ),
                    }
                }
                Some(Message::Pong(p)) => {
                    if p.error.is_empty() {
                        last_pong = Instant::now();
                    } else {
                        // frp answers an invalid ping with an error Pong; that is
                        // a credential problem, not a transient one.
                        break Err(anyhow!("upstream rejected our heartbeat: {}", p.error));
                    }
                }
                Some(other) => {
                    tracing::debug!("frpc: ignoring control message {:?}", other.type_byte() as char);
                }
            },
            _ = heartbeat.tick(), if !cfg.tcp_mux => {
                let ts = now_secs();
                let ping = msg::Ping {
                    privilege_key: msg::auth_key(&cfg.token, ts),
                    timestamp: ts,
                };
                if let Err(e) = send_control(&wr, &ping, msg::TYPE_PING).await {
                    break Err(anyhow!("sending Ping failed: {e:#}"));
                }
                if last_pong.elapsed() > HEARTBEAT_TIMEOUT {
                    break Err(anyhow!("no Pong for {}s", HEARTBEAT_TIMEOUT.as_secs()));
                }
            }
            _ = tokio::time::sleep_until(tokio::time::Instant::from_std(register_deadline)), if !pending.is_empty() => {
                for name in pending.keys() {
                    if let Some(rt) = session.proxies.get(name) {
                        tracing::warn!("frpc: no NewProxyResp for {name}, marking it failed");
                        rt.set("error", None, "no response from the upstream".into());
                    }
                }
                pending.clear();
            }
        }
    };

    // ---- teardown
    // `token` is only already cancelled when the *supervisor* was cancelled, so
    // this session was stopped from outside and `stop()` owns the reported
    // state (a `start` racing stop's grace period may already have a newer
    // session up, which must not be reported as disconnected by this one).
    let stopped_from_outside = token.is_cancelled();
    token.cancel();
    if let Some(mux) = &session.mux {
        mux.close().await;
    }
    reader.abort();
    if !stopped_from_outside {
        shared.set_connected(false, "");
    }
    result
}

/// Split the control connection into "frames in" events for the session loop.
///
/// A frame the peer defined but this client has no variant for is skipped (the
/// same policy as the server half); a type byte frp does not define at all ends
/// the session, because the stream is then out of sync.
async fn control_reader<R: AsyncRead + Unpin>(mut r: R, tx: mpsc::Sender<Message>, token: CancellationToken) {
    loop {
        let frame = tokio::select! {
            _ = token.cancelled() => return,
            f = msg::read_frame(&mut r) => f,
        };
        let (tb, body) = match frame {
            Ok(f) => f,
            Err(e) => {
                tracing::debug!("frpc: control connection read ended: {e:#}");
                return;
            }
        };
        match Message::decode(tb, &body) {
            Ok(m) => {
                if tx.send(m).await.is_err() {
                    return;
                }
            }
            Err(e) if is_known_frame_type(tb) => {
                tracing::debug!("frpc: skipping control message {tb:#04x}: {e}");
            }
            Err(e) => {
                tracing::warn!("frpc: unknown control message {tb:#04x}: {e}");
                return;
            }
        }
    }
}

/// Write one control message.
///
/// The body is the *payload* struct, never the `Message` enum: frp frames carry
/// the bare JSON object of the message type, and the enum's externally-tagged
/// form (`{"new_proxy":{…}}`) would decode on the far side as a message with
/// every field defaulted — silently, because frp's structs ignore unknown keys.
async fn send_control<W, T>(wr: &Arc<AsyncMutex<W>>, m: &T, type_byte: u8) -> Result<()>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let body = serde_json::to_vec(m)?;
    let mut w = wr.lock().await;
    msg::write_frame(&mut *w, type_byte, &body).await
}

// ---------------------------------------------------------------- dialing

/// Connect to the upstream: TCP, then optionally frp's custom TLS handshake.
async fn connect_upstream(cfg: &FrpcConfig) -> Result<BoxDuplex> {
    let timeout = Duration::from_secs(cfg.connect_timeout.max(1));
    let target = host_port(&cfg.server_addr, cfg.server_port);
    let tcp = tokio::time::timeout(timeout, TcpStream::connect(&target))
        .await
        .map_err(|_| anyhow!("timed out connecting to {target}"))?
        .with_context(|| format!("connecting to {target}"))?;
    let _ = tcp.set_nodelay(true);
    // With tcp_mux neither side sends an application-level heartbeat (frpc ≥0.52
    // removed it, and rust-yamux only pings while it is being polled and never
    // fails a connection on an unacknowledged ping). Without this, a peer whose
    // host dies silently — no FIN: a power loss, a dropped NAT mapping — leaves
    // the session reported as connected forever. TCP keepalive lets the kernel
    // notice; the timing is sysctl-driven on OpenBSD.
    if let Err(e) = socket2::SockRef::from(&tcp).set_keepalive(true) {
        tracing::debug!("frpc: could not enable tcp keepalive on {target}: {e}");
    }

    if !cfg.tls {
        return Ok(Box::new(tcp));
    }

    // frp's transport.tls: a single 0x17 byte, then the handshake (the server
    // sniffs that byte to tell TLS from the plain protocol).
    let mut tcp = tcp;
    tcp.write_all(&[0x17]).await.context("writing the frp TLS marker")?;
    tcp.flush().await.ok();

    let config = tls_client_config(cfg)?;
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let name = ServerName::try_from(server_name(cfg)).map_err(|e| anyhow!("invalid TLS server name: {e}"))?;
    let stream = tokio::time::timeout(timeout, connector.connect(name, tcp))
        .await
        .map_err(|_| anyhow!("timed out during the TLS handshake with {target}"))?
        .context("TLS handshake with the upstream")?;
    Ok(Box::new(stream))
}

fn server_name(cfg: &FrpcConfig) -> String {
    if cfg.server_name.trim().is_empty() {
        cfg.server_addr.clone()
    } else {
        cfg.server_name.clone()
    }
}

fn tls_client_config(cfg: &FrpcConfig) -> Result<rustls::ClientConfig> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])?;

    match cfg.trusted_ca_file.as_deref() {
        Some(path) if !path.trim().is_empty() => {
            let pem = std::fs::read(path).with_context(|| format!("reading trusted_ca_file {path}"))?;
            let mut roots = rustls::RootCertStore::empty();
            let mut added = 0usize;
            for cert in rustls_pemfile::certs(&mut pem.as_slice()) {
                let cert = cert.with_context(|| format!("parsing {path}"))?;
                roots.add(cert).with_context(|| format!("adding a certificate from {path}"))?;
                added += 1;
            }
            if added == 0 {
                bail!("trusted_ca_file {path} contains no PEM certificate");
            }
            Ok(builder.with_root_certificates(roots).with_no_client_auth())
        }
        // No CA configured: accept whatever the upstream presents. frp's own
        // certificates are self-signed by default, so verifying them against the
        // system roots would refuse every default deployment.
        _ => Ok(builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerification::new(provider)))
            .with_no_client_auth()),
    }
}

/// Certificate verifier that accepts any certificate. Only reachable through
/// the "no trusted_ca_file" configuration documented on `FrpcConfig::tls`.
#[derive(Debug)]
struct NoVerification {
    schemes: rustls::crypto::WebPkiSupportedAlgorithms,
}

impl NoVerification {
    fn new(provider: Arc<rustls::crypto::CryptoProvider>) -> Self {
        Self { schemes: provider.signature_verification_algorithms }
    }
}

impl rustls::client::danger::ServerCertVerifier for NoVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.schemes)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.schemes)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.schemes.supported_schemes()
    }
}

// ---------------------------------------------------------------- work conns

/// Serve one work connection: hand it to the proxy the upstream chose.
///
/// Pooled work connections sit in the `read_frame` below until the upstream
/// assigns a user to them, which is why that read has no deadline — it ends
/// with the connection or with the session, like frpc's own blocking read.
async fn serve_work_conn(session: Arc<Session>) -> Result<()> {
    let mut io = session.open_io().await?;

    let ts = now_secs();
    let nwc = msg::NewWorkConn {
        run_id: session.run_id.clone(),
        privilege_key: msg::auth_key(&session.cfg.token, ts),
        timestamp: ts,
    };
    msg::write_msg(&mut io, &nwc, msg::TYPE_NEW_WORK_CONN).await?;

    let frame = tokio::select! {
        _ = session.token.cancelled() => return Ok(()),
        f = msg::read_frame(&mut io) => f,
    };
    let (tb, body) = frame.context("reading StartWorkConn")?;
    if tb != msg::TYPE_START_WORK_CONN {
        bail!("expected StartWorkConn, got message type {tb:#04x}");
    }
    let start: msg::StartWorkConn = serde_json::from_slice(&body).context("parsing StartWorkConn")?;
    if !start.error.is_empty() {
        // frps puts the reason it refuses the connection here; frpc logs it and
        // drops the connection, and the proxy keeps its own retry next time.
        bail!("upstream refused the work connection: {}", start.error);
    }
    let Some(rt) = session.proxies.get(&start.proxy_name).cloned() else {
        bail!(
            "upstream started a work connection for unknown proxy {:?} (this client publishes: {})",
            start.proxy_name,
            session.proxies.keys().cloned().collect::<Vec<_>>().join(", ")
        );
    };
    rt.conns_total.fetch_add(1, Ordering::Relaxed);

    match rt.cfg.proxy_type.as_str() {
        "udp" => serve_udp(io, rt, session.clone()).await,
        _ => {
            tracing::debug!(
                "frpc: user connection for {} from {}:{}",
                start.proxy_name,
                start.src_addr,
                start.src_port
            );
            serve_tcp(io, rt, session.clone()).await
        }
    }
}

/// `UDPPacket` as frp's Go side sends it: `IP`/`Port`/`Zone` are all always
/// present (Go's `net.UDPAddr` has no `omitempty`) and `l` is nil on the client
/// side.
///
/// The shared `msg::UdpPacket` cannot be reused for either direction here:
/// ReMgr's own server writes datagrams with `skip_serializing_if =
/// "String::is_empty"` on `Zone` while `UdpAddrJson` has no serde default for
/// that field, so the shared struct drops every datagram it sends itself and
/// refuses to read one that omits the field. (A single `#[serde(default)]` on
/// that field in `msg.rs` would remove the need for both shapes below.)
#[derive(Serialize)]
struct UdpPacketOut<'a> {
    c: &'a str,
    r: UdpAddrOut<'a>,
}

#[derive(Serialize)]
struct UdpAddrOut<'a> {
    #[serde(rename = "IP")]
    ip: &'a str,
    #[serde(rename = "Port")]
    port: u16,
    #[serde(rename = "Zone")]
    zone: &'a str,
}

/// Lenient reader for the same shape: tolerates a missing `Zone` (a ReMgr
/// upstream omits it), a missing `l`, and lower-case keys — serde matches field
/// names case-sensitively where Go's decoder does not, the trap `msg.rs`
/// documents on its own `UdpAddrJson`.
#[derive(Deserialize)]
struct UdpPacketIn {
    #[serde(rename = "c", alias = "C", default)]
    content_b64: String,
    #[serde(rename = "r", alias = "R", default)]
    remote: Option<UdpAddrIn>,
}

#[derive(Deserialize)]
struct UdpAddrIn {
    #[serde(rename = "IP", alias = "ip", default)]
    ip: Option<String>,
    #[serde(rename = "Port", alias = "port", default)]
    port: u16,
}

impl UdpPacketIn {
    fn content(&self) -> Result<Vec<u8>> {
        use base64::Engine;
        Ok(base64::engine::general_purpose::STANDARD.decode(&self.content_b64)?)
    }

    fn remote_socket_addr(&self) -> Option<SocketAddr> {
        let r = self.remote.as_ref()?;
        let ip: std::net::IpAddr = r.ip.as_ref()?.parse().ok()?;
        Some(SocketAddr::new(ip, r.port))
    }
}

/// tcp: dial the local service, then copy bytes both ways.
async fn serve_tcp(io: BoxDuplex, rt: Arc<ProxyRuntime>, session: Arc<Session>) -> Result<()> {
    let addr = rt.cfg.local_addr();
    let local = tokio::time::timeout(LOCAL_DIAL_TIMEOUT, TcpStream::connect(&addr))
        .await
        .map_err(|_| anyhow!("timed out connecting to the local service {addr}"))?
        .with_context(|| format!("connecting to the local service {addr}"))?;
    let _ = local.set_nodelay(true);

    let (mut work_r, mut work_w) = tokio::io::split(io);
    let (mut local_r, mut local_w) = tokio::io::split(local);

    let to_local = ByteCounter { proxy: rt.bytes_in.clone(), total: session.shared.bytes_in.clone() };
    let to_upstream = ByteCounter { proxy: rt.bytes_out.clone(), total: session.shared.bytes_out.clone() };
    let token = session.token.clone();

    // Both directions end together: whichever side stops first, the other pump
    // is cancelled so the pair of sockets is released at once.
    let a = tokio::spawn(async move {
        tokio::select! {
            _ = token.cancelled() => {}
            _ = pump(&mut work_r, &mut local_w, to_local) => {}
        }
    });
    let b = tokio::spawn(async move {
        tokio::select! {
            _ = session.token.cancelled() => {}
            _ = pump(&mut local_r, &mut work_w, to_upstream) => {}
        }
    });
    let _ = a.await;
    let _ = b.await;
    Ok(())
}

/// udp: relay `UDPPacket` frames between the work connection and one local
/// socket per user address — frp's `Forwarder` semantics, including the 30s
/// idle expiry of the per-user sockets and the 30s keepalive Ping on the work
/// connection (frpc keeps the udp work connection framed, unlike tcp).
async fn serve_udp(io: BoxDuplex, rt: Arc<ProxyRuntime>, session: Arc<Session>) -> Result<()> {
    // Resolve the local service *before* anything is spawned: an up-front
    // failure then ends the whole tunnel, instead of leaving a writer task (and
    // the work connection it holds) pinging the upstream until the session ends.
    let local_addr = rt.cfg.local_addr();
    // frp resolves the local service once and then dials it with a wildcard
    // ephemeral socket per user (`net.DialUDP(nil, dstAddr)`); the family of the
    // resolved address decides the bind address.
    let local_dst = resolve_local(&local_addr).await?;
    let bind_addr: SocketAddr = match local_dst {
        SocketAddr::V4(_) => "0.0.0.0:0".parse()?,
        SocketAddr::V6(_) => "[::]:0".parse()?,
    };

    let (mut work_r, mut work_w) = tokio::io::split(io);
    let (tx, mut rx) = mpsc::channel::<(Vec<u8>, SocketAddr)>(128);
    // Child token: ending this work connection must not end the session, but the
    // session ending must stop everything this tunnel spawned.
    let tunnel = session.token.child_token();

    // Writer: everything the local sockets produce, plus the keepalive. A
    // dedicated task keeps the frame boundaries correct: one writer per stream.
    let writer_token = tunnel.clone();
    let writer_name = rt.cfg.name.clone();
    let writer = tokio::spawn(async move {
        let mut tick = tokio::time::interval(UDP_KEEPALIVE);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = writer_token.cancelled() => break,
                _ = tick.tick() => {
                    if msg::write_msg(&mut work_w, &msg::Ping::default(), msg::TYPE_PING).await.is_err() {
                        break;
                    }
                }
                item = rx.recv() => match item {
                    Some((content, user)) => {
                        use base64::Engine;
                        // `l` (our local socket) is `nil` in frp's forwarder; the
                        // upstream only routes on `r`, the user's address.
                        let b64 = base64::engine::general_purpose::STANDARD.encode(&content);
                        let ip = user.ip().to_string();
                        let out = UdpPacketOut {
                            c: &b64,
                            r: UdpAddrOut { ip: &ip, port: user.port(), zone: "" },
                        };
                        let body = match serde_json::to_vec(&out) {
                            Ok(b) => b,
                            Err(e) => {
                                tracing::debug!("frpc: serializing a UDPPacket failed: {e}");
                                continue;
                            }
                        };
                        // A frp frame body is capped at 10 KiB and base64 grows a
                        // datagram by 4/3, so a local service answering with more
                        // than ~7.6 KB cannot be represented. Dropping that one
                        // datagram (UDP is lossy) beats what used to happen: the
                        // "too large" error ended the tunnel, and the upstream
                        // had to fetch a fresh work connection.
                        if body.len() > msg::MAX_MSG_LEN as usize {
                            tracing::warn!(
                                "frpc: {}: dropping a {}-byte udp reply from {}, too large for a frp frame",
                                writer_name,
                                content.len(),
                                user
                            );
                            continue;
                        }
                        if msg::write_frame(&mut work_w, msg::TYPE_UDP_PACKET, &body).await.is_err() {
                            break;
                        }
                    }
                    None => break,
                }
            }
        }
        let _ = work_w.shutdown().await;
    });

    let counter = ByteCounter { proxy: rt.bytes_in.clone(), total: session.shared.bytes_in.clone() };
    let out_counter = ByteCounter { proxy: rt.bytes_out.clone(), total: session.shared.bytes_out.clone() };
    // One socket per user address, connected to the local service; a dead
    // session (30s idle, or a socket error) is replaced on the next datagram.
    let mut users: HashMap<SocketAddr, Arc<UdpUser>> = HashMap::new();

    let result = loop {
        let frame = tokio::select! {
            _ = tunnel.cancelled() => break Ok(()),
            f = msg::read_frame(&mut work_r) => f,
        };
        let (tb, body) = match frame {
            Ok(f) => f,
            Err(e) => break Err(e).context("reading a UDPPacket"),
        };
        match tb {
            // frp's server does not send these on a udp work connection; ignore
            // them rather than tear the tunnel down if some implementation does.
            msg::TYPE_PING | msg::TYPE_PONG => continue,
            msg::TYPE_UDP_PACKET => {}
            other => break Err(anyhow!("unexpected frame type {other:#04x} on a udp work connection")),
        }
        let pkt: UdpPacketIn = match serde_json::from_slice(&body) {
            Ok(p) => p,
            Err(e) => {
                tracing::debug!(
                    "frpc: unparsable UDPPacket on {}: {e} (body {})",
                    rt.cfg.name,
                    String::from_utf8_lossy(&body)
                );
                continue;
            }
        };
        let content = match pkt.content() {
            Ok(c) => c,
            Err(e) => {
                tracing::debug!("frpc: bad base64 in a UDPPacket on {}: {e}", rt.cfg.name);
                continue;
            }
        };
        let Some(user) = pkt.remote_socket_addr() else {
            tracing::debug!("frpc: UDPPacket without a usable remote address on {}", rt.cfg.name);
            continue;
        };

        if users.len() >= MAX_UDP_USER_SESSIONS && !users.contains_key(&user) {
            users.retain(|_, u| u.alive.load(Ordering::Relaxed));
            if users.len() >= MAX_UDP_USER_SESSIONS {
                tracing::warn!(
                    "frpc: {} exceeded {} udp user sessions, dropping the oldest ones",
                    rt.cfg.name,
                    MAX_UDP_USER_SESSIONS
                );
                // Cancel as well as forget: a task whose token is not cancelled
                // keeps its socket — an fd — until its 30s idle timeout fires.
                for (_, u) in users.drain() {
                    u.token.cancel();
                }
            }
        }
        let alive = match users.get(&user) {
            Some(u) if u.alive.load(Ordering::Relaxed) => u.clone(),
            _ => {
                // Whole-client cap: the remote addresses are chosen by whoever
                // can reach the public udp port (trivially spoofable), so the
                // upstream can ask for an arbitrary number of sockets.
                let live = session.shared.udp_user_sockets.load(Ordering::Relaxed);
                if live >= MAX_UDP_USER_SOCKETS {
                    tracing::warn!(
                        "frpc: {} already holds {} udp user sockets (limit {}), \
                         dropping a datagram from {}",
                        rt.cfg.name,
                        live,
                        MAX_UDP_USER_SOCKETS,
                        user
                    );
                    continue;
                }
                // Break instead of `?`: the teardown below has to run, or the
                // writer task (and with it the work connection) outlives this
                // tunnel.
                let sock = match UdpSocket::bind(bind_addr).await {
                    Ok(s) => Arc::new(s),
                    Err(e) => break Err(anyhow!("binding a udp socket for {local_addr} failed: {e}")),
                };
                // Connected, like frp's `net.DialUDP`: replies can only come from
                // the local service, and `recv` needs no address bookkeeping.
                if let Err(e) = sock.connect(local_dst).await {
                    break Err(anyhow!("connecting a udp socket to {local_addr} failed: {e}"));
                }
                let user_token = tunnel.child_token();
                let u = Arc::new(UdpUser {
                    sock: sock.clone(),
                    alive: Arc::new(AtomicBool::new(true)),
                    token: user_token.clone(),
                });
                let tx = tx.clone();
                let token = user_token;
                let user_key = user;
                let counter = out_counter.clone();
                let alive_flag = u.alive.clone();
                let session_shared = session.shared.clone();
                session.shared.udp_user_sockets.fetch_add(1, Ordering::Relaxed);
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 64 * 1024];
                    loop {
                        let got = tokio::select! {
                            _ = token.cancelled() => break,
                            r = tokio::time::timeout(UDP_USER_IDLE, sock.recv(&mut buf)) => r,
                        };
                        match got {
                            Ok(Ok(n)) => {
                                counter.add(n);
                                if tx.send((buf[..n].to_vec(), user_key)).await.is_err() {
                                    break;
                                }
                            }
                            // Idle for 30s or a socket error: frp closes this
                            // per-user socket, and so do we.
                            _ => break,
                        }
                    }
                    alive_flag.store(false, Ordering::Relaxed);
                    session_shared.udp_user_sockets.fetch_sub(1, Ordering::Relaxed);
                });
                users.insert(user, u.clone());
                u
            }
        };
        counter.add(content.len());
        if let Err(e) = alive.sock.send(&content).await {
            tracing::debug!("frpc: sending to the local service {local_addr} failed: {e}");
            alive.alive.store(false, Ordering::Relaxed);
            // let the task drop its socket now instead of after its idle timeout
            alive.token.cancel();
            users.remove(&user);
        }
    };

    tunnel.cancel();
    writer.abort();
    result
}

/// Resolve the local service address, preferring the first usable answer.
async fn resolve_local(addr: &str) -> Result<SocketAddr> {
    let mut it = tokio::net::lookup_host(addr)
        .await
        .with_context(|| format!("resolving the local service address {addr}"))?;
    it.next()
        .ok_or_else(|| anyhow!("no address found for the local service {addr}"))
}

struct UdpUser {
    sock: Arc<UdpSocket>,
    alive: Arc<AtomicBool>,
    /// Cancelled to close this user's socket at once (evicted, or its send
    /// failed) instead of leaving the task to notice after `UDP_USER_IDLE`.
    token: CancellationToken,
}

/// Copy until EOF or error, counting what went through, then shut the writer
/// down so the peer sees the end of the stream (mirrors the server's `pump`).
async fn pump<R, W>(r: &mut R, w: &mut W, counter: ByteCounter)
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        match r.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => {
                counter.add(n);
                if w.write_all(&buf[..n]).await.is_err() {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    let _ = w.shutdown().await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_lines_parse() {
        let p = FrpcProxyConfig::parse_line("web tcp 127.0.0.1 8080 7001").unwrap();
        assert_eq!(p.name, "web");
        assert_eq!(p.proxy_type, "tcp");
        assert_eq!(p.local_ip, "127.0.0.1");
        assert_eq!(p.local_port, 8080);
        assert_eq!(p.remote_port, 7001);

        // commas, defaults and a type-less form
        let p = FrpcProxyConfig::parse_line("dns,udp,10.0.0.5,53,5353").unwrap();
        assert_eq!((p.proxy_type.as_str(), p.local_ip.as_str(), p.remote_port), ("udp", "10.0.0.5", 5353));
        let p = FrpcProxyConfig::parse_line("db 5432 15432").unwrap();
        assert_eq!((p.proxy_type.as_str(), p.local_ip.as_str(), p.local_port, p.remote_port), ("tcp", "127.0.0.1", 5432, 15432));

        assert!(FrpcProxyConfig::parse_line("justaname").is_err());
        assert!(FrpcProxyConfig::parse_line("").is_err());
    }

    #[test]
    fn config_deserializes_from_tables_and_lines() {
        let json = r#"{
            "server_addr": "example.org",
            "proxies": [
                {"name": "a", "type": "udp", "local_ip": "127.0.0.1", "local_port": 53, "remote_port": 5353},
                "b tcp 127.0.0.1 8080 7001"
            ]
        }"#;
        let cfg: FrpcConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.server_port, 7000);
        assert!(cfg.tcp_mux);
        assert_eq!(cfg.pool_count, 5);
        assert_eq!(cfg.proxies.len(), 2);
        assert_eq!(cfg.proxies[0].proxy_type, "udp");
        assert_eq!(cfg.proxies[1].name, "b");
        assert_eq!(cfg.proxies[1].remote_port, 7001);
        cfg.validate().unwrap();
    }

    #[test]
    fn validate_rejects_unsupported_types_and_gaps() {
        let mut cfg = FrpcConfig { server_addr: "h".into(), ..Default::default() };
        assert!(cfg.validate().is_ok());

        cfg.proxies.push(FrpcProxyConfig { name: "x".into(), proxy_type: "http".into(), local_ip: "127.0.0.1".into(), local_port: 80, remote_port: 8080 });
        assert!(cfg.validate().unwrap_err().to_string().contains("http"));

        cfg.proxies[0].proxy_type = "tcp".into();
        cfg.proxies[0].remote_port = 0;
        assert!(cfg.validate().unwrap_err().to_string().contains("remote_port"));

        cfg.proxies.clear();
        cfg.server_addr = String::new();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn proxy_lines_reject_typos_instead_of_guessing() {
        // a second address, an extra port and an unusable port are all errors:
        // guessing turned them into a proxy dialing the wrong host
        assert!(FrpcProxyConfig::parse_line("web tcp 127.0.0.1 8080 7001 typo").is_err());
        assert!(FrpcProxyConfig::parse_line("web tcp 127.0.0.1 8080 7001 7002").is_err());
        assert!(FrpcProxyConfig::parse_line("web tcp 127.0.0.1 8080 70000").unwrap_err().contains("out of range"));
        assert!(FrpcProxyConfig::parse_line("web tcp 127.0.0.1 99999 7001").is_err());
        assert!(FrpcProxyConfig::parse_line("web tcp 127.0.0.1 -1 7001").is_err());
        // two types written out are still accepted (last one wins), an IPv6
        // literal is an address and not a port
        let p = FrpcProxyConfig::parse_line("v6 udp ::1 5353 5353").unwrap();
        assert_eq!((p.proxy_type.as_str(), p.local_ip.as_str()), ("udp", "::1"));
    }

    #[test]
    fn host_port_brackets_ipv6() {
        assert_eq!(host_port("127.0.0.1", 7000), "127.0.0.1:7000");
        assert_eq!(host_port("example.org", 7000), "example.org:7000");
        assert_eq!(host_port("::1", 7000), "[::1]:7000");
        assert_eq!(host_port("[::1]", 7000), "[::1]:7000");
        let p = FrpcProxyConfig::parse_line("v6 tcp ::1 5353 15353").unwrap();
        assert_eq!(p.local_addr(), "[::1]:5353");
    }

    #[test]
    fn validate_rejects_loops_and_absurd_pools() {
        let mut cfg = FrpcConfig { server_addr: "127.0.0.1".into(), ..Default::default() };
        // the upstream is this box: a proxy aimed at its own control port or at
        // its own published port would loop user traffic back into the tunnel
        cfg.proxies.push(FrpcProxyConfig { name: "ctl".into(), proxy_type: "tcp".into(), local_ip: "127.0.0.1".into(), local_port: 7000, remote_port: 8000 });
        assert!(cfg.validate().unwrap_err().to_string().contains("loop"));
        cfg.proxies[0].local_port = 8000;
        cfg.proxies[0].remote_port = 8000;
        assert!(cfg.validate().unwrap_err().to_string().contains("loop"));
        // the same port numbers against a *different* host stay fine
        cfg.server_addr = "example.org".into();
        assert!(cfg.validate().is_ok());
        // and so do distinct ports on the loopback upstream (the dev harness)
        cfg.server_addr = "127.0.0.1".into();
        cfg.proxies[0].local_port = 18080;
        cfg.proxies[0].remote_port = 17080;
        assert!(cfg.validate().is_ok());

        cfg.pool_count = MAX_POOL_COUNT + 1;
        assert!(cfg.validate().unwrap_err().to_string().contains("pool_count"));
    }

    #[tokio::test]
    async fn non_mux_session_carries_a_tcp_proxy_end_to_end() {
        // The one transport frp 0.52+ servers no longer speak: this client and
        // ReMgr's own frps both support it, so a ReMgr-to-ReMgr tunnel with
        // `tcp_mux` off has to work (login, work connection as its own TCP
        // connection, proxy registration, byte relay).
        use crate::config::FrpsConfig as ServerConfig;
        use crate::server::FrpsServer;

        let port = |p: u16| ("127.0.0.1", p);
        let (srv_port, echo_port, remote_port) = (19701u16, 19702u16, 19703u16);

        // local service: echoes what it receives, prefixed
        let listener = tokio::net::TcpListener::bind(port(echo_port)).await.unwrap();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 1024];
                    while let Ok(n) = s.read(&mut buf).await {
                        if n == 0 {
                            break;
                        }
                        let mut out = b"echo:".to_vec();
                        out.extend_from_slice(&buf[..n]);
                        if s.write_all(&out).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });

        let srv = Arc::new(FrpsServer::new(ServerConfig {
            server_port: srv_port,
            token: "nonmuxtoken".into(),
            tcp_mux: false,
            ..Default::default()
        }));
        srv.start().await.unwrap();

        let client = FrpcClient::new(FrpcConfig {
            enabled: true,
            server_addr: "127.0.0.1".into(),
            server_port: srv_port,
            token: "nonmuxtoken".into(),
            tcp_mux: false,
            connect_timeout: 5,
            pool_count: 1,
            proxies: vec![FrpcProxyConfig {
                name: "echo".into(),
                proxy_type: "tcp".into(),
                local_ip: "127.0.0.1".into(),
                local_port: echo_port,
                remote_port,
            }],
            ..Default::default()
        });
        client.start().await.unwrap();

        let mut up = false;
        for _ in 0..40 {
            tokio::time::sleep(Duration::from_millis(100)).await;
            let st = client.status().await;
            if st.connected && st.proxies.iter().all(|p| p.state == "running") {
                up = true;
                break;
            }
        }
        assert!(up, "the non-mux session never came up: {:?}", client.status().await.last_error);

        let mut s = TcpStream::connect(port(remote_port)).await.unwrap();
        s.write_all(b"non-mux\n").await.unwrap();
        let mut buf = vec![0u8; 64];
        let n = tokio::time::timeout(Duration::from_secs(5), s.read(&mut buf))
            .await
            .expect("a reply through the non-mux tunnel")
            .unwrap();
        assert_eq!(&buf[..n], b"echo:non-mux\n");

        client.stop().await.unwrap();
        srv.stop().await.unwrap();
        assert!(!client.status().await.connected);
    }

    #[tokio::test]
    async fn a_supervisor_that_gave_up_does_not_block_a_restart() {
        // A live configuration that becomes unusable ends the supervisor by
        // itself (there is no point retrying). The handle it leaves behind must
        // not turn a later `start` into a silent no-op: the console's Start
        // button would report success while nothing was running.
        let client = FrpcClient::new(FrpcConfig {
            enabled: true,
            server_addr: "127.0.0.1".into(),
            server_port: 1,
            connect_timeout: 1,
            ..Default::default()
        });
        client.start().await.unwrap();
        client.update_config(FrpcConfig { enabled: true, ..Default::default() }).await;
        for _ in 0..200 {
            if !client.status().await.running {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(!client.status().await.running, "the supervisor should have given up on the empty server_addr");
        // The configuration is still unusable, so the restart has to report
        // *that* — not the dead supervisor as a running client.
        assert!(client.start().await.is_err(), "start() answered from a stale handle");
    }
}
