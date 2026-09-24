//! Embedded frps server (frp server protocol, wire v1).
//!
//! Connection handling mirrors frp:
//! 1. accept TCP, sniff first byte: `0x16` → custom-TLS-first-byte marker,
//!    consume it and upgrade to TLS (frps always has a TLS config; when no
//!    cert/key is configured a self-signed pair is generated, like frp)
//! 2. if `tcp_mux` (frpc default): wrap in a yamux server session; the first
//!    inbound stream is the control connection, further streams are work conns
//! 3. non-mux: the stream itself carries `Login` (control) or `NewWorkConn`
//!    (work conn) as its first framed message
//! 4. control: token auth (`hex(md5(token+timestamp))`), proxy registration,
//!    work-conn pool (`ReqWorkConn`/`NewWorkConn`/`StartWorkConn`), heartbeats
//! 5. proxies: `tcp` (listener + byte bridge via work conns) and `udp`
//!    (socket + `UDPPacket` frames over one dedicated work conn); other proxy
//!    types are rejected with a protocol error

use std::collections::HashMap;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Result};
use serde::Serialize;
// yamux streams speak the futures-io traits; the anonymous import brings
// `poll_write` into scope without clashing with tokio's `AsyncWrite`.
use futures_util::AsyncWrite as _;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::mpsc;
use tokio::sync::{Mutex as AsyncMutex, RwLock};
use tokio_util::compat::FuturesAsyncReadCompatExt;
use tokio_util::compat::TokioAsyncReadCompatExt;
use tokio_util::sync::CancellationToken;

use crate::config::FrpsConfig;
use crate::crypto;
use crate::msg::{self, Message};

/// Read+Write object (TLS stream, yamux stream, plain TCP...).
pub trait Duplex: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Duplex for T {}
pub type BoxDuplex = Box<dyn Duplex>;

// ---------------------------------------------------------------- stats

#[derive(Debug, Default, Serialize, Clone)]
pub struct ProxyInfo {
    pub proxy_name: String,
    pub proxy_type: String,
    pub remote_port: u16,
    pub user: String,
    pub conns_total: u64,
}

#[derive(Debug, Default, Serialize, Clone)]
pub struct ServerStats {
    pub running: bool,
    pub bind: String,
    pub clients_online: u64,
    pub total_logins: u64,
    pub total_user_conns: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub proxies: Vec<ProxyInfo>,
}

#[derive(Debug, Default)]
struct Stats {
    total_logins: Arc<AtomicU64>,
    clients_online: Arc<AtomicU64>,
    total_user_conns: Arc<AtomicU64>,
    bytes_in: Arc<AtomicU64>,
    bytes_out: Arc<AtomicU64>,
    proxy_infos: Mutex<HashMap<String, ProxyInfo>>,
}

impl Stats {
    fn set_proxy(&self, info: ProxyInfo) {
        self.proxy_infos.lock().unwrap().insert(info.proxy_name.clone(), info);
    }
    fn remove_proxy(&self, name: &str) -> Option<ProxyInfo> {
        self.proxy_infos.lock().unwrap().remove(name)
    }
    fn snapshot(&self) -> Vec<ProxyInfo> {
        let mut v: Vec<ProxyInfo> = self.proxy_infos.lock().unwrap().values().cloned().collect();
        v.sort_by(|a, b| a.proxy_name.cmp(&b.proxy_name));
        v
    }
}

// ---------------------------------------------------------------- shared state

struct ServerShared {
    cfg: Arc<RwLock<FrpsConfig>>,
    stats: Arc<Stats>,
    /// Cancelled when the server stops. Every control is created as a child of
    /// it, so a login that races with `stop()` still tears itself down instead
    /// of surviving with listeners bound.
    run_token: CancellationToken,
    /// run_id -> control state
    controls: Mutex<HashMap<String, Arc<ControlState>>>,
    /// bound ports -> proxy name
    tcp_ports: Mutex<HashMap<u16, String>>,
    udp_ports: Mutex<HashMap<u16, String>>,
}

impl ServerShared {
    async fn server_token(&self) -> String {
        self.cfg.read().await.token.clone()
    }

    async fn token_is_empty(&self) -> bool {
        self.server_token().await.is_empty()
    }

    /// Constant-time check of `privilege_key = hex(md5(token + timestamp))`.
    /// Like frp, the timestamp itself is not bounded: it is only an input to
    /// the digest, so an out-of-window value cannot pass without the token.
    async fn auth_ok(&self, timestamp: i64, key: &str) -> bool {
        let expect = msg::auth_key(&self.server_token().await, timestamp);
        if expect.len() != key.len() {
            return false;
        }
        let mut diff = 0u8;
        for (a, b) in expect.bytes().zip(key.bytes()) {
            diff |= a ^ b;
        }
        diff == 0
    }

    fn register_proxy_port(&self, proxy_type: &str, port: u16, name: &str) -> Result<()> {
        let mut guard = match proxy_type {
            "tcp" => self.tcp_ports.lock().unwrap(),
            "udp" => self.udp_ports.lock().unwrap(),
            _ => return Ok(()),
        };
        if let Some(existing) = guard.get(&port) {
            if existing != name {
                bail!("remote port {} already used by proxy {}", port, existing);
            }
            return Ok(());
        }
        guard.insert(port, name.to_string());
        Ok(())
    }

    /// Release one port, and only while it is still owned by `name`: proxy
    /// names are only unique per control, so a name-keyed release would drop
    /// the reservation of another client's proxy that happens to share it.
    fn release_proxy_port(&self, proxy_type: &str, port: u16, name: &str) {
        let map = match proxy_type {
            "tcp" => &self.tcp_ports,
            "udp" => &self.udp_ports,
            _ => return,
        };
        let mut guard = map.lock().unwrap();
        if guard.get(&port).map(|owner| owner == name).unwrap_or(false) {
            guard.remove(&port);
        }
    }
}

// ---------------------------------------------------------------- prefixed stream

/// Replays a consumed first byte then streams the inner I/O.
struct Prefixed {
    prefix: Option<u8>,
    inner: BoxDuplex,
}

impl AsyncRead for Prefixed {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        // Only consume the replayed byte once there is somewhere to put it:
        // taking it with no room would silently drop the first byte of the
        // stream (a caller may legitimately poll with an empty buffer).
        if buf.remaining() > 0 {
            if let Some(b) = this.prefix.take() {
                buf.put_slice(&[b]);
                return Poll::Ready(Ok(()));
            }
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for Prefixed {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

// ---------------------------------------------------------------- control state

/// A control message queued for the writer task. The optional latch fires once
/// the frame has reached the wire, which lets proxy registration order itself
/// after the NewProxyResp (see [`ControlState::send_and_flush`]).
type Outgoing = (Message, Option<tokio::sync::oneshot::Sender<()>>);

struct ControlState {
    run_id: String,
    user: String,
    send_tx: mpsc::Sender<Outgoing>,
    work_tx: mpsc::Sender<BoxDuplex>,
    work_rx: AsyncMutex<mpsc::Receiver<BoxDuplex>>,
    last_active: AtomicU64,
    /// Whether this client sends control-connection heartbeats (see
    /// [`client_sends_heartbeats`]). Clients that do not must not be judged by
    /// the idle monitor, or every session ends after the timeout.
    enforce_idle: bool,
    token: CancellationToken,
    /// Cleared by the first teardown, so the online counter moves exactly once.
    online: AtomicBool,
    stats: Arc<Stats>,
    proxies: Mutex<HashMap<String, CancellationToken>>,
    shared: Arc<ServerShared>,
}

impl ControlState {
    fn touch(&self) {
        self.last_active.store(now_secs(), Ordering::Relaxed);
    }

    fn idle_secs(&self) -> u64 {
        now_secs().saturating_sub(self.last_active.load(Ordering::Relaxed))
    }

    /// Queue a control message, waiting for room in the writer's channel only.
    async fn send(&self, m: Message) {
        let _ = self.send_tx.send((m, None)).await;
    }

    /// Queue a control message and wait for the writer to put it on the wire.
    ///
    /// A proxy must not hand out work conns before its NewProxyResp has left:
    /// frpc ignores — and silently closes — a work conn that arrives while its
    /// proxy wrapper is still in `wait_start` (`client/proxy/proxy_wrapper.go`),
    /// so the proxy would answer "start proxy success" and then carry nothing
    /// for the rest of the session.
    async fn send_and_flush(&self, m: Message) {
        let (tx, rx) = tokio::sync::oneshot::channel();
        if self.send_tx.send((m, Some(tx))).await.is_ok() {
            // The writer drops the latch when it stops, so this cannot hang.
            let _ = rx.await;
        }
    }

    /// Take a ready work stream or request one over the control connection.
    async fn get_work_conn(&self) -> Result<BoxDuplex> {
        self.touch();
        let pooled = {
            let mut rx = self.work_rx.lock().await;
            rx.try_recv().ok()
        };
        if let Some(s) = pooled {
            // Replace what the pool just lost, like frp's server ("When we get
            // a work connection from pool, replace it with a new one"): the
            // next user connection then does not wait for a round trip.
            self.send(Message::ReqWorkConn(msg::ReqWorkConn {})).await;
            return Ok(s);
        }
        self.send(Message::ReqWorkConn(msg::ReqWorkConn {})).await;
        let mut rx = self.work_rx.lock().await;
        let waited = tokio::time::timeout(Duration::from_secs(20), rx.recv());
        let got = tokio::select! {
            // Without this, a user connection whose control died while it
            // waited would hold on until the timeout expires.
            _ = self.token.cancelled() => bail!("control closed waiting for a work conn"),
            r = waited => r,
        };
        match got {
            Ok(Some(s)) => {
                self.touch();
                Ok(s)
            }
            _ => bail!("timeout waiting for work conn"),
        }
    }

    fn close_proxy(&self, name: &str) {
        if let Some(tk) = self.proxies.lock().unwrap().remove(name) {
            tk.cancel();
            if let Some(info) = self.stats.remove_proxy(name) {
                self.shared.release_proxy_port(&info.proxy_type, info.remote_port, name);
            }
            tracing::info!("frps proxy {name} closed");
        }
    }

    fn teardown(&self) {
        self.token.cancel();
        // Pooled work conns are never handed out again, and in non-mux mode
        // they are plain TCP connections that nothing else would close; frp's
        // server drops its pool at the same point. Skipped while a waiter
        // holds the receiver — its own token-cancelled path runs next.
        if let Ok(mut rx) = self.work_rx.try_lock() {
            while rx.try_recv().is_ok() {}
        }
        let names: Vec<String> = self.proxies.lock().unwrap().keys().cloned().collect();
        for n in names {
            self.close_proxy(&n);
        }
        // Drop the map entry only if it still points at this control: a client
        // that re-logs in with the same run_id has already replaced it, and
        // removing the replacement would orphan the live session.
        let me = self as *const ControlState;
        let still_mine = {
            let controls = self.shared.controls.lock().unwrap();
            match controls.get(&self.run_id) {
                Some(cur) => std::ptr::eq(Arc::as_ptr(cur), me),
                None => false,
            }
        };
        if still_mine {
            self.shared.controls.lock().unwrap().remove(&self.run_id);
        }
        // teardown() runs both from the reader loop and from the heartbeat
        // monitor / stop(), so the online counter must be decremented once.
        if self.online.swap(false, Ordering::Relaxed) {
            self.stats.clients_online.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

/// Does this client keep the control connection alive with frp-level heartbeats?
///
/// frp <= 0.51 sends a Ping every `heartbeatInterval` (30s) and expects a Pong.
/// Modern clients keep the app-level heartbeat only while `tcpMux` is off: with
/// mux on (the default) frpc completes `heartbeatInterval` to -1 and leaves
/// liveness to yamux's own 30s keepalive, which the server never sees as a
/// message. So an idle-control monitor can only trust the old clients —
/// enforcing it for the new ones closes every session after the timeout and
/// makes frpc reconnect forever. An unknown or missing version is treated as
/// "no heartbeats", i.e. permissive, matching frp's own server behaviour.
fn client_sends_heartbeats(version: &str) -> bool {
    let mut it = version.trim().split(['.', '-', '+']);
    let (Some(major), Some(minor)) = (
        it.next().and_then(|s| s.parse::<u32>().ok()),
        it.next().and_then(|s| s.parse::<u32>().ok()),
    ) else {
        return false;
    };
    major == 0 && minor < 52
}

// ---------------------------------------------------------------- server

pub struct FrpsServer {
    cfg: Arc<RwLock<FrpsConfig>>,
    run: AsyncMutex<Option<RunHandle>>,
    stats: Arc<Stats>,
    shared: AsyncMutex<Option<Arc<ServerShared>>>,
}

struct RunHandle {
    token: CancellationToken,
    joins: Vec<tokio::task::JoinHandle<()>>,
}

impl FrpsServer {
    pub fn new(cfg: FrpsConfig) -> Self {
        Self {
            cfg: Arc::new(RwLock::new(cfg)),
            run: AsyncMutex::new(None),
            stats: Arc::new(Stats::default()),
            shared: AsyncMutex::new(None),
        }
    }

    pub async fn update_config(&self, cfg: FrpsConfig) {
        *self.cfg.write().await = cfg;
    }

    pub async fn config(&self) -> FrpsConfig {
        self.cfg.read().await.clone()
    }

    pub async fn is_running(&self) -> bool {
        self.run.lock().await.is_some()
    }

    pub async fn stats(&self) -> ServerStats {
        let c = self.cfg.read().await;
        ServerStats {
            running: self.run.lock().await.is_some(),
            bind: format!("{}:{}", c.bind_addr, c.server_port),
            clients_online: self.stats.clients_online.load(Ordering::Relaxed),
            total_logins: self.stats.total_logins.load(Ordering::Relaxed),
            total_user_conns: self.stats.total_user_conns.load(Ordering::Relaxed),
            bytes_in: self.stats.bytes_in.load(Ordering::Relaxed),
            bytes_out: self.stats.bytes_out.load(Ordering::Relaxed),
            proxies: self.stats.snapshot(),
        }
    }

    pub async fn start(&self) -> Result<()> {
        let mut run = self.run.lock().await;
        if run.is_some() {
            return Ok(());
        }
        let cfg = self.cfg.read().await.clone();
        if cfg.server_port == 0 {
            bail!("frps server_port is 0");
        }

        // frp installs a TLS config even without user certs (random self-signed).
        let tls = Arc::new(build_tls_acceptor(&cfg).await?);

        let bind_addr: SocketAddr = format!("{}:{}", cfg.bind_addr, cfg.server_port).parse()?;
        let listener = tokio::net::TcpListener::bind(bind_addr).await?;
        tracing::info!(
            "frps listening on {bind_addr} (tcp_mux={}, tls_cert={})",
            cfg.tcp_mux,
            cfg.tls_cert_path.is_some()
        );

        let token = CancellationToken::new();
        let shared = Arc::new(ServerShared {
            cfg: self.cfg.clone(),
            stats: self.stats.clone(),
            run_token: token.clone(),
            controls: Mutex::new(HashMap::new()),
            tcp_ports: Mutex::new(HashMap::new()),
            udp_ports: Mutex::new(HashMap::new()),
        });
        *self.shared.lock().await = Some(shared.clone());

        let accept_shared = shared.clone();
        let accept_tls = tls.clone();
        let accept_token = token.clone();
        let accept_join = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = accept_token.cancelled() => break,
                    accepted = listener.accept() => {
                        match accepted {
                            Ok((stream, _peer)) => {
                                let shared = accept_shared.clone();
                                let tls = accept_tls.clone();
                                tokio::spawn(async move {
                                    stream.set_nodelay(true).ok();
                                    if let Err(e) = handle_accepted(stream, shared, tls).await {
                                        tracing::debug!("frps connection ended: {e:#}");
                                    }
                                });
                            }
                            Err(e) => {
                                tracing::warn!("frps accept error: {e}");
                                tokio::time::sleep(Duration::from_millis(200)).await;
                            }
                        }
                    }
                }
            }
            tracing::info!("frps listener stopped");
        });

        // heartbeat monitor: close idle controls
        let hb_shared = shared.clone();
        let hb_token = token.clone();
        let hb_join = tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(15));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    _ = hb_token.cancelled() => break,
                    _ = tick.tick() => {
                        let timeout = hb_shared.cfg.read().await.heartbeat_timeout;
                        // 0 disables the monitor, like frp's HeartbeatTimeout
                        // ("set negative value to disable it") — treating it as
                        // "close everything idle for a second" would drop every
                        // client that does send heartbeats.
                        if timeout == 0 {
                            continue;
                        }
                        let entries: Vec<Arc<ControlState>> = hb_shared
                            .controls
                            .lock()
                            .unwrap()
                            .values()
                            .cloned()
                            .collect();
                        for st in entries {
                            if st.enforce_idle && st.idle_secs() > timeout {
                                tracing::info!("frps control {} idle {}s, closing", st.run_id, st.idle_secs());
                                st.teardown();
                            }
                        }
                    }
                }
            }
        });

        *run = Some(RunHandle { token, joins: vec![accept_join, hb_join] });
        Ok(())
    }

    pub async fn stop(&self) -> Result<()> {
        if let Some(handle) = self.run.lock().await.take() {
            // Cancel before looking at the controls: a login that is in flight
            // right now creates its control token as a child of this one, so it
            // tears itself down even though it is not in the map yet.
            handle.token.cancel();
            if let Some(shared) = self.shared.lock().await.take() {
                let entries: Vec<Arc<ControlState>> = shared.controls.lock().unwrap().values().cloned().collect();
                for st in entries {
                    st.teardown();
                }
            }
            for j in handle.joins {
                let _ = j.await;
            }
            tracing::info!("frps stopped");
        }
        Ok(())
    }
}

/// Self-signed pair used when no usable certificate is configured, matching
/// what frp itself does in that case.
fn ephemeral_self_signed() -> Result<(String, String)> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;
    Ok((cert.cert.pem(), cert.key_pair.serialize_pem()))
}

async fn build_tls_acceptor(cfg: &FrpsConfig) -> Result<tokio_rustls::TlsAcceptor> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    // A configured-but-unreadable certificate must not stop the server: the
    // console can generate or upload one, so until then frps keeps serving on
    // an ephemeral self-signed pair rather than failing to start.
    let configured = match (&cfg.tls_cert_path, &cfg.tls_key_path) {
        (Some(c), Some(k)) if !c.is_empty() && !k.is_empty() => Some((c.as_str(), k.as_str())),
        _ => None,
    };
    let (cert_pem, key_pem) = match configured {
        Some((cert_path, key_path)) => {
            match (
                std::fs::read_to_string(cert_path),
                std::fs::read_to_string(key_path),
            ) {
                (Ok(cert), Ok(key)) => (cert, key),
                (cert_res, key_res) => {
                    if let Err(e) = cert_res {
                        tracing::warn!("frps: cannot read TLS certificate {cert_path}: {e}");
                    }
                    if let Err(e) = key_res {
                        tracing::warn!("frps: cannot read TLS key {key_path}: {e}");
                    }
                    tracing::warn!("frps: using an ephemeral self-signed certificate instead");
                    ephemeral_self_signed()?
                }
            }
        }
        None => {
            tracing::info!("frps: no TLS cert configured, generating ephemeral self-signed certificate");
            ephemeral_self_signed()?
        }
    };

    let certs: Vec<rustls_pki_types::CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_pem.as_bytes())
        .collect::<std::result::Result<_, _>>()?;
    let key = rustls_pemfile::private_key(&mut key_pem.as_bytes())?
        .ok_or_else(|| anyhow!("no private key found in frps TLS key file"))?;

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])?
        .with_no_client_auth();
    let config = builder.with_single_cert(certs, key)?;
    Ok(tokio_rustls::TlsAcceptor::from(Arc::new(config)))
}

// ---------------------------------------------------------------- accept + dispatch

async fn handle_accepted(
    mut stream: tokio::net::TcpStream,
    shared: Arc<ServerShared>,
    tls: Arc<tokio_rustls::TlsAcceptor>,
) -> Result<()> {
    let cfg_mux = shared.cfg.read().await.tcp_mux;

    // Clients from frp 0.52 on send no application-level heartbeat, so a half-dead
    // peer (vanished host, dropped NAT mapping) would otherwise hold a control
    // connection forever. TCP keepalive lets the kernel reap it; the timing is
    // sysctl-driven on OpenBSD, so this only turns the probe on.
    {
        let sock = socket2::SockRef::from(&stream);
        if let Err(e) = sock.set_keepalive(true) {
            tracing::debug!("frps: could not enable tcp keepalive: {e}");
        }
    }

    // sniff first byte (frp custom TLS marker is 0x17; a standard TLS
    // ClientHello starts with 0x16 — both must upgrade to TLS)
    let mut first = [0u8; 1];
    tokio::time::timeout(Duration::from_secs(20), stream.read_exact(&mut first))
        .await
        .map_err(|_| anyhow!("timeout reading first byte"))??;
    tracing::debug!("frps first byte: {:#04x}", first[0]);

    let inner: BoxDuplex = if first[0] == 0x17 {
        // custom marker consumed; TLS handshake follows immediately
        let tls_stream = tokio::time::timeout(Duration::from_secs(15), tls.accept(stream)).await??;
        Box::new(tls_stream)
    } else {
        // replay the consumed byte (0x16 → TLS record header; anything else → v1)
        let replay = Prefixed { prefix: Some(first[0]), inner: Box::new(stream) };
        if first[0] == 0x16 {
            let tls_stream = tokio::time::timeout(Duration::from_secs(15), tls.accept(replay)).await??;
            Box::new(tls_stream)
        } else {
            Box::new(replay)
        }
    };

    if cfg_mux {
        // yamux is futures-io based; adapt tokio <-> futures on both sides.
        // yamux 0.13 exposes a poll API; drive it with a dedicated task that
        // forwards inbound streams over a channel.
        let mut conn = yamux::Connection::new(inner.compat(), yamux::Config::default(), yamux::Mode::Server);
        let (inbound_tx, mut inbound_rx) = mpsc::channel::<yamux::Stream>(16);
        let driver = tokio::spawn(async move {
            loop {
                match futures_util::future::poll_fn(|cx| conn.poll_next_inbound(cx)).await {
                    Some(Ok(s)) => {
                        if inbound_tx.send(s).await.is_err() {
                            break;
                        }
                    }
                    Some(Err(e)) => {
                        tracing::debug!("frps yamux session error: {e}");
                        break;
                    }
                    None => break,
                }
            }
        });

        // First inbound stream = control connection.
        let control_io: yamux::Stream =
            tokio::time::timeout(Duration::from_secs(30), inbound_rx.recv())
                .await
                .map_err(|_| anyhow!("timeout waiting for control stream"))?
                .ok_or_else(|| anyhow!("yamux session closed before control stream"))?;

        // Remaining inbound streams are work conns.
        let work_shared = shared.clone();
        let stream_fwd = tokio::spawn(async move {
            while let Some(mut s) = inbound_rx.recv().await {
                // rust-yamux acknowledges an inbound stream only when the
                // application first *writes* to it. A pooled work connection
                // carries no server→client bytes until a user connects, so
                // without this nudge the peer's `openStream` never completes and
                // hashicorp/yamux aborts the whole session ("aborted stream open:
                // i/o deadline reached") — frpc then reconnects every ~75s.
                // An empty write emits the zero-length ACK-flagged data frame
                // that acknowledges the stream.
                let _ = futures_util::future::poll_fn(|cx| {
                    std::pin::Pin::new(&mut s).poll_write(cx, &[])
                })
                .await;

                let shared = work_shared.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_work_io_tagged(shared, Box::new(s.compat())).await {
                        tracing::debug!("frps work stream error: {e:#}");
                    }
                });
            }
        });

        let res = run_control(shared, Box::new(control_io.compat())).await;
        driver.abort();
        stream_fwd.abort();
        res
    } else {
        // The first framed message distinguishes control (Login) from work conns.
        dispatch_first_frame(shared, inner).await
    }
}

/// Non-mux mode: read the first framed message and dispatch.
async fn dispatch_first_frame(shared: Arc<ServerShared>, mut io: BoxDuplex) -> Result<()> {
    let first = tokio::time::timeout(Duration::from_secs(30), msg::read_frame(&mut io)).await??;
    match first.0 {
        msg::TYPE_LOGIN => run_control_with_login(shared, io, first).await,
        msg::TYPE_NEW_WORK_CONN => {
            handle_work_io_with_frame(shared, io, first).await
        }
        other => bail!("unexpected first frp message type {other:#04x}"),
    }
}

/// Read NewWorkConn from a fresh work stream and deliver it to its control.
async fn handle_work_io(shared: Arc<ServerShared>, mut io: BoxDuplex) -> Result<()> {
    let first = tokio::time::timeout(Duration::from_secs(30), msg::read_frame(&mut io)).await??;
    handle_work_io_with_frame(shared, io, first).await
}

async fn handle_work_io_with_frame(
    shared: Arc<ServerShared>,
    mut io: BoxDuplex,
    first: msg::RawMsg,
) -> Result<()> {
    let (tb, body) = first;
    let outcome: Result<Arc<ControlState>> = async {
        if tb != msg::TYPE_NEW_WORK_CONN {
            bail!("first message on work conn is not NewWorkConn (type {tb:#04x})");
        }
        let nwc: msg::NewWorkConn = serde_json::from_slice(&body)?;
        let state = {
            let controls = shared.controls.lock().unwrap();
            controls.get(&nwc.run_id).cloned()
        };
        let Some(state) = state else {
            bail!("work conn for unknown run_id {}", nwc.run_id);
        };
        // frpc sends the same md5(token+ts) credential on work conns once a token is
        // configured; a wrong one is rejected outright, and a missing one is at
        // least surfaced (some client versions omit it, so it stays accepted).
        if !nwc.privilege_key.is_empty() {
            if !shared.auth_ok(nwc.timestamp, &nwc.privilege_key).await {
                bail!("work conn privilege key invalid for run_id {}", nwc.run_id);
            }
        } else if !shared.token_is_empty().await {
            tracing::debug!(
                "frps: work conn for run_id {} arrived without a privilege key",
                nwc.run_id
            );
        }
        Ok(state)
    }
    .await;

    let state = match outcome {
        Ok(state) => state,
        Err(e) => {
            // frpc blocks on the first message of a work conn it just opened and
            // reports whatever frps puts there ("StartWorkConn contains error"),
            // so name the reason before dropping it — an unexplained rejection
            // just looks like a hang on the client.
            let stwc = msg::StartWorkConn { error: e.to_string(), ..Default::default() };
            let _ = msg::write_msg(&mut io, &stwc, msg::TYPE_START_WORK_CONN).await;
            return Err(e);
        }
    };
    state.touch();
    let _ = state.work_tx.send(io).await;
    Ok(())
}

// ---------------------------------------------------------------- control

async fn run_control(shared: Arc<ServerShared>, io: BoxDuplex) -> Result<()> {
    let mut io = io;
    let first = tokio::time::timeout(Duration::from_secs(30), msg::read_frame(&mut io)).await??;
    run_control_with_login(shared, io, first).await
}

async fn run_control_with_login(
    shared: Arc<ServerShared>,
    mut io: BoxDuplex,
    first: msg::RawMsg,
) -> Result<()> {
    let (tb, body) = first;
    if tb != msg::TYPE_LOGIN {
        bail!("first control message is not Login (type {tb:#04x})");
    }
    let login: msg::Login = serde_json::from_slice(&body)?;

    if !shared.auth_ok(login.timestamp, &login.privilege_key).await {
        let resp = msg::LoginResp { error: "authentication failed".into(), ..Default::default() };
        let _ = msg::write_msg(&mut io, &resp, msg::TYPE_LOGIN_RESP).await;
        // Make sure the reason reaches the client. Over a yamux session the
        // frame is queued to the connection's driver, and returning here drops
        // the session — frpc would report a bare EOF instead of the reason. So
        // close the stream (which also ACKs it) and give the driver a moment.
        let _ = tokio::time::timeout(Duration::from_secs(2), io.shutdown()).await;
        tokio::time::sleep(Duration::from_millis(200)).await;
        bail!("frps login auth failed for user {:?}", login.user);
    }
    // Counted only once the credential checked out, so a wrong token does not
    // inflate the console's login total.
    shared.stats.total_logins.fetch_add(1, Ordering::Relaxed);

    let run_id = if login.run_id.is_empty() { uuid::Uuid::new_v4().to_string() } else { login.run_id.clone() };

    // Replace any stale control with the same run_id (clone + drop the lock
    // first: teardown() itself locks the map).
    {
        let old = shared.controls.lock().unwrap().get(&run_id).cloned();
        if let Some(old) = old {
            old.teardown();
        }
    }

    // A blocking read, not try_read: falling back to a default here would
    // derive the control cipher key from an empty token, which silently
    // garbles every message after the login response.
    let cfg = shared.cfg.read().await.clone();

    let (send_tx, send_rx) = mpsc::channel::<Outgoing>(256);
    let (work_tx, work_rx) = mpsc::channel::<BoxDuplex>(64);
    // Child of the server's run token, so a login that lands while the server
    // is stopping cannot keep its listeners once stop() has run.
    let token = shared.run_token.child_token();

    // Advertise the protocol generation, not a release number: this server
    // implements the classic V1 wire protocol that frpc still selects by
    // default (`transport.wireProtocol = "v1"`), and clients up to 0.51.3 only
    // speak that.
    let reply = msg::LoginResp { version: "0.51.3".into(), run_id: run_id.clone(), error: String::new() };
    msg::write_msg(&mut io, &reply, msg::TYPE_LOGIN_RESP).await?;
    tracing::info!("frps client logged in: user={:?} run_id={run_id} pool={}", login.user, login.pool_count);
    // Counted only after the response went out: an early return above used to
    // leave the online gauge incremented for a client that never logged in.
    shared.stats.clients_online.fetch_add(1, Ordering::Relaxed);

    // Everything after LoginResp travels through the golib-compatible CFB
    // stream, keyed by the server token — the same value frpc derives from
    // (see crypto::derive_key; the salt is frp's, configurable for pre-0.44
    // clients).
    let io = crypto::CryptoStream::with_salt(
        io,
        cfg.token.as_bytes(),
        None,
        cfg.crypto_salt.as_bytes(),
    );

    let state = Arc::new(ControlState {
        run_id: run_id.clone(),
        user: login.user.clone(),
        send_tx: send_tx.clone(),
        work_tx,
        work_rx: AsyncMutex::new(work_rx),
        last_active: AtomicU64::new(now_secs()),
        enforce_idle: client_sends_heartbeats(&login.version),
        token: token.clone(),
        online: AtomicBool::new(true),
        stats: shared.stats.clone(),
        proxies: Mutex::new(HashMap::new()),
        shared: shared.clone(),
    });
    shared.controls.lock().unwrap().insert(run_id.clone(), state.clone());

    let (mut r, mut w) = tokio::io::split(io);

    // writer task: serialize outgoing control messages
    let wtok = token.clone();
    let writer = tokio::spawn(async move {
        let mut send_rx = send_rx;
        loop {
            tokio::select! {
                _ = wtok.cancelled() => break,
                m = send_rx.recv() => {
                    let Some((m, written)) = m else { break };
                    let body = match &m {
                        Message::LoginResp(v) => serde_json::to_vec(v),
                        Message::NewProxyResp(v) => serde_json::to_vec(v),
                        Message::ReqWorkConn(v) => serde_json::to_vec(v),
                        Message::Pong(v) => serde_json::to_vec(v),
                        Message::StartWorkConn(v) => serde_json::to_vec(v),
                        Message::UdpPacket(v) => serde_json::to_vec(v),
                        _ => Ok(Vec::new()),
                    };
                    // Dropping `written` on the error paths below releases the
                    // sender's latch, so a wait can never outlive the writer.
                    let Ok(body) = body else { continue };
                    let sent = msg::write_frame(&mut w, m.type_byte(), &body).await.is_ok();
                    if let Some(tx) = written {
                        let _ = tx.send(());
                    }
                    if !sent {
                        break;
                    }
                }
            }
        }
    });

    // pre-issue pool work conns (capped)
    let pool = login.pool_count.clamp(0, cfg.max_pool_count as i64) as u32;
    for _ in 0..pool {
        state.send(Message::ReqWorkConn(msg::ReqWorkConn {})).await;
    }

    // reader loop
    let res = control_reader_loop(state.clone(), &mut r).await;

    state.teardown();
    let _ = writer.await;
    res
}

async fn control_reader_loop<R: AsyncRead + Unpin + Send>(state: Arc<ControlState>, r: &mut R) -> Result<()> {
    loop {
        tokio::select! {
            _ = state.token.cancelled() => return Ok(()),
            frame = msg::read_frame(r) => {
                let (tb, body) = frame.map_err(|e| anyhow!("control stream: {e}"))?;
                state.touch();
                match tb {
                    msg::TYPE_NEW_PROXY => {
                        let np: msg::NewProxy = match serde_json::from_slice(&body) {
                            Ok(np) => np,
                            Err(e) => {
                                tracing::error!("frps NewProxy parse failed: {e}; body={:02x?}", body);
                                return Err(anyhow!("NewProxy parse: {e}"));
                            }
                        };
                        tracing::debug!("frps NewProxy received: {} type {}", np.proxy_name, np.proxy_type);
                        let st = state.clone();
                        tokio::spawn(async move { handle_new_proxy(st, np).await; });
                    }
                    msg::TYPE_CLOSE_PROXY => {
                        let cp: msg::CloseProxy = serde_json::from_slice(&body)?;
                        state.close_proxy(&cp.proxy_name);
                    }
                    msg::TYPE_PING => {
                        let ping: msg::Ping = serde_json::from_slice(&body)?;
                        // default frpc sends unsigned pings (empty privilege key);
                        // only validate when one is present
                        let err = if ping.privilege_key.is_empty()
                            || state.shared.auth_ok(ping.timestamp, &ping.privilege_key).await
                        {
                            String::new()
                        } else {
                            "authentication failed".into()
                        };
                        state.send(Message::Pong(msg::Pong { error: err })).await;
                    }
                    msg::TYPE_NEW_WORK_CONN => {
                        // dedicated work conns are dispatched at accept time
                        tracing::debug!("unexpected NewWorkConn frame on control stream");
                    }
                    msg::TYPE_UDP_PACKET => { /* udp flows over work conns */ }
                    other => {
                        // frp's server only fails the connection on a type byte it
                        // does not know (`ErrMsgType`); a message it defines but has
                        // no handler for is skipped. Dropping the session here would
                        // break any client that sends one of those (a newer frpc, or
                        // a visitor message on a shared connection).
                        if !msg::is_known_type(other) {
                            bail!("unknown frp control message type {other:#04x}");
                        }
                        tracing::debug!("ignoring frp control message type {other:#04x}");
                    }
                }
            }
        }
    }
}

/// Port a proxy asked for, or `None` when the request does not name a usable
/// port. Upstream's field is an `int` and a bad value fails that one proxy
/// (`port … is not allowed` / allocation error) instead of the connection.
fn remote_port_of(np: &msg::NewProxy) -> Option<u16> {
    u16::try_from(np.remote_port).ok().filter(|p| *p != 0)
}

async fn handle_new_proxy(state: Arc<ControlState>, np: msg::NewProxy) {
    tracing::debug!("frps handle_new_proxy entered: {}", np.proxy_name);
    // Registration awaits a bind and a message write, so the control can be
    // gone by the time this runs: registering then would strand a listener and
    // its port reservation, since teardown() has already walked the map.
    if state.token.is_cancelled() {
        return;
    }
    // frp refuses a second proxy under a live name ("proxy name [%s] is already
    // in use"); replacing the entry silently would drop the previous token
    // without closing its listener.
    if state.proxies.lock().unwrap().contains_key(&np.proxy_name) {
        proxy_error(&state, &np, format!("proxy name {} is already in use", np.proxy_name)).await;
        return;
    }
    if np.use_encryption || np.use_compression {
        proxy_error(&state, &np, "use_encryption/use_compression not supported by remgr-frps".into()).await;
        return;
    }
    match np.proxy_type.as_str() {
        "tcp" => start_tcp_proxy(state, np).await,
        "udp" => start_udp_proxy(state, np).await,
        other => proxy_error(&state, &np, format!("proxy type \"{other}\" not supported by remgr-frps")).await,
    }
}

async fn proxy_error(state: &Arc<ControlState>, np: &msg::NewProxy, err: String) {
    tracing::info!("frps proxy {} rejected: {err}", np.proxy_name);
    // frpc keeps the proxy in `wait_start` until this arrives (and retries it),
    // so it must not be dropped on a full queue — that would look like a hang.
    state
        .send_and_flush(Message::NewProxyResp(msg::NewProxyResp {
            proxy_name: np.proxy_name.clone(),
            remote_addr: String::new(),
            error: err,
        }))
        .await;
}

async fn start_tcp_proxy(state: Arc<ControlState>, np: msg::NewProxy) {
    let cfg = state.shared.cfg.read().await.clone();
    let Some(remote_port) = remote_port_of(&np) else {
        proxy_error(&state, &np, format!("invalid remote port {}", np.remote_port)).await;
        return;
    };
    if !cfg.port_allowed(remote_port) {
        proxy_error(&state, &np, format!("remote port {} not allowed", remote_port)).await;
        return;
    }
    if let Err(e) = state.shared.register_proxy_port("tcp", remote_port, &np.proxy_name) {
        proxy_error(&state, &np, e.to_string()).await;
        return;
    }
    let addr: SocketAddr = match format!("{}:{}", cfg.bind_addr, remote_port).parse() {
        Ok(a) => a,
        Err(e) => {
            state.shared.release_proxy_port("tcp", remote_port, &np.proxy_name);
            proxy_error(&state, &np, format!("invalid bind addr: {e}")).await;
            return;
        }
    };
    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            state.shared.release_proxy_port("tcp", remote_port, &np.proxy_name);
            proxy_error(&state, &np, format!("bind tcp {} failed: {e}", remote_port)).await;
            return;
        }
    };
    tracing::info!("frps tcp proxy {} listening on {}", np.proxy_name, addr);
    state
        .send_and_flush(Message::NewProxyResp(msg::NewProxyResp {
            proxy_name: np.proxy_name.clone(),
            remote_addr: addr.to_string(),
            error: String::new(),
        }))
        .await;

    let ptk = state.token.child_token();
    state.proxies.lock().unwrap().insert(np.proxy_name.clone(), ptk.clone());
    // The control can disappear between the bind and the response. A token that
    // is born cancelled (or cancelled while we were binding) means teardown()
    // has already walked the map and will not notice this late entry, so undo
    // the reservation here instead of leaving the port taken for good.
    if ptk.is_cancelled() {
        state.shared.release_proxy_port("tcp", remote_port, &np.proxy_name);
        state.close_proxy(&np.proxy_name);
        return;
    }
    state.stats.set_proxy(ProxyInfo {
        proxy_name: np.proxy_name.clone(),
        proxy_type: "tcp".into(),
        remote_port,
        user: state.user.clone(),
        ..Default::default()
    });

    let st = state.clone();
    let proxy_name = np.proxy_name.clone();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = ptk.cancelled() => break,
                accepted = listener.accept() => {
                    let (user_stream, peer) = match accepted {
                        Ok(v) => v,
                        // A transient accept failure (out of file descriptors,
                        // for instance) must not end the proxy: frpc would keep
                        // reporting a healthy proxy that refuses every
                        // connection. Only cancellation closes the listener.
                        Err(e) => {
                            if ptk.is_cancelled() { break; }
                            tracing::warn!("frps tcp proxy {} accept error: {e}", proxy_name);
                            tokio::time::sleep(Duration::from_millis(200)).await;
                            continue;
                        }
                    };
                    user_stream.set_nodelay(true).ok();
                    st.stats.total_user_conns.fetch_add(1, Ordering::Relaxed);

                    let st = st.clone();
                    let proxy_name = proxy_name.clone();
                    tokio::spawn(async move {
                        if let Err(e) = bridge_tcp_user(st, proxy_name, user_stream, peer).await {
                            tracing::debug!("frps tcp user conn ended: {e:#}");
                        }
                    });
                }
            }
        }
    });
}

async fn bridge_tcp_user(
    state: Arc<ControlState>,
    proxy_name: String,
    mut user: tokio::net::TcpStream,
    peer: SocketAddr,
) -> Result<()> {
    let mut work = state.get_work_conn().await?;
    // Same src/dst pair frp's server sends (`userConn.RemoteAddr()` and
    // `userConn.LocalAddr()`); proxies that care about the destination — the
    // stcp/xtcp family — rely on it.
    let local = user.local_addr().ok();
    let swc = msg::StartWorkConn {
        proxy_name: proxy_name.clone(),
        src_addr: peer.ip().to_string(),
        src_port: peer.port(),
        dst_addr: local.map(|a| a.ip().to_string()).unwrap_or_default(),
        dst_port: local.map(|a| a.port()).unwrap_or_default(),
        ..Default::default()
    };
    msg::write_msg(&mut work, &swc, msg::TYPE_START_WORK_CONN).await?;

    let (mut ur, mut uw) = tokio::io::split(user);
    let (mut wr, mut ww) = tokio::io::split(work);

    // Feed the server-wide totals rather than throwaway counters, so the
    // console's traffic figures cover tcp proxies (the common case), not only udp.
    let c_in = state.stats.bytes_in.clone();
    let c_out = state.stats.bytes_out.clone();

    let t1 = tokio::spawn(async move { pump(&mut wr, &mut uw, c_in).await });
    let t2 = tokio::spawn(async move { pump(&mut ur, &mut ww, c_out).await });
    let _ = t1.await;
    let _ = t2.await;
    Ok(())
}

async fn pump<R, W>(r: &mut R, w: &mut W, counter: Arc<AtomicU64>)
where
    R: AsyncRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send,
{
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        match r.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => {
                counter.fetch_add(n as u64, Ordering::Relaxed);
                if w.write_all(&buf[..n]).await.is_err() {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    let _ = w.shutdown().await;
}

async fn start_udp_proxy(state: Arc<ControlState>, np: msg::NewProxy) {
    let cfg = state.shared.cfg.read().await.clone();
    let Some(remote_port) = remote_port_of(&np) else {
        proxy_error(&state, &np, format!("invalid remote port {}", np.remote_port)).await;
        return;
    };
    if !cfg.port_allowed(remote_port) {
        proxy_error(&state, &np, format!("remote port {} not allowed", remote_port)).await;
        return;
    }
    if let Err(e) = state.shared.register_proxy_port("udp", remote_port, &np.proxy_name) {
        proxy_error(&state, &np, e.to_string()).await;
        return;
    }
    let addr: SocketAddr = match format!("{}:{}", cfg.bind_addr, remote_port).parse() {
        Ok(a) => a,
        Err(e) => {
            state.shared.release_proxy_port("udp", remote_port, &np.proxy_name);
            proxy_error(&state, &np, format!("invalid bind addr: {e}")).await;
            return;
        }
    };
    let socket = Arc::new(match tokio::net::UdpSocket::bind(addr).await {
        Ok(s) => s,
        Err(e) => {
            state.shared.release_proxy_port("udp", remote_port, &np.proxy_name);
            proxy_error(&state, &np, format!("bind udp {} failed: {e}", remote_port)).await;
            return;
        }
    });
    tracing::info!("frps udp proxy {} listening on {}", np.proxy_name, addr);
    state
        .send_and_flush(Message::NewProxyResp(msg::NewProxyResp {
            proxy_name: np.proxy_name.clone(),
            remote_addr: addr.to_string(),
            error: String::new(),
        }))
        .await;

    let ptk = state.token.child_token();
    state.proxies.lock().unwrap().insert(np.proxy_name.clone(), ptk.clone());
    // See start_tcp_proxy: undo a registration that outlived its control.
    if ptk.is_cancelled() {
        state.shared.release_proxy_port("udp", remote_port, &np.proxy_name);
        state.close_proxy(&np.proxy_name);
        return;
    }
    // the udp task needs the name for StartWorkConn (see below)
    let proxy_name = np.proxy_name.clone();
    state.stats.set_proxy(ProxyInfo {
        proxy_name: np.proxy_name.clone(),
        proxy_type: "udp".into(),
        remote_port,
        user: state.user.clone(),
        ..Default::default()
    });

    tokio::spawn(async move {
        let local = socket.local_addr().ok();
        // frpc drops a work conn that arrives before it has processed this
        // proxy's NewProxyResp, and does so silently (its wrapper is still in
        // `wait_start`), which leaves the proxy registered on both sides but
        // carrying nothing. frp's own server waits out that window too.
        tokio::time::sleep(Duration::from_millis(500)).await;
        loop {
            if ptk.is_cancelled() { break; }
            let mut work = match state.get_work_conn().await {
                Ok(w) => w,
                Err(_) => { tokio::time::sleep(Duration::from_secs(2)).await; continue; }
            };
            // frpc activates its udp proxy only when it reads StartWorkConn on a
            // work connection (its `handleReqWorkConn` waits for that message and
            // then hands the connection to the proxy's datagram loops), so unlike
            // frp — which sends it from `GetWorkConnFromPool` for every proxy —
            // this must precede the first UdpPacket or every datagram is dropped.
            let swc = msg::StartWorkConn {
                proxy_name: proxy_name.clone(),
                ..Default::default()
            };
            if let Err(e) = msg::write_msg(&mut work, &swc, msg::TYPE_START_WORK_CONN).await {
                tracing::debug!("frps udp proxy: start work conn failed: {e:#}");
                tokio::time::sleep(Duration::from_millis(200)).await;
                continue;
            }
            let (mut wr, mut ww) = tokio::io::split(work);
            let sock_a = socket.clone();
            let sock_b = socket.clone();
            let ptk2 = ptk.clone();
            let ptk3 = ptk.clone();
            let bytes_in = state.stats.bytes_in.clone();
            let bytes_out = state.stats.bytes_out.clone();

            // work conn -> udp socket (user datagrams from the client)
            let t1 = tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = ptk2.cancelled() => break,
                        frame = msg::read_frame(&mut wr) => {
                            let Ok((tb, body)) = frame else { break };
                            // frpc keeps a udp work conn alive with a Ping every
                            // 30s (its udp proxy leaves the stream framed, unlike
                            // the tcp path) — dropping the tunnel on one would
                            // break every udp proxy three times a minute.
                            if tb == msg::TYPE_PING { continue; }
                            if tb != msg::TYPE_UDP_PACKET {
                                tracing::debug!("frps udp work conn: unexpected frame type {tb:#04x}");
                                break;
                            }
                            let Ok(pkt) = serde_json::from_slice::<msg::UdpPacket>(&body) else {
                                tracing::debug!(
                                    "frps udp work conn: unparsable packet: {}",
                                    String::from_utf8_lossy(&body)
                                );
                                break;
                            };
                            let Ok(content) = pkt.content() else {
                                tracing::debug!("frps udp work conn: bad base64 content");
                                break;
                            };
                            let Some(remote) = pkt.remote_socket_addr() else {
                                tracing::debug!(
                                    "frps udp work conn: packet without a usable destination: {}",
                                    String::from_utf8_lossy(&body)
                                );
                                continue;
                            };
                            bytes_in.fetch_add(content.len() as u64, Ordering::Relaxed);
                            if let Err(e) = sock_a.send_to(&content, remote).await {
                                tracing::debug!("frps udp proxy: send to {remote} failed: {e}");
                            }
                        }
                    }
                }
            });
            // udp socket -> work conn (user datagrams toward the client)
            let mut buf = vec![0u8; 1500];
            loop {
                tokio::select! {
                    _ = ptk3.cancelled() => break,
                    recvd = sock_b.recv_from(&mut buf) => {
                        let Ok((n, src)) = recvd else { break };
                        bytes_out.fetch_add(n as u64, Ordering::Relaxed);
                        let pkt = msg::UdpPacket::from_content(&buf[..n], local, src);
                        if msg::write_msg(&mut ww, &pkt, msg::TYPE_UDP_PACKET).await.is_err() { break; }
                    }
                }
            }
            let _ = t1.await;
            // work conn closed — fetch another
        }
    });
}

/// mux inbound work stream entry with error tagging.
async fn handle_work_io_tagged(shared: Arc<ServerShared>, io: BoxDuplex) -> Result<()> {
    if let Err(e) = handle_work_io(shared, io).await {
        bail!("work stream: {e:#}");
    }
    Ok(())
}
