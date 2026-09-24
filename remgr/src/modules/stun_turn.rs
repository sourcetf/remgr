//! STUN (RFC 5389) responder + TURN (RFC 5766) relay supervision.
//!
//! Everything is pure Rust and in-process: the plain STUN responder is
//! hand-rolled, the TURN relay uses the `turn` crate. TURN runs on UDP
//! (`stun_port`) and, when a certificate is available, on TLS (`tls_port`).
//! TLS is a stream transport, so `TlsTurnConn` re-frames it per RFC 5766
//! §11.5 (STUN messages pass through, ChannelData is padded to 4 bytes).

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;
use turn::auth::{generate_auth_key, AuthHandler};
use turn::relay::relay_range::RelayAddressGeneratorRanges;
use turn::relay::relay_static::RelayAddressGeneratorStatic;
use turn::relay::RelayAddressGenerator;
use turn::server::config::{ConnConfig, ServerConfig};
use turn::server::Server;
use util::Conn;

use crate::config::StunTurnConfig;
use crate::state::AppState;

const MAGIC_COOKIE: u32 = 0x2112_A442;
const BINDING_REQUEST: u16 = 0x0001;
const BINDING_SUCCESS: u16 = 0x0101;
const ATTR_CHANGE_REQUEST: u16 = 0x0003;
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
/// RFC 5780 RESPONSE-PORT; an alternative source port we cannot serve.
const ATTR_RESPONSE_PORT: u16 = 0x0027;
const ATTR_SOFTWARE: u16 = 0x8022;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TurnRuntimeInfo {
    pub allocations: u64,
    /// Bytes relayed **from clients** (Send Indication / ChannelData). The crate's
    /// counter is only bumped on that path, peer-to-client traffic is not counted:
    /// the figure is a lower bound, not the total relayed volume.
    pub bytes_relayed: u64,
}

pub struct StunTurnModule {
    state: std::sync::Weak<AppState>,
    run: tokio::sync::Mutex<Option<RunHandle>>,
}

struct RunHandle {
    token: CancellationToken,
    joins: Vec<tokio::task::JoinHandle<()>>,
    turn: Option<TurnHandles>,
}

impl RunHandle {
    /// Every task this module spawned is still running. A task that died (bind
    /// failure after a retry, runtime error, panic) means nothing is serving any
    /// more, so the module must not be reported as running.
    fn alive(&self) -> bool {
        !self.token.is_cancelled() && self.joins.iter().all(|j| !j.is_finished())
    }
}

impl StunTurnModule {
    pub fn new(state: &std::sync::Weak<AppState>) -> Self {
        Self { state: state.clone(), run: tokio::sync::Mutex::new(None) }
    }

    fn cfg(&self) -> StunTurnConfig {
        self.state
            .upgrade()
            .map(|s| s.config_blocking().stun_turn)
            .unwrap_or_default()
    }

    /// Real TURN counters, aggregated over the UDP listener and every live
    /// TURN-over-TLS connection.
    async fn turn_runtime(&self, run: &RunHandle) -> TurnRuntimeInfo {
        let mut info = TurnRuntimeInfo::default();
        let Some(turn) = &run.turn else {
            return info;
        };
        let mut servers: Vec<Arc<Server>> = vec![turn.udp.clone()];
        servers.extend(turn.tls.lock().await.values().cloned());

        for server in servers {
            match server.get_allocations_info(None).await {
                Ok(allocs) => {
                    info.allocations += allocs.len() as u64;
                    for a in allocs.values() {
                        info.bytes_relayed += a.relayed_bytes as u64;
                    }
                }
                Err(e) => tracing::debug!("TURN allocations query failed: {e}"),
            }
        }
        info
    }

    async fn spawn_stun(&self, token: CancellationToken, cfg: StunTurnConfig) -> anyhow::Result<tokio::task::JoinHandle<()>> {
        let addr = parse_bind(&cfg.bind_addr, cfg.stun_port)?;
        let socket = UdpSocket::bind(addr).await?;
        tracing::info!("STUN listening on udp://{addr}");
        Ok(tokio::spawn(async move {
            let socket = Arc::new(socket);
            let mut buf = vec![0u8; 1500];
            loop {
                tokio::select! {
                    _ = token.cancelled() => break,
                    recv = socket.recv_from(&mut buf) => {
                        match recv {
                            Ok((len, src)) => {
                                if let Err(e) = process_stun_packet(&buf[..len], src, &socket) {
                                    tracing::debug!("STUN: {e}");
                                }
                            }
                            Err(e) => tracing::warn!("STUN recv error: {e}"),
                        }
                    }
                }
            }
            tracing::info!("STUN stopped");
        }))
    }
}

#[async_trait]
impl super::ServiceModule for StunTurnModule {
    fn name(&self) -> &'static str {
        "stun_turn"
    }

    async fn status(&self) -> serde_json::Value {
        let cfg = self.cfg();
        let mut run = self.run.lock().await;
        // `run` holding a handle is not enough: a task that died must show up as
        // a stopped module, otherwise the console keeps offering "stop" for a
        // service that is not listening.
        let running = run.as_ref().map(|h| h.alive()).unwrap_or(false);
        let (allocations, bytes_relayed, tls_active, turn_available) = match run.as_mut() {
            Some(handle) => {
                let tls_active = handle.turn.as_ref().map(|t| t.tls_listening).unwrap_or(false);
                let info = self.turn_runtime(handle).await;
                (info.allocations, info.bytes_relayed, tls_active, handle.turn.is_some())
            }
            None => (0, 0, false, false),
        };
        // Credentials without a `:` cannot be used at all; the console must not
        // count them as users.
        let usable_users = cred_entries(&cfg).count();
        serde_json::json!({
            "enabled": cfg.enabled,
            "running": running,
            "bind_addr": cfg.bind_addr,
            "stun_port": cfg.stun_port,
            "turn_enabled": cfg.turn_enabled,
            // true only while a TURN relay is actually serving: with
            // turn_enabled set but the module stopped there are no allocations.
            "turn_available": turn_available,
            "turn_runtime": TurnRuntimeInfo { allocations, bytes_relayed },
            "tls_port": cfg.tls_port,
            "tls_active": tls_active,
            "domain": cfg.domain,
            "external_ip": cfg.external_ip,
            "relay_ports": format!("{}-{}", cfg.relay_min_port, cfg.relay_max_port),
            "users_count": usable_users,
            "realm": cfg.realm,
            "cert_path": cfg.cert_path,
            "key_path": cfg.key_path,
        })
    }

    async fn start(&self) -> anyhow::Result<()> {
        let mut run = self.run.lock().await;
        let mut stale = false;
        match run.as_ref() {
            Some(h) if h.alive() => return Ok(()),
            // A handle whose tasks are gone is not a running module: drop it (the
            // token stops the leftover close task) so this call really rebinds,
            // instead of reporting success while nothing is listening.
            Some(_) => stale = true,
            None => {}
        }
        if stale {
            if let Some(old) = run.take() {
                old.token.cancel();
                for j in old.joins {
                    let _ = j.await;
                }
            }
        }
        let cfg = self.cfg();
        if !cfg.enabled {
            anyhow::bail!("stun_turn module is disabled");
        }
        let token = CancellationToken::new();

        let (turn, joins) = if cfg.turn_enabled {
            // the TURN server answers STUN Binding requests on the same socket
            let cert_dir = self
                .state
                .upgrade()
                .map(|s| s.cert_dir())
                .unwrap_or_else(|| PathBuf::from("."));
            let mut attempt = 0u32;
            let (turn, joins) = loop {
                match spawn_turn_relay(token.clone(), cfg.clone(), cert_dir.clone()).await {
                    Ok(v) => break v,
                    Err(e) if attempt < 12 => {
                        // A prior incarnation releases its UDP/TLS sockets from
                        // an aborted task, not synchronously, so a quick restart
                        // can see EADDRINUSE. Retry briefly instead of failing
                        // the module (and leaving the service dead).
                        tracing::debug!("stun_turn bind retry after: {e:#}");
                        attempt += 1;
                        tokio::time::sleep(Duration::from_millis(250)).await;
                    }
                    Err(e) => return Err(e),
                }
            };
            (Some(turn), joins)
        } else {
            (None, vec![self.spawn_stun(token.clone(), cfg.clone()).await?])
        };

        *run = Some(RunHandle { token, joins, turn });
        Ok(())
    }

    async fn stop(&self) -> anyhow::Result<()> {
        if let Some(handle) = self.run.lock().await.take() {
            handle.token.cancel();
            for j in handle.joins {
                let _ = j.await;
            }
        }
        Ok(())
    }

    async fn apply_config(&self) -> anyhow::Result<()> {
        super::restart_if_running(self).await
    }
}

// ---------------------------------------------------------------- config plumbing

/// Socket address for a configured bind address and port.
///
/// The console field takes an IP (`0.0.0.0`, `::`) and operators routinely paste
/// the bracketed form of an IPv6 literal as it appears in URLs (`[::]`), so both
/// are accepted. A host name or a typo is reported: silently falling back to the
/// wildcard would bind a different address than the operator asked for.
fn parse_bind(bind_addr: &str, port: u16) -> anyhow::Result<SocketAddr> {
    let trimmed = bind_addr.trim();
    let bare = trimmed
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(trimmed);
    let ip: IpAddr = bare.parse().map_err(|_| {
        anyhow::anyhow!("invalid bind address {bind_addr:?} (use an IP such as 0.0.0.0 or ::)")
    })?;
    Ok(SocketAddr::new(ip, port))
}

/// The bind address as the `turn` crate's relay generator needs it:
/// `resolve_addr` formats `"<address>:<port>"` and parses it back, which only
/// works for an IPv6 literal when it is bracketed.
fn relay_bind_string(bind_addr: &str) -> String {
    match parse_bind(bind_addr, 0) {
        Ok(addr) if addr.is_ipv6() => format!("[{}]", addr.ip()),
        _ => bind_addr.trim().to_string(),
    }
}

/// The usable credential entries from `users`: `user:pass`, with a non-empty user
/// (the long-term key is derived from the user name, so an empty one cannot be
/// authenticated). Malformed entries are reported by [`cred_map`].
fn cred_entries(cfg: &StunTurnConfig) -> impl Iterator<Item = (&str, &str)> {
    cfg.users
        .iter()
        .filter_map(|u| u.split_once(':'))
        .filter(|(user, _)| !user.is_empty())
}

// ---------------------------------------------------------------- STUN wire

/// XOR-MAPPED-ADDRESS value (RFC 5389 §15.2).
///
/// The port and the address are XORed with `mask`, which is the magic cookie
/// followed by the transaction id. For IPv4 only the cookie (the first four
/// bytes) applies; for IPv6 the whole 16 bytes do — XORing a v6 address with the
/// cookie alone, as a "cookie repeated" mask would, makes a client decode an
/// address that is not its own.
fn xor_mapped_address(src: SocketAddr, mask: &[u8; 16]) -> Vec<u8> {
    let mut val = Vec::with_capacity(20);
    let xored_port = src.port() ^ (MAGIC_COOKIE >> 16) as u16;
    let family = if src.is_ipv4() { 0x01u8 } else { 0x02u8 };
    val.push(0x00);
    val.push(family);
    val.extend_from_slice(&xored_port.to_be_bytes());
    match src.ip() {
        IpAddr::V4(v4) => {
            for (octet, m) in v4.octets().iter().zip(mask.iter()) {
                val.push(octet ^ m);
            }
        }
        IpAddr::V6(v6) => {
            for (octet, m) in v6.octets().iter().zip(mask.iter()) {
                val.push(octet ^ m);
            }
        }
    }
    val
}

/// RFC 5780 CHANGE-REQUEST / RESPONSE-PORT ask the server to answer from a
/// different address or port. A single-socket responder cannot honour that, and
/// answering anyway would report a mapped address the client would then treat as
/// authoritative, so such requests are dropped instead.
///
/// Only attributes inside the declared message length are inspected: bytes behind
/// it are not part of the message (RFC 5389 §7.3), and reading them as attributes
/// could turn a valid request into a dropped one.
fn asks_for_alternate_address(packet: &[u8], body_len: usize) -> bool {
    let msg_end = (20 + body_len).min(packet.len());
    let mut pos = 20usize;
    while pos + 4 <= msg_end {
        let atype = u16::from_be_bytes([packet[pos], packet[pos + 1]]);
        let alen = u16::from_be_bytes([packet[pos + 2], packet[pos + 3]]) as usize;
        let end = (pos + 4 + alen).min(msg_end);
        let body = &packet[pos + 4..end];
        if matches!(atype, ATTR_CHANGE_REQUEST | ATTR_RESPONSE_PORT)
            && body.iter().any(|b| *b != 0)
        {
            return true;
        }
        // An attribute whose length runs past the end of the message cannot be
        // walked any further (the padding is unknown); stop instead of
        // resynchronising on whatever the rest of the datagram contains.
        if pos + 4 + alen > msg_end {
            return false;
        }
        pos = end + ((4 - alen % 4) % 4);
    }
    false
}

fn process_stun_packet(packet: &[u8], src: SocketAddr, socket: &UdpSocket) -> anyhow::Result<()> {
    if packet.len() < 20 {
        return Ok(());
    }
    let msg_type = u16::from_be_bytes([packet[0], packet[1]]);
    // A reply is only a reply to *this* request (RFC 5389 §7.3): without the
    // magic cookie the datagram is not a STUN message, and without a complete
    // body it is malformed — answering either invites a reflector/amplifier.
    if u32::from_be_bytes([packet[4], packet[5], packet[6], packet[7]]) != MAGIC_COOKIE {
        return Ok(());
    }
    let body_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    // Attributes are padded to four bytes, so a length that is not a multiple of
    // four cannot describe a valid message (the two low bits are always zero).
    if body_len % 4 != 0 || body_len + 20 > packet.len() {
        return Ok(());
    }
    let tid = &packet[8..20];
    // RFC 5389 §15.2: the address mask is the magic cookie concatenated with the
    // 96-bit transaction id of the request.
    let mut mask = [0u8; 16];
    mask[..4].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
    mask[4..].copy_from_slice(tid);

    if msg_type != BINDING_REQUEST {
        return Ok(()); // ignore indicators / other classes silently
    }
    if asks_for_alternate_address(packet, body_len) {
        tracing::debug!("STUN: ignoring request for an alternate address/port (unsupported)");
        return Ok(());
    }

    let xor_val = xor_mapped_address(src, &mask);
    let software: &[u8] = b"ReMgr";
    let software_padded = (software.len() + 3) / 4 * 4;
    let attr_len: u16 = 4 + xor_val.len() as u16 + 4 + software_padded as u16;

    let mut response = Vec::with_capacity(20 + attr_len as usize);
    response.extend_from_slice(&BINDING_SUCCESS.to_be_bytes());
    response.extend_from_slice(&attr_len.to_be_bytes());
    response.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
    response.extend_from_slice(tid);

    response.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
    response.extend_from_slice(&(xor_val.len() as u16).to_be_bytes());
    response.extend_from_slice(&xor_val);

    response.extend_from_slice(&ATTR_SOFTWARE.to_be_bytes());
    response.extend_from_slice(&(software.len() as u16).to_be_bytes());
    response.extend_from_slice(software);
    response.extend(std::iter::repeat(0u8).take(software_padded - software.len()));

    socket.try_send_to(&response, src)?;
    Ok(())
}

// ---------------------------------------------------------------- TURN relay

/// Long-term credentials (RFC 5766 §4) built from the `user:pass` entries.
///
/// An entry without a `:` (or with an empty user) never authenticates, and a
/// duplicate user silently replaces the earlier password, so both are reported
/// instead of leaving the operator with a client whose credentials "look right"
/// in the console but always get a 401.
fn cred_map(cfg: &StunTurnConfig) -> HashMap<String, Vec<u8>> {
    let mut m = HashMap::new();
    for (i, u) in cfg.users.iter().enumerate() {
        match u.split_once(':') {
            // The value holds a password, so only the position is named.
            Some((user, _)) if user.is_empty() => {
                tracing::warn!("TURN: ignoring credential entry #{}: empty user name", i + 1);
            }
            Some((user, pass)) => {
                if m.insert(user.to_string(), generate_auth_key(user, &cfg.realm, pass)).is_some() {
                    tracing::warn!(
                        "TURN: credential entry #{} repeats user {user:?}; the last one wins",
                        i + 1
                    );
                }
            }
            None => {
                tracing::warn!("TURN: ignoring credential entry #{} (expected user:pass)", i + 1);
            }
        }
    }
    m
}

struct Handler {
    creds: HashMap<String, Vec<u8>>,
}

impl AuthHandler for Handler {
    fn auth_handle(
        &self,
        username: &str,
        _realm: &str,
        _src_addr: SocketAddr,
    ) -> Result<Vec<u8>, turn::Error> {
        self.creds
            .get(username)
            .cloned()
            .ok_or(turn::Error::ErrFakeErr)
    }
}

/// Live TURN servers, queried by [`StunTurnModule::status`] for real counters.
struct TurnHandles {
    /// UDP listener; also answers STUN Binding requests
    udp: Arc<Server>,
    /// one [`Server`] per accepted TURN-over-TLS connection
    tls: Arc<Mutex<HashMap<u64, Arc<Server>>>>,
    tls_listening: bool,
}

/// Relay socket generator for TURN allocations.
///
/// Allocations must land inside the configured `relay_min_port`..`relay_max_port`
/// range: an operator opens exactly that range on the firewall, so a relay on
/// any other port would be silently unreachable for the client. An unset or
/// invalid range keeps the old behaviour of ephemeral ports, with a warning.
fn relay_generator(
    relay_ip: IpAddr,
    bind_addr: String,
    min_port: u16,
    max_port: u16,
) -> Box<dyn RelayAddressGenerator + Send + Sync> {
    let net = Arc::new(util::vnet::net::Net::new(None));
    if min_port != 0 && max_port >= min_port {
        tracing::debug!("TURN relay ports restricted to {min_port}-{max_port}");
        Box::new(RelayAddressGeneratorRanges {
            relay_address: relay_ip,
            min_port,
            max_port,
            max_retries: 0,
            address: bind_addr,
            net,
        })
    } else {
        if min_port != 0 || max_port != 0 {
            tracing::warn!(
                "TURN: invalid relay port range {min_port}-{max_port} (need 0 < min <= max); \
                 allocations will use ephemeral ports"
            );
        }
        Box::new(RelayAddressGeneratorStatic {
            relay_address: relay_ip,
            address: bind_addr,
            net,
        })
    }
}

/// TURN relay allocations via the pure-Rust webrtc-rs `turn` server
/// (RFC 5766: allocations, permissions, channel binds, long-term credentials).
/// Serves UDP on `stun_port` and, when a certificate is configured, TLS on
/// `tls_port`.
async fn spawn_turn_relay(
    token: CancellationToken,
    cfg: StunTurnConfig,
    cert_dir: PathBuf,
) -> anyhow::Result<(TurnHandles, Vec<tokio::task::JoinHandle<()>>)> {
    let mut joins = Vec::new();

    // Both addresses are resolved before anything binds: an unusable bind address
    // must fail while nothing is half-started (a socket that outlives the failed
    // start would make every retry fail too).
    let udp_addr = parse_bind(&cfg.bind_addr, cfg.stun_port)?;
    let tls_addr = if cfg.tls_port != 0 {
        Some(parse_bind(&cfg.bind_addr, cfg.tls_port)?)
    } else {
        None
    };

    let creds = cred_map(&cfg);
    if creds.is_empty() {
        tracing::warn!("TURN enabled but no users configured; RFC 5766 requires credentials, every request will be rejected");
    }
    let auth: Arc<dyn AuthHandler + Send + Sync> = Arc::new(Handler { creds });

    let relay_ip: IpAddr = if !cfg.external_ip.is_empty() {
        cfg.external_ip.parse()?
    } else {
        match local_ip().await {
            Some(ip) => ip,
            None => match parse_bind(&cfg.bind_addr, 0) {
                // No default route to probe: a concrete bind address is the
                // best guess at how clients reach this host.
                Ok(addr) if !addr.ip().is_unspecified() => {
                    let ip = addr.ip();
                    tracing::warn!(
                        "TURN: could not probe a route to the internet; advertising relay address {ip} (the bind address)"
                    );
                    ip
                }
                _ => {
                    tracing::warn!(
                        "TURN: no external_ip configured, no route to probe and bind_addr is a \
                         wildcard — relay candidates will be 127.0.0.1 and clients behind NAT \
                         will not receive media. Set 「外部 IP」 in the console."
                    );
                    IpAddr::from([127, 0, 0, 1])
                }
            },
        }
    };

    // ---- UDP listener (TURN allocations + STUN Binding on one socket)
    let udp_server = Arc::new(
        Server::new(ServerConfig {
            conn_configs: vec![ConnConfig {
                conn: Arc::new(UdpSocket::bind(udp_addr).await?),
                relay_addr_generator: relay_generator(
                    relay_ip,
                    relay_bind_string(&cfg.bind_addr),
                    cfg.relay_min_port,
                    cfg.relay_max_port,
                ),
            }],
            realm: cfg.realm.clone(),
            auth_handler: auth.clone(),
            channel_bind_timeout: Duration::from_secs(0),
            alloc_close_notify: None,
        })
        .await?,
    );
    tracing::info!(
        "TURN relay active on udp://{udp_addr} (external {relay_ip}, {} users)",
        cfg.users.len()
    );
    {
        let server = udp_server.clone();
        let token = token.clone();
        joins.push(tokio::spawn(async move {
            token.cancelled().await;
            let _ = server.close().await;
            tracing::info!("TURN relay stopped");
        }));
    }

    // ---- TLS listener: one TURN server per connection (RFC 5766 §11.5)
    let tls: Arc<Mutex<HashMap<u64, Arc<Server>>>> = Arc::new(Mutex::new(HashMap::new()));
    let mut tls_listening = false;
    if let Some(tls_addr) = tls_addr {
        match resolve_turn_cert(&cert_dir, &cfg)
            .and_then(|(cert, key)| build_tls_acceptor(&cert, &key))
        {
            Ok(acceptor) => {
                let listener = match TcpListener::bind(tls_addr).await {
                    Ok(l) => l,
                    Err(e) => {
                        // The caller retries the whole bind sequence; leaving the
                        // UDP server alive would keep its port bound and make every
                        // retry fail, so release it before reporting the error.
                        let _ = udp_server.close().await;
                        return Err(anyhow::anyhow!(
                            "TURN over TLS bind {tls_addr} failed: {e}"
                        ));
                    }
                };
                tls_listening = true;
                tracing::info!("TURN over TLS active on tls://{tls_addr} (external {relay_ip})");

                let map = tls.clone();
                let realm = cfg.realm.clone();
                let bind = relay_bind_string(&cfg.bind_addr);
                let relay_range = (cfg.relay_min_port, cfg.relay_max_port);
                joins.push(tokio::spawn(async move {
                    let mut next_id: u64 = 0;
                    loop {
                        let (stream, peer) = tokio::select! {
                            _ = token.cancelled() => break,
                            acc = listener.accept() => match acc {
                                Ok(v) => v,
                                Err(e) => {
                                    tracing::warn!("TURN/TLS accept failed: {e}");
                                    continue;
                                }
                            },
                        };
                        let id = next_id;
                        next_id += 1;
                        let acceptor = acceptor.clone();
                        let auth = auth.clone();
                        let realm = realm.clone();
                        let bind = bind.clone();
                        let map = map.clone();
                        let conn_token = token.clone();
                        tokio::spawn(serve_tls_turn_conn(
                            acceptor, stream, peer, auth, realm, bind, relay_range, relay_ip, map,
                            id, conn_token,
                        ));
                    }
                    for (_, s) in map.lock().await.drain() {
                        let _ = s.close().await;
                    }
                    tracing::info!("TURN over TLS stopped");
                }));
            }
            Err(e) => tracing::warn!("TURN over TLS disabled: {e}"),
        }
    }

    Ok((TurnHandles { udp: udp_server, tls, tls_listening }, joins))
}

/// Drive one accepted TURN-over-TLS connection for its whole lifetime.
#[allow(clippy::too_many_arguments)]
async fn serve_tls_turn_conn(
    acceptor: tokio_rustls::TlsAcceptor,
    stream: TcpStream,
    peer: SocketAddr,
    auth: Arc<dyn AuthHandler + Send + Sync>,
    realm: String,
    bind_addr: String,
    relay_range: (u16, u16),
    relay_ip: IpAddr,
    map: Arc<Mutex<HashMap<u64, Arc<Server>>>>,
    id: u64,
    token: CancellationToken,
) {
    let local = stream.local_addr().unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)));
    let tls = match acceptor.accept(stream).await {
        Ok(t) => t,
        Err(e) => {
            tracing::debug!("TURN/TLS handshake with {peer} failed: {e}");
            return;
        }
    };

    let conn = Arc::new(TlsTurnConn::new(tls, local, peer));
    let closed = conn.closed();
    let turn_conn: Arc<dyn Conn + Send + Sync> = conn.clone();

    let server = match Server::new(ServerConfig {
        conn_configs: vec![ConnConfig {
            conn: turn_conn,
            relay_addr_generator: relay_generator(
                relay_ip,
                bind_addr,
                relay_range.0,
                relay_range.1,
            ),
        }],
        realm,
        auth_handler: auth,
        channel_bind_timeout: Duration::from_secs(0),
        alloc_close_notify: None,
    })
    .await
    {
        Ok(s) => Arc::new(s),
        Err(e) => {
            tracing::warn!("TURN/TLS server for {peer}: {e}");
            return;
        }
    };

    map.lock().await.insert(id, server.clone());
    tracing::info!("TURN over TLS client {peer} connected");

    tokio::select! {
        _ = closed.notified() => {}
        _ = token.cancelled() => {}
    }

    let _ = server.close().await;
    map.lock().await.remove(&id);
    tracing::info!("TURN over TLS client {peer} disconnected");
}

/// Load the configured certificate/key into a rustls acceptor.
fn build_tls_acceptor(cert_path: &Path, key_path: &Path) -> anyhow::Result<tokio_rustls::TlsAcceptor> {
    let mut cert_rd = std::io::BufReader::new(std::fs::File::open(cert_path)?);
    let certs: Vec<rustls_pki_types::CertificateDer<'static>> =
        rustls_pemfile::certs(&mut cert_rd).collect::<Result<_, _>>()?;
    if certs.is_empty() {
        anyhow::bail!("no certificate found in {}", cert_path.display());
    }
    let mut key_rd = std::io::BufReader::new(std::fs::File::open(key_path)?);
    let key = rustls_pemfile::private_key(&mut key_rd)?
        .ok_or_else(|| anyhow::anyhow!("no private key found in {}", key_path.display()))?;

    let tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    Ok(tokio_rustls::TlsAcceptor::from(Arc::new(tls)))
}

/// Resolve the TURN certificate/key pair.
///
/// When the configured paths are the defaults and the files do not exist yet,
/// a self-signed certificate for the configured domain is generated (the same
/// files the console's certificate page manages). A custom path that is
/// missing is reported instead of silently ignored.
fn resolve_turn_cert(cert_dir: &Path, cfg: &StunTurnConfig) -> anyhow::Result<(PathBuf, PathBuf)> {
    let cert = PathBuf::from(&cfg.cert_path);
    let key = PathBuf::from(&cfg.key_path);
    if cert.exists() && key.exists() {
        return Ok((cert, key));
    }

    let (default_cert, default_key) = crate::certs::cert_paths(cert_dir, "turn");
    if cert != default_cert || key != default_key {
        anyhow::bail!(
            "TURN certificate {} or key {} not found",
            cfg.cert_path,
            cfg.key_path
        );
    }

    let domain = if cfg.domain.is_empty() {
        "localhost".to_string()
    } else {
        cfg.domain.clone()
    };
    let (cert, key) = crate::certs::generate_service_cert(cert_dir, "turn", &domain, 825)?;
    tracing::info!(
        "generated self-signed TURN certificate for {domain} at {}",
        cert.display()
    );
    Ok((cert, key))
}

/// Message length of the next RFC 5766 §11.5 frame on a stream transport.
///
/// Returns `(bytes_to_read, is_channel_data)`. The first two bits select the
/// framing: `0b00` is STUN, `0b01` is ChannelData (which is padded to a
/// multiple of four bytes on TCP/TLS, padding excluded from the length field).
/// `None` means a reserved framing type, which must not be processed.
fn frame_len(head: &[u8; 4]) -> Option<(usize, bool)> {
    let len = u16::from_be_bytes([head[2], head[3]]) as usize;
    match head[0] & 0xC0 {
        0x00 => Some((20 + len, false)),
        0x40 => Some((4 + len + (4 - len % 4) % 4, true)),
        _ => None,
    }
}

/// A [`Conn`] carrying TURN over TLS.
///
/// `turn` only ever sees one message per `recv_from` call, so this adapter
/// reassembles the stream framing and hands back exactly one STUN message or
/// ChannelData message (padding stripped) at a time.
struct TlsTurnConn {
    read: Mutex<tokio::io::ReadHalf<tokio_rustls::server::TlsStream<TcpStream>>>,
    write: Mutex<tokio::io::WriteHalf<tokio_rustls::server::TlsStream<TcpStream>>>,
    local: SocketAddr,
    remote: SocketAddr,
    closed: Arc<tokio::sync::Notify>,
}

impl TlsTurnConn {
    fn new(
        stream: tokio_rustls::server::TlsStream<TcpStream>,
        local: SocketAddr,
        remote: SocketAddr,
    ) -> Self {
        let (read, write) = tokio::io::split(stream);
        Self {
            read: Mutex::new(read),
            write: Mutex::new(write),
            local,
            remote,
            closed: Arc::new(tokio::sync::Notify::new()),
        }
    }

    fn closed(&self) -> Arc<tokio::sync::Notify> {
        self.closed.clone()
    }
}

#[async_trait]
impl Conn for TlsTurnConn {
    async fn connect(&self, _addr: SocketAddr) -> util::Result<()> {
        Ok(())
    }

    async fn recv(&self, buf: &mut [u8]) -> util::Result<usize> {
        Ok(self.recv_from(buf).await?.0)
    }

    async fn recv_from(&self, buf: &mut [u8]) -> util::Result<(usize, SocketAddr)> {
        let mut r = self.read.lock().await;

        let mut head = [0u8; 4];
        if let Err(e) = r.read_exact(&mut head).await {
            self.closed.notify_one();
            return Err(e.into());
        }
        let Some((total, is_channel)) = frame_len(&head) else {
            tracing::warn!("TURN/TLS: reserved frame type 0b{:02b}, closing", head[0] >> 6);
            self.closed.notify_one();
            return Err(util::Error::Other("reserved TURN/TLS frame type".into()));
        };
        if total > buf.len() {
            // The TURN server reads with a fixed 1500-byte buffer, so a larger
            // frame cannot be represented; the read loop tears the connection
            // down on any error, so there is nothing to resynchronise for.
            tracing::warn!("TURN/TLS frame of {total} bytes exceeds the {}-byte buffer", buf.len());
            self.closed.notify_one();
            return Err(util::Error::ErrBufferShort);
        }

        buf[..4].copy_from_slice(&head);
        let mut filled = 4;
        while filled < total {
            let n = r.read(&mut buf[filled..total]).await?;
            if n == 0 {
                self.closed.notify_one();
                return Err(util::Error::ErrUseClosedNetworkConn);
            }
            filled += n;
        }

        // ChannelData padding is a transport artefact, not part of the message
        let n = if is_channel {
            4 + u16::from_be_bytes([head[2], head[3]]) as usize
        } else {
            total
        };
        Ok((n, self.remote))
    }

    async fn send(&self, buf: &[u8]) -> util::Result<usize> {
        self.send_to(buf, self.remote).await
    }

    async fn send_to(&self, buf: &[u8], _target: SocketAddr) -> util::Result<usize> {
        let mut w = self.write.lock().await;
        w.write_all(buf).await?;
        // ChannelData must be padded to a multiple of four bytes on TCP/TLS
        if buf.len() >= 4 && buf[0] & 0xC0 == 0x40 {
            let pad = (4 - buf.len() % 4) % 4;
            if pad > 0 {
                w.write_all(&[0u8; 4][..pad]).await?;
            }
        }
        w.flush().await?;
        Ok(buf.len())
    }

    fn local_addr(&self) -> util::Result<SocketAddr> {
        Ok(self.local)
    }

    fn remote_addr(&self) -> Option<SocketAddr> {
        Some(self.remote)
    }

    async fn close(&self) -> util::Result<()> {
        // The `turn` crate closes the *client-facing* conn from
        // `Allocation::close()`, i.e. when one allocation goes away — for a UDP
        // socket that is a no-op, so the same call must not tear the stream down
        // here: that would kill every other allocation on the connection and cut
        // off the Refresh response still being written. Wake the connection task
        // instead; the socket is released when the last `Arc` is dropped, which
        // happens as soon as the serve task returns.
        self.closed.notify_one();
        Ok(())
    }

    fn as_any(&self) -> &(dyn std::any::Any + Send + Sync) {
        self
    }
}

/// local ip helper (avoid extra crate): best-effort via a UDP connect
async fn local_ip() -> Option<IpAddr> {
    // A UDP "connect" sends nothing — it only asks the kernel which source
    // address the route would use. Several targets, because a single unreachable
    // one (blocked, or no route to that net) says nothing about the others.
    for target in ["8.8.8.8:80", "1.1.1.1:80", "9.9.9.9:53"] {
        if let Ok(s) = UdpSocket::bind("0.0.0.0:0").await {
            if s.connect(target).await.is_ok() {
                if let Ok(addr) = s.local_addr() {
                    if !addr.ip().is_unspecified() && !addr.ip().is_loopback() {
                        return Some(addr.ip());
                    }
                }
            }
        }
    }
    None
}
