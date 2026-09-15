//! STUN (RFC 5389) responder + TURN (coturn FFI) supervision.
//!
//! The STUN half is pure Rust and portable. The TURN half embeds the coturn
//! core as a static library via C FFI (OpenBSD builds); on platforms without
//! the coturn integration `turn_enabled` reports as unavailable.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;

use crate::config::StunTurnConfig;
use crate::state::AppState;

const MAGIC_COOKIE: u32 = 0x2112_A442;
const BINDING_REQUEST: u16 = 0x0001;
const BINDING_SUCCESS: u16 = 0x0101;
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
const ATTR_SOFTWARE: u16 = 0x8022;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TurnRuntimeInfo {
    pub allocations: u64,
    pub bytes_relayed: u64,
}

pub struct StunTurnModule {
    state: std::sync::Weak<AppState>,
    run: tokio::sync::Mutex<Option<RunHandle>>,
}

struct RunHandle {
    token: CancellationToken,
    joins: Vec<tokio::task::JoinHandle<()>>,
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

    async fn spawn_stun(&self, token: CancellationToken, cfg: StunTurnConfig) -> anyhow::Result<tokio::task::JoinHandle<()>> {
        let addr: SocketAddr = format!("{}:{}", cfg.bind_addr, cfg.stun_port).parse()?;
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
        let running = self.run.lock().await.is_some();
        serde_json::json!({
            "enabled": cfg.enabled,
            "running": running,
            "bind_addr": cfg.bind_addr,
            "stun_port": cfg.stun_port,
            "turn_enabled": cfg.turn_enabled,
            "turn_available": true,
            "tls_port": cfg.tls_port,
            "domain": cfg.domain,
            "external_ip": cfg.external_ip,
            "relay_ports": format!("{}-{}", cfg.relay_min_port, cfg.relay_max_port),
            "users_count": cfg.users.len(),
            "realm": cfg.realm,
            "cert_path": cfg.cert_path,
            "key_path": cfg.key_path,
        })
    }

    async fn start(&self) -> anyhow::Result<()> {
        let mut run = self.run.lock().await;
        if run.is_some() {
            return Ok(());
        }
        let cfg = self.cfg();
        if !cfg.enabled {
            anyhow::bail!("stun_turn module is disabled");
        }
        let token = CancellationToken::new();
        let mut joins = Vec::new();

        if cfg.turn_enabled {
            // the TURN server answers STUN Binding requests on the same socket
            joins.push(spawn_turn_relay(token.clone(), cfg.clone()).await?);
        } else {
            joins.push(self.spawn_stun(token.clone(), cfg.clone()).await?);
        }

        *run = Some(RunHandle { token, joins });
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

// ---------------------------------------------------------------- STUN wire

fn xor_mapped_address(src: SocketAddr) -> Vec<u8> {
    let mut val = Vec::with_capacity(20);
    let cookie_be = MAGIC_COOKIE.to_be_bytes();
    match src.ip() {
        IpAddr::V4(v4) => {
            val.push(0x00);
            val.push(0x01);
            let xored_port = src.port() ^ (MAGIC_COOKIE >> 16) as u16;
            val.extend_from_slice(&xored_port.to_be_bytes());
            for (octet, mask) in v4.octets().iter().zip(cookie_be.iter()) {
                val.push(octet ^ mask);
            }
        }
        IpAddr::V6(v6) => {
            val.push(0x00);
            val.push(0x02);
            let xored_port = src.port() ^ (MAGIC_COOKIE >> 16) as u16;
            val.extend_from_slice(&xored_port.to_be_bytes());
            for (i, octet) in v6.octets().iter().enumerate() {
                val.push(octet ^ cookie_be[i % 4]);
            }
        }
    }
    val
}

fn process_stun_packet(packet: &[u8], src: SocketAddr, socket: &UdpSocket) -> anyhow::Result<()> {
    if packet.len() < 20 {
        return Ok(());
    }
    let msg_type = u16::from_be_bytes([packet[0], packet[1]]);
    let tid = &packet[8..20];

    if msg_type != BINDING_REQUEST {
        return Ok(()); // ignore indicators / other classes silently
    }

    let xor_val = xor_mapped_address(src);
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

/// TURN relay allocations via the pure-Rust webrtc-rs `turn` server
/// (RFC 5766: allocations, permissions, channel binds, long-term credentials).
/// The server also answers STUN Binding requests on the same socket.
async fn spawn_turn_relay(
    token: CancellationToken,
    cfg: StunTurnConfig,
) -> anyhow::Result<tokio::task::JoinHandle<()>> {
    use turn::auth::*;
    use turn::relay::relay_static::*;
    use turn::server::{config::*, *};
    use std::collections::HashMap;
    use std::str::FromStr;

    let bind_addr: SocketAddr = format!("{}:{}", cfg.bind_addr, cfg.stun_port).parse()?;
    let conn = Arc::new(UdpSocket::bind(bind_addr).await?);

    let mut cred_map: HashMap<String, Vec<u8>> = HashMap::new();
    for u in &cfg.users {
        if let Some((user, pass)) = u.split_once(':') {
            cred_map.insert(user.to_string(), generate_auth_key(user, &cfg.realm, pass));
        }
    }
    if cred_map.is_empty() {
        tracing::warn!("TURN enabled but no users configured; credentials required per RFC 5766");
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

    let relay_ip: IpAddr = if cfg.external_ip.is_empty() {
        local_ip().await.unwrap_or(IpAddr::from([127, 0, 0, 1]))
    } else {
        cfg.external_ip.parse()?
    };

    let server = Server::new(ServerConfig {
        conn_configs: vec![ConnConfig {
            conn,
            relay_addr_generator: Box::new(RelayAddressGeneratorStatic {
                relay_address: relay_ip,
                address: cfg.bind_addr.clone(),
                net: Arc::new(util::vnet::net::Net::new(None)),
            }),
        }],
        realm: cfg.realm.clone(),
        auth_handler: Arc::new(Handler { creds: cred_map }),
        channel_bind_timeout: Duration::from_secs(0),
        alloc_close_notify: None,
    })
    .await?;

    tracing::info!("TURN relay active on udp://{bind_addr} (external {relay_ip}, {} users)", cfg.users.len());

    Ok(tokio::spawn(async move {
        tokio::select! {
            _ = token.cancelled() => {}
        }
        let _ = server.close().await;
        tracing::info!("TURN relay stopped");
    }))
}

/// local ip helper (avoid extra crate): best-effort via a UDP connect
async fn local_ip() -> anyhow::Result<IpAddr> {
    let s = UdpSocket::bind("0.0.0.0:0").await?;
    s.connect("8.8.8.8:80").await?;
    Ok(s.local_addr()?.ip())
}
