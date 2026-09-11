// STUN/TURN Server Implementation
// Native Rust implementation for OpenBSD
// STUN protocol per RFC 5389 (no external stun crate).

use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::net::UdpSocket;

/// RFC 5389 magic cookie
const MAGIC_COOKIE: u32 = 0x2112_A442;
/// STUN message class 0 (request): type 0x0001 = Binding Request
const BINDING_REQUEST: u16 = 0x0001;
/// Binding Success Response
const BINDING_SUCCESS: u16 = 0x0101;
/// XOR-MAPPED-ADDRESS attribute type
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
/// SOFTWARE attribute type
const ATTR_SOFTWARE: u16 = 0x8022;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub enabled: bool,
    pub stun_port: u16,
    pub turn_port: u16,
    pub tls_port: u16,
    pub domain: String,
    pub ssl_cert: String,
    pub ssl_key: String,
    pub min_port: u16,
    pub max_port: u16,
    pub users: Vec<(String, String)>,
    pub log_file: String,
    pub relay_ip: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            enabled: true,
            stun_port: 3478,
            turn_port: 3478,
            tls_port: 5349,
            domain: "turn.remgr.local".to_string(),
            ssl_cert: "/etc/remgr/ssl/turn_cert.pem".to_string(),
            ssl_key: "/etc/remgr/ssl/turn_key.pem".to_string(),
            min_port: 49152,
            max_port: 65535,
            users: Vec::new(),
            log_file: "/var/log/remgr/turnserver.log".to_string(),
            relay_ip: "0.0.0.0".to_string(),
        }
    }
}

pub struct StunTurnServer {
    config: Config,
    relay_socket: Option<Arc<UdpSocket>>,
    running: bool,
}

impl std::fmt::Debug for StunTurnServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StunTurnServer")
            .field("config", &self.config)
            .field("relay_socket", &"Option<Arc<UdpSocket>>")
            .field("running", &self.running)
            .finish()
    }
}

impl StunTurnServer {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            relay_socket: None,
            running: false,
        }
    }

    pub async fn start(&mut self) -> anyhow::Result<()> {
        if self.running {
            return Ok(());
        }

        // Bind STUN socket
        let stun_addr: SocketAddr = format!("0.0.0.0:{}", self.config.stun_port).parse()?;
        let stun_socket = UdpSocket::bind(stun_addr).await?;
        self.relay_socket = Some(Arc::new(stun_socket));
        self.running = true;

        // Spawn STUN handler
        let socket = self.relay_socket.clone().unwrap();
        let config = self.config.clone();
        tokio::spawn(async move {
            StunTurnServer::handle_stun(socket, config).await;
        });

        log::info!("STUN/TURN server started on port {}", self.config.stun_port);
        Ok(())
    }

    async fn handle_stun(socket: Arc<UdpSocket>, config: Config) {
        let mut buf = vec![0u8; 1500];

        loop {
            match socket.recv_from(&mut buf).await {
                Ok((len, src)) => {
                    let packet = &buf[..len];
                    if let Err(e) = StunTurnServer::process_stun_packet(packet, src, &socket, &config) {
                        log::error!("STUN packet error: {:?}", e);
                    }
                }
                Err(e) => {
                    log::error!("STUN receive error: {:?}", e);
                    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                }
            }
        }
    }

    /// Build XOR-MAPPED-ADDRESS attribute value (RFC 5389 Section 14.2).
    /// Returns the VALUE part (not including 4-byte attribute header).
    fn xor_mapped_address(src: SocketAddr) -> Vec<u8> {
        let mut val = Vec::with_capacity(20);
        match src.ip() {
            IpAddr::V4(v4) => {
                // Family: 1 byte (0x01 = IPv4)
                val.push(0x00); // reserved byte
                val.push(0x01); // IPv4 family
                // XOR port: port XOR (magic_cookie >> 16)
                let xored_port = src.port() ^ (MAGIC_COOKIE >> 16) as u16;
                val.extend_from_slice(&xored_port.to_be_bytes());
                // XOR address: address XOR magic_cookie
                let xored: [u8; 4] = [
                    v4.octets()[0] ^ (MAGIC_COOKIE >> 24) as u8,
                    v4.octets()[1] ^ (MAGIC_COOKIE >> 16) as u8,
                    v4.octets()[2] ^ (MAGIC_COOKIE >> 8) as u8,
                    v4.octets()[3] ^ MAGIC_COOKIE as u8,
                ];
                val.extend_from_slice(&xored);
            }
            IpAddr::V6(v6) => {
                val.push(0x00); // reserved byte
                val.push(0x02); // IPv6 family
                let xored_port = src.port() ^ (MAGIC_COOKIE >> 16) as u16;
                val.extend_from_slice(&xored_port.to_be_bytes());
                // XOR address: address XOR (magic_cookie || magic_cookie)
                let cookie_bytes = MAGIC_COOKIE.to_be_bytes();
                let mut xored = [0u8; 16];
                for i in 0..16 {
                    xored[i] = v6.octets()[i] ^ cookie_bytes[i % 4];
                }
                val.extend_from_slice(&xored);
            }
        }
        val
    }

    fn process_stun_packet(
        packet: &[u8],
        src: SocketAddr,
        socket: &UdpSocket,
        _config: &Config,
    ) -> anyhow::Result<()> {
        // Minimal length check (STUN header = 20 bytes)
        if packet.len() < 20 {
            return Ok(());
        }
        let msg_type = ((packet[0] as u16) << 8) | (packet[1] as u16);
        // Transaction ID = bytes 8..20
        let tid = &packet[8..20];

        match msg_type {
            BINDING_REQUEST => {
                let xor_val = StunTurnServer::xor_mapped_address(src);
                let software: &[u8] = b"ReMgr STUN";
                // SOFTWARE padding to 4-byte boundary
                let software_len = software.len();
                let software_padded = (software_len + 3) / 4 * 4;

                // Calculate total attribute length (headers + values + padding)
                // XOR-MAPPED-ADDRESS: 4 header + xor_val.len()
                // SOFTWARE: 4 header + software_padded
                let attr_len: u16 = 4 + xor_val.len() as u16 + 4 + software_padded as u16;

                let mut response: Vec<u8> = Vec::with_capacity(20 + attr_len as usize);
                // Header: type(2) + length(2) + cookie(4) + tid(12) = 20 bytes
                response.extend_from_slice(&BINDING_SUCCESS.to_be_bytes());
                response.extend_from_slice(&attr_len.to_be_bytes());
                response.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
                response.extend_from_slice(tid);

                // XOR-MAPPED-ADDRESS attribute
                response.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
                response.extend_from_slice(&(xor_val.len() as u16).to_be_bytes());
                response.extend_from_slice(&xor_val);

                // SOFTWARE attribute
                response.extend_from_slice(&ATTR_SOFTWARE.to_be_bytes());
                response.extend_from_slice(&(software_len as u16).to_be_bytes());
                response.extend_from_slice(software);
                // Pad to 4-byte boundary
                let pad_len = software_padded - software_len;
                if pad_len > 0 {
                    response.extend_from_slice(&[0u8; 4][..pad_len.min(4)]);
                }

                let _ = socket.try_send_to(&response, src);
                log::debug!("STUN binding response sent to {:?}", src);
            }
            _ => {
                log::warn!("Unknown STUN packet type: {:04x}", msg_type);
            }
        }
        Ok(())
    }

    pub async fn stop(&mut self) -> anyhow::Result<()> {
        self.running = false;
        self.relay_socket = None;
        log::info!("STUN/TURN server stopped");
        Ok(())
    }

    pub fn is_running(&self) -> bool {
        self.running
    }

    pub fn get_config(&self) -> &Config {
        &self.config
    }

    pub fn update_config(&mut self, new_config: Config) {
        self.config = new_config;
    }
}