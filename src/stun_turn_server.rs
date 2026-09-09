// STUN/TURN Server Implementation
// Native Rust implementation for OpenBSD

use serde::{Deserialize, Serialize};
use std::net::{SocketAddr, Ipv4Addr, Ipv6Addr, IpAddr, Protocol};
use tokio::net::{UdpSocket, TcpListener, TcpStream};
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
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
            stun_port: 3478,
            turn_port: 3478,
            tls_port: 5349,
            domain: "turn.remgr.local".to_string(),
            ssl_cert: "/etc/turnserver/turn_cert.pem".to_string(),
            ssl_key: "/etc/turnserver/turn_pkey.pem".to_string(),
            min_port: 49152,
            max_port: 65535,
            users: Vec::new(),
            log_file: "/var/log/turnserver.log".to_string(),
            relay_ip: "0.0.0.0".to_string(),
        }
    }
}

pub struct StunTurnServer {
    config: Config,
    relay_socket: Option<Arc<UdpSocket>>,
    running: bool,
}

#[derive(Debug)]
struct Allocation {
    id: u64,
    socket_addr: SocketAddr,
    last_activity: std::time::Instant,
    permissions: Vec<String>,
    peer_perms: Vec<String>,
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
        let stun_addr = format!("0.0.0.0:{}", self.config.stun_port);
        let stun_socket = UdpSocket::bind(stun_addr.parse().unwrap()).await?;
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
                    if let Err(e) = StunTurnServer::process_stun_packet(packet, src, &socket, &config).await {
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
    
    async fn process_stun_packet(
        packet: &[u8],
        src: SocketAddr,
        socket: &UdpSocket,
        config: &Config,
    ) -> anyhow::Result<()> {
        use stun::packet::Packet;
        
        // Parse STUN header
        let header_type = ((packet[0] as u16) << 8) | (packet[1] as u16);
        
        match header_type {
            stun::rfc5389::BindingRequest::VALUE => {
                // Send STUN binding response
                let mut response = Vec::new();
                response.extend_from_slice(&[0x01, 0x01]); // Success response
                response.extend_from_slice(&[0x00, 0x00]); // No error
                
                // Add XOR-MAPPED-ADDRESS attribute
                let mut attr = Vec::new();
                attr.extend_from_slice(&stun::rfc5389::XOR_MAPPED_ADDRESS.get_bytes().unwrap());
                // Add address family (IPv4 or IPv6)
                if src.ip().is_ipv4() {
                    attr.push(0x01); // IPv4
                    attr.extend_from_slice(&[0, 0]); // Port
                    let port = src.port().to_be_bytes();
                    attr.extend_from_slice(&port);
                    let ipv4 = match src.ip() {
                        IpAddr::V4(v4) => v4,
                        _ => Ipv4Addr::UNSPECIFIED,
                    };
                    attr.extend_from_slice(&ipv4.octets());
                }
                
                let length = attr.len() as u16;
                response[2] = 0x00;
                response[3] = 0 as u8;
                response.extend_from_slice(&length.to_be_bytes());
                // Add magic cookie and transaction ID
                response.extend_from_slice(&stun::rfc5389::MAGIC_COOKIE);
                response.extend_from_slice(&[0; 12]); // Transaction ID
                response.extend_from_slice(&attr);
                
                socket.send_to(&response, src).await?;
                log::debug!("STUN binding response sent to {:?}", src);
            }
            _ => {
                log::warn!("Unknown STUN packet type: {:04x}", header_type);
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