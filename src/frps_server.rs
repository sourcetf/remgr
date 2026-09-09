// Frps (Fast Reverse Proxy) Server
// Rust implementation compatible with frp protocol

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub server_port: u16,
    pub dashboard_port: u16,
    pub vhost_http_port: u16,
    pub vhost_https_port: u16,
    pub token: String,
    pub dashboard_user: String,
    pub dashboard_pwd: String,
    pub max_pool_count: u32,
    pub sub_modules_per_pool: u32,
    pub tcp_mux: bool,
    pub allow_local_routes: bool,
    pub bind_addr: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server_port: 7000,
            dashboard_port: 7500,
            vhost_http_port: 80,
            vhost_https_port: 443,
            token: "default_token".to_string(),
            dashboard_user: "admin".to_string(),
            dashboard_pwd: "admin".to_string(),
            max_pool_count: 20,
            sub_modules_per_pool: 5,
            tcp_mux: true,
            allow_local_routes: false,
            bind_addr: "0.0.0.0".to_string(),
        }
    }
}

pub struct FrpsServer {
    config: Config,
    running: bool,
    // Track connected clients
    clients: Arc<RwLock<HashMap<String, ClientInfo>>>,
    // Track proxy tasks
    proxies: Arc<RwLock<HashMap<String, ProxyInfo>>>,
}

#[derive(Debug, Clone)]
pub struct ClientInfo {
    pub id: String,
    pub name: String,
    pub last_alive: std::time::SystemTime,
    pub protocols: Vec<String>,
    pub dashboards: HashMap<String, u16>,
}

#[derive(Debug, Clone)]
pub struct ProxyInfo {
    pub name: String,
    pub type_name: String,
    pub local_ip: String,
    pub local_port: u16,
    pub remote_port: Option<u16>,
    pub bind_addr: String,
    pub use_encryption: bool,
    pub use_compression: bool,
    pub max_connections: Option<u32>,
    pub login_timeout: Option<u32>,
}

impl FrpsServer {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            running: false,
            clients: Arc::new(RwLock::new(HashMap::new())),
            proxies: Arc::new(RwLock::new(HashMap::new())),
        }
    }
    
    pub async fn start(&mut self) -> anyhow::Result<()> {
        if self.running {
            return Ok(());
        }
        
        // Bind server port for client connections
        let server_addr = format!("{}:{}", self.config.bind_addr, self.config.server_port);
        let listener = tokio::net::TcpListener::bind(&server_addr).await?;
        
        self.running = true;
        
        // Spawn handler for each connection
        let clients = self.clients.clone();
        let proxies = self.proxies.clone();
        let config = self.config.clone();
        
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, addr)) => {
                        let clients = clients.clone();
                        let proxies = proxies.clone();
                        let config = config.clone();
                        
                        tokio::spawn(async move {
                            if let Err(e) = Self::handle_client(stream, addr, clients, proxies, config).await {
                                log::error!("Client handler error: {:?}", e);
                            }
                        });
                    }
                    Err(e) => {
                        log::error!("Accept error: {:?}", e);
                        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                    }
                }
            }
        });
        
        log::info!("Frps server started on port {}", self.config.server_port);
        Ok(())
    }
    
    async fn handle_client(
        stream: tokio::net::TcpStream,
        addr: std::net::SocketAddr,
        clients: Arc<RwLock<HashMap<String, ClientInfo>>>,
        proxies: Arc<RwLock<HashMap<String, ProxyInfo>>>,
        config: Config,
    ) -> anyhow::Result<()> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        
        let (mut reader, mut writer) = stream.into_split();
        
        // Handle frp protocol handshake
        // TODO: Implement full frp protocol
        // For now, just acknowledge connection
        
        let header = [b'i', b'p', b'c', b'2', b'.', b'0']; // frp version
        writer.write_all(&header).await?;
        
        // Keep connection alive
        let mut buf = [0u8; 4096];
        loop {
            match reader.read(&mut buf).await {
                Ok(0) => break, // Connection closed
                Ok(n) => {
                    // Process frp commands
                    let _data = &buf[..n];
                    // TODO: Parse and handle frp commands
                }
                Err(e) => {
                    log::error!("Read error: {:?}", e);
                    break;
                }
            }
        }
        
        Ok(())
    }
    
    pub async fn stop(&mut self) -> anyhow::Result<()> {
        self.running = false;
        log::info!("Frps server stopped");
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
    
    pub async fn list_clients(&self) -> Vec<ClientInfo> {
        let clients = self.clients.read().await;
        clients.values().cloned().collect()
    }
    
    pub async fn list_proxies(&self) -> Vec<ProxyInfo> {
        let proxies = self.proxies.read().await;
        proxies.values().cloned().collect()
    }
}