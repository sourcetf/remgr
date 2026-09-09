// EasyTier Center Server Integration
// Provides FFI-based control for easytier-core and easytier-web

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub config_port: u16,
    pub api_port: u16,
    pub db_path: String,
    pub log_dir: String,
    pub domains: Vec<String>,
    pub ssl_cert: Option<String>,
    pub ssl_key: Option<String>,
    pub network_name: Option<String>,
    pub network_secret: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            config_port: 22020,
            api_port: 11211,
            db_path: "/var/db/easytier/et.db".to_string(),
            log_dir: "/var/log/easytier".to_string(),
            domains: vec!["easytier://center".to_string()],
            ssl_cert: None,
            ssl_key: None,
            network_name: None,
            network_secret: None,
        }
    }
}

pub struct EasyTierCenter {
    config: Config,
    networks: Arc<RwLock<HashMap<String, NetworkInfo>>>,
}

#[derive(Debug, Clone)]
pub struct NetworkInfo {
    pub name: String,
    pub secret: String,
    pub machines: Vec<String>,
    pub enabled: bool,
}

impl EasyTierCenter {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            networks: Arc::new(RwLock::new(HashMap::new())),
        }
    }
    
    pub async fn start(&self) -> anyhow::Result<()> {
        // Ensure directories exist
        let db_path = std::path::Path::new(&self.config.db_path);
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        
        let log_path = std::path::Path::new(&self.config.log_dir);
        std::fs::create_dir_all(log_path)?;
        
        // Initialize database
        self.init_database().await?;
        
        // TODO: FFI integration with easytier-core library
        // For OpenBSD, we integrate with the existing easytier-core via FFI
        
        Ok(())
    }
    
    pub async fn stop(&self) -> anyhow::Result<()> {
        // Stop all managed networks
        let networks = self.networks.write().await;
        for (_, info) in networks.iter() {
            // Remove network configuration
            let _ = info;
        }
        Ok(())
    }
    
    pub async fn list_networks(&self) -> Vec<NetworkInfo> {
        let networks = self.networks.read().await;
        networks.values().cloned().collect()
    }
    
    pub async fn create_network(&self, name: &str, secret: &str) -> anyhow::Result<()> {
        let mut networks = self.networks.write().await;
        networks.insert(name.to_string(), NetworkInfo {
            name: name.to_string(),
            secret: secret.to_string(),
            machines: Vec::new(),
            enabled: true,
        });
        Ok(())
    }
    
    pub async fn add_machine(&self, network: &str, machine_id: &str) -> anyhow::Result<()> {
        let mut networks = self.networks.write().await;
        if let Some(info) = networks.get_mut(network) {
            if !info.machines.contains(&machine_id.to_string()) {
                info.machines.push(machine_id.to_string());
            }
        }
        Ok(())
    }
    
    pub async fn remove_machine(&self, network: &str, machine_id: &str) -> anyhow::Result<()> {
        let mut networks = self.networks.write().await;
        if let Some(info) = networks.get_mut(network) {
            info.machines.retain(|m| m != machine_id);
        }
        Ok(())
    }
    
    async fn init_database(&self) -> anyhow::Result<()> {
        use rusqlite::{Connection, NO_PARAMS};
        
        let conn = Connection::open(&self.config.db_path)?;
        
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS networks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                secret TEXT NOT NULL,
                enabled INTEGER DEFAULT 1,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );
            
            CREATE TABLE IF NOT EXISTS machines (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                network_id INTEGER,
                machine_id TEXT NOT NULL,
                public_ip TEXT,
                last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (network_id) REFERENCES networks(id)
            );
            
            CREATE TABLE IF NOT EXISTS network_config (
                network_name TEXT PRIMARY KEY,
                config TEXT,
                FOREIGN KEY (network_name) REFERENCES networks(name)
            );
            "#
        )?;
        
        Ok(())
    }
    
    pub fn get_config(&self) -> &Config {
        &self.config
    }
    
    pub fn update_config(&mut self, new_config: Config) {
        self.config = new_config;
    }
}