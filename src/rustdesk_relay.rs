// RustDesk Relay Server Integration
// FFI-based integration with rustdesk-server (hbbr/hbbs)

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub enabled: bool,
    pub relay_port: u16,
    pub broker_port: u16,
    pub key_path: String,
    pub db_path: String,
    pub token_expiry: u64,
    pub max_connections: u32,
    pub bandwidth_limit: u32,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            enabled: true,
            relay_port: 21116,
            broker_port: 21115,
            key_path: "/var/lib/remgr/rustdesk_key".to_string(),
            db_path: "/var/lib/remgr/rustdesk-server/db_v2.sqlite3".to_string(),
            token_expiry: 3600,
            max_connections: 10000,
            bandwidth_limit: 1024,
        }
    }
}

pub struct RustDeskRelay {
    config: Config,
    relay_running: bool,
    broker_running: bool,
}

impl std::fmt::Debug for RustDeskRelay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RustDeskRelay")
            .field("config", &self.config)
            .field("relay_running", &self.relay_running)
            .field("broker_running", &self.broker_running)
            .finish()
    }
}

impl RustDeskRelay {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            relay_running: false,
            broker_running: false,
        }
    }

    pub async fn start_relay(&mut self) -> anyhow::Result<()> {
        if self.relay_running {
            return Ok(());
        }

        // TODO: FFI integration with hbbr binary or direct Rust integration
        // For OpenBSD, use the existing hbbr binary via FFI

        self.relay_running = true;
        log::info!("RustDesk relay (hbbr) started on port {}", self.config.relay_port);
        Ok(())
    }

    pub async fn start_broker(&mut self) -> anyhow::Result<()> {
        if self.broker_running {
            return Ok(());
        }

        // TODO: FFI integration with hbbs binary

        self.broker_running = true;
        log::info!("RustDesk broker (hbbs) started on port {}", self.config.broker_port);
        Ok(())
    }

    pub async fn stop(&mut self) -> anyhow::Result<()> {
        self.relay_running = false;
        self.broker_running = false;
        log::info!("RustDesk relay and broker stopped");
        Ok(())
    }

    async fn init_database(&self) -> anyhow::Result<()> {
        use rusqlite::Connection;

        let conn = Connection::open(&self.config.db_path)?;

        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS connections (
                id TEXT PRIMARY KEY,
                client_id TEXT NOT NULL,
                peer_id TEXT,
                status INTEGER DEFAULT 0,
                bytes_tx INTEGER DEFAULT 0,
                bytes_rx INTEGER DEFAULT 0,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );
            
            CREATE TABLE IF NOT EXISTS keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key TEXT NOT NULL UNIQUE,
                salt TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );
            
            CREATE TABLE IF NOT EXISTS tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                token TEXT NOT NULL,
                expires_at DATETIME,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );
            "#,
        )?;

        Ok(())
    }

    pub fn is_running(&self) -> bool {
        self.relay_running && self.broker_running
    }

    pub fn get_config(&self) -> &Config {
        &self.config
    }

    pub fn update_config(&mut self, new_config: Config) {
        self.config = new_config;
    }
}