//! Shared application state.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, Weak};
use std::time::Instant;

use tokio::sync::RwLock;

use crate::config::Config;
use crate::logging::LogHub;
use crate::modules::{easytier::EasyTierModule, frps::FrpsModule, rustdesk::RustDeskModule, stun_turn::StunTurnModule};

pub struct AppState {
    pub config: RwLock<Config>,
    pub config_path: PathBuf,
    pub sessions: Mutex<HashMap<String, u64>>,
    pub logs: Arc<LogHub>,
    pub started_at: Instant,
    pub easytier: EasyTierModule,
    pub stun_turn: StunTurnModule,
    pub rustdesk: RustDeskModule,
    pub frps: FrpsModule,
}

impl AppState {
    pub fn new(config: Config) -> Arc<Self> {
        let config_path = config.config_path.clone();
        let logs = LogHub::new();
        Arc::new_cyclic(|weak: &Weak<AppState>| Self {
            config: RwLock::new(config),
            config_path,
            sessions: Mutex::new(HashMap::new()),
            logs,
            started_at: Instant::now(),
            easytier: EasyTierModule::new(weak),
            stun_turn: StunTurnModule::new(weak),
            rustdesk: RustDeskModule::new(weak),
            frps: FrpsModule::new(weak),
        })
    }

    /// Non-async config snapshot (sections are small; locks are never held
    /// across awaits by module code).
    pub fn config_blocking(&self) -> Config {
        match self.config.try_read() {
            Ok(c) => c.clone(),
            Err(_) => {
                for _ in 0..50 {
                    std::thread::sleep(std::time::Duration::from_millis(2));
                    if let Ok(c) = self.config.try_read() {
                        return c.clone();
                    }
                }
                Config::default()
            }
        }
    }

    pub async fn save_config(&self) -> anyhow::Result<()> {
        self.config.read().await.save()
    }

    pub fn module(&self, name: &str) -> Option<&dyn crate::modules::ServiceModule> {
        match name {
            "easytier" => Some(&self.easytier),
            "stun_turn" => Some(&self.stun_turn),
            "rustdesk" => Some(&self.rustdesk),
            "frps" => Some(&self.frps),
            _ => None,
        }
    }

    pub fn cert_dir(&self) -> PathBuf {
        if cfg!(target_os = "openbsd") {
            PathBuf::from("/etc/remgr/ssl")
        } else {
            self.config_path.parent().unwrap_or(&PathBuf::from(".")).join("ssl")
        }
    }
}
