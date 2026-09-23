//! Shared application state.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, Weak};
use std::time::Instant;

use tokio::sync::RwLock;

use crate::config::Config;
use crate::logging::LogHub;
use crate::modules::{easytier::EasyTierModule, frps::FrpsModule, rustdesk::RustDeskModule, stun_turn::StunTurnModule};

/// A console listening socket prepared but not served yet.
///
/// Preparing (binding the port, loading the TLS material) *before* the running
/// console is closed is what makes a failed reconfiguration harmless: the old
/// listener keeps serving and the caller only sees the error.
pub enum PreparedConsole {
    Plain(std::net::TcpListener),
    Tls(std::net::TcpListener, axum_server::tls_rustls::RustlsConfig),
}

pub struct AppState {
    pub config: RwLock<Config>,
    /// Last configuration successfully observed (see `config_blocking`).
    snapshot: Mutex<Config>,
    pub config_path: PathBuf,
    pub sessions: Mutex<HashMap<String, u64>>,
    pub logs: Arc<LogHub>,
    pub started_at: Instant,
    pub easytier: EasyTierModule,
    pub stun_turn: StunTurnModule,
    pub rustdesk: RustDeskModule,
    pub frps: FrpsModule,
    /// loopback client for the `/et` reverse proxy to the easytier-web API
    pub et_http: reqwest::Client,
    /// Asks the serving console to stop so it rebinds with current settings.
    pub console_stop: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
    /// Listener handed to the next console serve loop iteration.
    pub console_pending: Mutex<Option<PreparedConsole>>,
}

impl AppState {
    pub fn new(config: Config) -> Arc<Self> {
        let config_path = config.config_path.clone();
        let logs = LogHub::new();
        let et_http = reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap_or_default();
        Arc::new_cyclic(|weak: &Weak<AppState>| Self {
            snapshot: Mutex::new(config.clone()),
            config: RwLock::new(config),
            config_path,
            sessions: Mutex::new(HashMap::new()),
            logs,
            started_at: Instant::now(),
            easytier: EasyTierModule::new(weak),
            stun_turn: StunTurnModule::new(weak),
            rustdesk: RustDeskModule::new(weak),
            frps: FrpsModule::new(weak),
            et_http,
            console_stop: Mutex::new(None),
            console_pending: Mutex::new(None),
        })
    }

    /// Non-async config snapshot (sections are small; locks are never held
    /// across awaits by module code).
    ///
    /// Callers act on what this returns — they validate passwords against it,
    /// start modules with it, decide whether a token is configured — so it must
    /// never invent values. If the lock is briefly held by a writer, the last
    /// observed configuration is returned instead of a default one (which would
    /// mean an empty password hash, a blank frps token, or defaults written over
    /// a live setting).
    pub fn config_blocking(&self) -> Config {
        for _ in 0..20 {
            if let Ok(c) = self.config.try_read() {
                let cfg = c.clone();
                drop(c);
                *self.snapshot.lock().unwrap_or_else(|e| e.into_inner()) = cfg.clone();
                return cfg;
            }
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        tracing::warn!(
            "config lock still held after 40ms; reporting the last observed configuration"
        );
        self.snapshot.lock().unwrap_or_else(|e| e.into_inner()).clone()
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
