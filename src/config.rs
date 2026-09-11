// Configuration module for ReMgr

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub web_port: u16,
    pub easytier: EasyTierConfig,
    pub stun_turn: StunTurnConfig,
    pub rustdesk: RustDeskConfig,
    pub frps: FrpsConfig,
    #[serde(skip)]
    pub config_path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EasyTierConfig {
    #[serde(default = "default_config_port")]
    pub config_port: u16,
    #[serde(default = "default_api_port")]
    pub api_port: u16,
    #[serde(default = "default_db_path")]
    pub db_path: PathBuf,
    #[serde(default = "default_log_dir")]
    pub log_dir: PathBuf,
    #[serde(default)]
    pub domains: Vec<String>,
    pub ssl_cert: Option<PathBuf>,
    pub ssl_key: Option<PathBuf>,
    pub enabled: bool,
}

fn default_config_port() -> u16 { 22020 }
fn default_api_port() -> u16 { 11211 }
fn default_db_path() -> PathBuf { PathBuf::from("/var/db/remgr/easytier/et.db") }
fn default_log_dir() -> PathBuf { PathBuf::from("/var/log/remgr/easytier") }

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StunTurnConfig {
    #[serde(default = "default_stun_port")]
    pub stun_port: u16,
    #[serde(default = "default_turn_port")]
    pub turn_port: u16,
    #[serde(default = "default_tls_port")]
    pub tls_port: u16,
    #[serde(default = "default_turn_domain")]
    pub domain: String,
    #[serde(default = "default_turn_cert")]
    pub ssl_cert: PathBuf,
    #[serde(default = "default_turn_key")]
    pub ssl_key: PathBuf,
    #[serde(default = "default_min_port")]
    pub min_port: u16,
    #[serde(default = "default_max_port")]
    pub max_port: u16,
    #[serde(default)]
    pub users: Vec<(String, String)>,
    #[serde(default = "default_turn_log")]
    pub log_file: PathBuf,
    pub relay_ip: String,
    pub enabled: bool,
}

fn default_stun_port() -> u16 { 3478 }
fn default_turn_port() -> u16 { 3478 }
fn default_tls_port() -> u16 { 5349 }
fn default_turn_domain() -> String { "turn.remgr.local".to_string() }
fn default_turn_cert() -> PathBuf { PathBuf::from("/etc/remgr/ssl/turn_cert.pem") }
fn default_turn_key() -> PathBuf { PathBuf::from("/etc/remgr/ssl/turn_key.pem") }
fn default_min_port() -> u16 { 49152 }
fn default_max_port() -> u16 { 65535 }
fn default_turn_log() -> PathBuf { PathBuf::from("/var/log/remgr/turnserver.log") }

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RustDeskConfig {
    #[serde(default = "default_relay_port")]
    pub relay_port: u16,
    #[serde(default = "default_broker_port")]
    pub broker_port: u16,
    #[serde(default = "default_rustdesk_key")]
    pub key_path: PathBuf,
    #[serde(default = "default_rustdesk_db")]
    pub db_path: PathBuf,
    #[serde(default = "default_token_expiry")]
    pub token_expiry: u64,
    #[serde(default = "default_max_connections")]
    pub max_connections: u32,
    #[serde(default = "default_bandwidth_limit")]
    pub bandwidth_limit: u32,
    pub enabled: bool,
}

fn default_relay_port() -> u16 { 21116 }
fn default_broker_port() -> u16 { 21115 }
fn default_rustdesk_key() -> PathBuf { PathBuf::from("/var/lib/remgr/rustdesk_key") }
fn default_rustdesk_db() -> PathBuf { PathBuf::from("/var/lib/remgr/rustdesk-server/db_v2.sqlite3") }
fn default_token_expiry() -> u64 { 3600 }
fn default_max_connections() -> u32 { 10000 }
fn default_bandwidth_limit() -> u32 { 1024 }

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FrpsConfig {
    #[serde(default = "default_frps_port")]
    pub server_port: u16,
    #[serde(default = "default_dashboard_port")]
    pub dashboard_port: u16,
    #[serde(default = "default_vhost_http_port")]
    pub vhost_http_port: u16,
    #[serde(default = "default_vhost_https_port")]
    pub vhost_https_port: u16,
    #[serde(default = "default_frps_token")]
    pub token: String,
    #[serde(default = "default_dashboard_user")]
    pub dashboard_user: String,
    #[serde(default)]
    pub dashboard_pwd: String,
    #[serde(default = "default_max_pool_count")]
    pub max_pool_count: u32,
    #[serde(default = "default_sub_modules")]
    pub sub_modules_per_pool: u32,
    #[serde(default)]
    pub tcp_mux: bool,
    #[serde(default)]
    pub allow_local_routes: bool,
    #[serde(default = "default_bind_addr")]
    pub bind_addr: String,
    pub enabled: bool,
}

fn default_frps_port() -> u16 { 7000 }
fn default_dashboard_port() -> u16 { 7500 }
fn default_vhost_http_port() -> u16 { 80 }
fn default_vhost_https_port() -> u16 { 443 }
fn default_frps_token() -> String { "default_token".to_string() }
fn default_dashboard_user() -> String { "admin".to_string() }
fn default_max_pool_count() -> u32 { 200 }
fn default_sub_modules() -> u32 { 10 }
fn default_bind_addr() -> String { "0.0.0.0".to_string() }

impl Config {
    pub fn load() -> anyhow::Result<Self> {
        let config_path = Self::find_config_path();
        if config_path.exists() {
            let content = std::fs::read_to_string(&config_path)?;
            let mut cfg: Config = toml::from_str(&content)?;
            cfg.config_path = config_path;
            Ok(cfg)
        } else {
            let mut cfg = Self::default();
            cfg.config_path = config_path;
            Ok(cfg)
        }
    }

    pub fn save(&self) -> anyhow::Result<()> {
        if let Some(parent) = self.config_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let content = toml::to_string_pretty(self)?;
        std::fs::write(&self.config_path, content)?;
        Ok(())
    }

    fn find_config_path() -> PathBuf {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
        let mut path = PathBuf::from(home);
        path.push(".config/remgr/config.toml");
        path
    }
}

impl Default for Config {
    fn default() -> Self {
        let config_path = Self::find_config_path();
        Self {
            web_port: 9000,
            easytier: EasyTierConfig::default(),
            stun_turn: StunTurnConfig::default(),
            rustdesk: RustDeskConfig::default(),
            frps: FrpsConfig::default(),
            config_path,
        }
    }
}