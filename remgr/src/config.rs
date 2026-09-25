//! ReMgr configuration model, persisted as TOML.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub fn default_config_path() -> PathBuf {
    if cfg!(target_os = "openbsd") {
        PathBuf::from("/etc/remgr/config.toml")
    } else {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
        Path::new(&home).join(".config/remgr/config.toml")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Config {
    pub console: ConsoleConfig,
    pub easytier: EasyTierConfig,
    pub stun_turn: StunTurnConfig,
    pub rustdesk: RustDeskConfig,
    pub frps: FrpsConfig,
    /// frp client: expose local services through an upstream frps
    pub frpc: FrpcConfig,
    #[serde(skip_serializing, skip_deserializing)]
    pub config_path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ConsoleConfig {
    pub port: u16,
    /// Login user name. Stored as-is (it is not a secret — the password is the
    /// credential); change it on the 系统 page.
    pub username: String,
    /// argon2id PHC string (`$argon2id$v=19$m=65536,t=3,p=1$…`); empty → the
    /// default password is installed on first boot and logged.
    pub password_hash: String,
    pub tls: bool,
    pub tls_cert: String,
    pub tls_key: String,
    /// session lifetime (seconds)
    pub session_ttl: u64,
}

impl Default for ConsoleConfig {
    fn default() -> Self {
        Self {
            port: 9443,
            username: "admin".into(),
            password_hash: String::new(),
            tls: false,
            tls_cert: "/etc/remgr/ssl/console_cert.pem".into(),
            tls_key: "/etc/remgr/ssl/console_key.pem".into(),
            session_ttl: 7 * 24 * 3600,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct EasyTierConfig {
    pub enabled: bool,
    /// easytier-web embedded: config server (instances register here, udp)
    pub config_server_port: u16,
    /// easytier-web REST API bind address (proxied under /et by the console)
    pub api_addr: String,
    pub api_port: u16,
    pub db_path: String,
    /// local center node instance
    pub node_enabled: bool,
    pub node_name: String,
    pub network_name: String,
    pub network_secret: String,
    /// empty → DHCP (random virtual ip)
    pub virtual_ipv4: String,
    pub listeners: Vec<String>,
}

impl Default for EasyTierConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            config_server_port: 22020,
            api_addr: "127.0.0.1".into(),
            api_port: 11211,
            db_path: "/var/lib/remgr/easytier/et.db".into(),
            node_enabled: true,
            node_name: "remgr-node".into(),
            network_name: String::new(),
            network_secret: String::new(),
            virtual_ipv4: String::new(),
            listeners: vec![
                "tcp://0.0.0.0:11010".into(),
                "udp://0.0.0.0:11010".into(),
                "wg://0.0.0.0:11011".into(),
                "ws://0.0.0.0:11011/".into(),
                "wss://0.0.0.0:11012/".into(),
                "faketcp://0.0.0.0:11013".into(),
            ],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct StunTurnConfig {
    pub enabled: bool,
    pub bind_addr: String,
    /// STUN + TURN listening port (UDP/TCP)
    pub stun_port: u16,
    /// TURN relay allocations (RFC 5766, in-process)
    pub turn_enabled: bool,
    /// TURN over TLS port (requires cert/key; 0 disables)
    pub tls_port: u16,
    pub domain: String,
    pub relay_min_port: u16,
    pub relay_max_port: u16,
    /// public relay IP as seen by clients; empty = auto
    pub external_ip: String,
    /// credentials, entries like "user:pass"
    pub users: Vec<String>,
    pub realm: String,
    pub cert_path: String,
    pub key_path: String,
}

impl Default for StunTurnConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            bind_addr: "0.0.0.0".into(),
            stun_port: 3478,
            turn_enabled: true,
            tls_port: 5349,
            domain: String::new(),
            relay_min_port: 49152,
            relay_max_port: 65535,
            external_ip: String::new(),
            users: Vec::new(),
            realm: "remgr".into(),
            cert_path: "/etc/remgr/ssl/turn_cert.pem".into(),
            key_path: "/etc/remgr/ssl/turn_key.pem".into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RustDeskConfig {
    pub enabled: bool,
    /// server key (rustdesk `-k _` value); empty → generated and persisted
    pub key: String,
    /// relay server port (hbbr)
    pub relay_port: u16,
    /// rendezvous/ID server port (hbbs); 21115/21118 derived
    pub hbbs_port: u16,
}

impl Default for RustDeskConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            key: String::new(),
            relay_port: 21117,
            hbbs_port: 21116,
        }
    }
}

pub type FrpsConfig = remgr_frps::FrpsConfig;
pub type FrpcConfig = remgr_frps::FrpcConfig;

impl Config {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let mut cfg: Config = if path.exists() {
            let content = std::fs::read_to_string(path)?;
            toml::from_str(&content)?
        } else {
            Config::default()
        };
        cfg.config_path = path.to_path_buf();
        Ok(cfg)
    }

    pub fn save(&self) -> anyhow::Result<()> {
        let path = &self.config_path;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        // strip the runtime-only path field for serialization
        #[derive(Serialize)]
        #[serde(default)]
        struct Wire<'a> {
            console: &'a ConsoleConfig,
            easytier: &'a EasyTierConfig,
            stun_turn: &'a StunTurnConfig,
            rustdesk: &'a RustDeskConfig,
            frps: &'a FrpsConfig,
            frpc: &'a FrpcConfig,
        }
        let wire = Wire {
            console: &self.console,
            easytier: &self.easytier,
            stun_turn: &self.stun_turn,
            rustdesk: &self.rustdesk,
            frps: &self.frps,
            frpc: &self.frpc,
        };
        let mut out = toml::to_string_pretty(&wire)?;
        if !out.ends_with('\n') {
            out.push('\n');
        }
        // write via temp file + rename for atomicity. The file holds the console
        // password hash and every service token, so it is created owner-only;
        // fsync before the rename and on the directory after it, so a crash
        // between the two cannot leave an empty or half-written config behind.
        let tmp = path.with_extension("toml.tmp");
        {
            use std::io::Write;
            let mut f = open_private(&tmp)?;
            f.write_all(out.as_bytes())?;
            f.flush()?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, path)?;
        if let Some(parent) = path.parent() {
            if let Ok(dir) = std::fs::File::open(parent) {
                let _ = dir.sync_all();
            }
        }
        Ok(())
    }
}

/// Create (or truncate) a file that is never more readable than owner-only.
fn open_private(path: &Path) -> std::io::Result<std::fs::File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
    }
    #[cfg(not(unix))]
    {
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)
    }
}
