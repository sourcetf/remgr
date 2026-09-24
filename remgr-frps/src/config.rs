//! Server configuration for the embedded frps.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrpsConfig {
    #[serde(default = "d_enabled")]
    pub enabled: bool,
    #[serde(default = "d_bind_addr")]
    pub bind_addr: String,
    /// Port frpc connects to (control + work conns / yamux session).
    #[serde(default = "d_server_port")]
    pub server_port: u16,
    #[serde(default = "d_token")]
    pub token: String,
    /// Whether yamux multiplexing is used on the control connection.
    /// Must match the client's `transport.tcpMux` (frpc default: true).
    #[serde(default = "d_true")]
    pub tcp_mux: bool,
    /// TLS cert/key (PEM) enabling frpc `transport.tls` connections.
    /// Empty or unreadable paths fall back to an ephemeral self-signed pair,
    /// exactly like frp itself does when no certificate is configured.
    #[serde(default = "d_tls_cert")]
    pub tls_cert_path: Option<String>,
    #[serde(default = "d_tls_key")]
    pub tls_key_path: Option<String>,
    /// Cap on work connections pre-issued per control (client `poolCount`).
    /// frp's own default is 5; a larger cap only means the client opens more
    /// idle work conns up front when it asks for them.
    #[serde(default = "d_max_pool")]
    pub max_pool_count: u32,
    /// Seconds without control activity before a client that is known to send
    /// heartbeats (frp <= 0.51) is closed. 0 disables the monitor, like frp's
    /// `heartbeat_timeout`. Newer clients keep the connection alive through the
    /// multiplexer instead and are never judged by it.
    #[serde(default = "d_heartbeat")]
    pub heartbeat_timeout: u64,
    /// Optional allowed remote port range for tcp/udp proxies, e.g. "6000-6100,7000".
    #[serde(default)]
    pub allow_ports: Option<String>,
    /// PBKDF2 salt for the post-login control-channel cipher. frp has used
    /// "frp" since v0.44.0 (it overrides golib's own "crypto" in
    /// `client/service.go` and `cmd/frps/main.go`); only older clients need the
    /// golib default, so this exists purely as an escape hatch for them.
    #[serde(default = "d_crypto_salt")]
    pub crypto_salt: String,
}

fn d_enabled() -> bool { true }
fn d_bind_addr() -> String { "0.0.0.0".into() }
fn d_server_port() -> u16 { 7000 }
fn d_token() -> String { String::new() }
fn d_true() -> bool { true }
fn d_max_pool() -> u32 { 50 }
fn d_heartbeat() -> u64 { 90 }
/// Default certificate/key locations, so a certificate generated (or uploaded)
/// for the `frps` service in the console is picked up without further editing.
/// The module tolerates their absence by falling back to an ephemeral pair.
fn d_tls_cert() -> Option<String> { Some("/etc/remgr/ssl/frps_cert.pem".into()) }
fn d_tls_key() -> Option<String> { Some("/etc/remgr/ssl/frps_key.pem".into()) }
fn d_crypto_salt() -> String { crate::crypto::DEFAULT_SALT.to_string() }

impl Default for FrpsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            bind_addr: d_bind_addr(),
            server_port: d_server_port(),
            token: String::new(),
            tcp_mux: true,
            tls_cert_path: d_tls_cert(),
            tls_key_path: d_tls_key(),
            max_pool_count: 50,
            heartbeat_timeout: 90,
            allow_ports: None,
            crypto_salt: d_crypto_salt(),
        }
    }
}

impl FrpsConfig {
    /// Check a requested remote port against the optional allow list.
    pub fn port_allowed(&self, port: u16) -> bool {
        let Some(spec) = &self.allow_ports else {
            return true;
        };
        if spec.trim().is_empty() {
            return true;
        }
        for part in spec.split(',') {
            let part = part.trim();
            if let Some((lo, hi)) = part.split_once('-') {
                if let (Ok(lo), Ok(hi)) = (lo.trim().parse::<u16>(), hi.trim().parse::<u16>()) {
                    if port >= lo && port <= hi {
                        return true;
                    }
                }
            } else if let Ok(p) = part.parse::<u16>() {
                if p == port {
                    return true;
                }
            }
        }
        false
    }
}
