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
    #[serde(default)]
    pub tls_cert_path: Option<String>,
    #[serde(default)]
    pub tls_key_path: Option<String>,
    /// Cap on work connections pre-issued per control (client `poolCount`).
    #[serde(default = "d_max_pool")]
    pub max_pool_count: u32,
    /// Seconds without ping/work-conn activity before a control is closed.
    #[serde(default = "d_heartbeat")]
    pub heartbeat_timeout: u64,
    /// Optional allowed remote port range for tcp/udp proxies, e.g. "6000-6100,7000".
    #[serde(default)]
    pub allow_ports: Option<String>,
}

fn d_enabled() -> bool { true }
fn d_bind_addr() -> String { "0.0.0.0".into() }
fn d_server_port() -> u16 { 7000 }
fn d_token() -> String { String::new() }
fn d_true() -> bool { true }
fn d_max_pool() -> u32 { 50 }
fn d_heartbeat() -> u64 { 90 }

impl Default for FrpsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            bind_addr: d_bind_addr(),
            server_port: d_server_port(),
            token: String::new(),
            tcp_mux: true,
            tls_cert_path: None,
            tls_key_path: None,
            max_pool_count: 50,
            heartbeat_timeout: 90,
            allow_ports: None,
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
