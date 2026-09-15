//! frps module: supervises the embedded remgr-frps server.

use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::state::AppState;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FrpsRuntimeStats {
    pub clients_online: u64,
    pub total_logins: u64,
    pub total_user_conns: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub proxies: Vec<serde_json::Value>,
}

pub struct FrpsModule {
    state: std::sync::Weak<AppState>,
    server: Arc<remgr_frps::FrpsServer>,
}

impl FrpsModule {
    pub fn new(state: &std::sync::Weak<AppState>) -> Self {
        Self {
            state: state.clone(),
            server: Arc::new(remgr_frps::FrpsServer::new(remgr_frps::FrpsConfig::default())),
        }
    }

    fn cfg(&self) -> remgr_frps::FrpsConfig {
        self.state
            .upgrade()
            .map(|s| s.config_blocking().frps)
            .unwrap_or_default()
    }
}

#[async_trait]
impl super::ServiceModule for FrpsModule {
    fn name(&self) -> &'static str {
        "frps"
    }

    async fn status(&self) -> serde_json::Value {
        let cfg = self.cfg();
        let stats = self.server.stats().await;
        serde_json::json!({
            "enabled": cfg.enabled,
            "running": stats.running,
            "bind": stats.bind,
            "tcp_mux": cfg.tcp_mux,
            "token_set": !cfg.token.is_empty(),
            "tls": cfg.tls_cert_path.is_some() && cfg.tls_key_path.is_some(),
            "clients_online": stats.clients_online,
            "total_logins": stats.total_logins,
            "total_user_conns": stats.total_user_conns,
            "bytes_in": stats.bytes_in,
            "bytes_out": stats.bytes_out,
            "proxies": stats.proxies,
        })
    }

    async fn start(&self) -> anyhow::Result<()> {
        let cfg = self.cfg();
        if !cfg.enabled {
            anyhow::bail!("frps module is disabled");
        }
        if cfg.token.is_empty() {
            tracing::warn!("frps: token is empty — any client can authenticate");
        }
        self.server.update_config(cfg).await;
        self.server.start().await
    }

    async fn stop(&self) -> anyhow::Result<()> {
        self.server.stop().await
    }

    async fn apply_config(&self) -> anyhow::Result<()> {
        super::restart_if_running(self).await
    }
}
