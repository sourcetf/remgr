//! frps module: supervises the embedded remgr-frps server.

use std::sync::Arc;

use async_trait::async_trait;

use crate::state::AppState;

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

    /// Persist a generated token (best effort) so the console and later starts
    /// agree on the credential frpc must present.
    async fn pin_token(&self, token: &str) {
        let Some(state) = self.state.upgrade() else {
            return;
        };
        let mut cfg = state.config.write().await;
        cfg.frps.token = token.to_string();
        if let Err(e) = cfg.save() {
            tracing::warn!("frps: could not persist the generated token: {e:#}");
        }
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
            // "tls" means a usable configured certificate, not merely a path:
            // a missing file makes the server fall back to an ephemeral pair.
            "tls": matches!(
                (&cfg.tls_cert_path, &cfg.tls_key_path),
                (Some(c), Some(k))
                    if !c.is_empty() && !k.is_empty()
                        && std::path::Path::new(c).exists()
                        && std::path::Path::new(k).exists()
            ),
            "clients_online": stats.clients_online,
            "total_logins": stats.total_logins,
            "total_user_conns": stats.total_user_conns,
            "bytes_in": stats.bytes_in,
            "bytes_out": stats.bytes_out,
            "proxies": stats.proxies,
        })
    }

    async fn start(&self) -> anyhow::Result<()> {
        let mut cfg = self.cfg();
        if !cfg.enabled {
            anyhow::bail!("frps module is disabled");
        }
        if cfg.token.is_empty() {
            // Without a token frp lets any client register proxies. Mint one on
            // first use and persist it, so the console shows exactly what frpc
            // must send — the operator stays in control of the value.
            use rand::RngCore;
            let mut buf = [0u8; 16];
            rand::thread_rng().fill_bytes(&mut buf);
            let token: String = buf.iter().map(|b| format!("{b:02x}")).collect();
            tracing::warn!(
                "frps: no token configured — generated one: {token} \
                 (stored in the config; set frpc's auth.token to this value)"
            );
            self.pin_token(&token).await;
            cfg.token = token;
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
