//! frpc module: supervises the embedded frp *client*, so this box can publish
//! its own services on an upstream frp server (a real fatedier/frp frps,
//! another ReMgr, anything speaking the V1 wire protocol).
//!
//! The protocol work lives in `remgr_frps::client`; this module is the
//! `ServiceModule` shell around it: read `[frpc]` from the shared config, hand
//! it to the client on start/apply, and report the live session in `status()`.

use std::sync::Arc;

use async_trait::async_trait;

use crate::state::AppState;

pub struct FrpcModule {
    state: std::sync::Weak<AppState>,
    client: Arc<remgr_frps::FrpcClient>,
}

impl FrpcModule {
    pub fn new(state: &std::sync::Weak<AppState>) -> Self {
        Self {
            state: state.clone(),
            client: Arc::new(remgr_frps::FrpcClient::new(remgr_frps::FrpcConfig::default())),
        }
    }

    fn cfg(&self) -> remgr_frps::FrpcConfig {
        self.state
            .upgrade()
            .map(|s| s.config_blocking().frpc)
            .unwrap_or_default()
    }
}

#[async_trait]
impl super::ServiceModule for FrpcModule {
    fn name(&self) -> &'static str {
        "frpc"
    }

    async fn status(&self) -> serde_json::Value {
        let cfg = self.cfg();
        let st = self.client.status().await;
        serde_json::json!({
            "enabled": cfg.enabled,
            "running": st.running,
            // `connected` is the one that matters for a client: the module can be
            // started and still be backing off a failed upstream.
            "connected": st.connected,
            "upstream": st.upstream,
            "run_id": st.run_id,
            "tcp_mux": st.tcp_mux,
            "tls": st.tls,
            "token_set": !cfg.token.is_empty(),
            "pool_count": cfg.pool_count,
            "session_uptime_s": st.session_uptime_secs,
            "total_logins": st.total_logins,
            "total_work_conns": st.total_work_conns,
            "bytes_in": st.bytes_in,
            "bytes_out": st.bytes_out,
            "last_error": st.last_error,
            "proxies": st.proxies,
        })
    }

    async fn start(&self) -> anyhow::Result<()> {
        let cfg = self.cfg();
        // Adopt the saved configuration *before* the enabled check: the status
        // view is built from the client's own per-proxy state, so a config that
        // removed a proxy (or a PUT that disabled the module while it ran) must
        // still reach the client — otherwise the console keeps listing proxies
        // that no longer exist.
        self.client.update_config(cfg.clone()).await;
        if !cfg.enabled {
            anyhow::bail!("frpc module is disabled");
        }
        self.client.start().await
    }

    async fn stop(&self) -> anyhow::Result<()> {
        self.client.stop().await
    }

    async fn apply_config(&self) -> anyhow::Result<()> {
        // Same reason as `start`: adopt the edit even while stopped, then bounce
        // the session only if one is running.
        self.client.update_config(self.cfg()).await;
        super::restart_if_running(self).await
    }
}
