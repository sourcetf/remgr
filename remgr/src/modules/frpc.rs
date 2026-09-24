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
    /// Serializes `start`/`stop`/`apply_config`.
    ///
    /// A config save (`apply_config`) and a console button (`start`/`stop`) are
    /// independent requests handled on different tasks, so a `stop` from the
    /// operator can land between the stop and the start of a restart — which
    /// would resurrect the module they just stopped. The client's own run lock
    /// keeps the *sessions* from overlapping; this keeps the intended state of
    /// the module itself in order.
    ops: tokio::sync::Mutex<()>,
}

impl FrpcModule {
    pub fn new(state: &std::sync::Weak<AppState>) -> Self {
        Self {
            state: state.clone(),
            client: Arc::new(remgr_frps::FrpcClient::new(remgr_frps::FrpcConfig::default())),
            ops: tokio::sync::Mutex::new(()),
        }
    }

    fn cfg(&self) -> remgr_frps::FrpcConfig {
        self.state
            .upgrade()
            .map(|s| s.config_blocking().frpc)
            .unwrap_or_default()
    }

    /// Body of `start`; the caller holds `ops`.
    async fn start_locked(&self) -> anyhow::Result<()> {
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
        let _op = self.ops.lock().await;
        self.start_locked().await
    }

    async fn stop(&self) -> anyhow::Result<()> {
        let _op = self.ops.lock().await;
        self.client.stop().await
    }

    async fn apply_config(&self) -> anyhow::Result<()> {
        let _op = self.ops.lock().await;
        // Same rule as `restart_if_running` — adopt the edit even while stopped,
        // bounce the session only if one is running — but inlined: the helper
        // would call back into `start`/`stop`, which wait for the `ops` lock
        // held here.
        self.client.update_config(self.cfg()).await;
        if !self.client.is_running().await {
            return Ok(());
        }
        self.client.stop().await?;
        self.start_locked().await
    }
}
