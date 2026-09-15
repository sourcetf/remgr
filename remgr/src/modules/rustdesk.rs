//! RustDesk server module — hbbs (rendezvous/ID) + hbbr (relay) linked
//! in-process from the vendored rustdesk-server sources.
//!
//! Ports (rustdesk conventions): hbbs listens on `hbbs_port` (21116: udp+tcp,
//! NAT-test on -1, websocket on +2); hbbr listens on `relay_port` (21117,
//! websocket +2).

use std::sync::Arc;

use async_trait::async_trait;
use tokio_util::sync::CancellationToken;

use crate::state::AppState;

pub struct RustDeskModule {
    state: std::sync::Weak<AppState>,
    run: tokio::sync::Mutex<Option<RunHandle>>,
}

struct RunHandle {
    token: CancellationToken,
    hbbs: Option<tokio::task::JoinHandle<()>>,
    hbbr: Option<tokio::task::JoinHandle<()>>,
}

impl RustDeskModule {
    pub fn new(state: &std::sync::Weak<AppState>) -> Self {
        Self { state: state.clone(), run: tokio::sync::Mutex::new(None) }
    }

    fn cfg(&self) -> crate::config::RustDeskConfig {
        self.state
            .upgrade()
            .map(|s| s.config_blocking().rustdesk)
            .unwrap_or_default()
    }
}

#[async_trait]
impl super::ServiceModule for RustDeskModule {
    fn name(&self) -> &'static str {
        "rustdesk"
    }

    async fn status(&self) -> serde_json::Value {
        let cfg = self.cfg();
        let running = self.run.lock().await.is_some();
        serde_json::json!({
            "enabled": cfg.enabled,
            "running": running,
            "relay_port": cfg.relay_port,
            "hbbs_port": cfg.hbbs_port,
            "nat_test_port": cfg.hbbs_port.saturating_sub(1),
            "websocket_port": cfg.hbbs_port.saturating_add(2),
            "relay_websocket_port": cfg.relay_port.saturating_add(2),
            "key_set": !cfg.key.is_empty(),
        })
    }

    async fn start(&self) -> anyhow::Result<()> {
        let mut run = self.run.lock().await;
        if run.is_some() {
            return Ok(());
        }
        let cfg = self.cfg();
        if !cfg.enabled {
            anyhow::bail!("rustdesk module is disabled");
        }
        let token = CancellationToken::new();

        // hbbs: rendezvous/ID server (udp + tcp + websocket)
        let hbbs = {
            let token = token.clone();
            let bind = None; // all interfaces
            let port = cfg.hbbs_port as i32;
            let key = cfg.key.clone();
            tokio::spawn(async move {
                tracing::info!("rustdesk hbbs starting on port {port}");
                let res = hbbs::RendezvousServer::start_with_bind(
                    bind, port, 0, &key, 0,
                )
                .await;
                if let Err(e) = res {
                    tracing::error!("rustdesk hbbs stopped: {e:#}");
                }
                let _ = token;
            })
        };

        // hbbr: relay server (tcp + websocket)
        let hbbr = {
            let token = token.clone();
            let bind = None;
            let port = cfg.relay_port.to_string();
            let key = cfg.key.clone();
            tokio::spawn(async move {
                tracing::info!("rustdesk hbbr starting on port {port}");
                let res = hbbs::start_with_bind(bind, &port, &key).await;
                if let Err(e) = res {
                    tracing::error!("rustdesk hbbr stopped: {e:#}");
                }
                let _ = token;
            })
        };

        *run = Some(RunHandle { token, hbbs: Some(hbbs), hbbr: Some(hbbr) });
        Ok(())
    }

    async fn stop(&self) -> anyhow::Result<()> {
        if let Some(handle) = self.run.lock().await.take() {
            handle.token.cancel();
            if let Some(h) = handle.hbbs {
                h.abort();
            }
            if let Some(h) = handle.hbbr {
                h.abort();
            }
            tracing::info!("rustdesk servers stopped");
        }
        Ok(())
    }

    async fn apply_config(&self) -> anyhow::Result<()> {
        super::restart_if_running(self).await
    }
}
