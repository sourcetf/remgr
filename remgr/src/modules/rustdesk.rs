//! RustDesk server module — hbbs (rendezvous/ID) + hbbr (relay) linked
//! in-process from the vendored rustdesk-server sources.
//!
//! Ports (rustdesk conventions): hbbs listens on `hbbs_port` (21116: udp+tcp,
//! NAT-test on -1, websocket on +2); hbbr listens on `relay_port` (21117,
//! websocket +2).
//!
//! Server key: hbbs generates one on first boot (persisted to `id_ed25519`
//! in the working dir). When the config's `key` is empty, this module lets
//! hbbs generate the pair, then writes the public key back into
//! `config.toml` and restarts both servers pinned to that key — so the
//! dashboard/config reflects the real key and hbbr agrees on it.
//!
//! Stop: `start_with_bind` future holds all its listeners as locals, so
//! aborting the spawned task drops the sockets and releases the ports;
//! both server futures also select on the cancellation token so a stop
//! never hangs on an idle accept.

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

    /// spawn hbbs + hbbr pinned to `key`, wired to `token` for cancellation
    fn spawn_servers(&self, key: String, port: i32, relay_port: String, token: &CancellationToken) -> (tokio::task::JoinHandle<()>, tokio::task::JoinHandle<()>) {
        let t_hbbs = token.clone();
        let hbbs = {
            let key = key.clone();
            tokio::spawn(async move {
                tracing::info!("rustdesk hbbs starting on port {port}");
                let res = tokio::select! {
                    r = hbbs::RendezvousServer::start_with_bind(None, port, 0, &key, 0) => r,
                    _ = t_hbbs.cancelled() => Ok(()),
                };
                if let Err(e) = res {
                    tracing::error!("rustdesk hbbs stopped: {e:#}");
                }
            })
        };
        let t_hbbr = token.clone();
        let hbbr = tokio::spawn(async move {
            tracing::info!("rustdesk hbbr starting on port {relay_port}");
            let res = tokio::select! {
                r = hbbs::start_with_bind(None, &relay_port, &key) => r,
                _ = t_hbbr.cancelled() => Ok(()),
            };
            if let Err(e) = res {
                tracing::error!("rustdesk hbbr stopped: {e:#}");
            }
        });
        (hbbs, hbbr)
    }

    /// persist the generated key into the console config (best effort) so the
    /// UI and subsequent restarts see the real key
    async fn pin_key(&self, key: &str) {
        let Some(state) = self.state.upgrade() else { return };
        {
            let mut cfg = state.config.write().await;
            cfg.rustdesk.key = key.to_string();
            if let Err(e) = cfg.save() {
                tracing::warn!("rustdesk: could not persist server key: {e:#}");
            } else {
                tracing::info!("rustdesk: generated server key pinned into config");
            }
        }
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
            "key": cfg.key,
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
        // hbbs' built-in self-test kills the PROCESS (std::process::exit) on
        // failure — unacceptable in an embedded single-process manager.
        std::env::set_var("TEST_HBBS", "no");
        let token = CancellationToken::new();

        let key = if cfg.key.is_empty() {
            // No configured key: generate (and persist) an ed25519 keypair the
            // same way the stock hbbs does on first boot (id_ed25519 /
            // id_ed25519.pub in the working dir), then pin the public key for
            // both servers so hbbr agrees with hbbs.
            let (pk, _sk) = hbbs::common::gen_sk(0);
            if pk.is_empty() {
                anyhow::bail!("rustdesk: server key generation failed");
            }
            self.pin_key(&pk).await;
            pk
        } else {
            cfg.key.clone()
        };

        let (hbbs, hbbr) =
            self.spawn_servers(key, cfg.hbbs_port as i32, cfg.relay_port.to_string(), &token);
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
