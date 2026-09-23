//! RustDesk server module — hbbs (rendezvous/ID) + hbbr (relay) linked
//! in-process from the vendored rustdesk-server sources.
//!
//! Ports (rustdesk conventions): hbbs listens on `hbbs_port` (21116: udp+tcp,
//! NAT-test on -1, websocket on +2); hbbr listens on `relay_port` (21117,
//! websocket +2).
//!
//! Server key: the pair lives in `id_ed25519` / `id_ed25519.pub` in the data
//! dir (the working directory, pinned to `/var/lib/remgr` by `main`). When the
//! config's `key` is empty both servers are started with `"_"`, which makes them
//! load that file — hbbs keeps the secret half, which it needs to sign peer
//! keys. Pinning a bare public key into the config instead (as `-k <pubkey>`
//! does) leaves the server without a signing key, so that is only done when the
//! operator sets one deliberately.
//!
//! Stop: `start_with_bind` holds all its listeners as locals, so aborting the
//! spawned task drops the sockets and releases the ports.

use std::time::Duration;

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
        // Bind IPv4 explicitly. With no bind address the servers ask for a
        // dual-stack socket (`new_v6` + `set_only_v6(false)`), which OpenBSD
        // refuses — the socket stays IPv6-only, so IPv4 clients (i.e. almost all
        // of them) can neither connect nor let hbbs' own self-test pass.
        let bind = Some(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
        let t_hbbs = token.clone();
        let hbbs_task = {
            let key = key.clone();
            tokio::spawn(async move {
                tracing::info!("rustdesk hbbs starting on port {port} (ipv4)");
                let res = tokio::select! {
                    r = hbbs::RendezvousServer::start_with_bind(bind, port, 0, &key, 0) => r,
                    _ = t_hbbs.cancelled() => Ok(()),
                };
                if let Err(e) = res {
                    tracing::error!("rustdesk hbbs stopped: {e:#}");
                }
            })
        };
        let t_hbbr = token.clone();
        let hbbr_task = tokio::spawn(async move {
            tracing::info!("rustdesk hbbr starting on port {relay_port} (ipv4)");
            let res = tokio::select! {
                r = hbbs::start_with_bind(bind, &relay_port, &key) => r,
                _ = t_hbbr.cancelled() => Ok(()),
            };
            if let Err(e) = res {
                tracing::error!("rustdesk hbbr stopped: {e:#}");
            }
        });
        (hbbs_task, hbbr_task)
    }
}

#[async_trait]
impl super::ServiceModule for RustDeskModule {
    fn name(&self) -> &'static str {
        "rustdesk"
    }

    async fn status(&self) -> serde_json::Value {
        let cfg = self.cfg();
        // A task that died (bind failure, runtime error) must not be reported as
        // a running relay: both halves are required for clients to connect.
        let alive = |j: &Option<tokio::task::JoinHandle<()>>| matches!(j, Some(h) if !h.is_finished());
        let running = self
            .run
            .lock()
            .await
            .as_ref()
            .map(|h| alive(&h.hbbs) && alive(&h.hbbr))
            .unwrap_or(false);
        // The public key is what a client needs; when no explicit key is set it
        // is read back from the file hbbs wrote on first boot.
        let public_key = if cfg.key.is_empty() {
            std::fs::read_to_string("id_ed25519.pub")
                .map(|s| s.trim().to_string())
                .unwrap_or_default()
        } else {
            cfg.key.clone()
        };
        serde_json::json!({
            "enabled": cfg.enabled,
            "running": running,
            "relay_port": cfg.relay_port,
            "hbbs_port": cfg.hbbs_port,
            "nat_test_port": cfg.hbbs_port.saturating_sub(1),
            "websocket_port": cfg.hbbs_port.saturating_add(2),
            "relay_websocket_port": cfg.relay_port.saturating_add(2),
            "key": cfg.key,
            "public_key": public_key,
            "key_set": !public_key.is_empty(),
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

        let disk_key = std::fs::read_to_string("id_ed25519.pub")
            .map(|s| s.trim().to_string())
            .unwrap_or_default();
        let key = if cfg.key.is_empty() || cfg.key == disk_key {
            // Both halves read `id_ed25519`; make sure it exists before either
            // starts, otherwise they race on first boot and generate different
            // keys. gen_sk returns the existing pair when the file is present.
            let (pk, _sk) = hbbs::common::gen_sk(0);
            if pk.is_empty() {
                anyhow::bail!(
                    "rustdesk: no usable server key — id_ed25519 is missing or corrupt \
                     (fix or remove it and try again)"
                );
            }
            // "_" = "use the key on disk": hbbs then keeps the secret half too.
            // A bare public key (including the value an older build pinned into
            // the config, which is just this file's public half) would leave the
            // server unable to sign peer keys.
            if !cfg.key.is_empty() {
                tracing::info!("rustdesk: configured key matches id_ed25519.pub, using the on-disk pair");
            }
            "_".to_string()
        } else {
            cfg.key.clone()
        };

        let (hbbs_task, hbbr_task) =
            self.spawn_servers(key, cfg.hbbs_port as i32, cfg.relay_port.to_string(), &token);

        // Never report a running relay before it is actually listening: a failed
        // bind happens inside the spawned task, where it would only be logged.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(6);
        loop {
            if port_listening(cfg.hbbs_port).await && port_listening(cfg.relay_port).await {
                break;
            }
            if hbbs_task.is_finished() || hbbr_task.is_finished() {
                token.cancel();
                anyhow::bail!(
                    "rustdesk: a server task exited during startup (check the log for the bind error)"
                );
            }
            if tokio::time::Instant::now() >= deadline {
                token.cancel();
                anyhow::bail!(
                    "rustdesk: hbbs/hbbr are not listening on {} / {} after 6s \
                     (another process may hold the ports)",
                    cfg.hbbs_port,
                    cfg.relay_port
                );
            }
            tokio::time::sleep(Duration::from_millis(150)).await;
        }
        tracing::info!(
            "rustdesk: hbbs listening on {} (tcp+udp), hbbr listening on {}",
            cfg.hbbs_port,
            cfg.relay_port
        );

        *run = Some(RunHandle { token, hbbs: Some(hbbs_task), hbbr: Some(hbbr_task) });
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

/// Is something accepting TCP connections on `port` yet? Both loopback
/// families are probed: the servers bind one of them depending on the address
/// they were given (OpenBSD cannot dual-stack), and a probe on the other family
/// would report a healthy listener as missing.
async fn port_listening(port: u16) -> bool {
    for host in ["127.0.0.1", "::1"] {
        let ok = matches!(
            tokio::time::timeout(
                Duration::from_millis(300),
                tokio::net::TcpStream::connect((host, port)),
            )
            .await,
            Ok(Ok(_))
        );
        if ok {
            return true;
        }
    }
    false
}
