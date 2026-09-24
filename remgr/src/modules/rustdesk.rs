//! RustDesk server module — hbbs (rendezvous/ID) + hbbr (relay) linked
//! in-process from the vendored rustdesk-server sources.
//!
//! Ports (rustdesk conventions): hbbs listens on `hbbs_port` (21116: udp+tcp,
//! NAT-test on -1, websocket on +2); hbbr listens on `relay_port` (21117,
//! websocket +2). All of them are probed before the module reports running, so a
//! collision on a derived port is a startup error instead of a relay that half
//! works.
//!
//! Server key: the pair lives in `id_ed25519` / `id_ed25519.pub` in the data
//! dir (the working directory, pinned to `/var/lib/remgr` by `main`). What hbbs
//! needs (`-k`) is the *secret* half, or `"_"`/`"-"` for "read that file" —
//! `get_server_sk` derives the public half from a secret key and keeps it as the
//! signing key; with a bare public key it has no signing key at all and every
//! client fails (`get_pk` returns nothing, so peers can never be verified). The
//! module therefore starts both servers with `"_"` whenever the configured value
//! is empty or the on-disk pair, passes a configured *secret* key through, and
//! refuses anything shorter than a secret key instead of serving a dead relay.
//!
//! Clients put the **public** key (`id_ed25519.pub`, base64) in their
//! "ID/Relay Server → Key" field: that is what the console shows.
//!
//! Stop: `start_with_bind` holds all its listeners as locals, so the tasks are
//! aborted *and awaited* — dropping the futures is what releases the ports, and
//! the console's "restart" runs start() immediately afterwards.

use std::time::Duration;

use async_trait::async_trait;
use tokio_util::sync::CancellationToken;

use crate::state::AppState;

const SECRET_FILE: &str = "id_ed25519";
const PUBLIC_FILE: &str = "id_ed25519.pub";
/// An ed25519 secret key is 64 bytes (88 base64 characters), the public half 32
/// bytes (44). The length is the only way to tell them apart here, and getting it
/// wrong is what makes hbbs unable to sign.
const MIN_SECRET_KEY_LEN: usize = 60;

/// The on-disk pair as `(public, secret)`; either is empty when the file is
/// missing or unreadable.
fn disk_keys() -> (String, String) {
    let read = |name: &str| {
        std::fs::read_to_string(name)
            .map(|s| s.trim().to_string())
            .unwrap_or_default()
    };
    (read(PUBLIC_FILE), read(SECRET_FILE))
}

/// The key argument to start hbbs/hbbr with.
fn resolve_key(cfg: &crate::config::RustDeskConfig) -> anyhow::Result<String> {
    let (disk_pub, disk_sk) = disk_keys();
    let key = cfg.key.trim();
    if key.is_empty() || key == disk_pub || key == disk_sk {
        // Both halves read `id_ed25519`; make sure it exists before either starts,
        // otherwise they race on first boot and generate different keys. gen_sk
        // returns the existing pair when the file is present.
        let (pk, _sk) = hbbs::common::gen_sk(0);
        if pk.is_empty() {
            anyhow::bail!(
                "rustdesk: no usable server key — id_ed25519 is missing or corrupt \
                 (fix or remove it and try again)"
            );
        }
        if !key.is_empty() {
            tracing::info!("rustdesk: configured key is the on-disk pair, using id_ed25519");
        }
        // "_" = "use the key on disk": hbbs then keeps the secret half too.
        return Ok("_".to_string());
    }
    if key.len() < MIN_SECRET_KEY_LEN {
        // A public key here is not a valid configuration: hbbs would start (and
        // look healthy to the console) without a signing key, so every client
        // that tries to connect fails. Say so instead.
        anyhow::bail!(
            "rustdesk: the configured key is {} characters, the length of a *public* key. \
             hbbs must get the secret half (the 88-character value `rustdesk-utils \
             genkeypair` prints), or an empty field to use id_ed25519",
            key.len()
        );
    }
    // A hand-set secret key: hbbs/hbbr derive its public half themselves, so the
    // server works, but nothing here can show that half in the console.
    tracing::info!("rustdesk: using the configured secret key (its public half is not shown here)");
    Ok(key.to_string())
}

/// Port sanity check before anything binds.
///
/// hbbs derives its NAT-test port as `port - 1` and both servers use `port + 2`
/// for websockets: a zero main port would bind ephemeral ports (and the readiness
/// probe a port nobody listens on), a port near 65535 has no room for the derived
/// one, and overlapping groups collide with each other before any client connects.
fn check_ports(cfg: &crate::config::RustDeskConfig) -> anyhow::Result<()> {
    if cfg.hbbs_port < 2 || cfg.relay_port < 2 {
        anyhow::bail!(
            "rustdesk: hbbs_port and relay_port must be at least 2 (hbbs uses port-1 for the NAT test)"
        );
    }
    if cfg.hbbs_port > 65533 || cfg.relay_port > 65533 {
        anyhow::bail!("rustdesk: hbbs_port and relay_port must leave room for the websocket port (+2)");
    }
    let hbbs_group = [cfg.hbbs_port, cfg.hbbs_port - 1, cfg.hbbs_port + 2];
    let relay_group = [cfg.relay_port, cfg.relay_port + 2];
    if let Some(p) = hbbs_group.iter().find(|p| relay_group.contains(*p)) {
        anyhow::bail!(
            "rustdesk: port {p} would be used by both hbbs and hbbr — hbbs takes {}-{}, \
             hbbr {}-{} once the derived ports are included",
            cfg.hbbs_port - 1,
            cfg.hbbs_port + 2,
            cfg.relay_port,
            cfg.relay_port + 2
        );
    }
    Ok(())
}

pub struct RustDeskModule {
    state: std::sync::Weak<AppState>,
    run: tokio::sync::Mutex<Option<RunHandle>>,
}

struct RunHandle {
    token: CancellationToken,
    hbbs: Option<tokio::task::JoinHandle<()>>,
    hbbr: Option<tokio::task::JoinHandle<()>>,
}

impl RunHandle {
    /// Both halves are still running. One that died (bind failure, runtime error)
    /// is enough to make the relay unusable for clients, so it must not be
    /// reported as running.
    fn alive(&self) -> bool {
        !self.token.is_cancelled()
            && matches!(&self.hbbs, Some(h) if !h.is_finished())
            && matches!(&self.hbbr, Some(h) if !h.is_finished())
    }
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
        let running = self.run.lock().await.as_ref().map(|h| h.alive()).unwrap_or(false);
        let (disk_pub, disk_sk) = disk_keys();
        let configured = cfg.key.trim();
        // The public key is what a client needs; it is only known here while the
        // servers work from the on-disk pair. A hand-set secret key derives its
        // public half inside hbbs, and the secret must never be shown in the field
        // operators copy into their clients.
        let using_disk = configured.is_empty() || configured == disk_pub || configured == disk_sk;
        let public_key = if using_disk { disk_pub } else { String::new() };
        let key_set = running || !configured.is_empty() || !public_key.is_empty();
        serde_json::json!({
            "enabled": cfg.enabled,
            "running": running,
            "relay_port": cfg.relay_port,
            "hbbs_port": cfg.hbbs_port,
            "nat_test_port": cfg.hbbs_port.saturating_sub(1),
            "websocket_port": cfg.hbbs_port.saturating_add(2),
            "relay_websocket_port": cfg.relay_port.saturating_add(2),
            // the configured value can be the *secret* key, so it stays out of the
            // status payload; the console needs the public half and whether a key
            // is set, and operators edit the key in the config form
            "public_key": public_key,
            "key_set": key_set,
        })
    }

    async fn start(&self) -> anyhow::Result<()> {
        let mut run = self.run.lock().await;
        let mut stale = false;
        match run.as_ref() {
            Some(h) if h.alive() => return Ok(()),
            // A handle whose halves are gone is not a running module: drop it (and
            // its token) so this call really starts the servers again, instead of
            // reporting success while the relay is dead.
            Some(_) => stale = true,
            None => {}
        }
        if stale {
            if let Some(old) = run.take() {
                old.token.cancel();
                for h in [old.hbbs, old.hbbr].into_iter().flatten() {
                    h.abort();
                    let _ = h.await;
                }
            }
        }
        let cfg = self.cfg();
        if !cfg.enabled {
            anyhow::bail!("rustdesk module is disabled");
        }
        check_ports(&cfg)?;
        let token = CancellationToken::new();

        let key = resolve_key(&cfg)?;
        let (hbbs_task, hbbr_task) =
            self.spawn_servers(key, cfg.hbbs_port as i32, cfg.relay_port.to_string(), &token);

        // Never report a running relay before it is actually listening: a failed
        // bind happens inside the spawned task, where it would only be logged.
        // Every TCP port the two servers bind is probed, derived ones included.
        let mut ports = vec![
            cfg.hbbs_port,
            cfg.relay_port,
            cfg.hbbs_port - 1,
            cfg.hbbs_port + 2,
            cfg.relay_port + 2,
        ];
        ports.sort_unstable();
        ports.dedup();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
        loop {
            let missing: Vec<u16> = {
                let mut missing = Vec::new();
                for p in &ports {
                    if !port_listening(*p).await {
                        missing.push(*p);
                    }
                }
                missing
            };
            if missing.is_empty() {
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
                    "rustdesk: hbbs/hbbr are not listening on {} after 8s \
                     (another process may hold the ports)",
                    missing.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(", ")
                );
            }
            tokio::time::sleep(Duration::from_millis(150)).await;
        }
        tracing::info!(
            "rustdesk: hbbs listening on {} (tcp+udp, NAT test {}, websocket {}), \
             hbbr listening on {} (websocket {})",
            cfg.hbbs_port,
            cfg.hbbs_port - 1,
            cfg.hbbs_port + 2,
            cfg.relay_port,
            cfg.relay_port + 2
        );

        *run = Some(RunHandle { token, hbbs: Some(hbbs_task), hbbr: Some(hbbr_task) });
        Ok(())
    }

    async fn stop(&self) -> anyhow::Result<()> {
        if let Some(handle) = self.run.lock().await.take() {
            handle.token.cancel();
            // Await the aborted tasks: dropping their futures is what drops the
            // listeners. The console's "restart" calls start() right after this
            // returns, and a port still held by the old incarnation would make the
            // new bind fail (reported as a port conflict).
            if let Some(h) = handle.hbbs {
                h.abort();
                let _ = h.await;
            }
            if let Some(h) = handle.hbbr {
                h.abort();
                let _ = h.await;
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
