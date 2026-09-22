//! EasyTier center module — the vendored EasyTier-OpenBSD workspace linked
//! in-process:
//!
//! - `easytier-web`: sqlite db + config server (instances register, udp) +
//!   REST api (dashboard / programmatic management) — via its `start` module
//! - one local center node: `NativeInstanceManager` + `run_web_client`
//!   (registers with the embedded config server) + an optional static
//!   "default network" instance with the listeners from the config

use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use async_trait::async_trait;
use tokio_util::sync::CancellationToken;

use crate::state::AppState;

pub struct EasyTierModule {
    state: std::sync::Weak<AppState>,
    run: tokio::sync::Mutex<Option<RunHandle>>,
}

struct RunHandle {
    /// cancels the web-client registration task
    token: CancellationToken,
    /// strong ref: dropping the manager stops its background drivers
    _manager: Arc<easytier::instance::factory::NativeInstanceManager>,
    /// keeps the embedded easytier-web config server (udp) and REST api
    /// alive — dropping this handle aborts them (AbortOnDrop semantics),
    /// which is what releases udp:22020 / tcp:11211 on restart
    _web: easytier_web::start::RunningEasyTierWeb,
}

impl EasyTierModule {
    pub fn new(state: &std::sync::Weak<AppState>) -> Self {
        Self { state: state.clone(), run: tokio::sync::Mutex::new(None) }
    }

    fn cfg(&self) -> crate::config::EasyTierConfig {
        self.state
            .upgrade()
            .map(|s| s.config_blocking().easytier)
            .unwrap_or_default()
    }

    fn build_instance_toml(cfg: &crate::config::EasyTierConfig) -> anyhow::Result<String> {
        let mut listeners = String::new();
        for l in &cfg.listeners {
            listeners.push_str(&format!("  \"{l}\",\n"));
        }
        let network_secret = if cfg.network_secret.is_empty() {
            // stable per-install secret so the node can rejoin after restarts
            let mut h: u64 = 1469598103934665603;
            for b in cfg.network_name.as_bytes() {
                h ^= u64::from(*b);
                h = h.wrapping_mul(1099511628211);
            }
            format!("{h:016x}")
        } else {
            cfg.network_secret.clone()
        };
        // The EasyTier TOML key is `ipv4`, not `virtual_ipv4`: unknown keys are
        // dropped silently, so the node fell back to DHCP and — with no peer to
        // lease from — never created its TUN device at all.
        let ip_part = if cfg.virtual_ipv4.is_empty() {
            "dhcp = true".to_string()
        } else {
            format!("ipv4 = \"{}\"\ndhcp = false", cfg.virtual_ipv4)
        };
        Ok(format!(
            "listeners = [\n{listeners}]\n\
             hostname = \"{host}\"\n\
             {ip_part}\n\
             [network_identity]\n\
             network_name = \"{name}\"\n\
             network_secret = \"{secret}\"\n\
             [flags]\n\
             default_protocol = \"tcp\"\n\
             latency_first = true\n",
            host = cfg.node_name,
            name = cfg.network_name,
            secret = network_secret,
        ))
    }
}

#[async_trait]
impl super::ServiceModule for EasyTierModule {
    fn name(&self) -> &'static str {
        "easytier"
    }

    async fn status(&self) -> serde_json::Value {
        let cfg = self.cfg();
        let running = self.run.lock().await.is_some();
        serde_json::json!({
            "enabled": cfg.enabled,
            "running": running,
            "config_server_port": cfg.config_server_port,
            "api_addr": cfg.api_addr,
            "api_port": cfg.api_port,
            "node_enabled": cfg.node_enabled,
            "node_name": cfg.node_name,
            "network_name": cfg.network_name,
            "virtual_ipv4": cfg.virtual_ipv4,
            "listeners": cfg.listeners,
            "db_path": cfg.db_path,
        })
    }

    async fn start(&self) -> anyhow::Result<()> {
        let mut run = self.run.lock().await;
        if run.is_some() {
            return Ok(());
        }
        let cfg = self.cfg();
        if !cfg.enabled {
            anyhow::bail!("easytier module is disabled");
        }

        // ensure the sqlite parent dir exists (sqlite won't mkdir)
        let db_dir = std::path::Path::new(&cfg.db_path)
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_default();
        std::fs::create_dir_all(&db_dir)
            .with_context(|| format!("create easytier db dir {}", db_dir.display()))?;

        // 1) embedded easytier-web: db + config server + REST api.
        //
        // A previous incarnation releases its sockets from an aborted task, not
        // synchronously, so a restart can lose the race and see EADDRINUSE.
        // Retry briefly rather than failing the whole module.
        let web_cfg = easytier_web::start::WebConfig {
            db_path: cfg.db_path.clone(),
            config_server_protocol: "udp".into(),
            config_server_port: cfg.config_server_port,
            api_addr: cfg.api_addr.parse()?,
            api_port: cfg.api_port,
            geoip_db: None,
            heartbeat_min_response_ms: 0,
            feature_flags: Arc::new(easytier_web::FeatureFlags {
                disable_registration: false,
                allow_auto_create_user: true,
            }),
        };
        let mut web = None;
        let mut last_err: Option<anyhow::Error> = None;
        for attempt in 0..24u32 {
            match easytier_web::start::start_web(web_cfg.clone()).await {
                Ok(w) => {
                    web = Some(w);
                    break;
                }
                Err(e) => {
                    last_err = Some(e);
                    if attempt < 23 {
                        tokio::time::sleep(Duration::from_millis(250)).await;
                    }
                }
            }
        }
        let web = web.ok_or_else(|| {
            last_err
                .map(|e| e.context(format!("easytier-web start (db={})", cfg.db_path)))
                .unwrap_or_else(|| anyhow::anyhow!("easytier-web start failed"))
        })?;

        let token = CancellationToken::new();

        // Dashboard credential bootstrap.
        //
        // The easytier-web migration seeds an `admin` user with a fixed hash
        // whose plaintext is not published, so the embedded dashboard has no
        // usable login until the password is replaced. On first boot — no
        // password file yet — a fresh random password is hashed into that
        // account and written root-only; once the file exists the operator has
        // been given a working credential and may have changed it from the
        // dashboard, so it is left alone.
        {
            let db = web.db.clone();
            const PW_FILE: &str = "/var/run/remgr/easytier_dashboard_password";
            if !std::path::Path::new(PW_FILE).exists() {
                let password: String = {
                    use rand::Rng;
                    const ALPH: &[u8] = b"abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ23456789";
                    let mut rng = rand::thread_rng();
                    (0..14)
                        .map(|_| ALPH[rng.gen_range(0..ALPH.len())] as char)
                        .collect()
                };
                match tokio::task::spawn_blocking({
                    let pw = password.clone();
                    move || password_auth::generate_hash(&pw)
                })
                .await
                {
                    Ok(hash) => {
                        let spare = hash.clone();
                        // Replace the seeded credential; only create the account
                        // if a previous run removed it.
                        let installed = match db.set_user_password("admin", hash).await {
                            Ok(true) => Ok(()),
                            _ => db
                                .create_user_and_join_users_group("admin", spare)
                                .await
                                .map(|_| ()),
                        };
                        match installed {
                            Ok(()) => {
                                let _ = std::fs::write(PW_FILE, format!("{password}\n"));
                                #[cfg(unix)]
                                {
                                    use std::os::unix::fs::PermissionsExt;
                                    let _ = std::fs::set_permissions(
                                        PW_FILE,
                                        std::fs::Permissions::from_mode(0o600),
                                    );
                                }
                                tracing::warn!(
                                    "easytier dashboard initial password: {password}  \
                                     (user admin, also in {PW_FILE})"
                                );
                            }
                            Err(e) => {
                                tracing::warn!("easytier: dashboard credential bootstrap failed: {e}")
                            }
                        }
                    }
                    Err(e) => tracing::warn!("easytier: password hash task failed: {e}"),
                }
            }
        }

        // 2) local node instance manager
        let manager = Arc::new(easytier::instance::factory::native_cli_instance_manager());
        let mut instance_ids: Vec<uuid::Uuid> = Vec::new();

        // 3) register the node with the embedded config server so the
        //    easytier-web dashboard can manage it (in-process)
        let wc_token = token.clone();
        let wc_mgr = manager.clone();
        let config_server_port = web.config_server_port;
        let node_name = if cfg.node_name.is_empty() { "remgr-node".to_string() } else { cfg.node_name.clone() };
        // stable machine id: persisted once, reused across restarts (the
        // platform state-dir lookup is unsupported on openbsd)
        let machine_id_path = std::path::Path::new(&db_dir).join("machine_id");
        let machine_id = match std::fs::read_to_string(&machine_id_path) {
            Ok(s) => s.trim().to_string(),
            Err(_) => {
                let id = uuid::Uuid::new_v4().to_string();
                let _ = std::fs::write(&machine_id_path, &id);
                id
            }
        };
        tokio::spawn(async move {
            match easytier::web_client::run_web_client(
                // The embedded config server identifies a node by the token in
                // the URL — and this easytier-web build resolves that token as
                // *the user name* (`get_user_id_by_token`), auto-creating an
                // account when unknown. Registering with the machine id made the
                // centre node a separate device that the `admin` dashboard never
                // listed; registering as `admin` binds it to that account so the
                // console's EasyTier dashboard can manage it.
                &format!("udp://127.0.0.1:{config_server_port}/admin"),
                easytier::common::MachineIdOptions {
                    explicit_machine_id: Some(machine_id),
                    state_dir: None,
                },
                Some(node_name),
                false,
                wc_mgr.clone(),
                None,
            )
            .await
            {
                Ok(_client) => {
                    tracing::info!("easytier web client registered with config server");
                    tokio::select! {
                        _ = wc_token.cancelled() => {}
                    }
                }
                Err(e) => tracing::error!("easytier web client failed: {e:#}"),
            }
        });

        // 4) default network instance (the "center" node identity)
        if cfg.node_enabled && !cfg.network_name.is_empty() {
            let toml = Self::build_instance_toml(&cfg)?;
            let loader = easytier::common::config::TomlConfigLoader::new_from_str(&toml)?;
            match manager.run_network_instance(loader, easytier::common::config::ConfigFileControl::STATIC_CONFIG) {
                Ok(id) => {
                    tracing::info!("easytier node instance started: {id}");
                    instance_ids.push(id);
                }
                Err(e) => tracing::error!("easytier node instance failed: {e:#}"),
            }
        }

        // NOTE: `web` must live in the handle — dropping it aborts the
        // config-server and REST api tasks (AbortOnDropHandle semantics), which
        // is what frees udp:22020 / tcp:11211 for the next start.
        *run = Some(RunHandle { token, _manager: manager, _web: web });
        let _ = instance_ids;
        Ok(())
    }

    async fn stop(&self) -> anyhow::Result<()> {
        // Take the handle out under the lock, then release it before waiting:
        // dropping `web` aborts the easytier-web tasks, and the abort is
        // asynchronous, so the sockets need a moment to actually close before
        // a caller rebinds the same ports.
        let handle = self.run.lock().await.take();
        if let Some(handle) = handle {
            handle.token.cancel();
            drop(handle);
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
        Ok(())
    }

    async fn apply_config(&self) -> anyhow::Result<()> {
        super::restart_if_running(self).await
    }
}
