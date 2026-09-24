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

/// Node name used when the config leaves `node_name` empty: the dashboard needs
/// something non-empty to list the node and its instance under.
const DEFAULT_NODE_NAME: &str = "remgr-node";

/// Password a fresh install gets for the embedded dashboard's `admin` account,
/// matching the console's default. Changeable from the dashboard itself.
const DEFAULT_DASHBOARD_PASSWORD: &str = "admin";

pub struct EasyTierModule {
    state: std::sync::Weak<AppState>,
    run: tokio::sync::Mutex<Option<RunHandle>>,
}

struct RunHandle {
    /// cancels the web-client registration task
    token: CancellationToken,
    /// owns the node instances. The web-client task holds a second Arc to the
    /// manager, so dropping this handle does not stop them — `stop` does that
    /// explicitly, before the handle goes away.
    manager: Arc<easytier::instance::factory::NativeInstanceManager>,
    /// the "center" instance started from the config, if the config asked for
    /// one — `None` when node_enabled was off or the network name was empty.
    /// Reported by `status` so it matches what is actually running.
    node_instance: Option<uuid::Uuid>,
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

    /// Quote a value for a TOML basic string. A quote or a backslash in any of
    /// the configured fields would otherwise terminate the string (or start an
    /// escape) and make the whole document unparseable — the start then fails
    /// with a TOML error that does not name the offending field. Control
    /// characters are dropped: every one of these fields is a single-line
    /// identifier or secret.
    fn toml_string(value: &str) -> String {
        let mut out = String::with_capacity(value.len());
        for c in value.chars() {
            match c {
                '"' => out.push_str("\\\""),
                '\\' => out.push_str("\\\\"),
                c if c.is_control() => {}
                c => out.push(c),
            }
        }
        out
    }

    fn build_instance_toml(cfg: &crate::config::EasyTierConfig) -> anyhow::Result<String> {
        let mut listeners = String::new();
        for l in &cfg.listeners {
            listeners.push_str(&format!("  \"{}\",\n", Self::toml_string(l)));
        }
        let node_name = if cfg.node_name.is_empty() { DEFAULT_NODE_NAME } else { cfg.node_name.as_str() };
        // `network_secret` goes in verbatim: an empty secret is a valid EasyTier
        // setting ("no secret"), and peers are admitted by the digest of
        // (network_name, network_secret) — synthesizing a value here silently
        // gave this node a secret that no stock easytier node in the same
        // network can match.
        // The EasyTier TOML key is `ipv4`, not `virtual_ipv4`: unknown keys are
        // dropped silently, so the node fell back to DHCP and — with no peer to
        // lease from — never created its TUN device at all.
        let ip_part = if cfg.virtual_ipv4.is_empty() {
            "dhcp = true".to_string()
        } else {
            format!("ipv4 = \"{}\"\ndhcp = false", Self::toml_string(&cfg.virtual_ipv4))
        };
        // Both names come from `node_name`: `hostname` is what the node reports
        // in lists, and `instance_name` is the label the easytier-web dashboard
        // shows for this instance (NetworkMeta) — without it the centre node
        // shows up as "default".
        Ok(format!(
            "listeners = [\n{listeners}]\n\
             instance_name = \"{host}\"\n\
             hostname = \"{host}\"\n\
             {ip_part}\n\
             [network_identity]\n\
             network_name = \"{name}\"\n\
             network_secret = \"{secret}\"\n\
             [flags]\n\
             default_protocol = \"tcp\"\n\
             latency_first = true\n",
            host = Self::toml_string(node_name),
            name = Self::toml_string(&cfg.network_name),
            secret = Self::toml_string(&cfg.network_secret),
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
        let run = self.run.lock().await;
        let running = run.is_some();
        // The center node is an EasyTier *instance*, and an instance only exists
        // once it has a network to join: `node_enabled` alone starts nothing.
        // It also only exists while this module holds the handle that started
        // it, so a stopped module reports the node as stopped too.
        let node_running = run
            .as_ref()
            .map(|h| h.node_instance.is_some())
            .unwrap_or(false);
        drop(run);
        serde_json::json!({
            "enabled": cfg.enabled,
            "running": running,
            "config_server_port": cfg.config_server_port,
            "api_addr": cfg.api_addr,
            "api_port": cfg.api_port,
            "node_enabled": cfg.node_enabled,
            "node_running": node_running,
            "node_note": if cfg.node_enabled && cfg.network_name.is_empty() {
                "已启用本地节点，但「网络名称」为空，节点实例不会启动"
            } else {
                ""
            },
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
            api_addr: cfg.api_addr.parse().with_context(|| {
                format!(
                    "easytier api_addr \"{}\" is not an IP address (the console proxies /et to it)",
                    cfg.api_addr
                )
            })?,
            api_port: cfg.api_port,
            geoip_db: None,
            heartbeat_min_response_ms: 0,
            feature_flags: Arc::new(easytier_web::FeatureFlags {
                disable_registration: false,
                allow_auto_create_user: true,
            }),
        };
        const WEB_START_ATTEMPTS: u32 = 24;
        let mut web = None;
        let mut last_err: Option<anyhow::Error> = None;
        for attempt in 0..WEB_START_ATTEMPTS {
            match easytier_web::start::start_web(web_cfg.clone()).await {
                Ok(w) => {
                    web = Some(w);
                    break;
                }
                Err(e) => {
                    last_err = Some(e);
                    if attempt + 1 < WEB_START_ATTEMPTS {
                        tokio::time::sleep(Duration::from_millis(250)).await;
                    }
                }
            }
        }
        let web = match web {
            Some(w) => w,
            None => {
                // The console reports `to_string()` of the error, which stops at
                // the outermost context — so the cause (which socket, which
                // errno) has to be part of the message itself, otherwise a port
                // conflict reads as a bare "start failed".
                let cause = match last_err {
                    Some(e) => format!("{e:#}"),
                    None => "no attempt was made".to_string(),
                };
                anyhow::bail!(
                    "easytier-web did not start after {WEB_START_ATTEMPTS} attempts \
                     (config server udp:{}, api {}:{}, db={}): {cause}",
                    cfg.config_server_port,
                    cfg.api_addr,
                    cfg.api_port,
                    cfg.db_path
                );
            }
        };

        // 2) local node instance manager
        let manager = Arc::new(easytier::instance::factory::native_cli_instance_manager());

        // The static node config is built before anything is spawned: it is the
        // only step left that can fail, and a failure must not leave the
        // web-client task (and with it a registration against the config
        // server) behind, orphaned and retrying forever.
        let node_loader = if cfg.node_enabled && !cfg.network_name.is_empty() {
            let toml = Self::build_instance_toml(&cfg)?;
            Some(easytier::common::config::TomlConfigLoader::new_from_str(&toml)?)
        } else {
            None
        };

        // Cancels the registration task when the module stops.
        let token = CancellationToken::new();

        // Dashboard credential bootstrap.
        //
        // The easytier-web migration seeds an `admin` user with a fixed hash
        // whose plaintext is not published, so the embedded dashboard has no
        // usable login until the password is replaced.
        //
        // The dashboard hashes what the operator types with MD5 before sending it
        // (`frontend/src/modules/api.ts`: `Md5.hashStr(data.password)`), and the
        // backend then stores/verifies the argon2 hash *of that digest* — so a
        // credential is only usable when it is installed the same way. Hashing the
        // plaintext here (which this used to do) produces an account nobody can
        // log into.
        //
        // The file records whether a credential has been handed out, and its value
        // is checked against the stored hash on every start: if it no longer
        // authenticates — the database was recreated, or an older build installed
        // the wrong hash — a fresh one is generated instead of leaving the
        // dashboard permanently unreachable.
        {
            let db = web.db.clone();
            const PW_FILE: &str = "/var/run/remgr/easytier_dashboard_password";

            // md5 hex of the password, exactly what the dashboard frontend sends
            fn dashboard_credential(password: &str) -> String {
                use md5::{Digest, Md5};
                let mut h = Md5::new();
                h.update(password.as_bytes());
                format!("{:x}", h.finalize())
            }

            let existing = std::fs::read_to_string(PW_FILE)
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty());

            let mut usable = false;
            if let Some(pw) = existing.clone() {
                if let Ok(Some(hash)) = db.get_user_password_hash("admin").await {
                    let digest = dashboard_credential(&pw);
                    usable = tokio::task::spawn_blocking(move || {
                        password_auth::verify_password(&digest, &hash).is_ok()
                    })
                    .await
                    .unwrap_or(false);
                    if !usable {
                        tracing::warn!(
                            "easytier: the stored dashboard password no longer matches the \
                             database — generating a new one"
                        );
                    }
                }
            }

            if !usable {
                // Same default as the console, so the two logins on this box are
                // the same value until the operator changes them.
                let password: String = DEFAULT_DASHBOARD_PASSWORD.to_string();
                let digest = dashboard_credential(&password);
                match tokio::task::spawn_blocking({
                    let d = digest.clone();
                    move || password_auth::generate_hash(&d)
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
                                    "easytier dashboard password: {password}  \
                                     (user admin, also in {PW_FILE}; API clients must send \
                                     md5(password) — the dashboard does this itself)"
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

            // The migration also seeds a demo account whose password is literally
            // "user", i.e. a working default credential on every fresh install.
            // Rotate it as well, but only while it still carries that default —
            // an operator who set something else keeps their choice.
            const DEMO_FILE: &str = "/var/run/remgr/easytier_dashboard_password_user";
            let demo_default = {
                let digest = dashboard_credential("user");
                match db.get_user_password_hash("user").await {
                    Ok(Some(hash)) => tokio::task::spawn_blocking(move || {
                        password_auth::verify_password(&digest, &hash).is_ok()
                    })
                    .await
                    .unwrap_or(false),
                    _ => false,
                }
            };
            if demo_default {
                let password: String = {
                    use rand::Rng;
                    const ALPH: &[u8] = b"abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ23456789";
                    let mut rng = rand::thread_rng();
                    (0..14)
                        .map(|_| ALPH[rng.gen_range(0..ALPH.len())] as char)
                        .collect()
                };
                let digest = dashboard_credential(&password);
                match tokio::task::spawn_blocking(move || password_auth::generate_hash(&digest)).await
                {
                    Ok(hash) => match db.set_user_password("user", hash).await {
                        Ok(_) => {
                            let _ = std::fs::write(DEMO_FILE, format!("{password}\n"));
                            #[cfg(unix)]
                            {
                                use std::os::unix::fs::PermissionsExt;
                                let _ = std::fs::set_permissions(
                                    DEMO_FILE,
                                    std::fs::Permissions::from_mode(0o600),
                                );
                            }
                            tracing::warn!(
                                "easytier: the seeded demo account \"user\" had the default \
                                 password — replaced with a random one (user: {password}, also in \
                                 {DEMO_FILE}); use the admin account for the dashboard"
                            );
                        }
                        Err(e) => tracing::warn!("easytier: could not rotate the demo account: {e}"),
                    },
                    Err(e) => tracing::warn!("easytier: demo password hash task failed: {e}"),
                }
            }
        }

        // 3) register the node with the embedded config server so the
        //    easytier-web dashboard can manage it (in-process)
        let wc_token = token.clone();
        let wc_mgr = manager.clone();
        let config_server_port = web.config_server_port;
        let node_name = if cfg.node_name.is_empty() { DEFAULT_NODE_NAME.to_string() } else { cfg.node_name.clone() };
        // stable machine id: persisted once, reused across restarts (the
        // platform state-dir lookup is unsupported on openbsd)
        let machine_id_path = std::path::Path::new(&db_dir).join("machine_id");
        // The file is read back as-is, and a value the library cannot parse is
        // *hashed* into a machine id — an empty or truncated file would then
        // give this install the same id as any other install with the same
        // garbage, so only a well-formed one is reused.
        let stored = std::fs::read_to_string(&machine_id_path)
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| uuid::Uuid::parse_str(s).is_ok());
        let machine_id = match stored {
            Some(id) => id,
            None => {
                let id = uuid::Uuid::new_v4().to_string();
                if let Err(e) = std::fs::write(&machine_id_path, &id) {
                    tracing::warn!(
                        "easytier: cannot persist the machine id in {} ({e}) — the config \
                         server will list a new device after the next process restart",
                        machine_id_path.display()
                    );
                }
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

        // 4) default network instance (the "center" node identity). The config
        //    was parsed above; `run_network_instance` only queues the instance,
        //    so a listener that cannot bind is reported by the instance itself
        //    (and shows up in the dashboard's node events).
        let mut node_instance = None;
        if let Some(loader) = node_loader {
            match manager.run_network_instance(loader, easytier::common::config::ConfigFileControl::STATIC_CONFIG) {
                Ok(id) => {
                    tracing::info!("easytier node instance started: {id}");
                    node_instance = Some(id);
                }
                Err(e) => tracing::error!("easytier node instance failed: {e:#}"),
            }
        }

        // NOTE: `web` must live in the handle — dropping it aborts the
        // config-server and REST api tasks (AbortOnDropHandle semantics), which
        // is what frees udp:22020 / tcp:11211 for the next start.
        *run = Some(RunHandle { token, manager, node_instance, _web: web });
        Ok(())
    }

    async fn stop(&self) -> anyhow::Result<()> {
        // Take the handle out under the lock, then release it before waiting:
        // dropping `web` aborts the easytier-web tasks, and the abort is
        // asynchronous, so the sockets need a moment to actually close before
        // a caller rebinds the same ports.
        let handle = self.run.lock().await.take();
        if let Some(handle) = handle {
            // Stop the node instances explicitly instead of relying on the
            // handle's drop: the web-client task holds a second Arc to the
            // manager, so the manager (and with it the instances: TUN device,
            // listener sockets, routes) is only released once that task is
            // scheduled and drops its clone — well after `stop` returned. A
            // restart would then race the old instance for the same ports.
            let instance_ids = handle.manager.instance_ids();
            if !instance_ids.is_empty() {
                if let Err(e) = handle.manager.delete_network_instances(instance_ids).await {
                    tracing::warn!("easytier: stopping the node instance failed: {e:#}");
                }
            }
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
