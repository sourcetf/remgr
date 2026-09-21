//! EasyTier center module — the vendored EasyTier-OpenBSD workspace linked
//! in-process:
//!
//! - `easytier-web`: sqlite db + config server (instances register, udp) +
//!   REST api (dashboard / programmatic management) — via its `start` module
//! - one local center node: `NativeInstanceManager` + `run_web_client`
//!   (registers with the embedded config server) + an optional static
//!   "default network" instance with the listeners from the config

use std::sync::Arc;

use anyhow::Context;
use async_trait::async_trait;
use tokio_util::sync::CancellationToken;

use crate::state::AppState;

pub struct EasyTierModule {
    state: std::sync::Weak<AppState>,
    run: tokio::sync::Mutex<Option<RunHandle>>,
}

struct RunHandle {
    token: CancellationToken,
    /// strong ref: dropping the manager stops its background drivers
    _manager: Arc<easytier::instance::factory::NativeInstanceManager>,
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
        let ip_part = if cfg.virtual_ipv4.is_empty() {
            "dhcp = true".to_string()
        } else {
            format!("virtual_ipv4 = \"{}\"\ndhcp = false", cfg.virtual_ipv4)
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
             enable_latency_first = true\n",
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

        // 1) embedded easytier-web: db + config server + REST api
        let web = easytier_web::start::start_web(easytier_web::start::WebConfig {
            // auto-create the dashboard user for the local machine's token
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
        })
        .await
        .with_context(|| format!("easytier-web start (db={})", cfg.db_path))?;

        let token = CancellationToken::new();
        let web_token = web.token.clone();

        // 2) local node instance manager
        let manager = Arc::new(easytier::instance::factory::native_cli_instance_manager());
        let mut instance_ids: Vec<uuid::Uuid> = Vec::new();

        // 3) register the node with the embedded config server so the
        //    easytier-web dashboard can manage it (in-process)
        let wc_token = token.clone();
        let wc_mgr = manager.clone();
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
                &format!("udp://127.0.0.1:{}/{}", web.config_server_port, machine_id),
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
        if !cfg.network_name.is_empty() {
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

        *run = Some(RunHandle { token, _manager: manager });
        let _ = instance_ids;
        Ok(())
    }

    async fn stop(&self) -> anyhow::Result<()> {
        if let Some(handle) = self.run.lock().await.take() {
            handle.token.cancel();
            // _manager drop + web token cancel tear the stack down
        }
        Ok(())
    }

    async fn apply_config(&self) -> anyhow::Result<()> {
        super::restart_if_running(self).await
    }
}
