//! ReMgr — all-in-one relay manager for OpenBSD.
//!
//! One static binary, one process: EasyTier center (easytier-web embedded),
//! STUN/TURN, RustDesk relay, frps — all supervised as in-process task trees,
//! managed through a web console, sandboxed with pledge/unveil.

mod certs;

mod config;
mod console;
mod logging;
mod modules;
mod secure;
mod state;

use anyhow::Result;
use std::sync::Arc;
#[cfg(not(unix))]
use std::time::Duration;

use state::AppState;

fn main() {
    let mut config_path = config::default_config_path();
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--config" | "-c" => {
                if let Some(p) = args.next() {
                    config_path = std::path::PathBuf::from(p);
                }
            }
            "--version" | "-V" => {
                println!("remgr {}", env!("CARGO_PKG_VERSION"));
                return;
            }
            "--help" | "-h" => {
                println!("remgr {} — all-in-one relay manager", env!("CARGO_PKG_VERSION"));
                println!("usage: remgr [--config /etc/remgr/config.toml]");
                return;
            }
            other => {
                eprintln!("unknown argument: {other}");
                std::process::exit(2);
            }
        }
    }

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    if let Err(e) = runtime.block_on(run(config_path)) {
        eprintln!("remgr: fatal: {e:#}");
        std::process::exit(1);
    }
}

async fn run(config_path: std::path::PathBuf) -> Result<()> {
    // logging first (needs no filesystem)
    let hub = logging::LogHub::new();
    logging::init(hub.clone());
    tracing::info!("remgr {} starting", env!("CARGO_PKG_VERSION"));

    // rustls crypto provider (process-wide, ring)
    let _ = rustls::crypto::ring::default_provider().install_default();

    // config
    let mut cfg = config::Config::load(&config_path)?;
    cfg.config_path = config_path.clone();

    // runtime dirs must exist before pledge/unveil
    secure::prepare_dirs(&config_path)?;

    // vendored components (rustdesk key/db files) use relative paths — pin the
    // working directory to the data dir so everything lands under the unveiled
    // /var/lib/remgr
    #[cfg(target_os = "openbsd")]
    {
        std::env::set_current_dir("/var/lib/remgr")
            .map_err(|e| anyhow::anyhow!("chdir /var/lib/remgr: {e}"))?;
    }

    // bootstrap console password
    let mut initial_password: Option<String> = None;
    if cfg.console.password_hash.is_empty() {
        use rand::RngCore;
        let mut buf = [0u8; 8];
        rand::thread_rng().fill_bytes(&mut buf);
        let pw: String = buf.iter().map(|b| format!("{b:02x}")).collect();
        use argon2::password_hash::PasswordHasher;
        let salt = argon2::password_hash::SaltString::generate(&mut rand::rngs::OsRng);
        let hash = argon2::Argon2::default()
            .hash_password(pw.as_bytes(), &salt)
            .map_err(|e| anyhow::anyhow!("hash password: {e}"))?
            .to_string();
        cfg.console.password_hash = hash;
        initial_password = Some(pw);
        cfg.save()?;
        let _ = std::fs::create_dir_all("/var/run/remgr");
        let _ = std::fs::write(
            "/var/run/remgr/initial_password",
            format!("{}\n", initial_password.as_deref().unwrap_or("")),
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(
                "/var/run/remgr/initial_password",
                std::fs::Permissions::from_mode(0o600),
            );
        }
    }

    // Platform resources that need unrestricted syscalls must be acquired
    // before the sandbox locks down. On OpenBSD this opens the routing
    // socket, which pledge(2) would otherwise refuse to create.
    easytier::common::ifcfg::init_platform();

    // pledge/unveil: everything above needed the filesystem we are about to lock.
    secure::apply()?;
    let state = AppState::new(cfg);
    if let Some(pw) = &initial_password {
        tracing::warn!("initial console password: {pw}  (also written to /var/run/remgr/initial_password)");
        println!("initial console password: {pw}");
    }

    // auto-start enabled modules
    {
        let snapshot = state.config_blocking();
        let order: [(&str, bool); 4] = [
            ("easytier", snapshot.easytier.enabled),
            ("stun_turn", snapshot.stun_turn.enabled),
            ("rustdesk", snapshot.rustdesk.enabled),
            ("frps", snapshot.frps.enabled),
        ];
        for (name, enabled) in order {
            if !enabled {
                continue;
            }
            if let Some(module) = state.module(name) {
                if let Err(e) = module.start().await {
                    tracing::error!("module {name} failed to start: {e:#}");
                }
            }
        }
    }

    // graceful shutdown on SIGTERM/SIGINT (rc.d sends SIGTERM)
    let stop_state = state.clone();
    tokio::spawn(async move {
        wait_for_shutdown_signal().await;
        tracing::info!("shutdown signal received, stopping modules");
        let snapshot = stop_state.config_blocking();
        let _ = snapshot;
        for name in ["frps", "rustdesk", "stun_turn", "easytier"] {
            if let Some(module) = stop_state.module(name) {
                module.stop().await.ok();
            }
        }
        std::process::exit(0);
    });

    // Serves until the process exits. Console settings (port, TLS, certificate
    // paths, session lifetime) are applied by rebinding the listener through
    // POST /api/console/apply, which never leaves the console unreachable.
    console::serve_console(state.clone()).await?;
    Ok(())
}

async fn wait_for_shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = signal(SignalKind::terminate()).expect("SIGTERM handler");
        let mut int = signal(SignalKind::interrupt()).expect("SIGINT handler");
        tokio::select! {
            _ = term.recv() => {}
            _ = int.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        tokio::time::sleep(Duration::from_secs(3600 * 24 * 365)).await;
    }
}

// silence unused import when building without openbsd
#[allow(unused)]
fn _keep(_: Arc<AppState>) {}
