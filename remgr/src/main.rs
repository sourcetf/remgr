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
mod platform;
mod secure;
mod state;

use anyhow::Result;
use std::path::{Path, PathBuf};
use std::sync::Arc;
#[cfg(not(unix))]
use std::time::Duration;

use state::AppState;

/// Password a fresh install gets for the console. Changeable from the console's
/// 系统 page afterwards; only used while no hash is configured.
const DEFAULT_CONSOLE_PASSWORD: &str = "admin";

/// Names the console certificate should cover: the host name plus the addresses
/// this machine answers on (loopback and the interface the default route uses).
fn console_cert_names() -> Vec<String> {
    fn add(names: &mut Vec<String>, n: String) {
        if !n.is_empty() && !names.contains(&n) {
            names.push(n);
        }
    }

    let mut names: Vec<String> = Vec::new();

    // the machine's name, from the platform (gethostname(3) on unix,
    // COMPUTERNAME on Windows). A default "localhost" says nothing about how the
    // box is actually reached, so it is not worth a SAN entry.
    if let Some(h) = platform::hostname() {
        if h != "localhost" {
            add(&mut names, h);
        }
    }
    add(&mut names, "localhost".to_string());
    add(&mut names, "127.0.0.1".to_string());
    add(&mut names, "::1".to_string());

    // the address a default route would use — the usual way this box is reached
    if let Ok(sock) = std::net::UdpSocket::bind("0.0.0.0:0") {
        for target in ["8.8.8.8:80", "1.1.1.1:80"] {
            if sock.connect(target).is_ok() {
                if let Ok(addr) = sock.local_addr() {
                    add(&mut names, addr.ip().to_string());
                    break;
                }
            }
        }
    }
    names
}

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
                println!("usage: remgr [--config <path>]");
                println!();
                // The layout is platform-dependent, so it cannot be written out
                // as a literal in the help text — print what this build uses.
                println!("paths on this platform ({}):", std::env::consts::OS);
                println!("  config  {}", platform::default_config_path().display());
                println!("  certs   {}", platform::cert_dir().display());
                println!("  data    {}", platform::data_dir().display());
                println!("  logs    {}", platform::log_file().display());
                println!("  runtime {}", platform::run_dir().display());
                println!();
                println!("environment: REMGR_HOME relocates all of the above under one directory");
                return;
            }
            other => {
                eprintln!("unknown argument: {other}");
                std::process::exit(2);
            }
        }
    }

    // run() pins the working directory to /var/lib/remgr, after which a relative
    // --config would be re-resolved against the new cwd: the file would be read
    // from one place and every later save written to another.
    if config_path.is_relative() {
        if let Ok(cwd) = std::env::current_dir() {
            config_path = cwd.join(config_path);
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
    // Log where this instance keeps its files: the layout differs per platform,
    // and an operator reading the log should not have to guess (or read the
    // source) to find the config, the certificates or the log file itself.
    tracing::info!("paths: {}", platform::layout_summary());

    // rustls crypto provider (process-wide, ring)
    let _ = rustls::crypto::ring::default_provider().install_default();

    // config
    let mut cfg = config::Config::load(&config_path)?;
    cfg.config_path = config_path.clone();

    // runtime dirs must exist before pledge/unveil
    secure::prepare_dirs(&config_path)?;

    // vendored components (rustdesk key/db files) use relative paths — pin the
    // working directory to the data dir so everything lands under the unveiled
    // data directory. Only on OpenBSD: that is where the sandbox makes a relative
    // path land somewhere unveiled, and where the vendored components were
    // written with that assumption. Elsewhere the working directory is left alone
    // (a Windows service and a Linux foreground run both expect to keep theirs).
    #[cfg(target_os = "openbsd")]
    {
        let data = platform::data_dir();
        std::env::set_current_dir(&data)
            .map_err(|e| anyhow::anyhow!("chdir {}: {e}", data.display()))?;
    }

    // bootstrap console password
    //
    // A fresh install gets the well-known default below, so the console can be
    // logged into without first reading a file off the box. This only ever runs
    // while the hash is empty: a password the operator set (系统 page, or
    // `password_hash` in the config) is never overwritten.
    let mut initial_password: Option<String> = None;
    if cfg.console.password_hash.is_empty() {
        let pw = DEFAULT_CONSOLE_PASSWORD.to_string();
        // One hashing implementation for the whole process: `console::hash_password`
        // owns the Argon2id parameters.
        cfg.console.password_hash = console::hash_password(&pw)?;
        initial_password = Some(pw.clone());
        cfg.save()?;
        let pw_file = platform::run_dir().join("initial_password");
        let _ = std::fs::create_dir_all(platform::run_dir());
        let _ = std::fs::write(&pw_file, format!("{pw}\n"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&pw_file, std::fs::Permissions::from_mode(0o600));
        }
        tracing::warn!(
            "console: installed the default login {user} / \"{DEFAULT_CONSOLE_PASSWORD}\" — change it on the \
             系统 page if this console is reachable from the network (also written to {})",
            pw_file.display(),
            user = cfg.console.username,
        );
    }

    // console TLS bootstrap: a fresh install must not serve the admin console
    // over plain HTTP. A P-384 self-signed certificate is minted on first start
    // (the file's absence is the "first start" marker — once it exists, an
    // operator who turns TLS off is taken at their word), pointing at the host
    // name and the addresses this box answers on, and TLS is switched on.
    if !cfg.console.tls && !Path::new(&cfg.console.tls_cert).exists() {
        let names = console_cert_names();
        let cn = names.first().cloned().unwrap_or_else(|| "remgr.local".into());
        // write beside the configured certificate; fall back to the platform's
        // certificate directory when the configured path has no parent at all
        let dir = Path::new(&cfg.console.tls_cert)
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(platform::cert_dir);
        match certs::generate_service_cert_names(&dir, "console", &names, &cn, 825) {
            Ok((cert_path, key_path)) => {
                cfg.console.tls = true;
                cfg.console.tls_cert = cert_path.display().to_string();
                cfg.console.tls_key = key_path.display().to_string();
                cfg.save()?;
                tracing::info!(
                    "console: generated a P-384 self-signed certificate (SANs: {}) at {} — \
                     the browser will warn until a real certificate is installed, which the \
                     系统/系统设置 page can upload",
                    names.join(", "),
                    cert_path.display()
                );
            }
            Err(e) => tracing::error!(
                "console: could not generate a TLS certificate ({e:#}); serving plain HTTP — \
                 upload a certificate from the console and enable TLS there"
            ),
        }
    }

    // Platform resources that need unrestricted syscalls must be acquired
    // before the sandbox locks down. On OpenBSD this opens the routing
    // socket, which pledge(2) would otherwise refuse to create.
    easytier::common::ifcfg::init_platform();

    // pledge/unveil: everything above needed the filesystem we are about to lock.
    secure::apply()?;
    let state = AppState::new(cfg, hub.clone());
    if let Some(pw) = &initial_password {
        tracing::warn!("initial console password: {pw}  (also written to /var/run/remgr/initial_password)");
        println!("initial console password: {pw}");
    }

    // auto-start enabled modules
    {
        let snapshot = state.config_blocking();
        let order: [(&str, bool); 5] = [
            ("easytier", snapshot.easytier.enabled),
            ("stun_turn", snapshot.stun_turn.enabled),
            ("rustdesk", snapshot.rustdesk.enabled),
            ("frps", snapshot.frps.enabled),
            ("frpc", snapshot.frpc.enabled),
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
        for name in ["frpc", "frps", "rustdesk", "stun_turn", "easytier"] {
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

async fn wait_for_shutdown_signal() {    #[cfg(unix)]
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
