//! ReMgr — all-in-one relay manager for OpenBSD.
//!
//! One static binary, one process: EasyTier center (easytier-web embedded),
//! STUN/TURN, RustDesk relay, frps — all supervised as in-process task trees,
//! managed through a web console, sandboxed with pledge/unveil.

mod acct;
mod certs;

mod config;
mod console;
mod logging;
mod modules;
mod platform;
mod secure;
mod signals;
mod state;

use anyhow::Result;
use std::path::{Path, PathBuf};
use std::sync::Arc;

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
                logging::say_err(&format!("unknown argument: {other}"));
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
        logging::say_err(&format!("remgr: fatal: {e:#}"));
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

    // Signals first, before anything that can take a while (config load, the
    // database, the modules): a SIGTERM that arrives during start-up is recorded
    // and obeyed from here on, instead of leaving the process running until
    // rc.subr gives up and escalates to SIGKILL. The second install below is the
    // one that decides, because start-up is also when the embedded servers
    // install handlers of their own.
    signals::install().map_err(|e| anyhow::anyhow!("installing the signal handler: {e}"))?;

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
        // say, not println!: as a service stdout is rc.subr's logger pipe, and
        // a logger that stopped reading must not panic the daemon (see logging).
        logging::say(&format!("initial console password: {pw}"));
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

    // Graceful shutdown on SIGTERM/SIGINT (rc.d sends SIGTERM), and a record of
    // who sent it — see `signals.rs`. Installed again here, after the modules
    // are up: the embedded servers register signal listeners of their own while
    // they start, and the last disposition installed is the one that runs.
    signals::install().map_err(|e| anyhow::anyhow!("installing the signal handler: {e}"))?;
    let stop_state = state.clone();
    tokio::spawn(async move {
        // SIGHUP is logged and ignored (nothing to reload); the first signal that
        // stops the process leaves the loop, a second one exits from the handler.
        loop {
            let signal: signals::Termination = signals::next().await;
            tracing::warn!("{}", signal.describe());
            if signal.stops() {
                break;
            }
        }
        // Who sent it, as far as this platform can say. On OpenBSD that is not
        // the siginfo (kill(2) reports no sender — see signals.rs), so the tail of
        // the kernel's accounting file is what names the commands that ran just
        // before. Logged before the modules stop, so a module hanging on its way
        // out cannot cost us the record.
        trace_recent_commands(12, "before the shutdown");
        for name in ["frpc", "frps", "rustdesk", "stun_turn", "easytier"] {
            if let Some(module) = stop_state.module(name) {
                module.stop().await.ok();
            }
        }
        // Read the accounting tail once more, a moment later: a sender that is
        // still running when it signals (a shell, a script) only gets its record
        // written when it exits. For a signal sent by `kill` in a session that
        // then closes, that is a fraction of a second — this wait is what puts
        // "the command that did it" in the log, and it costs the shutdown 1.2s of
        // its 120s rc.subr budget.
        tokio::time::sleep(std::time::Duration::from_millis(1200)).await;
        trace_recent_commands(6, "while the shutdown completed");
        tracing::info!("stopped; exiting");
        std::process::exit(0);
    });

    // Serves until the process exits. Console settings (port, TLS, certificate
    // paths, session lifetime) are applied by rebinding the listener through
    // POST /api/console/apply, which never leaves the console unreachable.
    console::serve_console(state.clone()).await?;
    Ok(())
}

/// Log the last commands the kernel recorded before a termination signal.
///
/// This is the daemon's answer to "who stopped me" on a platform whose signals do
/// not carry a sender (`acct.rs` has the details). It is best-effort by design: a
/// missing or unreadable accounting file is reported in one line and never stops
/// the shutdown — the signal itself is already recorded by then.
fn trace_recent_commands(wanted: usize, when: &str) {
    let path = Path::new(acct::ACCT_PATH);
    match acct::recent(path, wanted) {
        Ok(entries) if entries.is_empty() => tracing::warn!(
            "accounting: {} has no records yet — enable accounting (accounting=YES in              rc.conf.local, then accton(8)) to have the commands before a signal recorded",
            path.display()
        ),
        Ok(entries) => {
            tracing::warn!(
                "accounting ({when}): the last {} commands the kernel recorded:",
                entries.len()
            );
            for entry in entries {
                tracing::warn!("accounting: {}", entry.describe());
            }
        }
        Err(e) => tracing::warn!("accounting ({when}): cannot read {}: {e}", path.display()),
    }
}

// silence unused import when building without openbsd
#[allow(unused)]
fn _keep(_: Arc<AppState>) {}
