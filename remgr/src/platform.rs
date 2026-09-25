//! Platform-specific filesystem layout and host facts.
//!
//! ReMgr was written for OpenBSD and kept a BSD/FHS layout. That layout is kept
//! unchanged on every unix (OpenBSD, Linux, macOS) so existing deployments,
//! documentation and the rc.d/login.conf files stay valid. Windows has neither
//! `/etc` nor `/var`, so everything lives under one root there
//! (`%ProgramData%\ReMgr`), mirroring the same subdirectory names — a path in
//! the docs translates one-to-one.
//!
//! `REMGR_HOME` overrides the root on any platform. That is what makes a
//! relocatable or per-user install possible (and what lets CI and the tests run
//! without touching a system directory).
//!
//! Deliberately NOT here: the sandbox (`secure.rs`, OpenBSD only) and the
//! service-manager files (`scripts/rc.d`, `scripts/login.conf.d`) — those are
//! platform-specific by nature and do not belong in a path helper.

use std::path::PathBuf;

/// Root everything lives under, honouring `REMGR_HOME`.
fn home() -> Option<PathBuf> {
    std::env::var_os("REMGR_HOME")
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
}

/// A child of `REMGR_HOME`, or `None` when the override is not set.
///
/// Under the override the same subdirectory names are used on every platform —
/// a relocated tree should look identical whether it sits on OpenBSD or Windows,
/// which is what makes the layout predictable in tests and in CI.
fn under_home(sub: &str) -> Option<PathBuf> {
    home().map(|h| h.join(sub))
}

/// The system-wide root for platforms without `/etc` and `/var`.
fn system_root() -> PathBuf {
    if cfg!(windows) {
        program_data().join("ReMgr")
    } else {
        PathBuf::from("/etc/remgr")
    }
}

/// Where the configuration lives.
pub fn config_dir() -> PathBuf {
    home().unwrap_or_else(system_root)
}

/// Service data: databases, generated keys, per-service state.
pub fn data_dir() -> PathBuf {
    under_home("lib").unwrap_or_else(|| {
        if cfg!(windows) {
            system_root().join("lib")
        } else {
            PathBuf::from("/var/lib/remgr")
        }
    })
}

/// Runtime state: files another process may need to read (bootstrap passwords,
/// the EasyTier node's private key). Cleared on reboot on unix; under the data
/// root on Windows, where nothing clears it.
pub fn run_dir() -> PathBuf {
    under_home("run").unwrap_or_else(|| {
        if cfg!(windows) {
            system_root().join("run")
        } else {
            PathBuf::from("/var/run/remgr")
        }
    })
}

/// Log directory.
pub fn log_dir() -> PathBuf {
    under_home("log").unwrap_or_else(|| {
        if cfg!(windows) {
            system_root().join("log")
        } else {
            PathBuf::from("/var/log/remgr")
        }
    })
}

/// Certificates, beside the configuration on every platform.
pub fn cert_dir() -> PathBuf {
    under_home("ssl").unwrap_or_else(|| config_dir().join("ssl"))
}

/// `%ProgramData%`, falling back to a per-machine default when the variable is
/// missing (it is set on every supported Windows, but a service started with a
/// minimal environment has surprised people before).
fn program_data() -> PathBuf {
    if let Some(p) = std::env::var_os("ProgramData") {
        return PathBuf::from(p);
    }
    PathBuf::from(r"C:\ProgramData")
}

pub fn default_config_path() -> PathBuf {
    config_dir().join("config.toml")
}

/// The persisted log file. Lives in `log_dir` on unix; on Windows the same
/// directory is used (there is no syslog equivalent to fall back on).
pub fn log_file() -> PathBuf {
    log_dir().join("remgr.log")
}

/// The rotated generation kept beside it.
pub fn log_file_previous() -> PathBuf {
    log_dir().join("remgr.log.1")
}

/// Host name, for the certificate's subject and for `node_name` hints.
///
/// `libc::gethostname` is the right call on unix (and on OpenBSD `HOSTNAME` is
/// not exported into the environment at all); Windows has no such symbol in a
/// portable form, so `COMPUTERNAME` is used there — it is what the machine is
/// called on the network, which is exactly what belongs in a certificate.
pub fn hostname() -> Option<String> {
    #[cfg(unix)]
    {
        let mut buf = [0u8; 256];
        // SAFETY: a valid, writable buffer of the given length.
        let rc = unsafe { libc::gethostname(buf.as_mut_ptr() as *mut libc::c_char, buf.len()) };
        if rc == 0 {
            let end = buf.iter().position(|b| *b == 0).unwrap_or(buf.len());
            if let Ok(h) = std::str::from_utf8(&buf[..end]) {
                let h = h.trim().trim_end_matches('.').to_string();
                if !h.is_empty() {
                    return Some(h);
                }
            }
        }
        None
    }
    #[cfg(not(unix))]
    {
        std::env::var("COMPUTERNAME")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    }
}

/// Directories the process needs to exist before it does anything else, in
/// creation order. The caller creates them; keeping the list here means the
/// Windows layout cannot drift away from the unix one.
pub fn required_dirs() -> Vec<PathBuf> {
    vec![config_dir(), cert_dir(), data_dir(), log_dir(), run_dir()]
}

/// A human-readable description of the layout, used by `--help` and the startup
/// log so an operator can see where files will land without guessing.
pub fn layout_summary() -> String {
    format!(
        "config={} certs={} data={} logs={} runtime={}",
        config_dir().display(),
        cert_dir().display(),
        data_dir().display(),
        log_dir().display(),
        run_dir().display()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One test, not several: they would all mutate `REMGR_HOME`, and cargo runs
    /// tests in parallel threads of one process — two tests setting the same
    /// environment variable race and fail intermittently.
    #[test]
    fn the_layout_is_consistent_and_home_moves_all_of_it() {
        // Without the override the paths are the platform's own.
        std::env::remove_var("REMGR_HOME");
        let unix = !cfg!(windows);
        if unix {
            assert_eq!(config_dir(), PathBuf::from("/etc/remgr"));
            assert_eq!(cert_dir(), PathBuf::from("/etc/remgr/ssl"));
            assert_eq!(default_config_path(), PathBuf::from("/etc/remgr/config.toml"));
            assert_eq!(log_file(), PathBuf::from("/var/log/remgr/remgr.log"));
        } else {
            assert!(config_dir().ends_with("ReMgr"));
            assert!(cert_dir().ends_with("ssl"));
        }

        // The override exists so a whole instance can be relocated (CI, tests, a
        // per-user install); every path must follow it, or a "relocated" instance
        // would still write to /etc and /var.
        let root = std::env::temp_dir().join("remgr-layout-test");
        std::env::set_var("REMGR_HOME", &root);
        let paths = [
            config_dir(),
            data_dir(),
            run_dir(),
            log_dir(),
            cert_dir(),
            default_config_path(),
            log_file(),
            log_file_previous(),
        ];
        let dirs = required_dirs();
        std::env::remove_var("REMGR_HOME");

        for p in paths.iter().chain(dirs.iter()) {
            assert!(p.starts_with(&root), "{p:?} escaped REMGR_HOME ({root:?})");
        }
        assert!(default_config_path().ends_with("config.toml"));
        assert!(log_file().ends_with("remgr.log"));
        assert!(log_file_previous().ends_with("remgr.log.1"));

        // distinct directories, or one would shadow another
        let mut sorted = dirs.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), dirs.len(), "duplicate directory in {dirs:?}");
        assert!(dirs.contains(&cert_dir()), "cert dir is not prepared");
        assert!(!default_config_path().starts_with(cert_dir()));
    }
}