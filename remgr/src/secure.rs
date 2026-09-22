//! OpenBSD sandbox: unveil(2) + pledge(2).
//!
//! All paths are unveiled up front, the visibility set is locked, then the
//! process pledges a fixed promise set. No `exec` promise: the binary can
//! never spawn subprocesses, by construction.
//!
//! `route` / `wroute` cover the interface and route ioctls the EasyTier node
//! needs (`SIOCGIFADDR`, `SIOCAIFADDR`, `SIOCDIFADDR`, `SIOCSIFMTU`). Route
//! table updates go through a routing socket that `main` opens before this
//! runs, since pledge(2) refuses to create `AF_ROUTE` sockets.

use anyhow::{Context, Result};

pub const PROMISES: &str = "stdio rpath wpath cpath fattr flock inet unix dns getpw route wroute";

/// (path, permissions) pairs unveiled before pledging.
#[cfg(target_os = "openbsd")]
fn unveil_paths() -> Vec<(String, &'static str)> {
    // /var/lib/remgr must come first: the working directory (and the sqlite
    // files under it) are created relative to it after the unveil set locks
    let mut v = vec![
        ("/var/lib/remgr".to_string(), "rwc"),
        ("/etc/remgr".to_string(), "rwc"),
        ("/var/db/remgr".to_string(), "rwc"),
        ("/var/log/remgr".to_string(), "rwc"),
        ("/var/run/remgr".to_string(), "rwc"),
        ("/etc/ssl".to_string(), "r"),
        ("/etc/resolv.conf".to_string(), "r"),
        ("/etc/hosts".to_string(), "r"),
        ("/etc/services".to_string(), "r"),
    ];
    // TUN devices for the EasyTier node + entropy
    for i in 0..8 {
        v.push((format!("/dev/tun{i}"), "rw"));
    }
    v.push(("/dev/urandom".to_string(), "r"));
    v
}

#[cfg(target_os = "openbsd")]
pub fn apply() -> Result<()> {
    use std::ffi::CString;

    // unveil(2) narrows the namespace from the moment it is called, not when
    // the set is locked. Probing for a path first (exists()) therefore fails
    // for everything after the first entry, so the calls must be
    // unconditional; a missing path simply reports ENOENT and is skipped.
    for (path, perms) in unveil_paths() {
        let c = CString::new(path.as_str())?;
        let p = CString::new(perms)?;
        let rc = unsafe { libc::unveil(c.as_ptr(), p.as_ptr()) };
        if rc != 0 {
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() != Some(libc::ENOENT) {
                tracing::warn!("unveil({path}, {perms}) failed: {e}");
            }
        }
    }
    // lock the visibility set
    unsafe {
        libc::unveil(std::ptr::null(), std::ptr::null());
    }

    let promises = CString::new(PROMISES)?;
    let rc = unsafe { libc::pledge(promises.as_ptr(), std::ptr::null()) };
    if rc != 0 {
        let e = std::io::Error::last_os_error();
        anyhow::bail!("pledge(\"{PROMISES}\") failed: {e}");
    }
    tracing::info!("openbsd sandbox active: pledge \"{PROMISES}\" + unveil locked");
    Ok(())
}

#[cfg(not(target_os = "openbsd"))]
pub fn apply() -> Result<()> {
    tracing::debug!("pledge/unveil not available on this platform");
    Ok(())
}

/// Create runtime directories (before unveil/pledge).
pub fn prepare_dirs(config_path: &std::path::Path) -> Result<()> {
    let dirs = [
        "/etc/remgr",
        "/var/lib/remgr",
        "/var/db/remgr",
        "/var/log/remgr",
        "/var/run/remgr",
    ];
    for d in dirs {
        let _ = std::fs::create_dir_all(d);
    }
    if let Some(parent) = config_path.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("create dir {}", parent.display()))?;
    }
    Ok(())
}
