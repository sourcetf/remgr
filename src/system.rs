// System module for OpenBSD pledge/unveil support.
//
// pledge(2) restricts syscall classes; unveil(2) restricts the filesystem view.
// Both are in libc on OpenBSD. The correct order is:
//   1. create every directory we will ever need (before unveil seals the tree),
//   2. bind/listen on all sockets (needs the "wpath"/"inet" promises, which we
//      still hold at this point),
//   3. unveil() each path prefix we want reachable,
//   4. pledge() last — nothing can be widened afterwards.
//
// We deliberately do NOT use umakedir(2): it is not exported by modern OpenBSD
// libc and pulling in -lutil just to avoid std::fs is not worth it. Directory
// creation happens before the lockdown with the ordinary filesystem API.

#[cfg(target_os = "openbsd")]
mod openbsd {
    use std::ffi::CString;
    use std::os::raw::c_char;

    extern "C" {
        fn pledge(promises: *const c_char, execpromises: *const c_char) -> i32;
        fn unveil(path: *const c_char, permissions: *const c_char) -> i32;
    }

    /// The promise string ReMgr pledges. `wpath`/`cpath` are dropped only after
    /// all state files are opened, so we keep them for the process lifetime to
    /// allow runtime cert rotation and state writes; `inet` covers all eight
    /// relay/control listeners. `dns` lets engine peer resolution work.
    /// We do not request `exec` — everything runs in-process, no subprocesses.
    const PROMISES: &str = "stdio rpath wpath cpath fattr inet dns proc sendfd";

    /// Paths to unveil and the permissions to grant under each.
    const UNVEILS: &[(&str, &str)] = &[
        ("/etc/remgr", "rwc"),      // config + tls certs/keys
        ("/var/lib/remgr", "rwc"),  // persistent state (dbs, keys)
        ("/var/db/remgr", "rwc"),   // easytier + rustdesk sqlite dbs
        ("/var/log/remgr", "rw"),   // logs
        ("/var/run/remgr", "rw"),   // pid/sock runtime files
        ("/tmp", "rw"),             // transient relay allocations
        ("/usr/local", "rx"),       // root certs for tls verification
        ("/etc/ssl", "r"),          // CA bundle
        ("/etc/resolv.conf", "r"),  // resolver
    ];

    /// Directories that must exist before the filesystem view is sealed.
    const MKDIRS: &[&str] = &[
        "/etc/remgr",
        "/etc/remgr/ssl",
        "/var/lib/remgr",
        "/var/db/remgr",
        "/var/db/remgr/easytier",
        "/var/db/remgr/rustdesk",
        "/var/log/remgr",
        "/var/log/remgr/easytier",
        "/var/run/remgr",
    ];

    pub fn create_dirs() -> anyhow::Result<()> {
        for path in MKDIRS {
            std::fs::create_dir_all(path)?;
        }
        Ok(())
    }

    /// Apply unveil for every declared path, then seal the tree.
    pub fn apply_unveil() -> anyhow::Result<()> {
        for (path, perms) in UNVEILS {
            let c_path = CString::new(*path)?;
            let c_perms = CString::new(*perms)?;
            let rc = unsafe { unveil(c_path.as_ptr(), c_perms.as_ptr()) };
            if rc != 0 {
                log::warn!(
                    "unveil({} \"{}\") failed: {}",
                    path,
                    perms,
                    std::io::Error::last_os_error()
                );
            }
        }
        // NULL/NULL seals the set: no further subtree can be unveiled.
        let rc = unsafe { unveil(std::ptr::null(), std::ptr::null()) };
        if rc != 0 {
            anyhow::bail!("unveil finalize: {}", std::io::Error::last_os_error());
        }
        Ok(())
    }

    /// Drop privileges via pledge. Call this last, after all file handles are
    /// open and all sockets are bound.
    pub fn apply_pledge() -> anyhow::Result<()> {
        let promises = CString::new(PROMISES)?;
        let rc = unsafe { pledge(promises.as_ptr(), std::ptr::null()) };
        if rc != 0 {
            anyhow::bail!(
                "pledge(\"{}\") failed: {}",
                PROMISES,
                std::io::Error::last_os_error()
            );
        }
        log::info!("pledge applied: {}", PROMISES);
        Ok(())
    }
}

#[cfg(target_os = "openbsd")]
pub fn init_system_security() -> anyhow::Result<()> {
    openbsd::create_dirs()
}

#[cfg(target_os = "openbsd")]
pub fn apply_pledge_unveil() -> anyhow::Result<()> {
    openbsd::apply_unveil()?;
    openbsd::apply_pledge()
}

#[cfg(not(target_os = "openbsd"))]
pub fn apply_pledge_unveil() -> anyhow::Result<()> {
    // No-op on non-OpenBSD platforms
    log::debug!("pledge/unveil not available on this platform");
    Ok(())
}

#[cfg(not(target_os = "openbsd"))]
pub fn init_system_security() -> anyhow::Result<()> {
    // No-op on non-OpenBSD platforms
    log::debug!("System security initialization not needed on this platform");
    Ok(())
}