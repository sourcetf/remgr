// System module for OpenBSD pledge/unveil support
// Provides security sandboxing for OpenBSD

#[cfg(target_os = "openbsd")]
mod openbsd {
    use std::ffi::CString;
    use std::os::raw::c_char;

    // External pledge function from libutil
    extern "C" {
        pub fn pledge(promises: *const c_char, execprom: *const c_char) -> i32;
        pub fn unveil(path: *const c_char, permissions: *const c_char) -> i32;
        pub fn umakedir(path: *const c_char, mode: libc::mode_t) -> i32;
    }

    pub fn apply_pledge_unveil() -> anyhow::Result<()> {
        let promises = CString::new("stdio rpath wpath cpath inet")?;
        let result = unsafe { pledge(promises.as_ptr(), std::ptr::null()) };
        if result < 0 {
            anyhow::bail!("pledge failed");
        }

        // Unveil allowed paths
        let unveil_paths = [
            ("/etc/remgr", "rwc"),
            ("/var/lib/remgr", "rwc"),
            ("/var/log/remgr", "rwc"),
            ("/var/run/remgr", "rwc"),
            ("/root", "r"),
            ("/usr/local", "rx"),
        ];

        for (path, perms) in unveil_paths {
            let c_path = CString::new(path)?;
            let c_perms = CString::new(perms)?;
            let result = unsafe { unveil(c_path.as_ptr(), c_perms.as_ptr()) };
            if result < 0 {
                // Log but continue - not all paths may exist
                log::warn!("unveil failed for {}: {}", path, std::io::Error::last_os_error());
            }
        }

        // Reveal current directory
        let c_path = CString::new(".")?;
        unsafe { unveil(c_path.as_ptr(), std::ptr::null()) };

        Ok(())
    }

    pub fn create_secure_dirs() -> anyhow::Result<()> {
        let paths = [
            "/var/lib/remgr",
            "/var/log/remgr",
            "/var/run/remgr",
            "/etc/remgr",
        ];

        for path in paths {
            let c_path = CString::new(path)?;
            let result = unsafe {
                umakedir(c_path.as_ptr(), 0o755)
            };
            if result < 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::EEXIST) {
                log::warn!("Failed to create directory {}: {}", path, std::io::Error::last_os_error());
            }
        }

        Ok(())
    }
}

#[cfg(target_os = "openbsd")]
pub fn init_system_security() -> anyhow::Result<()> {
    openbsd::create_secure_dirs()?;
    Ok(())
}

#[cfg(target_os = "openbsd")]
pub fn apply_pledge_unveil() -> anyhow::Result<()> {
    openbsd::apply_pledge_unveil()
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