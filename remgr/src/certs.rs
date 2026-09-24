//! Certificate generation and storage for services (self-signed, P-384).
//!
//! Files: <dir>/<service>_cert.pem + <service>_key.pem (key chmod 0600).

use anyhow::{bail, Context, Result};
use rcgen::{KeyPair, PKCS_ECDSA_P384_SHA384};
use std::path::{Path, PathBuf};

/// Longest certificate lifetime this module will mint. `time::OffsetDateTime +
/// Duration` panics ("resulting value is out of range") once the expiry leaves
/// the representable date range, so the caller-supplied `days` must be clamped
/// before it reaches that arithmetic — `days: 4000000000` used to abort the
/// request task.
pub const MAX_CERT_DAYS: u32 = 3650;

pub fn cert_paths(dir: &Path, service: &str) -> (PathBuf, PathBuf) {
    (
        dir.join(format!("{service}_cert.pem")),
        dir.join(format!("{service}_key.pem")),
    )
}

/// Service names become part of a file name, so nothing that could name another
/// directory (`/`, `.`) is accepted.
pub fn valid_service_name(service: &str) -> bool {
    !service.is_empty() && service.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

pub fn generate_service_cert(dir: &Path, service: &str, domain: &str, days: u32) -> Result<(PathBuf, PathBuf)> {
    generate_service_cert_names(dir, service, &[domain.to_string(), "localhost".to_string()], domain, days)
}

/// Same, with an explicit SAN list. `common_name` is only a label; browsers match
/// on the SANs, so the console certificate carries the host name and every
/// address the box can be reached at.
pub fn generate_service_cert_names(
    dir: &Path,
    service: &str,
    names: &[String],
    common_name: &str,
    days: u32,
) -> Result<(PathBuf, PathBuf)> {
    if !valid_service_name(service) {
        bail!("invalid service name");
    }
    if names.is_empty() {
        bail!("at least one name is required");
    }
    let days = days.clamp(1, MAX_CERT_DAYS);
    let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384)?;

    let mut params = rcgen::CertificateParams::new(names.to_vec())?;
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, common_name);
    params.distinguished_name.push(rcgen::DnType::OrganizationName, "ReMgr");
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::new(3600, 0);
    params.not_after = now + time::Duration::new(days as i64 * 86400, 0);

    let cert = params.self_signed(&key_pair)?;
    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();
    write_service_cert(dir, service, &cert_pem, &key_pem)
}

pub fn write_service_cert(dir: &Path, service: &str, cert_pem: &str, key_pem: &str) -> Result<(PathBuf, PathBuf)> {
    if !valid_service_name(service) {
        bail!("invalid service name");
    }
    if !cert_pem.contains("BEGIN CERTIFICATE") || !cert_pem.contains("END CERTIFICATE") {
        bail!("cert_pem does not look like a PEM certificate");
    }
    if !key_pem.contains("PRIVATE KEY") || !key_pem.contains("END") {
        bail!("key_pem does not look like a PEM private key");
    }
    std::fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    let (cert_path, key_path) = cert_paths(dir, service);
    // Stage both files fully, then move them into place. Writing the live names
    // directly leaves a truncated certificate (or a new cert beside the old key)
    // behind when a write fails — a full disk, mostly — and the service would
    // then be pointed at that unusable pair.
    let cert_tmp = dir.join(format!("{service}_cert.pem.new"));
    let key_tmp = dir.join(format!("{service}_key.pem.new"));
    write_mode(&cert_tmp, cert_pem.as_bytes(), 0o644)
        .with_context(|| format!("write {}", cert_tmp.display()))?;
    write_mode(&key_tmp, key_pem.as_bytes(), 0o600)
        .with_context(|| format!("write {}", key_tmp.display()))?;
    std::fs::rename(&cert_tmp, &cert_path).context("install cert")?;
    std::fs::rename(&key_tmp, &key_path).context("install key")?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // a pre-existing destination keeps its own mode across rename
        let _ = std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600));
        let _ = std::fs::set_permissions(&cert_path, std::fs::Permissions::from_mode(0o644));
    }
    Ok((cert_path, key_path))
}

/// Write `data` to `path` with the file created at `mode` (unix): the private
/// key must not exist world-readable even for the instant between the write and
/// a later chmod.
fn write_mode(path: &Path, data: &[u8], mode: u32) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(mode)
            .open(path)?;
        f.write_all(data)?;
        f.flush()
    }
    #[cfg(not(unix))]
    {
        let _ = mode;
        std::fs::write(path, data)
    }
}

pub fn cert_exists(dir: &Path, service: &str) -> bool {
    let (cert_path, _) = cert_paths(dir, service);
    matches!(std::fs::metadata(&cert_path), Ok(m) if m.len() > 0)
}
