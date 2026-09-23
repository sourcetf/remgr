//! Certificate generation and storage for services (self-signed, P-384).
//!
//! Files: <dir>/<service>_cert.pem + <service>_key.pem (key chmod 0600).

use anyhow::{bail, Context, Result};
use rcgen::{KeyPair, PKCS_ECDSA_P384_SHA384};
use std::path::{Path, PathBuf};

pub fn cert_paths(dir: &Path, service: &str) -> (PathBuf, PathBuf) {
    (
        dir.join(format!("{service}_cert.pem")),
        dir.join(format!("{service}_key.pem")),
    )
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
    if service.is_empty() || !service.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        bail!("invalid service name");
    }
    if names.is_empty() {
        bail!("at least one name is required");
    }
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
    if service.is_empty() || !service.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        bail!("invalid service name");
    }
    if !cert_pem.contains("BEGIN CERTIFICATE") {
        bail!("cert_pem does not look like a PEM certificate");
    }
    if !key_pem.contains("PRIVATE KEY") {
        bail!("key_pem does not look like a PEM private key");
    }
    std::fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    let (cert_path, key_path) = cert_paths(dir, service);
    std::fs::write(&cert_path, cert_pem.as_bytes()).context("write cert")?;
    std::fs::write(&key_path, key_pem.as_bytes()).context("write key")?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600));
        let _ = std::fs::set_permissions(&cert_path, std::fs::Permissions::from_mode(0o644));
    }
    Ok((cert_path, key_path))
}

pub fn cert_exists(dir: &Path, service: &str) -> bool {
    let (cert_path, _) = cert_paths(dir, service);
    matches!(std::fs::metadata(&cert_path), Ok(m) if m.len() > 0)
}
