// SSL Certificate Module for ReMgr
// Generates self-signed certificates using P-384 elliptic curve.
// Pure Rust implementation (no Python) for production use.

use anyhow::Result;
use rcgen::{
    CertificateParams, DistinguishedName, DnType,
    KeyPair, PKCS_ECDSA_P384_SHA384, SanType,
};
use std::net::IpAddr;
use std::path::PathBuf;

/// Default SSL certificate directory on OpenBSD
pub const DEFAULT_CERT_DIR: &str = "/etc/remgr/ssl";
pub const DEFAULT_CERT_FILE: &str = "cert.pem";
pub const DEFAULT_KEY_FILE: &str = "key.pem";

/// Options for self-signed certificate generation
#[derive(Debug, Clone)]
pub struct CertOptions {
    pub common_name: String,
    pub dns_names: Vec<String>,
    pub ips: Vec<IpAddr>,
    pub organization: String,
    pub country: Option<String>,
    pub state: Option<String>,
    pub locality: Option<String>,
    pub validity_days: u32,
    pub output_dir: PathBuf,
}

impl Default for CertOptions {
    fn default() -> Self {
        Self {
            common_name: "remgr.local".to_string(),
            dns_names: vec!["localhost".to_string()],
            ips: vec![IpAddr::from([127, 0, 0, 1])],
            organization: "ReMgr".to_string(),
            country: Some("US".to_string()),
            state: None,
            locality: None,
            validity_days: 3650,
            output_dir: PathBuf::from(DEFAULT_CERT_DIR),
        }
    }
}

/// Result of certificate generation containing PEM-encoded cert and key
#[derive(Debug, Clone)]
pub struct GeneratedCert {
    pub cert_pem: String,
    pub key_pem: String,
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
}

/// Generate a self-signed certificate using P-384 ECDSA.
pub fn generate_self_signed_p384(opts: &CertOptions) -> Result<GeneratedCert> {
    // Build a P-384 key pair
    let key_pair = KeyPair::generate(&PKCS_ECDSA_P384_SHA384)?;

    // Collect SAN DNS names
    let mut params = CertificateParams::new(opts.dns_names.clone());

    params.distinguished_name = build_dn(opts);
    params.not_before = time::OffsetDateTime::now_utc();
    params.not_after = params.not_before + time::Duration::days(opts.validity_days as i64);

    // Add IP SANs
    for ip in &opts.ips {
        params.subject_alt_names.push(SanType::IpAddress(*ip));
    }

    // Self-sign the certificate
    let cert = rcgen::Certificate::from_params(params)?;

    let cert_pem = cert.serialize_pem()?;
    let key_pem = key_pair.serialize_pem();

    // Write to disk
    std::fs::create_dir_all(&opts.output_dir)?;

    let cert_path = opts.output_dir.join(DEFAULT_CERT_FILE);
    let key_path = opts.output_dir.join(DEFAULT_KEY_FILE);

    std::fs::write(&cert_path, cert_pem.as_bytes())?;
    std::fs::write(&key_path, key_pem.as_bytes())?;

    // Set proper permissions (0600 for key, 0644 for cert)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600));
        let _ = std::fs::set_permissions(&cert_path, std::fs::Permissions::from_mode(0o644));
    }

    log::info!(
        "Generated P-384 self-signed cert: {:?} / {:?}",
        cert_path,
        key_path
    );

    Ok(GeneratedCert {
        cert_pem,
        key_pem,
        cert_path,
        key_path,
    })
}

/// Build distinguished name from options
fn build_dn(opts: &CertOptions) -> DistinguishedName {
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, &opts.common_name);
    dn.push(DnType::OrganizationName, &opts.organization);
    if let Some(c) = &opts.country {
        dn.push(DnType::CountryName, c);
    }
    if let Some(s) = &opts.state {
        dn.push(DnType::StateOrProvinceName, s);
    }
    if let Some(l) = &opts.locality {
        dn.push(DnType::LocalityName, l);
    }
    dn
}

/// Generate certificates for all services (easytier, stun-turn, rustdesk, frps).
/// Each service gets its own cert in its own subdirectory.
pub fn generate_all_service_certs(
    base_dir: &PathBuf,
    domain: &str,
) -> Result<Vec<(String, GeneratedCert)>> {
    let mut results = Vec::new();
    for service in &["easytier", "stun_turn", "rustdesk", "frps"] {
        let out = base_dir.join(service);
        let opts = CertOptions {
            common_name: format!("{}.{}", service, domain),
            dns_names: vec![
                format!("{}.{}", service, domain),
                domain.to_string(),
                "localhost".to_string(),
            ],
            ips: vec![IpAddr::from([127, 0, 0, 1])],
            organization: "ReMgr".to_string(),
            country: Some("US".to_string()),
            state: None,
            locality: None,
            validity_days: 3650,
            output_dir: out,
        };
        let cert = generate_self_signed_p384(&opts)?;
        results.push((service.to_string(), cert));
    }
    Ok(results)
}

/// Check if a cert file exists and is non-empty
pub fn cert_exists(cert_path: &PathBuf) -> bool {
    match std::fs::metadata(cert_path) {
        Ok(m) => m.len() > 0,
        Err(_) => false,
    }
}