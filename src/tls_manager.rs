use std::path::PathBuf;
use std::sync::Arc;

use crate::config::Config;
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use log::error;
use rustls::server::WebPkiClientVerifier;
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use rustls_pki_types::{pem::PemObject, PrivateKeyDer};
use tokio::fs;
use tokio::sync::RwLock;
use x509_parser::{parse_x509_certificate};

pub struct TlsManager {
    pub server_config: RwLock<Option<Arc<ServerConfig>>>,
    pub server_required: bool,
    pub client_config: RwLock<Option<Arc<ClientConfig>>>,
    pub client_required: bool,
    pub earliest_expiry: RwLock<Option<DateTime<Utc>>>,
}

impl TlsManager {
    pub fn new() -> Self {
        TlsManager {
            server_config: RwLock::new(None),
            server_required: false,
            client_config: RwLock::new(None),
            client_required: false,
            earliest_expiry: RwLock::new(None),
        }
    }

    pub async fn set_server_config(&self, server_config: Option<Arc<ServerConfig>>) {
        *self.server_config.write().await = server_config;
    }

    pub async fn set_client_config(&self, client_config: Option<Arc<ClientConfig>>) {
        *self.client_config.write().await = client_config;
    }

    pub async fn reload(&self, config: &Config) -> Result<()> {
        // Load CA certs, server cert/key, client cert/key
        let ca_certs = Self::load_ca_certs(
            &config.ca_dir,
            &config.server_cert_dir,
            &config.client_cert_dir,
        )
        .await?;
        let server_cert_key_opt = if let Some(server_cert_dir) = &config.server_cert_dir {
            Self::load_server_cert_and_key(server_cert_dir).await?
        } else {
            None
        };
        let client_cert_key_opt = if let Some(client_cert_dir) = &config.client_cert_dir {
            Self::load_client_cert_and_key(client_cert_dir).await?
        } else {
            None
        };

        // Compute and update earliest expiry
        let mut earliest_expiry: DateTime<Utc> = Utc::now(); // TODO: now + 1 minute?
        Self::update_earliest_expiry(&mut earliest_expiry, &ca_certs);
        if let Some((certs, _)) = &server_cert_key_opt {
            Self::update_earliest_expiry(&mut earliest_expiry, &certs);
        }
        if let Some((certs, _)) = &client_cert_key_opt {
            Self::update_earliest_expiry(&mut earliest_expiry, &certs);
        }
        *self.earliest_expiry.write().await = Some(earliest_expiry);

        // Update server config
        let mut server_config: Option<Arc<ServerConfig>> = None;
        if let Some((certs, key)) = server_cert_key_opt {
            server_config = Some(Arc::new(Self::build_server_config(
                certs.clone(),
                key,
                ca_certs.clone(),
            )?));
        }
        *self.server_config.write().await = server_config;

        // Update client config
        let mut client_config: Option<Arc<ClientConfig>> = None;
        if let Some((certs, key)) = client_cert_key_opt {
            client_config = Some(Arc::new(Self::build_client_config(
                certs.clone(),
                key,
                ca_certs.clone(),
            )?));
        }
        *self.client_config.write().await = client_config;

        Ok(())
    }

    async fn load_ca_certs(
        ca_dir_opt: &Option<PathBuf>,
        server_cert_dir_opt: &Option<PathBuf>,
        client_cert_dir_opt: &Option<PathBuf>,
    ) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>> {
        let mut ca_certs = Vec::new();

        if let Some(ca_dir) = ca_dir_opt {
            // From ca_dir
            if let Ok(ca_pem) = fs::read(ca_dir.join("ca-bundle.crt")).await {
                ca_certs.extend(
                    rustls_pemfile::certs(&mut ca_pem.as_slice())
                        .collect::<Result<Vec<_>, _>>()
                        .context("Failed to parse CA bundle from ca-bundle.crt")?,
                );
            } else if let Ok(ca_pem) = fs::read(ca_dir.join("ca.crt")).await {
                ca_certs.extend(
                    rustls_pemfile::certs(&mut ca_pem.as_slice())
                        .collect::<Result<Vec<_>, _>>()
                        .context("Failed to parse CA bundle from ca.crt")?,
                );
            } else {
                error!("No CA bundle found in ca_dir: {}", ca_dir.to_string_lossy());
            }
        }

        if let Some(server_cert_dir) = server_cert_dir_opt {
            // From server_cert_dir
            if let Ok(ca_pem) = fs::read(server_cert_dir.join("ca.crt")).await {
                ca_certs.extend(
                    rustls_pemfile::certs(&mut ca_pem.as_slice())
                        .collect::<Result<Vec<_>, _>>()
                        .context("Failed to parse CA bundle from server_cert_dir/ca.crt")?,
                );
            } else if let Ok(ca_pem) = fs::read(server_cert_dir.join("issuing_ca")).await {
                ca_certs.extend(
                    rustls_pemfile::certs(&mut ca_pem.as_slice())
                        .collect::<Result<Vec<_>, _>>()
                        .context("Failed to parse CA bundle from issuing_ca")?,
                );
            }
        }

        if let Some(client_cert_dir) = client_cert_dir_opt {
            // From client_cert_dir
            if let Ok(ca_pem) = fs::read(client_cert_dir.join("ca.crt")).await {
                ca_certs.extend(
                    rustls_pemfile::certs(&mut ca_pem.as_slice())
                        .collect::<Result<Vec<_>, _>>()
                        .context("Failed to parse CA bundle from client_cert_dir/ca.crt")?,
                );
            } else if let Ok(ca_pem) = fs::read(client_cert_dir.join("issuing_ca")).await {
                ca_certs.extend(
                    rustls_pemfile::certs(&mut ca_pem.as_slice())
                        .collect::<Result<Vec<_>, _>>()
                        .context("Failed to parse CA bundle from client_cert_dir/issuing_ca")?,
                );
            }
        }

        Ok(ca_certs)
    }

    async fn load_server_cert_and_key(
        cert_dir: &PathBuf,
    ) -> Result<
        Option<(
            Vec<rustls::pki_types::CertificateDer<'static>>,
            PrivateKeyDer<'static>,
        )>,
    > {
        // Auto-detect cert and key files
        let (cert_path, key_path) = Self::find_cert_key(&cert_dir, "tls.crt", "tls.key")
            .or_else(|| Self::find_cert_key(&cert_dir, "certificate", "private_key"))
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "No valid cert/key pair found in {}",
                    cert_dir.to_string_lossy()
                )
            })?;

        // Log the paths being used
        tracing::info!("Using certificate: {}", cert_path.to_string_lossy());
        tracing::info!("Using private key: {}", key_path.to_string_lossy());

        // Read certificate
        let cert_pem = fs::read(&cert_path).await.context(format!(
            "Failed to read server certificate from {}",
            cert_path.to_string_lossy()
        ))?;
        let certs = rustls_pemfile::certs(&mut cert_pem.as_slice())
            .collect::<Result<Vec<_>, _>>()
            .context("Failed to parse server certificate")?;

        // Read private key
        let key_pem = fs::read(&key_path).await.context(format!(
            "Failed to read private key from {}",
            key_path.to_string_lossy()
        ))?;
        let key = PrivateKeyDer::from_pem_slice(key_pem.as_slice())
            .context("Failed to parse private key from PEM")?;

        Ok(Some((certs, key)))
    }

    async fn load_client_cert_and_key(
        cert_dir: &PathBuf,
    ) -> Result<
        Option<(
            Vec<rustls::pki_types::CertificateDer<'static>>,
            PrivateKeyDer<'static>,
        )>,
    > {
        // Auto-detect cert and key files
        let (cert_path, key_path) = Self::find_cert_key(&cert_dir, "tls.crt", "tls.key")
            .or_else(|| Self::find_cert_key(&cert_dir, "certificate", "private_key"))
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "No valid cert/key pair found in {}",
                    cert_dir.to_string_lossy()
                )
            })?;

        // Log the paths being used
        tracing::info!("Using client certificate: {}", cert_path.to_string_lossy());
        tracing::info!("Using client private key: {}", key_path.to_string_lossy());

        // Read certificate
        let cert_pem = fs::read(&cert_path).await.context(format!(
            "Failed to read client certificate from {}",
            cert_path.to_string_lossy()
        ))?;
        let certs = rustls_pemfile::certs(&mut cert_pem.as_slice())
            .collect::<Result<Vec<_>, _>>()
            .context("Failed to parse client certificate")?;

        // Read private key
        let key_pem = fs::read(&key_path).await.context(format!(
            "Failed to read client private key from {}",
            key_path.to_string_lossy()
        ))?;
        let key = PrivateKeyDer::from_pem_slice(key_pem.as_slice())
            .context("Failed to parse client private key from PEM")?;

        Ok(Some((certs, key)))
    }

    fn find_cert_key(dir: &PathBuf, cert_name: &str, key_name: &str) -> Option<(PathBuf, PathBuf)> {
        let cert_path = dir.join(cert_name);
        let key_path = dir.join(key_name);
        if !cert_path.try_exists().unwrap_or(false) || !key_path.try_exists().unwrap() {
            return None;
        }
        Some((cert_path, key_path))
    }

    fn update_earliest_expiry(
        earliest: &mut DateTime<Utc>,
        certs: &[rustls::pki_types::CertificateDer<'static>],
    ) {
        for cert_der in certs {
            match parse_x509_certificate(cert_der) {
                Ok((_, cert)) => {
                    let validity = cert.validity();
                    let not_after_dt = validity.not_after.to_datetime();
                    let expiry = chrono::DateTime::from_timestamp(not_after_dt.unix_timestamp(), 0)
                        .unwrap_or_else(|| Utc::now()); // fallback if conversion fails
                    *earliest = (*earliest).min(expiry);
                }
                Err(e) => {
                    tracing::warn!("Failed to parse certificate for expiry check: {:?}", e);
                }
            }
        }
    }

    fn build_server_config(
        certs: Vec<rustls::pki_types::CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
        ca_certs: Vec<rustls::pki_types::CertificateDer<'static>>,
    ) -> Result<ServerConfig> {
        if ca_certs.is_empty() {
            return Err(anyhow::anyhow!("No CA certificates found"));
        }

        // Build root cert store
        let mut roots = RootCertStore::empty();
        for cert in ca_certs {
            roots
                .add(cert)
                .map_err(|e| anyhow::anyhow!("Failed to add CA cert: {}", e))?;
        }

        // Create client verifier that requires client certs
        let client_verifier = WebPkiClientVerifier::builder(Arc::new(roots))
            .build()
            .context("Failed to build client verifier")?;

        // Build server config
        let config = ServerConfig::builder()
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(certs, key)
            .map_err(|e| anyhow::anyhow!("Failed to build server config: {}", e))?;

        Ok(config)
    }

    fn build_client_config(
        certs: Vec<rustls::pki_types::CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
        ca_certs: Vec<rustls::pki_types::CertificateDer<'static>>,
    ) -> Result<ClientConfig> {
        // Build root cert store
        let mut roots = RootCertStore::empty();
        for cert in ca_certs {
            roots
                .add(cert)
                .map_err(|e| anyhow::anyhow!("Failed to add CA cert: {}", e))?;
        }

        // Build client config
        let config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_client_auth_cert(certs, key)
            .map_err(|e| anyhow::anyhow!("Failed to build client config: {}", e))?;

        Ok(config)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::DnValue::PrintableString;
    use rcgen::{
        BasicConstraints, Certificate, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa,
        Issuer, KeyPair, KeyUsagePurpose,
    };
    use std::fs;
    use std::path::PathBuf;
    use tempfile::TempDir;
    use time::{Duration, OffsetDateTime};

    fn new_config() -> Config {
        Config {
            tls_listen_port: Some(8443),
            upstream_url: "http://localhost:8080".to_string(),
            upstream_readiness_url: "http://localhost:8080/ready".to_string(),
            ca_dir: None,
            server_cert_dir: None,
            client_cert_dir: None,
            inject_client_headers: false,
            outbound_proxy_port: None,
            monitor_port: 8081,
            enable_metrics: false,
        }
    }

    fn new_ca<'a>() -> (Certificate, Issuer<'a, KeyPair>) {
        let mut params = CertificateParams::new(Vec::default())
            .expect("empty subject alt name can't produce error");
        let (yesterday, tomorrow) = validity_period();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(DnType::OrganizationName, "Testing");
        params.key_usages.push(KeyUsagePurpose::DigitalSignature);
        params.key_usages.push(KeyUsagePurpose::KeyCertSign);
        params.key_usages.push(KeyUsagePurpose::CrlSign);

        params.not_before = yesterday;
        params.not_after = tomorrow;

        let key_pair = KeyPair::generate().unwrap();
        let cert = params.self_signed(&key_pair).unwrap();
        let issuer = Issuer::new(params, key_pair);
        (cert, issuer)
    }

    fn config_ca(
        config: &mut Config,
        ca_dir: PathBuf,
    ) -> (&mut Config, Certificate, Issuer<'_, KeyPair>) {
        let (ca_cert, ca_key) = new_ca();
        let ca_cert_pem = ca_cert.pem();
        fs::create_dir(&ca_dir).unwrap();
        fs::write(ca_dir.join("ca-bundle.crt"), &ca_cert_pem).unwrap();
        config.ca_dir = Some(ca_dir);
        (config, ca_cert, ca_key)
    }

    fn new_end_entity(
        issuer: &Issuer<KeyPair>,
        purpose: ExtendedKeyUsagePurpose,
    ) -> (Certificate, KeyPair) {
        let name = "entity.other.host";
        let mut params =
            CertificateParams::new(vec![name.into()]).expect("we know the name is valid");
        let (yesterday, tomorrow) = validity_period();
        params.distinguished_name.push(DnType::CommonName, name);
        params.use_authority_key_identifier_extension = true;
        params.key_usages.push(KeyUsagePurpose::DigitalSignature);
        params.extended_key_usages.push(purpose);
        params.not_before = yesterday;
        params.not_after = tomorrow;

        let key_pair = KeyPair::generate().unwrap();
        let cert = params.signed_by(&key_pair, issuer).unwrap();
        (cert, key_pair)
    }

    fn config_server_cert<'a>(
        config: &'a mut Config,
        issuer: &Issuer<KeyPair>,
        cert_dir: PathBuf,
    ) -> &'a mut Config {
        let (cert, key) = new_end_entity(issuer, ExtendedKeyUsagePurpose::ServerAuth);
        let cert_pem = cert.pem();
        let key_pem = key.serialize_pem();
        fs::create_dir(&cert_dir).unwrap();
        fs::write(cert_dir.join("tls.crt"), &cert_pem).unwrap();
        fs::write(cert_dir.join("tls.key"), &key_pem).unwrap();
        config.server_cert_dir = Some(cert_dir);
        config
    }

    fn validity_period() -> (OffsetDateTime, OffsetDateTime) {
        let day = Duration::new(86400, 0);
        let yesterday = OffsetDateTime::now_utc().checked_sub(day).unwrap();
        let tomorrow = OffsetDateTime::now_utc().checked_add(day).unwrap();
        (yesterday, tomorrow)
    }

    #[tokio::test]
    async fn test_tls_manager_new_with_valid_certs() {
        let temp_dir = TempDir::new().unwrap();
        let mut config = new_config();

        let ca_dir = temp_dir.path().join("ca");
        let (mut config, _ca, issuer) = config_ca(&mut config, ca_dir.clone());

        let cert_dir = temp_dir.path().join("certs");
        let config = config_server_cert(&mut config, &issuer, cert_dir.clone());

        let tls_manager = TlsManager::new();
        let result = tls_manager.reload(&config).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_tls_manager_new_invalid_pem() {
        let temp_dir = TempDir::new().unwrap();
        let tls_manager = TlsManager::new();
        let mut config = new_config();

        // Write a valid CA and invalid server cert/key
        let ca_dir = temp_dir.path().join("ca");
        let (config, _, _) = config_ca(&mut config, ca_dir);
        let cert_dir = temp_dir.path().join("certs");
        fs::create_dir(&cert_dir).unwrap();
        fs::write(cert_dir.join("tls.crt"), b"invalid cert").unwrap();
        fs::write(cert_dir.join("tls.key"), b"invalid key").unwrap();
        config.server_cert_dir = Some(cert_dir);

        // Test TlsManager::reload should fail
        let result = tls_manager.reload(&config).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_tls_manager_reload() {
        let temp_dir = TempDir::new().unwrap();
        let ca_dir = temp_dir.path().join("ca");
        let cert_dir = temp_dir.path().join("certs");

        // Generate initial certs
        let (ca, issuer) = new_ca();
        let ca_cert_pem = ca.pem();
        fs::create_dir(&ca_dir).unwrap();
        fs::write(ca_dir.join("ca-bundle.crt"), &ca_cert_pem).unwrap();

        let (end_entity, end_entity_key) =
            new_end_entity(&issuer, ExtendedKeyUsagePurpose::ServerAuth);
        let end_entity_pem = end_entity.pem();
        let end_entity_key_pem = end_entity_key.serialize_pem();
        fs::create_dir(&cert_dir).unwrap();
        fs::write(cert_dir.join("tls.crt"), &end_entity_pem).unwrap();
        fs::write(cert_dir.join("tls.key"), &end_entity_key_pem).unwrap();

        let config = Config {
            tls_listen_port: Some(8443),
            upstream_url: "http://localhost:8080".to_string(),
            upstream_readiness_url: "http://localhost:8080/ready".to_string(),
            ca_dir: Some(ca_dir.clone()),
            server_cert_dir: Some(cert_dir.clone()),
            client_cert_dir: None,
            inject_client_headers: false,
            outbound_proxy_port: None,
            monitor_port: 8081,
            enable_metrics: false,
        };
        let tls_manager = TlsManager::new();
        tls_manager.reload(&config).await.unwrap();

        // Generate new certs
        let (new_ca, _) = new_ca();
        let (new_end_entity, new_end_entity_key) =
            new_end_entity(&issuer, ExtendedKeyUsagePurpose::ServerAuth);

        let new_end_entity_pem = new_end_entity.pem();
        let new_ca_cert_pem = new_ca.pem();
        let new_end_entity_key_pem = new_end_entity_key.serialize_pem();

        // Overwrite files
        fs::write(ca_dir.join("ca-bundle.crt"), &new_ca_cert_pem).unwrap();
        fs::write(cert_dir.join("tls.crt"), &new_end_entity_pem).unwrap();
        fs::write(cert_dir.join("tls.key"), &new_end_entity_key_pem).unwrap();

        // Reload
        tls_manager.reload(&config).await.unwrap();

        // Check that config was updated (we can't easily check the content, but at least it didn't panic)
        // In a real test, we might check some property, but for now, just ensure reload succeeds
    }
}
