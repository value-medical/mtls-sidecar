use std::sync::Arc;

use anyhow::{Context, Result};
use rustls::pki_types::PrivateKeyDer;
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use tokio::fs;
use tokio::sync::RwLock;

use crate::config::Config;

pub struct TlsManager {
    pub config: Arc<RwLock<Arc<ServerConfig>>>,
}

impl TlsManager {
    pub async fn new(config: &Config) -> Result<Self> {
        let cert_dir = &config.cert_dir;
        let ca_dir = &config.ca_dir;

        // Auto-detect cert and key files
        let (cert_path, key_path) = if fs::try_exists(format!("{}/tls.crt", cert_dir))
            .await
            .unwrap_or(false)
            && fs::try_exists(format!("{}/tls.key", cert_dir))
                .await
                .unwrap_or(false)
        {
            (
                format!("{}/tls.crt", cert_dir),
                format!("{}/tls.key", cert_dir),
            )
        } else if fs::try_exists(format!("{}/certificate", cert_dir))
            .await
            .unwrap_or(false)
            && fs::try_exists(format!("{}/private_key", cert_dir))
                .await
                .unwrap_or(false)
        {
            (
                format!("{}/certificate", cert_dir),
                format!("{}/private_key", cert_dir),
            )
        } else {
            return Err(anyhow::anyhow!(
                "No valid cert/key pair found in {}",
                cert_dir
            ));
        };

        // Read certificate
        let cert_pem = fs::read(&cert_path).await.context(format!(
            "Failed to read server certificate from {}",
            cert_path
        ))?;
        let certs = rustls_pemfile::certs(&mut cert_pem.as_slice())
            .collect::<Result<Vec<_>, _>>()
            .context("Failed to parse server certificate")?;

        // Read private key
        let key_pem = fs::read(&key_path)
            .await
            .context(format!("Failed to read private key from {}", key_path))?;
        let key_der = rustls_pemfile::pkcs8_private_keys(&mut key_pem.as_slice())
            .next()
            .ok_or_else(|| anyhow::anyhow!("No private key found"))??;
        let key = PrivateKeyDer::Pkcs8(key_der);

        // Collect CA certificates
        let mut ca_certs = Vec::new();
        // From ca_dir
        if let Ok(ca_pem) = fs::read(format!("{}/ca-bundle.pem", ca_dir)).await {
            ca_certs.extend(
                rustls_pemfile::certs(&mut ca_pem.as_slice())
                    .collect::<Result<Vec<_>, _>>()
                    .context("Failed to parse CA bundle from ca-bundle.pem")?,
            );
        } else if let Ok(ca_pem) = fs::read(format!("{}/ca.crt", ca_dir)).await {
            ca_certs.extend(
                rustls_pemfile::certs(&mut ca_pem.as_slice())
                    .collect::<Result<Vec<_>, _>>()
                    .context("Failed to parse CA bundle from ca.crt")?,
            );
        }
        // From cert_dir
        if let Ok(ca_pem) = fs::read(format!("{}/ca.crt", cert_dir)).await {
            ca_certs.extend(
                rustls_pemfile::certs(&mut ca_pem.as_slice())
                    .collect::<Result<Vec<_>, _>>()
                    .context("Failed to parse CA bundle from cert_dir/ca.crt")?,
            );
        } else if let Ok(ca_pem) = fs::read(format!("{}/issuing_ca", cert_dir)).await {
            ca_certs.extend(
                rustls_pemfile::certs(&mut ca_pem.as_slice())
                    .collect::<Result<Vec<_>, _>>()
                    .context("Failed to parse CA bundle from issuing_ca")?,
            );
        }

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

        Ok(TlsManager {
            config: Arc::new(RwLock::new(Arc::new(config))),
        })
    }

    pub async fn reload(&self, cert_dir: &str, ca_dir: &str) -> Result<()> {
        // Auto-detect cert and key files
        let (cert_path, key_path) = if fs::try_exists(format!("{}/tls.crt", cert_dir))
            .await
            .unwrap_or(false)
            && fs::try_exists(format!("{}/tls.key", cert_dir))
                .await
                .unwrap_or(false)
        {
            (
                format!("{}/tls.crt", cert_dir),
                format!("{}/tls.key", cert_dir),
            )
        } else if fs::try_exists(format!("{}/certificate", cert_dir))
            .await
            .unwrap_or(false)
            && fs::try_exists(format!("{}/private_key", cert_dir))
                .await
                .unwrap_or(false)
        {
            (
                format!("{}/certificate", cert_dir),
                format!("{}/private_key", cert_dir),
            )
        } else {
            return Err(anyhow::anyhow!(
                "No valid cert/key pair found in {}",
                cert_dir
            ));
        };

        // Read certificate
        let cert_pem = fs::read(&cert_path).await.context(format!(
            "Failed to read server certificate from {}",
            cert_path
        ))?;
        let certs = rustls_pemfile::certs(&mut cert_pem.as_slice())
            .collect::<Result<Vec<_>, _>>()
            .context("Failed to parse server certificate")?;

        // Read private key
        let key_pem = fs::read(&key_path)
            .await
            .context(format!("Failed to read private key from {}", key_path))?;
        let key_der = rustls_pemfile::pkcs8_private_keys(&mut key_pem.as_slice())
            .next()
            .ok_or_else(|| anyhow::anyhow!("No private key found"))??;
        let key = PrivateKeyDer::Pkcs8(key_der);

        // Collect CA certificates
        let mut ca_certs = Vec::new();
        // From ca_dir
        if let Ok(ca_pem) = fs::read(format!("{}/ca-bundle.pem", ca_dir)).await {
            ca_certs.extend(
                rustls_pemfile::certs(&mut ca_pem.as_slice())
                    .collect::<Result<Vec<_>, _>>()
                    .context("Failed to parse CA bundle from ca-bundle.pem")?,
            );
        } else if let Ok(ca_pem) = fs::read(format!("{}/ca.crt", ca_dir)).await {
            ca_certs.extend(
                rustls_pemfile::certs(&mut ca_pem.as_slice())
                    .collect::<Result<Vec<_>, _>>()
                    .context("Failed to parse CA bundle from ca.crt")?,
            );
        }
        // From cert_dir
        if let Ok(ca_pem) = fs::read(format!("{}/ca.crt", cert_dir)).await {
            ca_certs.extend(
                rustls_pemfile::certs(&mut ca_pem.as_slice())
                    .collect::<Result<Vec<_>, _>>()
                    .context("Failed to parse CA bundle from cert_dir/ca.crt")?,
            );
        } else if let Ok(ca_pem) = fs::read(format!("{}/issuing_ca", cert_dir)).await {
            ca_certs.extend(
                rustls_pemfile::certs(&mut ca_pem.as_slice())
                    .collect::<Result<Vec<_>, _>>()
                    .context("Failed to parse CA bundle from issuing_ca")?,
            );
        }

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

        // Update the config atomically
        let new_arc = Arc::new(config);
        *self.config.write().await = new_arc;

        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::DnValue::PrintableString;
    use rcgen::{
        BasicConstraints, Certificate, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa,
        KeyPair, KeyUsagePurpose,
    };
    use std::fs;
    use tempfile::TempDir;
    use time::{Duration, OffsetDateTime};

    #[tokio::test]
    async fn test_tls_manager_new_with_valid_certs() {
        rustls::crypto::CryptoProvider::install_default(rustls::crypto::ring::default_provider())
            .unwrap();

        let temp_dir = TempDir::new().unwrap();
        let cert_dir = temp_dir.path().join("certs");
        let ca_dir = temp_dir.path().join("ca");
        fs::create_dir(&cert_dir).unwrap();
        fs::create_dir(&ca_dir).unwrap();

        // Generate CA and end-entity certs
        let (ca, _) = new_ca();
        let (end_entity, end_entity_key) = new_end_entity();

        let end_entity_pem = end_entity.pem();
        let ca_cert_pem = ca.pem();
        let end_entity_key_pem = end_entity_key.serialize_pem();

        // Write to files
        fs::write(cert_dir.join("tls.crt"), &end_entity_pem).unwrap();
        fs::write(cert_dir.join("tls.key"), &end_entity_key_pem).unwrap();
        fs::write(ca_dir.join("ca-bundle.pem"), &ca_cert_pem).unwrap();

        // Test TlsManager::new
        let config = Config {
            tls_listen_port: 8443,
            upstream_url: "http://localhost:8080".to_string(),
            upstream_readiness_url: "http://localhost:8080/ready".to_string(),
            cert_dir: cert_dir.to_str().unwrap().to_string(),
            ca_dir: ca_dir.to_str().unwrap().to_string(),
            inject_client_headers: false,
            monitor_port: 8081,
        };
        let result = TlsManager::new(&config).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_tls_manager_new_invalid_pem() {
        let temp_dir = TempDir::new().unwrap();
        let cert_dir = temp_dir.path().join("certs");
        let ca_dir = temp_dir.path().join("ca");
        fs::create_dir(&cert_dir).unwrap();
        fs::create_dir(&ca_dir).unwrap();

        // Write invalid PEM
        fs::write(cert_dir.join("tls.crt"), b"invalid cert").unwrap();
        fs::write(cert_dir.join("tls.key"), b"invalid key").unwrap();
        fs::write(ca_dir.join("ca-bundle.pem"), b"invalid ca").unwrap();

        // Test TlsManager::new should fail
        let config = Config {
            tls_listen_port: 8443,
            upstream_url: "http://localhost:8080".to_string(),
            upstream_readiness_url: "http://localhost:8080/ready".to_string(),
            cert_dir: cert_dir.to_str().unwrap().to_string(),
            ca_dir: ca_dir.to_str().unwrap().to_string(),
            inject_client_headers: false,
            monitor_port: 8081,
        };
        let result = TlsManager::new(&config).await;
        assert!(result.is_err());
    }

    fn new_ca() -> (Certificate, KeyPair) {
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
        (cert, key_pair)
    }

    fn new_end_entity() -> (Certificate, KeyPair) {
        let name = "entity.other.host";
        let mut params =
            CertificateParams::new(vec![name.into()]).expect("we know the name is valid");
        let (yesterday, tomorrow) = validity_period();
        params.distinguished_name.push(DnType::CommonName, name);
        params.use_authority_key_identifier_extension = true;
        params.key_usages.push(KeyUsagePurpose::DigitalSignature);
        params
            .extended_key_usages
            .push(ExtendedKeyUsagePurpose::ServerAuth);
        params.not_before = yesterday;
        params.not_after = tomorrow;

        let key_pair = KeyPair::generate().unwrap();
        let cert = params.self_signed(&key_pair).unwrap();
        (cert, key_pair)
    }

    fn validity_period() -> (OffsetDateTime, OffsetDateTime) {
        let day = Duration::new(86400, 0);
        let yesterday = OffsetDateTime::now_utc().checked_sub(day).unwrap();
        let tomorrow = OffsetDateTime::now_utc().checked_add(day).unwrap();
        (yesterday, tomorrow)
    }

    #[tokio::test]
    async fn test_tls_manager_reload() {
        let temp_dir = TempDir::new().unwrap();
        let cert_dir = temp_dir.path().join("certs");
        let ca_dir = temp_dir.path().join("ca");
        fs::create_dir(&cert_dir).unwrap();
        fs::create_dir(&ca_dir).unwrap();

        // Generate initial certs
        let (ca, _) = new_ca();
        let (end_entity, end_entity_key) = new_end_entity();

        let end_entity_pem = end_entity.pem();
        let ca_cert_pem = ca.pem();
        let end_entity_key_pem = end_entity_key.serialize_pem();

        // Write initial files
        fs::write(cert_dir.join("tls.crt"), &end_entity_pem).unwrap();
        fs::write(cert_dir.join("tls.key"), &end_entity_key_pem).unwrap();
        fs::write(ca_dir.join("ca-bundle.pem"), &ca_cert_pem).unwrap();

        let config = Config {
            tls_listen_port: 8443,
            upstream_url: "http://localhost:8080".to_string(),
            upstream_readiness_url: "http://localhost:8080/ready".to_string(),
            cert_dir: cert_dir.to_str().unwrap().to_string(),
            ca_dir: ca_dir.to_str().unwrap().to_string(),
            inject_client_headers: false,
            monitor_port: 8081,
        };
        let tls_manager = TlsManager::new(&config).await.unwrap();

        // Generate new certs
        let (new_ca, _) = new_ca();
        let (new_end_entity, new_end_entity_key) = new_end_entity();

        let new_end_entity_pem = new_end_entity.pem();
        let new_ca_cert_pem = new_ca.pem();
        let new_end_entity_key_pem = new_end_entity_key.serialize_pem();

        // Overwrite files
        fs::write(cert_dir.join("tls.crt"), &new_end_entity_pem).unwrap();
        fs::write(cert_dir.join("tls.key"), &new_end_entity_key_pem).unwrap();
        fs::write(ca_dir.join("ca-bundle.pem"), &new_ca_cert_pem).unwrap();

        // Reload
        tls_manager
            .reload(&config.cert_dir, &config.ca_dir)
            .await
            .unwrap();

        // Check that config was updated (we can't easily check the content, but at least it didn't panic)
        // In a real test, we might check some property, but for now, just ensure reload succeeds
    }
}
