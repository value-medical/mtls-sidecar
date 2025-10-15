use std::sync::Arc;

use anyhow::{Context, Result};
use rustls::pki_types::PrivateKeyDer;
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use tokio::fs;

pub struct TlsManager {
    pub config: Arc<ServerConfig>,
}

impl TlsManager {
    pub async fn new(cert_dir: &str, ca_dir: &str) -> Result<Self> {
        let cert_path = format!("{}/tls.crt", cert_dir);
        let key_path = format!("{}/tls.key", cert_dir);
        let ca_path = format!("{}/ca-bundle.pem", ca_dir);

        // Read certificate
        let cert_pem = fs::read(cert_path)
            .await
            .context("Failed to read server certificate")?;
        let certs = rustls_pemfile::certs(&mut cert_pem.as_slice())
            .collect::<Result<Vec<_>, _>>()
            .context("Failed to parse server certificate")?;

        // Read private key
        let key_pem = fs::read(key_path)
            .await
            .context("Failed to read private key")?;
        let key_der = rustls_pemfile::pkcs8_private_keys(&mut key_pem.as_slice())
            .next()
            .ok_or_else(|| anyhow::anyhow!("No private key found"))??;
        let key = PrivateKeyDer::Pkcs8(key_der);

        // Read CA bundle
        let ca_pem = fs::read(ca_path)
            .await
            .context("Failed to read CA bundle")?;
        let ca_certs = rustls_pemfile::certs(&mut ca_pem.as_slice())
            .collect::<Result<Vec<_>, _>>()
            .context("Failed to parse CA bundle")?;

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
            config: Arc::new(config),
        })
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
        rustls::crypto::CryptoProvider::install_default(rustls::crypto::ring::default_provider()).unwrap();

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
        let result = TlsManager::new(cert_dir.to_str().unwrap(), ca_dir.to_str().unwrap()).await;
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
        let result = TlsManager::new(cert_dir.to_str().unwrap(), ca_dir.to_str().unwrap()).await;
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
}
