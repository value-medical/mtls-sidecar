use anyhow::Result;
use bytes::Bytes;
use http_body_util::Full;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use rcgen::CertificateParams;
use rcgen::DnType;
use rcgen::KeyPair;
use reqwest::Certificate;
use std::sync::Arc;
use tempfile::TempDir;
use time::Duration;
use time::OffsetDateTime;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use mtls_sidecar::tls_manager::TlsManager;

#[tokio::test]
async fn test_proxy_with_valid_cert() -> Result<()> {
    rustls::crypto::CryptoProvider::install_default(rustls::crypto::ring::default_provider())
        .unwrap();

    // Generate CA, server cert, and client cert
    let (ca_cert, ca_key) = generate_ca();
    let (server_cert, server_key) = generate_server_cert(&ca_cert, &ca_key);
    let (client_cert, client_key) = generate_client_cert(&ca_cert, &ca_key);

    // Write certs to temp dirs
    let temp_dir = TempDir::new()?;
    let cert_dir = temp_dir.path().join("certs");
    let ca_dir = temp_dir.path().join("ca");
    std::fs::create_dir(&cert_dir)?;
    std::fs::create_dir(&ca_dir)?;

    std::fs::write(cert_dir.join("tls.crt"), server_cert.pem())?;
    std::fs::write(cert_dir.join("tls.key"), server_key.serialize_pem())?;
    std::fs::write(ca_dir.join("ca-bundle.pem"), ca_cert.pem())?;

    // Start mock upstream on 8080
    let upstream_listener = TcpListener::bind("127.0.0.1:8080").await?;
    tokio::spawn(async move {
        loop {
            let (stream, _) = upstream_listener.accept().await.unwrap();
            tokio::spawn(async move {
                let service = service_fn(|_req| async {
                    Ok::<_, hyper::Error>(hyper::Response::new(Full::new(Bytes::from(
                        "Hello from upstream",
                    ))))
                });
                http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await
                    .unwrap();
            });
        }
    });

    // Start sidecar on 8443
    let config = mtls_sidecar::config::Config {
        tls_listen_port: 8443,
        upstream_url: "http://127.0.0.1:8080".to_string(),
        upstream_readiness_url: "http://127.0.0.1:8080/ready".to_string(),
        cert_dir: cert_dir.to_str().unwrap().to_string(),
        ca_dir: ca_dir.to_str().unwrap().to_string(),
    };
    let tls_manager = Arc::new(TlsManager::new(&config).await?);
    let sidecar_listener = TcpListener::bind("127.0.0.1:8443").await?;
    let upstream_url = config.upstream_url.clone();
    tokio::spawn(async move {
        loop {
            let (stream, _) = sidecar_listener.accept().await.unwrap();
            let tls_manager = Arc::clone(&tls_manager);
            let upstream = upstream_url.clone();
            tokio::spawn(async move {
                let acceptor = TlsAcceptor::from(Arc::clone(&tls_manager.config));
                let stream = acceptor.accept(stream).await.unwrap();
                let (_, server_conn) = stream.get_ref();
                let client_cert = server_conn
                    .peer_certificates()
                    .and_then(|certs| certs.first().cloned());
                let service = service_fn(move |mut req| {
                    if let Some(cert) = &client_cert {
                        req.extensions_mut().insert(cert.clone());
                    }
                    let up = upstream.clone();
                    async move { mtls_sidecar::proxy::handler(req, &up).await }
                });
                http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await
                    .unwrap();
            });
        }
    });

    // Wait a bit
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Make request with client cert
    let client = reqwest::Client::builder()
        .add_root_certificate(Certificate::from_pem(ca_cert.pem().as_bytes())?)
        .identity(reqwest::Identity::from_pem(
            format!("{}{}", client_cert.pem(), client_key.serialize_pem()).as_bytes(),
        )?)
        .build()?;

    let resp = client.get("https://localhost:8443/").send().await?;
    assert_eq!(resp.status(), 200);
    let text = resp.text().await?;
    assert_eq!(text, "Hello from upstream");

    Ok(())
}

fn generate_ca() -> (rcgen::Certificate, KeyPair) {
    let mut params = CertificateParams::new(vec![]).unwrap();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(DnType::OrganizationName, "Test CA");
    let (yesterday, tomorrow) = validity_period();
    params.not_before = yesterday;
    params.not_after = tomorrow;
    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let cert = params.self_signed(&key_pair).unwrap();
    (cert, key_pair)
}

fn generate_server_cert(
    ca_cert: &rcgen::Certificate,
    ca_key: &KeyPair,
) -> (rcgen::Certificate, KeyPair) {
    let mut params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    params
        .distinguished_name
        .push(DnType::CommonName, "localhost");
    params
        .extended_key_usages
        .push(rcgen::ExtendedKeyUsagePurpose::ServerAuth);
    let (yesterday, tomorrow) = validity_period();
    params.not_before = yesterday;
    params.not_after = tomorrow;
    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let cert = params.signed_by(&key_pair, ca_cert, ca_key).unwrap();
    (cert, key_pair)
}

fn generate_client_cert(
    ca_cert: &rcgen::Certificate,
    ca_key: &KeyPair,
) -> (rcgen::Certificate, KeyPair) {
    let mut params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    params.distinguished_name.push(DnType::CommonName, "client");
    params
        .extended_key_usages
        .push(rcgen::ExtendedKeyUsagePurpose::ClientAuth);
    let (yesterday, tomorrow) = validity_period();
    params.not_before = yesterday;
    params.not_after = tomorrow;
    let key_pair = KeyPair::generate().unwrap();
    let cert = params.signed_by(&key_pair, ca_cert, ca_key).unwrap();
    (cert, key_pair)
}

fn validity_period() -> (OffsetDateTime, OffsetDateTime) {
    let day = Duration::new(86400, 0);
    let yesterday = OffsetDateTime::now_utc().checked_sub(day).unwrap();
    let tomorrow = OffsetDateTime::now_utc().checked_add(day).unwrap();
    (yesterday, tomorrow)
}
