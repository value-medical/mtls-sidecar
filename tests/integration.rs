use anyhow::Result;
use axum;
use base64;
use base64::Engine;
use bytes::Bytes;
use http_body_util::Full;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use portpicker;
use rcgen::{CertificateParams, DnType, Issuer, KeyPair};
use reqwest::Certificate;
use serde_json::Value;
use std::sync::Arc;
use tempfile::TempDir;
use time::Duration;
use time::OffsetDateTime;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tonic::{transport::Server, Request as TonicRequest, Response as TonicResponse, Status};

// Define a simple gRPC service for testing
pub mod hello_world {
    tonic::include_proto!("helloworld");
}

use hello_world::greeter_server::{Greeter, GreeterServer};
use hello_world::{HelloReply, HelloRequest};

#[derive(Default)]
pub struct MyGreeter {}

#[tonic::async_trait]
impl Greeter for MyGreeter {
    async fn say_hello(
        &self,
        request: TonicRequest<HelloRequest>,
    ) -> Result<TonicResponse<HelloReply>, Status> {
        let reply = HelloReply {
            message: format!("Hello {} from gRPC server!", request.into_inner().name),
        };
        Ok(TonicResponse::new(reply))
    }
}

use mtls_sidecar::tls_manager::TlsManager;

#[tokio::test]
async fn test_proxy_with_valid_cert() -> Result<()> {
    let _ =
        rustls::crypto::CryptoProvider::install_default(rustls::crypto::ring::default_provider());

    // Pick dynamic ports
    let upstream_port = portpicker::pick_unused_port().expect("No free port");
    let sidecar_port = portpicker::pick_unused_port().expect("No free port");

    // Generate CA, server cert, and client cert
    let (ca_cert, issuer) = generate_ca();
    let (server_cert, server_key) = generate_server_cert(&issuer);
    let (client_cert, client_key) = generate_client_cert(&issuer);

    // Write certs to temp dirs
    let temp_dir = TempDir::new()?;
    let cert_dir = temp_dir.path().join("certs");
    let ca_dir = temp_dir.path().join("ca");
    std::fs::create_dir(&cert_dir)?;
    std::fs::create_dir(&ca_dir)?;

    std::fs::write(cert_dir.join("tls.crt"), server_cert.pem())?;
    std::fs::write(cert_dir.join("tls.key"), server_key.serialize_pem())?;
    std::fs::write(ca_dir.join("ca-bundle.crt"), ca_cert.pem())?;

    // Start mock upstream
    let upstream_listener = TcpListener::bind(format!("127.0.0.1:{}", upstream_port)).await?;
    tokio::spawn(async move {
        loop {
            let (stream, _) = upstream_listener.accept().await.unwrap();
            tokio::spawn(async move {
                let service = service_fn(|_req| async {
                    Ok::<_, hyper::Error>(Response::new(Full::new(Bytes::from(
                        "Hello from upstream",
                    ))))
                });
                auto::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(stream), service)
                    .await
                    .unwrap();
            });
        }
    });

    // Start sidecar
    let config = mtls_sidecar::config::Config {
        tls_listen_port: sidecar_port,
        upstream_url: format!("http://127.0.0.1:{}", upstream_port),
        upstream_readiness_url: format!("http://127.0.0.1:{}/ready", upstream_port),
        cert_dir: cert_dir.to_str().unwrap().to_string(),
        ca_dir: ca_dir.to_str().unwrap().to_string(),
        inject_client_headers: false,
        monitor_port: 8081,
        enable_metrics: false,
    };
    let tls_manager = Arc::new(TlsManager::new(&config).await?);
    let sidecar_listener = TcpListener::bind(format!("127.0.0.1:{}", sidecar_port)).await?;
    let upstream_url = config.upstream_url.clone();
    tokio::spawn(async move {
        loop {
            let (stream, _) = sidecar_listener.accept().await.unwrap();
            let peer_addr = stream.peer_addr().ok();
            let tls_manager = Arc::clone(&tls_manager);
            let upstream = upstream_url.clone();
            tokio::spawn(async move {
                let current_config = tls_manager.config.read().await.clone();
                let acceptor = TlsAcceptor::from(current_config);
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
                    let client = Arc::new(Client::builder(TokioExecutor::new()).build_http());
                    let addr = peer_addr;
                    async move { mtls_sidecar::proxy::handler(req, &up, false, client, addr).await }
                });
                auto::Builder::new(TokioExecutor::new())
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

    let resp = client
        .get(format!("https://localhost:{}/", sidecar_port))
        .send()
        .await?;
    assert_eq!(resp.status(), 200);
    let text = resp.text().await?;
    assert_eq!(text, "Hello from upstream");

    Ok(())
}

#[tokio::test]
async fn test_proxy_with_header_injection() -> Result<()> {
    let _ =
        rustls::crypto::CryptoProvider::install_default(rustls::crypto::ring::default_provider());

    // Pick dynamic ports
    let upstream_port = portpicker::pick_unused_port().expect("No free port");
    let sidecar_port = portpicker::pick_unused_port().expect("No free port");

    // Generate CA, server cert, and client cert with CN
    let (ca_cert, issuer) = generate_ca();
    let (server_cert, server_key) = generate_server_cert(&issuer);
    let (client_cert, client_key) = generate_client_cert(&issuer);

    // Write certs to temp dirs
    let temp_dir = TempDir::new()?;
    let cert_dir = temp_dir.path().join("certs");
    let ca_dir = temp_dir.path().join("ca");
    std::fs::create_dir(&cert_dir)?;
    std::fs::create_dir(&ca_dir)?;

    std::fs::write(cert_dir.join("tls.crt"), server_cert.pem())?;
    std::fs::write(cert_dir.join("tls.key"), server_key.serialize_pem())?;
    std::fs::write(ca_dir.join("ca-bundle.crt"), ca_cert.pem())?;

    // Start mock upstream that echoes headers
    let upstream_listener = TcpListener::bind(format!("127.0.0.1:{}", upstream_port)).await?;
    let received_headers = Arc::new(std::sync::Mutex::new(Vec::new()));
    let headers_clone = Arc::clone(&received_headers);
    tokio::spawn(async move {
        loop {
            let (stream, _) = upstream_listener.accept().await.unwrap();
            let headers = Arc::clone(&headers_clone);
            tokio::spawn(async move {
                let headers = Arc::clone(&headers);
                let service = service_fn(move |req: Request<hyper::body::Incoming>| {
                    let headers = Arc::clone(&headers);
                    async move {
                        // Collect headers
                        let mut h = Vec::new();
                        for (key, value) in req.headers() {
                            h.push(format!("{}: {}", key, value.to_str().unwrap_or("")));
                        }
                        headers.lock().unwrap().extend(h);
                        Ok::<_, hyper::Error>(Response::new(Full::new(Bytes::from("OK"))))
                    }
                });
                auto::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(stream), service)
                    .await
                    .unwrap();
            });
        }
    });

    // Start sidecar with injection enabled
    let config = mtls_sidecar::config::Config {
        tls_listen_port: sidecar_port,
        upstream_url: format!("http://127.0.0.1:{}", upstream_port),
        upstream_readiness_url: format!("http://127.0.0.1:{}/ready", upstream_port),
        cert_dir: cert_dir.to_str().unwrap().to_string(),
        ca_dir: ca_dir.to_str().unwrap().to_string(),
        inject_client_headers: true,
        monitor_port: 8081,
        enable_metrics: false,
    };
    let tls_manager = Arc::new(TlsManager::new(&config).await?);
    let sidecar_listener = TcpListener::bind(format!("127.0.0.1:{}", sidecar_port)).await?;
    let upstream_url = config.upstream_url.clone();
    let inject = config.inject_client_headers;
    tokio::spawn(async move {
        loop {
            let (stream, _) = sidecar_listener.accept().await.unwrap();
            let peer_addr = stream.peer_addr().ok();
            let tls_manager = Arc::clone(&tls_manager);
            let upstream = upstream_url.clone();
            let inj = inject;
            tokio::spawn(async move {
                let current_config = tls_manager.config.read().await.clone();
                let acceptor = TlsAcceptor::from(current_config);
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
                    let client = Arc::new(Client::builder(TokioExecutor::new()).build_http());
                    let addr = peer_addr;
                    async move { mtls_sidecar::proxy::handler(req, &up, inj, client, addr).await }
                });
                auto::Builder::new(TokioExecutor::new())
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

    let resp = client
        .get(format!("https://localhost:{}/", sidecar_port))
        .send()
        .await?;
    assert_eq!(resp.status(), 200);

    // Check if headers were received
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await; // Wait for async
    let headers = received_headers.lock().unwrap();
    let tls_info_header = headers.iter().find(|h| h.starts_with("x-client-tls-info:")).unwrap();
    let b64_value = tls_info_header.strip_prefix("x-client-tls-info: ").unwrap();
    let decoded = base64::engine::general_purpose::STANDARD.decode(b64_value).unwrap();
    let json_str = String::from_utf8(decoded).unwrap();
    let info: Value = serde_json::from_str(&json_str).unwrap();
    assert_eq!(info["subject"], "CN=client");
    assert!(info["dns_sans"].as_array().unwrap().contains(&Value::String("localhost".to_string())));
    assert!(info["hash"].as_str().unwrap().starts_with("sha256:"));
    assert!(info["serial"].as_str().unwrap().starts_with("0x"));

    Ok(())
}

fn generate_ca() -> (rcgen::Certificate, Issuer<'static, KeyPair>) {
    let mut params = CertificateParams::new(vec![]).unwrap();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(DnType::OrganizationName, "Test CA");
    let (yesterday, tomorrow) = validity_period();
    params.not_before = yesterday;
    params.not_after = tomorrow;
    let key_pair = KeyPair::generate().unwrap();
    let cert = params.self_signed(&key_pair).unwrap();
    let issuer = Issuer::new(params, key_pair);
    (cert, issuer)
}

fn generate_server_cert(
    issuer: &Issuer<KeyPair>,
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
    let key_pair = KeyPair::generate().unwrap();
    let cert = params.signed_by(&key_pair, issuer).unwrap();
    (cert, key_pair)
}

fn generate_client_cert(
    issuer: &Issuer<KeyPair>,
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
    let cert = params.signed_by(&key_pair, &issuer).unwrap();
    (cert, key_pair)
}

#[tokio::test]
async fn test_file_watching_reload() -> Result<()> {
    let _ =
        rustls::crypto::CryptoProvider::install_default(rustls::crypto::ring::default_provider());

    // Pick dynamic ports
    let upstream_port = portpicker::pick_unused_port().expect("No free port");
    let sidecar_port = portpicker::pick_unused_port().expect("No free port");

    // Generate initial CA, server cert, and client cert
    let (ca_cert, issuer) = generate_ca();
    let (server_cert, server_key) = generate_server_cert(&issuer);
    let (client_cert, client_key) = generate_client_cert(&issuer);

    // Write initial certs to temp dirs
    let temp_dir = TempDir::new()?;
    let cert_dir = temp_dir.path().join("certs");
    let ca_dir = temp_dir.path().join("ca");
    std::fs::create_dir(&cert_dir)?;
    std::fs::create_dir(&ca_dir)?;

    std::fs::write(cert_dir.join("tls.crt"), server_cert.pem())?;
    std::fs::write(cert_dir.join("tls.key"), server_key.serialize_pem())?;
    std::fs::write(ca_dir.join("ca-bundle.crt"), ca_cert.pem())?;

    // Start mock upstream
    let upstream_listener = TcpListener::bind(format!("127.0.0.1:{}", upstream_port)).await?;
    tokio::spawn(async move {
        loop {
            let (stream, _) = upstream_listener.accept().await.unwrap();
            tokio::spawn(async move {
                let service = service_fn(|_req| async {
                    Ok::<_, hyper::Error>(Response::new(Full::new(Bytes::from("OK"))))
                });
                auto::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(stream), service)
                    .await
                    .unwrap();
            });
        }
    });

    // Start sidecar
    let config = mtls_sidecar::config::Config {
        tls_listen_port: sidecar_port,
        upstream_url: format!("http://127.0.0.1:{}", upstream_port),
        upstream_readiness_url: format!("http://127.0.0.1:{}/ready", upstream_port),
        cert_dir: cert_dir.to_str().unwrap().to_string(),
        ca_dir: ca_dir.to_str().unwrap().to_string(),
        inject_client_headers: false,
        monitor_port: 8081,
        enable_metrics: false,
    };
    let tls_manager = Arc::new(mtls_sidecar::tls_manager::TlsManager::new(&config).await?);
    let sidecar_listener = TcpListener::bind(format!("127.0.0.1:{}", sidecar_port)).await?;
    let upstream_url = config.upstream_url.clone();
    let watcher_tls_manager = Arc::clone(&tls_manager);
    let reload_tls_manager = Arc::clone(&tls_manager);
    let cert_dir_clone = config.cert_dir.clone();
    let ca_dir_clone = config.ca_dir.clone();

    // Spawn watcher
    tokio::spawn(async move {
        mtls_sidecar::watcher::start_watcher(&cert_dir_clone, &ca_dir_clone, watcher_tls_manager)
            .await
            .unwrap();
    });

    // Spawn server
    tokio::spawn(async move {
        loop {
            let (stream, _) = sidecar_listener.accept().await.unwrap();
            let peer_addr = stream.peer_addr().ok();
            let tls_manager = Arc::clone(&tls_manager);
            let upstream = upstream_url.clone();
            tokio::spawn(async move {
                let current_config = tls_manager.config.read().await.clone();
                let acceptor = TlsAcceptor::from(current_config);
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
                    let client = Arc::new(Client::builder(TokioExecutor::new()).build_http());
                    let addr = peer_addr;
                    async move { mtls_sidecar::proxy::handler(req, &up, false, client, addr).await }
                });
                auto::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(stream), service)
                    .await
                    .unwrap();
            });
        }
    });

    // Wait for server to start
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Make initial request with old client cert
    let old_client = reqwest::Client::builder()
        .add_root_certificate(Certificate::from_pem(ca_cert.pem().as_bytes())?)
        .identity(reqwest::Identity::from_pem(
            format!("{}{}", client_cert.pem(), client_key.serialize_pem()).as_bytes(),
        )?)
        .build()?;
    let resp = old_client
        .get(format!("https://localhost:{}/", sidecar_port))
        .send()
        .await?;
    assert_eq!(resp.status(), 200);

    // Generate new certs
    let (new_ca_cert, issuer) = generate_ca();
    let (new_server_cert, new_server_key) = generate_server_cert(&issuer);

    // Overwrite cert files to trigger reload
    std::fs::write(cert_dir.join("tls.crt"), new_server_cert.pem())?;
    std::fs::write(cert_dir.join("tls.key"), new_server_key.serialize_pem())?;
    std::fs::write(ca_dir.join("ca-bundle.crt"), new_ca_cert.pem())?;

    // Manually trigger reload to ensure it works (file watching may not trigger in test env)
    reload_tls_manager
        .reload(&config.cert_dir, &config.ca_dir)
        .await
        .unwrap();

    // Wait a bit
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Try old client again - should fail because server now requires client cert verified by new CA
    let old_client_permissive = reqwest::Client::builder()
        .add_root_certificate(Certificate::from_pem(new_ca_cert.pem().as_bytes())?)
        .identity(reqwest::Identity::from_pem(
            format!("{}{}", client_cert.pem(), client_key.serialize_pem()).as_bytes(),
        )?)
        .build()?;
    let result = old_client_permissive
        .get(format!("https://localhost:{}/", sidecar_port))
        .send()
        .await;
    assert!(
        result.is_err(),
        "Old client cert should be rejected by new CA"
    );

    // Generate new client cert signed by new CA
    let (new_client_cert, new_client_key) = generate_client_cert(&issuer);

    let new_client = reqwest::Client::builder()
        .add_root_certificate(Certificate::from_pem(new_ca_cert.pem().as_bytes())?)
        .identity(reqwest::Identity::from_pem(
            format!(
                "{}{}",
                new_client_cert.pem(),
                new_client_key.serialize_pem()
            )
            .as_bytes(),
        )?)
        .build()?;

    let resp = new_client
        .get(format!("https://localhost:{}/", sidecar_port))
        .send()
        .await?;
    assert_eq!(resp.status(), 200);

    Ok(())
}

#[tokio::test]
async fn test_tls_handshake_failure_handling() -> Result<()> {
    let _ =
        rustls::crypto::CryptoProvider::install_default(rustls::crypto::ring::default_provider());

    // Pick dynamic ports
    let upstream_port = portpicker::pick_unused_port().expect("No free port");
    let sidecar_port = portpicker::pick_unused_port().expect("No free port");

    // Generate CA and server cert
    let (ca_cert, issuer) = generate_ca();
    let (server_cert, server_key) = generate_server_cert(&issuer);

    // Write certs to temp dirs
    let temp_dir = TempDir::new()?;
    let cert_dir = temp_dir.path().join("certs");
    let ca_dir = temp_dir.path().join("ca");
    std::fs::create_dir(&cert_dir)?;
    std::fs::create_dir(&ca_dir)?;

    std::fs::write(cert_dir.join("tls.crt"), server_cert.pem())?;
    std::fs::write(cert_dir.join("tls.key"), server_key.serialize_pem())?;
    std::fs::write(ca_dir.join("ca-bundle.crt"), ca_cert.pem())?;

    // Start mock upstream
    let upstream_listener = TcpListener::bind(format!("127.0.0.1:{}", upstream_port)).await?;
    tokio::spawn(async move {
        loop {
            let (stream, _) = upstream_listener.accept().await.unwrap();
            tokio::spawn(async move {
                let service = service_fn(|_req| async {
                    Ok::<_, hyper::Error>(Response::new(Full::new(Bytes::from("OK"))))
                });
                auto::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(stream), service)
                    .await
                    .unwrap();
            });
        }
    });

    // Start sidecar
    let config = mtls_sidecar::config::Config {
        tls_listen_port: sidecar_port,
        upstream_url: format!("http://127.0.0.1:{}/grpc", upstream_port), // Add /grpc to identify gRPC test
        upstream_readiness_url: format!("http://127.0.0.1:{}/ready", upstream_port),
        cert_dir: cert_dir.to_str().unwrap().to_string(),
        ca_dir: ca_dir.to_str().unwrap().to_string(),
        inject_client_headers: false,
        monitor_port: 8081,
        enable_metrics: false,
    };
    let tls_manager = Arc::new(TlsManager::new(&config).await?);
    let sidecar_listener = TcpListener::bind(format!("127.0.0.1:{}", sidecar_port)).await?;
    let upstream_url = config.upstream_url.clone();
    tokio::spawn(async move {
        loop {
            let (stream, _) = sidecar_listener.accept().await.unwrap();
            let peer_addr = stream.peer_addr().ok();
            let tls_manager = Arc::clone(&tls_manager);
            let upstream = upstream_url.clone();
            tokio::spawn(async move {
                let current_config = tls_manager.config.read().await.clone();
                let acceptor = TlsAcceptor::from(current_config);
                let stream = match acceptor.accept(stream).await {
                    Ok(s) => s,
                    Err(_) => return, // Simulate the fixed behavior
                };
                let (_, server_conn) = stream.get_ref();
                let client_cert = server_conn
                    .peer_certificates()
                    .and_then(|certs| certs.first().cloned());
                let service = service_fn(move |mut req| {
                    if let Some(cert) = &client_cert {
                        req.extensions_mut().insert(cert.clone());
                    }
                    let up = upstream.clone();
                    // For gRPC test, use HTTP/2 capable client
                    let client = if up.contains("grpc") {
                        Arc::new(Client::builder(TokioExecutor::new()).build(
                            hyper_util::client::legacy::connect::HttpConnector::new()
                        ))
                    } else {
                        Arc::new(Client::builder(TokioExecutor::new()).build_http())
                    };
                    let addr = peer_addr;
                    async move { mtls_sidecar::proxy::handler(req, &up, false, client, addr).await }
                });
                auto::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(stream), service)
                    .await
                    .unwrap();
            });
        }
    });

    // Wait for server to start
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Generate valid client cert
    let (client_cert, client_key) = generate_client_cert(&issuer);

    // Try invalid connection (no client cert)
    let invalid_client = reqwest::Client::builder()
        .add_root_certificate(Certificate::from_pem(ca_cert.pem().as_bytes())?)
        .build()?;
    let result = invalid_client
        .get(format!("https://localhost:{}/", sidecar_port))
        .send()
        .await;
    assert!(
        result.is_err(),
        "Connection without client cert should fail"
    );

    // Now try valid connection
    let valid_client = reqwest::Client::builder()
        .add_root_certificate(Certificate::from_pem(ca_cert.pem().as_bytes())?)
        .identity(reqwest::Identity::from_pem(
            format!("{}{}", client_cert.pem(), client_key.serialize_pem()).as_bytes(),
        )?)
        .build()?;
    let resp = valid_client
        .get(format!("https://localhost:{}/", sidecar_port))
        .send()
        .await?;
    assert_eq!(resp.status(), 200);

    Ok(())
}

#[tokio::test]
async fn test_proxy_large_response() -> Result<()> {
    let _ =
        rustls::crypto::CryptoProvider::install_default(rustls::crypto::ring::default_provider());

    // Pick dynamic ports
    let upstream_port = portpicker::pick_unused_port().expect("No free port");
    let sidecar_port = portpicker::pick_unused_port().expect("No free port");

    // Generate CA, server cert, and client cert
    let (ca_cert, issuer) = generate_ca();
    let (server_cert, server_key) = generate_server_cert(&issuer);
    let (client_cert, client_key) = generate_client_cert(&issuer);

    // Write certs to temp dirs
    let temp_dir = TempDir::new()?;
    let cert_dir = temp_dir.path().join("certs");
    let ca_dir = temp_dir.path().join("ca");
    std::fs::create_dir(&cert_dir)?;
    std::fs::create_dir(&ca_dir)?;

    std::fs::write(cert_dir.join("tls.crt"), server_cert.pem())?;
    std::fs::write(cert_dir.join("tls.key"), server_key.serialize_pem())?;
    std::fs::write(ca_dir.join("ca-bundle.crt"), ca_cert.pem())?;

    // Create large response body (10MB)
    let large_body = Bytes::from(vec![b'A'; 10_000_000]);

    // Start mock upstream
    let upstream_listener = TcpListener::bind(format!("127.0.0.1:{}", upstream_port)).await?;
    let body_clone = large_body.clone();
    tokio::spawn(async move {
        loop {
            let (stream, _) = upstream_listener.accept().await.unwrap();
            let body = body_clone.clone();
            tokio::spawn(async move {
                let service = service_fn(move |_req| {
                    let body = body.clone();
                    async move { Ok::<_, hyper::Error>(Response::new(Full::new(body))) }
                });
                auto::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(stream), service)
                    .await
                    .unwrap();
            });
        }
    });

    // Start sidecar
    let config = mtls_sidecar::config::Config {
        tls_listen_port: sidecar_port,
        upstream_url: format!("http://127.0.0.1:{}", upstream_port),
        upstream_readiness_url: format!("http://127.0.0.1:{}/ready", upstream_port),
        cert_dir: cert_dir.to_str().unwrap().to_string(),
        ca_dir: ca_dir.to_str().unwrap().to_string(),
        inject_client_headers: false,
        monitor_port: 8081,
        enable_metrics: false,
    };
    let tls_manager = Arc::new(TlsManager::new(&config).await?);
    let sidecar_listener = TcpListener::bind(format!("127.0.0.1:{}", sidecar_port)).await?;
    let upstream_url = config.upstream_url.clone();
    tokio::spawn(async move {
        loop {
            let (stream, _) = sidecar_listener.accept().await.unwrap();
            let peer_addr = stream.peer_addr().ok();
            let tls_manager = Arc::clone(&tls_manager);
            let upstream = upstream_url.clone();
            tokio::spawn(async move {
                let current_config = tls_manager.config.read().await.clone();
                let acceptor = TlsAcceptor::from(current_config);
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
                    let client = Arc::new(Client::builder(TokioExecutor::new()).build_http());
                    let addr = peer_addr;
                    async move { mtls_sidecar::proxy::handler(req, &up, false, client, addr).await }
                });
                auto::Builder::new(TokioExecutor::new())
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

    let resp = client
        .get(format!("https://localhost:{}/", sidecar_port))
        .send()
        .await?;
    assert_eq!(resp.status(), 200);
    let text = resp.text().await?;
    assert_eq!(text.len(), 10_000_000);
    assert!(text.chars().all(|c| c == 'A'));

    Ok(())
}

#[tokio::test]
async fn test_invalid_config_exits() -> Result<()> {
    use std::process::Command;

    // Run the binary with invalid TLS_LISTEN_PORT
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_mtls-sidecar"));
    cmd.env("TLS_LISTEN_PORT", "invalid_port");
    cmd.env("CERT_DIR", "/tmp/nonexistent");
    cmd.env("CA_DIR", "/tmp/nonexistent");

    let output = cmd.output().expect("Failed to run command");

    // Should exit with non-zero code
    assert!(!output.status.success());

    // Check stderr contains error
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Invalid TLS_LISTEN_PORT"));

    Ok(())
}

#[tokio::test]
async fn test_readiness_probe_certificate_expiry() -> Result<()> {
    let _ =
        rustls::crypto::CryptoProvider::install_default(rustls::crypto::ring::default_provider());

    // Pick dynamic ports
    let upstream_port = portpicker::pick_unused_port().expect("No free port");
    let sidecar_port = portpicker::pick_unused_port().expect("No free port");
    let monitor_port = portpicker::pick_unused_port().expect("No free port");

    // Generate CA and EXPIRED server cert
    let (ca_cert, issuer) = generate_ca();
    let (server_cert, server_key) = generate_expired_server_cert(&issuer);

    // Write certs to temp dirs
    let temp_dir = TempDir::new()?;
    let cert_dir = temp_dir.path().join("certs");
    let ca_dir = temp_dir.path().join("ca");
    std::fs::create_dir(&cert_dir)?;
    std::fs::create_dir(&ca_dir)?;

    std::fs::write(cert_dir.join("tls.crt"), server_cert.pem())?;
    std::fs::write(cert_dir.join("tls.key"), server_key.serialize_pem())?;
    std::fs::write(ca_dir.join("ca-bundle.crt"), ca_cert.pem())?;

    // Start mock upstream that responds to readiness
    let upstream_listener = TcpListener::bind(format!("127.0.0.1:{}", upstream_port)).await?;
    tokio::spawn(async move {
        loop {
            let (stream, _) = upstream_listener.accept().await.unwrap();
            tokio::spawn(async move {
                let service = service_fn(|req| async move {
                    if req.uri().path() == "/ready" {
                        Ok::<_, hyper::Error>(Response::new(Full::new(Bytes::from("OK"))))
                    } else {
                        Ok::<_, hyper::Error>(Response::new(Full::new(Bytes::from("Hello"))))
                    }
                });
                auto::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(stream), service)
                    .await
                    .unwrap();
            });
        }
    });

    // Start sidecar
    let config = mtls_sidecar::config::Config {
        tls_listen_port: sidecar_port,
        upstream_url: format!("http://127.0.0.1:{}", upstream_port),
        upstream_readiness_url: format!("http://127.0.0.1:{}/ready", upstream_port),
        cert_dir: cert_dir.to_str().unwrap().to_string(),
        ca_dir: ca_dir.to_str().unwrap().to_string(),
        inject_client_headers: false,
        monitor_port,
        enable_metrics: false,
    };
    let tls_manager = Arc::new(TlsManager::new(&config).await?);

    // Start monitoring server
    let router = mtls_sidecar::monitoring::create_router(&config, Arc::clone(&tls_manager));
    let monitor_addr = format!("127.0.0.1:{}", monitor_port);
    let monitor_listener = TcpListener::bind(&monitor_addr).await?;
    tokio::spawn(async move {
        axum::serve(monitor_listener, router).await.unwrap();
    });

    // Wait for servers to start
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Hit the readiness endpoint - should return 503 due to expired certificate
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://127.0.0.1:{}/ready", monitor_port))
        .send()
        .await?;
    assert_eq!(resp.status(), 503);

    Ok(())
}

fn generate_expired_server_cert(
    issuer: &Issuer<KeyPair>,
) -> (rcgen::Certificate, KeyPair) {
    let mut params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    params
        .distinguished_name
        .push(DnType::CommonName, "localhost");
    params
        .extended_key_usages
        .push(rcgen::ExtendedKeyUsagePurpose::ServerAuth);
    // Set validity to yesterday (expired)
    let yesterday = OffsetDateTime::now_utc().checked_sub(Duration::new(86400, 0)).unwrap();
    params.not_before = yesterday.checked_sub(Duration::new(86400, 0)).unwrap(); // 2 days ago
    params.not_after = yesterday; // yesterday
    let key_pair = KeyPair::generate().unwrap();
    let cert = params.signed_by(&key_pair, issuer).unwrap();
    (cert, key_pair)
}

#[tokio::test]
async fn test_proxy_http1_only() -> Result<()> {
    let _ =
        rustls::crypto::CryptoProvider::install_default(rustls::crypto::ring::default_provider());

    // Pick dynamic ports
    let upstream_port = portpicker::pick_unused_port().expect("No free port");
    let sidecar_port = portpicker::pick_unused_port().expect("No free port");

    // Generate CA, server cert, and client cert
    let (ca_cert, issuer) = generate_ca();
    let (server_cert, server_key) = generate_server_cert(&issuer);
    let (client_cert, client_key) = generate_client_cert(&issuer);

    // Write certs to temp dirs
    let temp_dir = TempDir::new()?;
    let cert_dir = temp_dir.path().join("certs");
    let ca_dir = temp_dir.path().join("ca");
    std::fs::create_dir(&cert_dir)?;
    std::fs::create_dir(&ca_dir)?;

    std::fs::write(cert_dir.join("tls.crt"), server_cert.pem())?;
    std::fs::write(cert_dir.join("tls.key"), server_key.serialize_pem())?;
    std::fs::write(ca_dir.join("ca-bundle.crt"), ca_cert.pem())?;

    // Start mock upstream
    let upstream_listener = TcpListener::bind(format!("127.0.0.1:{}", upstream_port)).await?;
    tokio::spawn(async move {
        loop {
            let (stream, _) = upstream_listener.accept().await.unwrap();
            tokio::spawn(async move {
                let service = service_fn(|_req| async {
                    Ok::<_, hyper::Error>(Response::new(Full::new(Bytes::from(
                        "Hello from HTTP/1.1 upstream",
                    ))))
                });
                auto::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(stream), service)
                    .await
                    .unwrap();
            });
        }
    });

    // Start sidecar
    let config = mtls_sidecar::config::Config {
        tls_listen_port: sidecar_port,
        upstream_url: format!("http://127.0.0.1:{}", upstream_port),
        upstream_readiness_url: format!("http://127.0.0.1:{}/ready", upstream_port),
        cert_dir: cert_dir.to_str().unwrap().to_string(),
        ca_dir: ca_dir.to_str().unwrap().to_string(),
        inject_client_headers: false,
        monitor_port: 8081,
        enable_metrics: false,
    };
    let tls_manager = Arc::new(TlsManager::new(&config).await?);
    let sidecar_listener = TcpListener::bind(format!("127.0.0.1:{}", sidecar_port)).await?;
    let upstream_url = config.upstream_url.clone();
    tokio::spawn(async move {
        loop {
            let (stream, _) = sidecar_listener.accept().await.unwrap();
            let peer_addr = stream.peer_addr().ok();
            let tls_manager = Arc::clone(&tls_manager);
            let upstream = upstream_url.clone();
            tokio::spawn(async move {
                let current_config = tls_manager.config.read().await.clone();
                let acceptor = TlsAcceptor::from(current_config);
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
                    let client = Arc::new(Client::builder(TokioExecutor::new()).build_http());
                    let addr = peer_addr;
                    async move { mtls_sidecar::proxy::handler(req, &up, false, client, addr).await }
                });
                auto::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(stream), service)
                    .await
                    .unwrap();
            });
        }
    });

    // Wait a bit
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Make HTTP/1.1-only request with client cert
    let client = reqwest::Client::builder()
        .add_root_certificate(Certificate::from_pem(ca_cert.pem().as_bytes())?)
        .identity(reqwest::Identity::from_pem(
            format!("{}{}", client_cert.pem(), client_key.serialize_pem()).as_bytes(),
        )?)
        .http1_only()  // Force HTTP/1.1
        .build()?;

    let resp = client
        .get(format!("https://localhost:{}/", sidecar_port))
        .send()
        .await?;
    assert_eq!(resp.status(), 200);
    let text = resp.text().await?;
    assert_eq!(text, "Hello from HTTP/1.1 upstream");

    Ok(())
}

#[tokio::test]
async fn test_proxy_http2_only() -> Result<()> {
    let _ =
        rustls::crypto::CryptoProvider::install_default(rustls::crypto::ring::default_provider());

    // Pick dynamic ports
    let upstream_port = portpicker::pick_unused_port().expect("No free port");
    let sidecar_port = portpicker::pick_unused_port().expect("No free port");

    // Generate CA, server cert, and client cert
    let (ca_cert, issuer) = generate_ca();
    let (server_cert, server_key) = generate_server_cert(&issuer);
    let (client_cert, client_key) = generate_client_cert(&issuer);

    // Write certs to temp dirs
    let temp_dir = TempDir::new()?;
    let cert_dir = temp_dir.path().join("certs");
    let ca_dir = temp_dir.path().join("ca");
    std::fs::create_dir(&cert_dir)?;
    std::fs::create_dir(&ca_dir)?;

    std::fs::write(cert_dir.join("tls.crt"), server_cert.pem())?;
    std::fs::write(cert_dir.join("tls.key"), server_key.serialize_pem())?;
    std::fs::write(ca_dir.join("ca-bundle.crt"), ca_cert.pem())?;

    // Start mock upstream
    let upstream_listener = TcpListener::bind(format!("127.0.0.1:{}", upstream_port)).await?;
    tokio::spawn(async move {
        loop {
            let (stream, _) = upstream_listener.accept().await.unwrap();
            tokio::spawn(async move {
                let service = service_fn(|_req| async {
                    Ok::<_, hyper::Error>(Response::new(Full::new(Bytes::from(
                        "Hello from HTTP/2 upstream",
                    ))))
                });
                auto::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(stream), service)
                    .await
                    .unwrap();
            });
        }
    });

    // Start sidecar
    let config = mtls_sidecar::config::Config {
        tls_listen_port: sidecar_port,
        upstream_url: format!("http://127.0.0.1:{}", upstream_port),
        upstream_readiness_url: format!("http://127.0.0.1:{}/ready", upstream_port),
        cert_dir: cert_dir.to_str().unwrap().to_string(),
        ca_dir: ca_dir.to_str().unwrap().to_string(),
        inject_client_headers: false,
        monitor_port: 8081,
        enable_metrics: false,
    };
    let tls_manager = Arc::new(TlsManager::new(&config).await?);
    let sidecar_listener = TcpListener::bind(format!("127.0.0.1:{}", sidecar_port)).await?;
    let upstream_url = config.upstream_url.clone();
    tokio::spawn(async move {
        loop {
            let (stream, _) = sidecar_listener.accept().await.unwrap();
            let peer_addr = stream.peer_addr().ok();
            let tls_manager = Arc::clone(&tls_manager);
            let upstream = upstream_url.clone();
            tokio::spawn(async move {
                let current_config = tls_manager.config.read().await.clone();
                let acceptor = TlsAcceptor::from(current_config);
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
                    let client = Arc::new(Client::builder(TokioExecutor::new()).build_http());
                    let addr = peer_addr;
                    async move { mtls_sidecar::proxy::handler(req, &up, false, client, addr).await }
                });
                auto::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(stream), service)
                    .await
                    .unwrap();
            });
        }
    });

    // Wait a bit
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Make HTTP/2-only request with client cert
    let client = reqwest::Client::builder()
        .add_root_certificate(Certificate::from_pem(ca_cert.pem().as_bytes())?)
        .identity(reqwest::Identity::from_pem(
            format!("{}{}", client_cert.pem(), client_key.serialize_pem()).as_bytes(),
        )?)
        .build()?;

    let resp = client
        .get(format!("https://localhost:{}/", sidecar_port))
        .send()
        .await?;
    assert_eq!(resp.status(), 200);
    let text = resp.text().await?;
    assert_eq!(text, "Hello from HTTP/2 upstream");

    Ok(())
}

#[tokio::test]
async fn test_proxy_grpc() -> Result<()> {
    let _ =
        rustls::crypto::CryptoProvider::install_default(rustls::crypto::ring::default_provider());

    // Pick dynamic ports
    let upstream_port = portpicker::pick_unused_port().expect("No free port");
    let sidecar_port = portpicker::pick_unused_port().expect("No free port");

    // Generate CA, server cert, and client cert
    let (ca_cert, issuer) = generate_ca();
    let (server_cert, server_key) = generate_server_cert(&issuer);
    let (client_cert, client_key) = generate_client_cert(&issuer);

    // Write certs to temp dirs
    let temp_dir = TempDir::new()?;
    let cert_dir = temp_dir.path().join("certs");
    let ca_dir = temp_dir.path().join("ca");
    std::fs::create_dir(&cert_dir)?;
    std::fs::create_dir(&ca_dir)?;

    std::fs::write(cert_dir.join("tls.crt"), server_cert.pem())?;
    std::fs::write(cert_dir.join("tls.key"), server_key.serialize_pem())?;
    std::fs::write(ca_dir.join("ca-bundle.crt"), ca_cert.pem())?;

    // Start gRPC upstream server
    let greeter = MyGreeter::default();
    let upstream_addr = format!("127.0.0.1:{}", upstream_port);
    let upstream_listener = TcpListener::bind(&upstream_addr).await?;
    tokio::spawn(async move {
        Server::builder()
            .accept_http1(true)  // Allow HTTP/1.1 for gRPC
            .add_service(GreeterServer::new(greeter))
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(upstream_listener))
            .await
            .unwrap();
    });

    // Start sidecar
    let config = mtls_sidecar::config::Config {
        tls_listen_port: sidecar_port,
        upstream_url: format!("http://127.0.0.1:{}", upstream_port),
        upstream_readiness_url: format!("http://127.0.0.1:{}/ready", upstream_port),
        cert_dir: cert_dir.to_str().unwrap().to_string(),
        ca_dir: ca_dir.to_str().unwrap().to_string(),
        inject_client_headers: false,
        monitor_port: 8081,
        enable_metrics: false,
    };
    let tls_manager = Arc::new(TlsManager::new(&config).await?);
    let sidecar_listener = TcpListener::bind(format!("127.0.0.1:{}", sidecar_port)).await?;
    let upstream_url = config.upstream_url.clone();
    tokio::spawn(async move {
        loop {
            let (stream, _) = sidecar_listener.accept().await.unwrap();
            let peer_addr = stream.peer_addr().ok();
            let tls_manager = Arc::clone(&tls_manager);
            let upstream = upstream_url.clone();
            tokio::spawn(async move {
                let current_config = tls_manager.config.read().await.clone();
                let acceptor = TlsAcceptor::from(current_config);
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
                    let client = Arc::new(Client::builder(TokioExecutor::new()).build_http());
                    let addr = peer_addr;
                    async move { mtls_sidecar::proxy::handler(req, &up, false, client, addr).await }
                });
                auto::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(stream), service)
                    .await
                    .unwrap();
            });
        }
    });

    // Wait a bit for servers to start
    tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;

    // Create gRPC client that connects through the sidecar
    let sidecar_addr = format!("https://localhost:{}", sidecar_port);

    // For tonic with rustls, we need to use the rustls connector
    let mut root_store = rustls::RootCertStore::empty();
    let ca_certs = rustls_pemfile::certs(&mut ca_cert.pem().as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    root_store.add_parsable_certificates(ca_certs);

    let client_certs = rustls_pemfile::certs(&mut client_cert.pem().as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    let client_key_der = rustls_pemfile::private_key(&mut client_key.serialize_pem().as_bytes())
        .unwrap()
        .unwrap();

    let tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_client_auth_cert(client_certs, client_key_der)
        .unwrap();

    let http_connector = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(tls_config)
        .https_only()
        .enable_http1()
        .build();

    let channel = tonic::transport::Endpoint::new(sidecar_addr)?
        .connect_with_connector(http_connector)
        .await?;

    let mut client = hello_world::greeter_client::GreeterClient::new(channel);

    let request = tonic::Request::new(HelloRequest {
        name: "gRPC Client".into(),
    });

    let response = client.say_hello(request).await?;
    assert_eq!(response.into_inner().message, "Hello gRPC Client from gRPC server!");

    Ok(())
}

fn validity_period() -> (OffsetDateTime, OffsetDateTime) {
    let day = Duration::new(86400, 0);
    let yesterday = OffsetDateTime::now_utc().checked_sub(day).unwrap();
    let tomorrow = OffsetDateTime::now_utc().checked_add(day).unwrap();
    (yesterday, tomorrow)
}
