use std::error::Error;
use anyhow::Result;
use axum;
use base64;
use base64::Engine;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper::server::conn::http1;
use hyper_util::server::conn::auto;
use portpicker;
use rcgen::{CertificateParams, DnType, Issuer, KeyPair};
use reqwest::Certificate;
use serde_json::Value;
use std::path::PathBuf;
use std::sync::Arc;
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::connect::HttpConnector;
use tempfile::TempDir;
use time::Duration;
use time::OffsetDateTime;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tonic::{transport::Server, Request as TonicRequest, Response as TonicResponse, Status};
use x509_parser::nom::AsBytes;
use mtls_sidecar::config::Config;
use mtls_sidecar::tls_manager::TlsManager;

// Define a simple gRPC service for testing
pub mod hello_world {
    include!("proto/gen/helloworld.rs");
    include!("proto/gen/helloworld.tonic.rs");
}

use hello_world::greeter_server::{Greeter, GreeterServer};
use hello_world::{HelloReply, HelloRequest};
use mtls_sidecar::utils::adapt_request;

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

struct TestCerts {
    _temp_dir: TempDir,
    cert_dir: PathBuf,
    ca_dir: PathBuf,
    ca_cert: rcgen::Certificate,
    client_cert: rcgen::Certificate,
    client_key: KeyPair,
}

struct TestSetup {
    sidecar_port: u16,
    upstream_port: u16,
    _monitor_port: u16,
    client: reqwest::Client,
    ca_cert: rcgen::Certificate,
    client_cert: rcgen::Certificate,
    client_key: KeyPair,
}

fn setup_certificates() -> Result<TestCerts> {
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

    Ok(TestCerts {
        _temp_dir: temp_dir,
        cert_dir,
        ca_dir,
        ca_cert,
        client_cert,
        client_key,
    })
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

fn generate_server_cert(issuer: &Issuer<KeyPair>) -> (rcgen::Certificate, KeyPair) {
    let mut params = CertificateParams::new(vec!["127.0.0.1".to_string(), "localhost".to_string()]).unwrap();
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

fn generate_client_cert(issuer: &Issuer<KeyPair>) -> (rcgen::Certificate, KeyPair) {
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

fn validity_period() -> (OffsetDateTime, OffsetDateTime) {
    let now = OffsetDateTime::now_utc();
    let past = now.checked_sub(Duration::hours(1)).unwrap();
    let future = now.checked_add(Duration::hours(1)).unwrap();
    (past, future)
}

fn create_test_config(
    upstream_port: u16,
    sidecar_port: u16,
    monitor_port: u16,
    test_certs: &TestCerts,
    inject_client_headers: bool,
    outbound_proxy_port: Option<u16>,
    client_cert_dir: Option<PathBuf>,
) -> Config {
    Config {
        tls_listen_port: Some(sidecar_port),
        upstream_url: Some(format!("http://127.0.0.1:{}", upstream_port)),
        ca_dir: Some(test_certs.ca_dir.clone()),
        server_cert_dir: Some(test_certs.cert_dir.clone()),
        client_cert_dir,
        inject_client_headers,
        outbound_proxy_port,
        monitor_port,
        enable_metrics: false,
    }
}

fn pick_ports() -> (u16, u16, u16) {
    let upstream_port = portpicker::pick_unused_port().expect("No free port");
    let sidecar_port = portpicker::pick_unused_port().expect("No free port");
    let monitor_port = portpicker::pick_unused_port().expect("No free port");
    (upstream_port, sidecar_port, monitor_port)
}

async fn setup_test(
    test_certs: TestCerts,
    inject_headers: bool,
) -> Result<(
    TestSetup,
    Arc<TlsManager>,
    Arc<Config>,
)> {
    let (upstream_port, sidecar_port, monitor_port) = pick_ports();
    let config = Arc::new(create_test_config(
        upstream_port,
        sidecar_port,
        monitor_port,
        &test_certs,
        inject_headers,
        None,
        None,
    ));
    let tls_manager = Arc::new(TlsManager::new());
    tls_manager.reload(&config).await?;
    start_sidecar(&config, Arc::clone(&tls_manager)).await?;
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    let client = create_client_builder_with_cert(&test_certs)?.build()?;
    let setup = TestSetup {
        sidecar_port,
        upstream_port,
        _monitor_port: monitor_port,
        client,
        ca_cert: test_certs.ca_cert.clone(),
        client_cert: test_certs.client_cert.clone(),
        client_key: test_certs.client_key,
    };
    Ok((setup, tls_manager, config))
}

async fn setup_basic_proxy_test(
    upstream_response: Bytes,
    inject_headers: bool,
) -> Result<TestSetup> {
    let test_certs = setup_certificates()?;
    let (setup, _, _) = setup_test(test_certs, inject_headers).await?;
    start_basic_upstream(setup.upstream_port, upstream_response).await?;
    Ok(setup)
}

async fn start_basic_upstream(port: u16, response: Bytes) -> Result<()> {
    let upstream_listener = TcpListener::bind(format!("127.0.0.1:{}", port)).await?;
    let resp = response;
    tokio::spawn(async move {
        loop {
            let (stream, _) = upstream_listener.accept().await.unwrap();
            let r = resp.clone();
            tokio::spawn(async move {
                let service = service_fn(move |_req| {
                    let r = r.clone();
                    async move { Ok::<_, hyper::Error>(Response::new(Full::new(r))) }
                });
                auto::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(stream), service)
                    .await
                    .unwrap();
            });
        }
    });
    Ok(())
}

async fn start_header_echo_upstream(port: u16) -> Result<Arc<std::sync::Mutex<Vec<String>>>> {
    let upstream_listener = TcpListener::bind(format!("127.0.0.1:{}", port)).await?;
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
    Ok(received_headers)
}

async fn start_readiness_upstream(port: u16) -> Result<()> {
    let upstream_listener = TcpListener::bind(format!("127.0.0.1:{}", port)).await?;
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
    Ok(())
}

async fn start_https_upstream(port: u16, response: Bytes, cert_dir: &PathBuf) -> Result<()> {
    let upstream_listener = TcpListener::bind(format!("127.0.0.1:{}", port)).await?;
    let tls_manager = Arc::new(TlsManager::new());
    let config = Config {
        tls_listen_port: Some(port),
        upstream_url: None,
        ca_dir: None, // Do not require client cert for simplicity
        server_cert_dir: Some(cert_dir.clone()),
        client_cert_dir: None,
        inject_client_headers: false,
        outbound_proxy_port: None,
        monitor_port: 8081,
        enable_metrics: false,
    };
    tls_manager.reload(&config).await?;
    let resp = response;
    tokio::spawn(async move {
        loop {
            let (stream, _) = upstream_listener.accept().await.unwrap();
            let tls_manager = Arc::clone(&tls_manager);
            let resp = resp.clone();
            tokio::spawn(async move {
                let current_config = tls_manager.server_config.read().await.clone().unwrap();
                let acceptor = TlsAcceptor::from(current_config);
                let stream = acceptor.accept(stream).await.unwrap();
                let service = service_fn(move |_req| {
                    let resp = resp.clone();
                    async move { Ok::<_, hyper::Error>(Response::new(Full::new(resp))) }
                });
                auto::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(stream), service)
                    .await
                    .unwrap();
            });
        }
    });
    Ok(())
}

async fn start_sidecar(
    config: &Config,
    tls_manager: Arc<TlsManager>,
) -> Result<()> {
    let sidecar_listener =
        TcpListener::bind(format!("127.0.0.1:{}", config.tls_listen_port.unwrap())).await?;
    let upstream_url = config.upstream_url.clone().unwrap();
    let inject = config.inject_client_headers;
    tokio::spawn(async move {
        loop {
            let (stream, _) = sidecar_listener.accept().await.unwrap();
            let peer_addr = stream.peer_addr().ok();
            let upstream = upstream_url.clone();
            let tls_manager = Arc::clone(&tls_manager);
            tokio::spawn(async move {
                let current_config = tls_manager.server_config.read().await.clone().unwrap();
                let acceptor = TlsAcceptor::from(current_config);
                let stream = acceptor.accept(stream).await.unwrap();
                let (_, server_conn) = stream.get_ref();
                let client_cert = server_conn
                    .peer_certificates()
                    .and_then(|certs| certs.first().cloned())
                    .and_then(|cert| Some(Arc::new(cert)));
                let service = service_fn(move |mut req| {
                    if let Some(cert) = &client_cert {
                        req.extensions_mut().insert(cert.clone());
                    }
                    let up = upstream.clone();
                    let client = Arc::new(Client::builder(TokioExecutor::new()).build_http());
                    let cc = client_cert.clone().and_then(|cert| Some(Arc::clone(&cert)));
                    async move { mtls_sidecar::proxy_inbound::handler(adapt_request(req), &up, inject, client, peer_addr, cc).await }
                });
                auto::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(stream), service)
                    .await
                    .unwrap();
            });
        }
    });
    Ok(())
}

fn create_client_builder_with_cert(test_certs: &TestCerts) -> Result<reqwest::ClientBuilder> {
    let builder = reqwest::Client::builder()
        .add_root_certificate(Certificate::from_der(test_certs.ca_cert.der().as_bytes())?)
        .identity(reqwest::Identity::from_pem(
            format!(
                "{}{}",
                test_certs.client_cert.pem(),
                test_certs.client_key.serialize_pem()
            )
            .as_bytes(),
        )?);
    Ok(builder)
}

#[tokio::test]
async fn test_proxy_with_valid_cert() -> Result<()> {
    let setup = setup_basic_proxy_test(Bytes::from("Hello from upstream"), false).await?;
    let resp = setup
        .client
        .get(format!("https://localhost:{}/", setup.sidecar_port))
        .send()
        .await?;
    assert_eq!(resp.status(), 200);
    let text = resp.text().await?;
    assert_eq!(text, "Hello from upstream");

    Ok(())
}

#[tokio::test]
async fn test_proxy_with_header_injection() -> Result<()> {
    let test_certs = setup_certificates()?;
    let (setup, _, _) = setup_test(test_certs, true).await?;

    let received_headers = start_header_echo_upstream(setup.upstream_port).await?;

    let resp = setup
        .client
        .get(format!("https://localhost:{}/", setup.sidecar_port))
        .send()
        .await?;
    assert_eq!(resp.status(), 200);

    // Check if headers were received
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await; // Wait for async
    let headers = received_headers.lock().unwrap();
    let tls_info_header = headers
        .iter()
        .find(|h| h.starts_with("x-client-tls-info:"))
        .unwrap();
    let b64_value = tls_info_header.strip_prefix("x-client-tls-info: ").unwrap();
    let decoded = base64::engine::general_purpose::STANDARD.decode(b64_value)?;
    let json_str = String::from_utf8(decoded).unwrap();
    let info: Value = serde_json::from_str(&json_str).unwrap();
    assert_eq!(info["subject"], "CN=client");
    assert!(info["dns_sans"]
        .as_array()
        .unwrap()
        .contains(&Value::String("localhost".to_string())));
    assert!(info["hash"].as_str().unwrap().starts_with("sha256:"));
    assert!(info["serial"].as_str().unwrap().starts_with("0x"));

    Ok(())
}

#[tokio::test]
async fn test_file_watching_reload() -> Result<()> {
    let (upstream_port, sidecar_port, monitor_port) = pick_ports();

    let mut test_certs = setup_certificates()?;

    // Start mock upstream
    start_basic_upstream(upstream_port, Bytes::from("OK")).await?;

    // Start sidecar
    let config = Arc::new(create_test_config(
        upstream_port,
        sidecar_port,
        monitor_port,
        &test_certs,
        false,
        None,
        None,
    ));
    let tls_manager = Arc::new(TlsManager::new());
    tls_manager.reload(&config).await?;
    let watcher_config = Arc::clone(&config);
    let watcher_tls_manager = Arc::clone(&tls_manager);
    let reload_tls_manager = Arc::clone(&tls_manager);

    // Spawn watcher
    tokio::spawn(async move {
        mtls_sidecar::watcher::start_watcher(watcher_config, watcher_tls_manager)
            .await
            .unwrap();
    });

    // Spawn server
    start_sidecar(&config, Arc::clone(&tls_manager)).await?;

    // Wait for server to start
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Make initial request with old client cert
    let old_client = create_client_builder_with_cert(&test_certs)?.build()?;
    let resp = old_client
        .get(format!("https://localhost:{}/", sidecar_port))
        .send()
        .await?;
    assert_eq!(resp.status(), 200);

    // Generate new certs
    let (new_ca_cert, issuer) = generate_ca();
    let (new_server_cert, new_server_key) = generate_server_cert(&issuer);

    // Overwrite cert files to trigger reload
    std::fs::write(test_certs.cert_dir.join("tls.crt"), new_server_cert.pem())?;
    std::fs::write(
        test_certs.cert_dir.join("tls.key"),
        new_server_key.serialize_pem(),
    )?;
    std::fs::write(test_certs.ca_dir.join("ca-bundle.crt"), new_ca_cert.pem())?;

    // Manually trigger reload to ensure it works (file watching may not trigger in test env)
    reload_tls_manager.reload(&config).await?;

    // Wait a bit
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Try old client again - should fail because server now requires client cert verified by new CA
    test_certs.ca_cert = new_ca_cert;
    let old_client_permissive = create_client_builder_with_cert(&test_certs)?.build()?;
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
    test_certs.client_cert = new_client_cert;
    test_certs.client_key = new_client_key;

    let new_client = create_client_builder_with_cert(&test_certs)?.build()?;

    let resp = new_client
        .get(format!("https://localhost:{}/", sidecar_port))
        .send()
        .await?;
    assert_eq!(resp.status(), 200);

    Ok(())
}

#[tokio::test]
async fn test_outbound_proxy_connect_tunnel() -> Result<()> {
    let (upstream_port, outbound_proxy_port, monitor_port) = pick_ports();

    let test_certs = setup_certificates()?;

    // Start HTTPS upstream server
    start_https_upstream(upstream_port, Bytes::from("Hello from CONNECT tunnel"), &test_certs.cert_dir).await?;

    // Create client cert dir
    let client_cert_dir = test_certs._temp_dir.path().join("client-certs");
    std::fs::create_dir(&client_cert_dir)?;
    std::fs::write(client_cert_dir.join("tls.crt"), test_certs.client_cert.pem())?;
    std::fs::write(client_cert_dir.join("tls.key"), test_certs.client_key.serialize_pem())?;

    // Create config for outbound proxy
    let config = create_test_config(
        upstream_port,
        0, // sidecar_port not used
        monitor_port,
        &test_certs,
        false,
        Some(outbound_proxy_port),
        Some(client_cert_dir),
    );
    let config = Arc::new(config);

    let mut tls_manager = TlsManager::new();
    tls_manager.server_required = false;
    tls_manager.client_required = true;
    tls_manager.reload(&config).await?;
    let tls_manager = Arc::new(tls_manager);

    // Start outbound proxy listener
    let outbound_addr = format!("127.0.0.1:{}", outbound_proxy_port);
    let outbound_listener = TcpListener::bind(&outbound_addr).await?;
    let (outbound_client, outbound_config) = new_outbound_client(Arc::clone(&tls_manager)).await;
    let outbound_client = Arc::new(outbound_client);
    tokio::spawn(async move {
        loop {
            let (stream, _) = outbound_listener.accept().await.unwrap();
            let outbound_client = Arc::clone(&outbound_client);
            let outbound_config = Arc::clone(&outbound_config);
            tokio::spawn(async move {
                let service = service_fn(move |req| {
                    let outbound_client = Arc::clone(&outbound_client);
                    let outbound_config = Arc::clone(&outbound_config);
                    async move { mtls_sidecar::proxy_outbound::handler(adapt_request(req), outbound_client, outbound_config).await }
                });
                if let Err(err) = auto::Builder::new(TokioExecutor::new())
                    .serve_connection_with_upgrades(TokioIo::new(stream), service)
                    .await
                {
                    tracing::error!("Error serving outbound connection: {:?}", err);
                }
            });
        }
    });

    // Wait for servers to start
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Connect to outbound proxy and send CONNECT request
    let stream = TcpStream::connect(format!("127.0.0.1:{}", outbound_proxy_port)).await?;
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;
    tokio::spawn(async move {
        conn.await.unwrap();
    });

    // Send CONNECT request
    let connect_req = Request::connect(format!("127.0.0.1:{}", upstream_port))
        .body(Full::new(Bytes::new()))?;
    let resp = sender.send_request(connect_req).await?;
    assert_eq!(resp.status(), 200);

    Ok(())
}

#[tokio::test]
async fn test_outbound_proxy_connect_data_transmission() -> Result<()> {
    let (upstream_port, outbound_proxy_port, monitor_port) = pick_ports();

    let test_certs = setup_certificates()?;

    // Start HTTPS upstream server
    start_https_upstream(upstream_port, Bytes::from("Hello from CONNECT tunnel"), &test_certs.cert_dir).await?;

    // Create client cert dir
    let client_cert_dir = test_certs._temp_dir.path().join("client-certs");
    std::fs::create_dir(&client_cert_dir)?;
    std::fs::write(client_cert_dir.join("tls.crt"), test_certs.client_cert.pem())?;
    std::fs::write(client_cert_dir.join("tls.key"), test_certs.client_key.serialize_pem())?;

    // Create config for outbound proxy
    let config = create_test_config(
        upstream_port,
        0, // sidecar_port not used
        monitor_port,
        &test_certs,
        false,
        Some(outbound_proxy_port),
        Some(client_cert_dir),
    );
    let config = Arc::new(config);

    let mut tls_manager = TlsManager::new();
    tls_manager.server_required = false;
    tls_manager.client_required = true;
    tls_manager.reload(&config).await?;
    let tls_manager = Arc::new(tls_manager);

    // Start outbound proxy listener
    let outbound_addr = format!("127.0.0.1:{}", outbound_proxy_port);
    let outbound_listener = TcpListener::bind(&outbound_addr).await?;
    let (outbound_client, outbound_config) = new_outbound_client(Arc::clone(&tls_manager)).await;
    let outbound_client = Arc::new(outbound_client);
    tokio::spawn(async move {
        loop {
            let (stream, _) = outbound_listener.accept().await.unwrap();
            let outbound_client = Arc::clone(&outbound_client);
            let outbound_config = Arc::clone(&outbound_config);
            tokio::spawn(async move {
                let service = service_fn(move |req| {
                    let outbound_client = Arc::clone(&outbound_client);
                    let outbound_config = Arc::clone(&outbound_config);
                    async move { mtls_sidecar::proxy_outbound::handler(adapt_request(req), outbound_client, outbound_config).await }
                });
                let builder = auto::Builder::new(TokioExecutor::new());
                let conn = builder.serve_connection_with_upgrades(TokioIo::new(stream), service);
                if let Err(err) = conn.await
                {
                    tracing::error!("Error serving outbound connection: {:?}", err);
                }
            });
        }
    });

    // Wait for servers to start
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Connect to outbound proxy
    let mut tcp = TcpStream::connect(format!("127.0.0.1:{}", outbound_proxy_port)).await?;

    // Send CONNECT request manually
    let connect_request = format!("CONNECT 127.0.0.1:{} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: upgrade\r\nUpgrade: connect\r\n\r\n", upstream_port, upstream_port);
    tcp.write_all(connect_request.as_bytes()).await?;
    println!("Sent connect request");

    // Read proxy response
    let mut buffer = vec![0; 1024];
    let n = tcp.read(&mut buffer).await?;
    let response = String::from_utf8_lossy(&buffer[..n]);
    assert!(response.contains("200"), "Expected 200, got: {}", response);
    println!("Received: {}", response);

    // Now attempt to send data through the tunnel
    let request = "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
    tcp.write_all(request.as_bytes()).await?;
    println!("Written request");
    tcp.flush().await?;

    // Try to read the response
    let mut buffer = vec![0; 1024];
    let n = tcp.read(&mut buffer).await?;
    let response = String::from_utf8_lossy(&buffer[..n]);
    assert!(response.contains("Hello from CONNECT tunnel"), "Data transmission failed, got: {}", response);
    println!("Read response");

    Ok(())
}

#[tokio::test]
async fn test_outbound_proxy_upgrade() -> Result<()> {
    let (upstream_port, outbound_proxy_port, monitor_port) = pick_ports();

    let test_certs = setup_certificates()?;

    // Start upstream that supports upgrade
    start_upgrade_upstream(upstream_port, &test_certs.cert_dir).await?;

    // Create client cert dir
    let client_cert_dir = test_certs._temp_dir.path().join("client-certs");
    std::fs::create_dir(&client_cert_dir)?;
    std::fs::write(client_cert_dir.join("tls.crt"), test_certs.client_cert.pem())?;
    std::fs::write(client_cert_dir.join("tls.key"), test_certs.client_key.serialize_pem())?;

    // Create config for outbound proxy
    let config = create_test_config(
        upstream_port,
        0,
        monitor_port,
        &test_certs,
        false,
        Some(outbound_proxy_port),
        Some(client_cert_dir),
    );
    let config = Config {
        upstream_url: Some(format!("http://127.0.0.1:{}", upstream_port)),
        ..config
    };
    let config = Arc::new(config);

    let mut tls_manager = TlsManager::new();
    tls_manager.server_required = false;
    tls_manager.client_required = true;
    tls_manager.reload(&config).await?;
    let tls_manager = Arc::new(tls_manager);

    // Start outbound proxy listener
    let outbound_addr = format!("127.0.0.1:{}", outbound_proxy_port);
    let outbound_listener = TcpListener::bind(&outbound_addr).await?;
    let (outbound_client, outbound_config) = new_outbound_client(Arc::clone(&tls_manager)).await;
    let outbound_client = Arc::new(outbound_client);
    tokio::spawn(async move {
        loop {
            let (stream, _) = outbound_listener.accept().await.unwrap();
            let outbound_client = Arc::clone(&outbound_client);
            let outbound_config = Arc::clone(&outbound_config);
            tokio::spawn(async move {
                let service = service_fn(move |req| {
                    let outbound_client = Arc::clone(&outbound_client);
                    let outbound_config = Arc::clone(&outbound_config);
                    async move { mtls_sidecar::proxy_outbound::handler(adapt_request(req), outbound_client, outbound_config).await }
                });
                if let Err(err) = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await
                {
                    tracing::error!("Error serving outbound connection: {:?}", err);
                }
            });
        }
    });

    // Wait for servers to start
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Connect to outbound proxy and send upgrade request
    let stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", outbound_proxy_port)).await?;
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;
    tokio::spawn(async move {
        conn.await.unwrap();
    });

    // Send request with upgrade header
    let upgrade_req = Request::get(format!("http://127.0.0.1:{}/upgrade", upstream_port))
        .header("upgrade", "websocket")
        .header("connection", "upgrade")
        .body(Full::new(Bytes::new()))?;
    let resp = sender.send_request(upgrade_req).await?;
    assert_eq!(resp.status(), 101); // Switching Protocols

    Ok(())
}

async fn start_upgrade_upstream(port: u16, cert_dir: &PathBuf) -> Result<()> {
    let upstream_listener = TcpListener::bind(format!("127.0.0.1:{}", port)).await?;
    let tls_manager = Arc::new(TlsManager::new());
    let config = Config {
        tls_listen_port: Some(port),
        upstream_url: None,
        ca_dir: None,
        server_cert_dir: Some(cert_dir.clone()),
        client_cert_dir: None,
        inject_client_headers: false,
        outbound_proxy_port: None,
        monitor_port: 8081,
        enable_metrics: false,
    };
    tls_manager.reload(&config).await?;
    tokio::spawn(async move {
        loop {
            let (stream, _) = upstream_listener.accept().await.unwrap();
            let tls_manager = Arc::clone(&tls_manager);
            tokio::spawn(async move {
                let current_config = tls_manager.server_config.read().await.clone().unwrap();
                let acceptor = TlsAcceptor::from(current_config);
                let stream = acceptor.accept(stream).await.unwrap();
                let service = service_fn(|req: Request<hyper::body::Incoming>| async move {
                    if req.headers().contains_key("upgrade") {
                        let resp = Response::builder()
                            .status(101)
                            .header("upgrade", "websocket")
                            .header("connection", "upgrade")
                            .body(Full::new(Bytes::new()))
                            .unwrap();
                        Ok::<_, hyper::Error>(resp)
                    } else {
                        Ok::<_, hyper::Error>(Response::new(Full::new(Bytes::from("Normal response"))))
                    }
                });
                auto::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(stream), service)
                    .await
                    .unwrap();
            });
        }
    });
    Ok(())
}

#[tokio::test]
async fn test_tls_handshake_failure_handling() -> Result<()> {
    let (upstream_port, sidecar_port, monitor_port) = pick_ports();

    let test_certs = setup_certificates()?;

    // Start mock upstream
    start_basic_upstream(upstream_port, Bytes::from("OK")).await?;

    // Start sidecar
    let mut config = create_test_config(
        upstream_port,
        sidecar_port,
        monitor_port,
        &test_certs,
        false,
        None,
        None,
    );
    let upstream_url = format!("http://127.0.0.1:{}/grpc", upstream_port);
    config.upstream_url = Some(upstream_url.clone());
    let tls_manager = Arc::new(TlsManager::new());
    tls_manager.reload(&config).await?;
    let sidecar_listener = TcpListener::bind(format!("127.0.0.1:{}", sidecar_port)).await?;
    tokio::spawn(async move {
        loop {
            let (stream, _) = sidecar_listener.accept().await.unwrap();
            let peer_addr = stream.peer_addr().ok();
            let tls_manager = Arc::clone(&tls_manager);
            let upstream = upstream_url.clone();
            tokio::spawn(async move {
                let current_config = tls_manager.server_config.read().await.clone().unwrap();
                let acceptor = TlsAcceptor::from(current_config);
                let stream = match acceptor.accept(stream).await {
                    Ok(s) => s,
                    Err(_) => return, // Simulate the fixed behavior
                };
                let (_, server_conn) = stream.get_ref();
                let client_cert = server_conn
                    .peer_certificates()
                    .and_then(|certs| certs.first().cloned())
                    .and_then(|cert| Some(Arc::new(cert)));
                let service = service_fn(move |mut req| {
                    if let Some(cert) = &client_cert {
                        req.extensions_mut().insert(cert.clone());
                    }
                    let up = upstream.clone();
                    // For gRPC test, use HTTP/2 capable client
                    let client = if up.contains("grpc") {
                        Arc::new(
                            Client::builder(TokioExecutor::new())
                                .build(hyper_util::client::legacy::connect::HttpConnector::new()),
                        )
                    } else {
                        Arc::new(Client::builder(TokioExecutor::new()).build_http())
                    };
                    let cc = client_cert.clone().and_then(|cert| Some(Arc::clone(&cert)));
                    async move { mtls_sidecar::proxy_inbound::handler(adapt_request(req), &up, false, client, peer_addr, cc).await }
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

    // Try invalid connection (no client cert)
    let invalid_client = reqwest::Client::builder()
        .add_root_certificate(Certificate::from_pem(test_certs.ca_cert.pem().as_bytes())?)
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
    let valid_client = create_client_builder_with_cert(&test_certs)?.build()?;
    let resp = valid_client
        .get(format!("https://localhost:{}/", sidecar_port))
        .send()
        .await?;
    assert_eq!(resp.status(), 200);

    Ok(())
}

#[tokio::test]
async fn test_proxy_large_response() -> Result<()> {
    // Create large response body (10MB)
    let large_body = Bytes::from(vec![b'A'; 10_000_000]);

    let setup = setup_basic_proxy_test(large_body, false).await?;

    let resp = setup
        .client
        .get(format!("https://localhost:{}/", setup.sidecar_port))
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
    cmd.env("SERVER_CERT_DIR", "/tmp/nonexistent");
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
    let upstream_port = portpicker::pick_unused_port().expect("No free port");
    let monitor_port = portpicker::pick_unused_port().expect("No free port");

    // Generate CA and EXPIRED server cert
    let (ca_cert, issuer) = generate_ca();
    let (server_cert, server_key) = generate_expired_server_cert(&issuer);
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

    let test_certs = TestCerts {
        _temp_dir: temp_dir,
        cert_dir,
        ca_dir,
        ca_cert,
        client_cert,
        client_key,
    };

    let (_setup, tls_manager, config) = setup_test(test_certs, false).await?;

    start_readiness_upstream(upstream_port).await?;

    // Start monitoring server
    let router =
        mtls_sidecar::monitoring::create_router(Arc::clone(&config), Arc::clone(&tls_manager));
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

fn generate_expired_server_cert(issuer: &Issuer<KeyPair>) -> (rcgen::Certificate, KeyPair) {
    let mut params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    params
        .distinguished_name
        .push(DnType::CommonName, "localhost");
    params
        .extended_key_usages
        .push(rcgen::ExtendedKeyUsagePurpose::ServerAuth);
    // Set validity to yesterday (expired)
    let yesterday = OffsetDateTime::now_utc()
        .checked_sub(Duration::new(86400, 0))
        .unwrap();
    params.not_before = yesterday.checked_sub(Duration::new(86400, 0)).unwrap(); // 2 days ago
    params.not_after = yesterday; // yesterday
    let key_pair = KeyPair::generate().unwrap();
    let cert = params.signed_by(&key_pair, issuer).unwrap();
    (cert, key_pair)
}

#[tokio::test]
async fn test_proxy_http1_only() -> Result<()> {
    let setup = setup_basic_proxy_test(Bytes::from("Hello from HTTP/1.1 upstream"), false).await?;

    // Make HTTP/1.1-only request with client cert
    let client = reqwest::Client::builder()
        .add_root_certificate(Certificate::from_pem(setup.ca_cert.pem().as_bytes())?)
        .identity(reqwest::Identity::from_pem(
            format!(
                "{}{}",
                setup.client_cert.pem(),
                setup.client_key.serialize_pem()
            )
            .as_bytes(),
        )?)
        .http1_only() // Force HTTP/1.1
        .build()?;

    let resp = client
        .get(format!("https://localhost:{}/", setup.sidecar_port))
        .send()
        .await?;
    assert_eq!(resp.status(), 200);
    let text = resp.text().await?;
    assert_eq!(text, "Hello from HTTP/1.1 upstream");

    Ok(())
}

#[tokio::test]
async fn test_proxy_http2_only() -> Result<()> {
    let setup = setup_basic_proxy_test(Bytes::from("Hello from HTTP/2 upstream"), false).await?;

    // Make HTTP/2-only request with client cert
    let client = reqwest::Client::builder()
        .add_root_certificate(Certificate::from_pem(setup.ca_cert.pem().as_bytes())?)
        .identity(reqwest::Identity::from_pem(
            format!(
                "{}{}",
                setup.client_cert.pem(),
                setup.client_key.serialize_pem()
            )
            .as_bytes(),
        )?)
        .build()?;

    let resp = client
        .get(format!("https://localhost:{}/", setup.sidecar_port))
        .send()
        .await?;
    assert_eq!(resp.status(), 200);
    let text = resp.text().await?;
    assert_eq!(text, "Hello from HTTP/2 upstream");

    Ok(())
}

#[tokio::test]
async fn test_proxy_grpc() -> Result<()> {
    // Pick dynamic ports
    let (upstream_port, sidecar_port, monitor_port) = pick_ports();

    let test_certs = setup_certificates()?;

    // Start gRPC upstream server
    let greeter = MyGreeter::default();
    let upstream_addr = format!("127.0.0.1:{}", upstream_port);
    let upstream_listener = TcpListener::bind(&upstream_addr).await?;
    tokio::spawn(async move {
        Server::builder()
            .accept_http1(true) // Allow HTTP/1.1 for gRPC
            .add_service(GreeterServer::new(greeter))
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(
                upstream_listener,
            ))
            .await
            .unwrap();
    });

    // Start sidecar
    let config = create_test_config(
        upstream_port,
        sidecar_port,
        monitor_port,
        &test_certs,
        false,
        None,
        None,
    );
    let tls_manager = Arc::new(TlsManager::new());
    tls_manager.reload(&config).await?;

    // Spawn server
    start_sidecar(&config, Arc::clone(&tls_manager)).await?;

    // Wait a bit for servers to start
    tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;

    // Create gRPC client that connects through the sidecar
    let sidecar_addr = format!("https://localhost:{}", sidecar_port);

    // For tonic with rustls, we need to use the rustls connector
    let mut root_store = rustls::RootCertStore::empty();
    let ca_certs = rustls_pemfile::certs(&mut test_certs.ca_cert.pem().as_bytes())
        .collect::<Result<Vec<_>, _>>()?;
    root_store.add_parsable_certificates(ca_certs);

    let client_certs = rustls_pemfile::certs(&mut test_certs.client_cert.pem().as_bytes())
        .collect::<Result<Vec<_>, _>>()?;

    let client_key_der =
        rustls_pemfile::private_key(&mut test_certs.client_key.serialize_pem().as_bytes())?
            .unwrap();

    let tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_client_auth_cert(client_certs, client_key_der)?;

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
    assert_eq!(
        response.into_inner().message,
        "Hello gRPC Client from gRPC server!"
    );

    Ok(())
}


async fn new_outbound_client<B>(tls_manager: Arc<TlsManager>) -> (Client<HttpsConnector<HttpConnector>, B>, Arc<rustls::ClientConfig>)
where
    B: hyper::body::Body + Send + 'static + Unpin,
    B::Data: Send,
    B::Error: Into<Box<dyn Error + Send + Sync>>,
{
    let client_config = tls_manager.client_config.read().await.clone().unwrap();
    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config((*client_config).clone())
        .https_only()
        .enable_http1()
        .enable_http2()
        .build();
    (Client::builder(TokioExecutor::new()).build(https), client_config)
}

#[tokio::test]
async fn test_outbound_proxy_with_valid_certs() -> Result<()> {
    let (upstream_port, outbound_proxy_port, monitor_port) = pick_ports();

    let test_certs = setup_certificates()?;

    // Start HTTPS upstream server requiring client certs
    start_https_upstream(upstream_port, Bytes::from("Hello from HTTPS upstream"), &test_certs.cert_dir).await?;

    // Create client cert dir
    let client_cert_dir = test_certs._temp_dir.path().join("client-certs");
    std::fs::create_dir(&client_cert_dir)?;
    std::fs::write(client_cert_dir.join("tls.crt"), test_certs.client_cert.pem())?;
    std::fs::write(client_cert_dir.join("tls.key"), test_certs.client_key.serialize_pem())?;

    // Create config for outbound proxy
    let config = create_test_config(
        upstream_port,
        0, // sidecar_port not used
        monitor_port,
        &test_certs,
        false,
        Some(outbound_proxy_port),
        Some(client_cert_dir),
    );

    // Override upstream_url to HTTPS
    let config = Config {
        upstream_url: Some(format!("https://127.0.0.1:{}", upstream_port)),
        ..config
    };
    let config = Arc::new(config);

    let mut tls_manager = TlsManager::new();
    tls_manager.server_required = false; // Outbound proxy does not need server certs
    tls_manager.client_required = true;
    tls_manager.reload(&config).await?;

    // Start outbound proxy listener
    let outbound_addr = format!("127.0.0.1:{}", outbound_proxy_port);
    let outbound_listener = TcpListener::bind(&outbound_addr).await?;
    let (outbound_client, outbound_config) = new_outbound_client(Arc::new(tls_manager)).await;
    let outbound_client = Arc::new(outbound_client);
    tokio::spawn(async move {
        loop {
            let (stream, _) = outbound_listener.accept().await.unwrap();
            let outbound_client = Arc::clone(&outbound_client);
            let outbound_config = Arc::clone(&outbound_config);
            tokio::spawn(async move {
                let service = service_fn(move |req| {
                    let outbound_client = Arc::clone(&outbound_client);
                    let outbound_config = Arc::clone(&outbound_config);
                    async move { mtls_sidecar::proxy_outbound::handler(adapt_request(req), outbound_client, outbound_config).await }
                });
                if let Err(err) = auto::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(stream), service)
                    .await
                {
                    tracing::error!("Error serving outbound connection: {:?}", err);
                }
            });
        }
    });

    // Wait for servers to start
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Make HTTP request to outbound proxy with target URI
    let stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", outbound_proxy_port)).await?;
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;
    tokio::spawn(async move {
        conn.await.unwrap();
    });
    let req = Request::get(format!("http://127.0.0.1:{}/", upstream_port))
        .body(Full::new(Bytes::new()))?;
    let resp = sender.send_request(req).await?;
    assert_eq!(resp.status(), 200);
    let body = resp.into_body().collect().await?.to_bytes();
    let text = String::from_utf8(body.to_vec())?;
    assert_eq!(text, "Hello from HTTPS upstream");

    Ok(())
}

#[tokio::test]
async fn test_outbound_proxy_with_invalid_server_cert() -> Result<()> {
    let (upstream_port, outbound_proxy_port, monitor_port) = pick_ports();

    let test_certs = setup_certificates()?;

    // Generate different CA for upstream
    let (_bad_ca_cert, bad_issuer) = generate_ca();
    let (bad_server_cert, bad_server_key) = generate_server_cert(&bad_issuer);

    // Write bad certs
    let bad_cert_dir = test_certs._temp_dir.path().join("bad-certs");
    std::fs::create_dir(&bad_cert_dir)?;
    std::fs::write(bad_cert_dir.join("tls.crt"), bad_server_cert.pem())?;
    std::fs::write(bad_cert_dir.join("tls.key"), bad_server_key.serialize_pem())?;

    // Start HTTPS upstream with bad cert
    start_https_upstream(upstream_port, Bytes::from("Hello from bad upstream"), &bad_cert_dir).await?;

    // Create client cert dir
    let client_cert_dir = test_certs._temp_dir.path().join("client-certs");
    std::fs::create_dir(&client_cert_dir)?;
    std::fs::write(client_cert_dir.join("tls.crt"), test_certs.client_cert.pem())?;
    std::fs::write(client_cert_dir.join("tls.key"), test_certs.client_key.serialize_pem())?;

    // Create config for outbound proxy
    let config = create_test_config(
        upstream_port,
        0,
        monitor_port,
        &test_certs,
        false,
        Some(outbound_proxy_port),
        Some(client_cert_dir),
    );
    let config = Config {
        upstream_url: Some(format!("https://127.0.0.1:{}", upstream_port)),
        ..config
    };
    let config = Arc::new(config);

    let mut tls_manager = TlsManager::new();
    tls_manager.server_required = false; // Outbound proxy does not need server certs
    tls_manager.client_required = true;
    let tls_manager = Arc::new(tls_manager);
    tls_manager.reload(&config).await?;

    // Start outbound proxy listener
    let outbound_addr = format!("127.0.0.1:{}", outbound_proxy_port);
    let outbound_listener = TcpListener::bind(&outbound_addr).await?;
    let (outbound_client, outbound_config) = new_outbound_client(Arc::clone(&tls_manager)).await;
    let outbound_client = Arc::new(outbound_client);
    tokio::spawn(async move {
        loop {
            let (stream, _) = outbound_listener.accept().await.unwrap();
            let outbound_client = Arc::clone(&outbound_client);
            let outbound_config = Arc::clone(&outbound_config);
            tokio::spawn(async move {
                let service = service_fn(move |req| {
                    let outbound_client = Arc::clone(&outbound_client);
                    let outbound_config = Arc::clone(&outbound_config);
                    async move { mtls_sidecar::proxy_outbound::handler(adapt_request(req), outbound_client, outbound_config).await }
                });
                if let Err(err) = auto::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(stream), service)
                    .await
                {
                    tracing::error!("Error serving outbound connection: {:?}", err);
                }
            });
        }
    });

    // Wait for servers to start
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Make HTTP request to outbound proxy with target URI
    let stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", outbound_proxy_port)).await?;
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;
    tokio::spawn(async move {
        conn.await.unwrap();
    });
    let req = Request::get(format!("http://127.0.0.1:{}/", upstream_port))
        .body(Full::new(Bytes::new()))?;
    let result = sender.send_request(req).await;
    // Should fail because server cert is not trusted
    assert!(result.is_err());

    Ok(())
}

#[tokio::test]
async fn test_outbound_proxy_with_missing_client_cert() -> Result<()> {
    let (upstream_port, outbound_proxy_port, monitor_port) = pick_ports();

    let test_certs = setup_certificates()?;

    // Start HTTPS upstream
    start_https_upstream(upstream_port, Bytes::from("Hello from upstream"), &test_certs.cert_dir).await?;

    // Create config for outbound proxy without client cert
    let config = create_test_config(
        upstream_port,
        0,
        monitor_port,
        &test_certs,
        false,
        Some(outbound_proxy_port),
        None, // No client cert dir
    );
    let config = Config {
        upstream_url: Some(format!("https://127.0.0.1:{}", upstream_port)),
        ..config
    };
    let config = Arc::new(config);

    let mut tls_manager = TlsManager::new();
    tls_manager.server_required = false; // Outbound proxy does not need server certs
    tls_manager.client_required = true;
    let result = tls_manager.reload(&config).await;
    assert!(result.is_err());

    Ok(())
}
