use anyhow::{Context, Error, Result};
use bytes::Bytes;
use http::{Request, StatusCode};
use http_body_util::combinators::BoxBody;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::client::legacy::{connect::HttpConnector, Client};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::signal::unix::{signal, SignalKind};
use tokio_rustls::TlsAcceptor;

use mtls_sidecar::error::{DomainError, DynError};
use mtls_sidecar::utils::adapt_request;
use mtls_sidecar::{config, monitoring, proxy_inbound, tls_manager, watcher};
use tls_manager::TlsManager;

fn setup_crypto_provider() {
    rustls::crypto::CryptoProvider::install_default(rustls::crypto::aws_lc_rs::default_provider())
        .expect("Failed to install rustls crypto provider");
}

fn setup_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .json()
        .init();
}

fn load_config() -> Result<Arc<config::Config>, Error> {
    let config = config::Config::from_env().context("Failed to load config")?;
    tracing::debug!("config = {:?}", config);
    Ok(Arc::new(config))
}

async fn create_tls_manager(config: &Arc<config::Config>) -> Result<Arc<TlsManager>, Error> {
    let mut tls_manager = TlsManager::new();
    if config.tls_listen_port.is_none() {
        tls_manager.server_required = false;
    }
    if config.outbound_proxy_port.is_some() {
        tls_manager.client_required = true;
    }
    tls_manager
        .reload(config)
        .await
        .context("Failed to load TLS config")?;
    tracing::info!("TLS loaded");
    Ok(Arc::new(tls_manager))
}

async fn start_watcher(config: Arc<config::Config>, tls_manager: Arc<TlsManager>) {
    tokio::spawn(async move {
        if let Err(e) = watcher::start_watcher(config, tls_manager).await {
            tracing::error!("Watcher error: {:?}", e);
        }
    });
}

async fn start_monitoring_server(
    config: Arc<config::Config>,
    tls_manager: Arc<TlsManager>,
) -> Result<(), Error> {
    if config.monitor_port != 0 {
        let router = monitoring::create_router(Arc::clone(&config), Arc::clone(&tls_manager));
        let addr = format!("0.0.0.0:{}", config.monitor_port);
        let listener = TcpListener::bind(&addr)
            .await
            .context(format!("Failed to bind monitor to {}", addr))?;
        tracing::info!("Monitoring server listening on {}", addr);
        tokio::spawn(async move {
            if let Err(e) = axum::serve(listener, router).await {
                tracing::error!("Monitoring server error: {:?}", e);
            }
        });
    }
    Ok(())
}

fn setup_signals() -> Result<(tokio::signal::unix::Signal, tokio::signal::unix::Signal), Error> {
    let sigterm = signal(SignalKind::terminate()).context("Failed to register SIGTERM handler")?;
    let sigint = signal(SignalKind::interrupt()).context("Failed to register SIGINT handler")?;
    Ok((sigterm, sigint))
}

async fn accept_outbound_connection(stream: TcpStream, tls_manager: Arc<TlsManager>) {
    // Create a new HTTP client with current TLS config for every connection;
    // this ensures that we always use the latest certs, with pooling still
    // effective for multiple requests over the same connection.
    let client_config = tls_manager.client_config.read().await.clone().unwrap();
    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config((*client_config).clone())
        .https_only()
        .enable_http1()
        .enable_http2()
        .build();
    let client = Arc::new(Client::builder(TokioExecutor::new()).build(https));

    // Handle connection
    let service = move |req: Request<Incoming>| {
        let client = Arc::clone(&client);
        let config = Arc::clone(&client_config);
        async move { mtls_sidecar::proxy_outbound::handler(adapt_request(req), client, config).await }
    };

    if let Err(err) = auto::Builder::new(TokioExecutor::new())
        .serve_connection_with_upgrades(TokioIo::new(stream), service_fn(service))
        .await
    {
        tracing::error!("Error serving outbound connection: {:?}", err);
    }
}

async fn accept_inbound_connection(
    stream: TcpStream,
    tls_manager: Arc<TlsManager>,
    upstream_url: String,
    inject: bool,
    client: Arc<Client<HttpConnector, BoxBody<Bytes, DynError>>>,
) {
    let peer_addr = stream.peer_addr().ok();
    let current_config = tls_manager
        .server_config
        .read()
        .await
        .as_ref()
        .unwrap()
        .clone();
    let acceptor = TlsAcceptor::from(current_config);

    let stream = match acceptor.accept(stream).await {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("TLS handshake failed: {:?}", e);
            return;
        }
    };
    tracing::info!("Client connected");

    let (_, server_conn) = stream.get_ref();
    let client_cert = server_conn
        .peer_certificates()
        .and_then(|certs| certs.first().cloned())
        .and_then(|cert| Some(Arc::new(cert)));

    let service = service_fn(move |req: Request<Incoming>| {
        let up = upstream_url.clone();
        let cli = Arc::clone(&client);
        let cc = client_cert.clone().and_then(|cert| Some(Arc::clone(&cert)));
        async move { proxy_inbound::handler(adapt_request(req), &up, inject, cli, peer_addr, cc).await }
    });

    if let Err(err) = auto::Builder::new(TokioExecutor::new())
        .serve_connection(TokioIo::new(stream), service)
        .await
    {
        tracing::error!("Error serving connection: {:?}", err);
    }
}

fn maybe_accept(
    listener: &Option<TcpListener>,
) -> Pin<Box<dyn futures::Future<Output = io::Result<(TcpStream, SocketAddr)>> + '_>> {
    match listener {
        Some(l) => Box::pin(l.accept()),
        None => Box::pin(futures::future::pending::<
            io::Result<(TcpStream, SocketAddr)>,
        >()),
    }
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    setup_crypto_provider();
    setup_tracing();
    let config = load_config()?;
    let tls_manager = create_tls_manager(&config).await?;
    start_watcher(Arc::clone(&config), Arc::clone(&tls_manager)).await;
    start_monitoring_server(Arc::clone(&config), Arc::clone(&tls_manager)).await?;
    let active_connections = Arc::new(AtomicUsize::new(0));

    let mut outbound_listener = None;
    if let Some(outbound_port) = config.outbound_proxy_port {
        let outbound_addr = format!("0.0.0.0:{}", outbound_port);
        outbound_listener = Some(TcpListener::bind(&outbound_addr).await.context(format!(
            "Failed to bind outbound proxy to {}",
            outbound_addr
        ))?);
        tracing::info!("Outbound proxy listening on {}", outbound_addr);
    }

    let mut inbound_listener = None;
    let upstream_url = config.upstream_url.clone();
    let inject_headers = config.inject_client_headers;
    let http_client = Arc::new(Client::builder(TokioExecutor::new()).build_http());
    if let Some(inbound_port) = config.tls_listen_port {
        let inbound_addr = format!("0.0.0.0:{}", inbound_port);
        inbound_listener = Some(
            TcpListener::bind(&inbound_addr)
                .await
                .context(format!("Failed to bind to {}", inbound_addr))?,
        );
        tracing::info!("Inbound proxy listening on {}", inbound_addr);
        if upstream_url.is_none() {
            return Err(DomainError::Config(
                "upstream_url must be set for inbound proxy".to_string(),
            )
            .into());
        }
    }

    let (mut sigterm, mut sigint) = setup_signals()?;

    loop {
        tokio::select! {
            _ = sigterm.recv() => {
                tracing::info!("Shutdown signal received (SIGTERM)");
                break;
            }
            _ = sigint.recv() => {
                tracing::info!("Shutdown signal received (SIGINT)");
                break;
            }
            result = maybe_accept(&outbound_listener), if outbound_listener.is_some() => {
                match result {
                    Ok((stream, _)) => {
                        active_connections.fetch_add(1, Ordering::Relaxed);
                        let tls_mgr = Arc::clone(&tls_manager);
                        let active_conn = Arc::clone(&active_connections);
                        tokio::spawn(async move {
                            accept_outbound_connection(stream, tls_mgr).await;
                            active_conn.fetch_sub(1, Ordering::Relaxed);
                        });
                    }
                    Err(e) => {
                        tracing::error!("Failed to accept outbound connection: {:?}", e);
                    }
                }
            }
            result = maybe_accept(&inbound_listener), if inbound_listener.is_some() => {
                match result {
                    Ok((stream, _)) => {
                        active_connections.fetch_add(1, Ordering::Relaxed);
                        let tls_mgr = Arc::clone(&tls_manager);
                        let upstream = upstream_url.clone().unwrap();
                        let inject = inject_headers;
                        let client = Arc::clone(&http_client);
                        let active_conn = Arc::clone(&active_connections);
                        tokio::spawn(async move {
                            accept_inbound_connection(stream, tls_mgr, upstream, inject, client).await;
                            active_conn.fetch_sub(1, Ordering::Relaxed);
                        });
                    }
                    Err(e) => {
                        tracing::error!("Failed to accept inbound connection: {:?}", e);
                    }
                }
            }
        }
    }

    shutdown(active_connections).await;
    Ok(())
}

async fn shutdown(active_connections: Arc<AtomicUsize>) {
    tracing::info!("Waiting for in-flight requests to complete...");
    while active_connections.load(Ordering::Relaxed) > 0 {
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
    }
    tracing::info!("Shutdown complete");
}
