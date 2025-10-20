use anyhow::{Context, Error, Result};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::{connect::HttpConnector, Client};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::signal::unix::{signal, SignalKind};
use tokio_rustls::TlsAcceptor;

use mtls_sidecar::error::DomainError;
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

async fn start_outbound_proxy(
    outbound_port: u16,
    tls_manager: Arc<TlsManager>,
) -> Result<(), Error> {
    let outbound_addr = format!("0.0.0.0:{}", outbound_port);
    let outbound_listener = TcpListener::bind(&outbound_addr).await.context(format!(
        "Failed to bind outbound proxy to {}",
        outbound_addr
    ))?;
    tracing::info!("Outbound proxy listening on {}", outbound_addr);

    tokio::spawn(async move {
        loop {
            let (stream, _) = outbound_listener.accept().await.unwrap();
            let tls_manager = Arc::clone(&tls_manager);
            tokio::spawn(async move {

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
                let client: Arc<Client<HttpsConnector<HttpConnector>, Incoming>> =
                    Arc::new(Client::builder(TokioExecutor::new()).build(https));

                // Handle connection
                let service = service_fn(move |req| {
                    let client = Arc::clone(&client);
                    async move { mtls_sidecar::proxy_outbound::handler(req, client).await }
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
    Ok(())
}

async fn start_inbound_proxy(
    tls_listen_port: u16,
    config: Arc<config::Config>,
    tls_manager: Arc<TlsManager>,
) -> Result<(), Error> {
    let inbound_addr = format!("0.0.0.0:{}", tls_listen_port);
    let listener = TcpListener::bind(&inbound_addr)
        .await
        .context(format!("Failed to bind to {}", inbound_addr))?;
    tracing::info!("Inbound proxy listening on {}", inbound_addr);

    let upstream_url = config.upstream_url.clone().ok_or(DomainError::Config(
        "upstream_url must be set for inbound proxy".to_string(),
    ))?;
    let inject_headers = config.inject_client_headers;
    let http_client = Arc::new(Client::builder(TokioExecutor::new()).build_http());
    let active_connections = Arc::new(AtomicUsize::new(0));

    let (sigterm, sigint) = setup_signals()?;
    run_server_loop(
        listener,
        upstream_url,
        inject_headers,
        http_client,
        tls_manager,
        active_connections.clone(),
        sigterm,
        sigint,
    )
    .await?;
    shutdown(active_connections).await;
    Ok(())
}

fn setup_signals() -> Result<(tokio::signal::unix::Signal, tokio::signal::unix::Signal), Error> {
    let sigterm = signal(SignalKind::terminate()).context("Failed to register SIGTERM handler")?;
    let sigint = signal(SignalKind::interrupt()).context("Failed to register SIGINT handler")?;
    Ok((sigterm, sigint))
}

async fn handle_connection(
    stream: tokio::net::TcpStream,
    tls_manager: Arc<TlsManager>,
    upstream_url: String,
    inject: bool,
    client: Arc<Client<HttpConnector, Incoming>>,
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

    let service = service_fn(move |req| {
        let up = upstream_url.clone();
        let cli = Arc::clone(&client);
        let cc = client_cert.clone().and_then(|cert| Some(Arc::clone(&cert)));
        async move { proxy_inbound::handler(req, &up, inject, cli, peer_addr, cc).await }
    });

    if let Err(err) = auto::Builder::new(TokioExecutor::new())
        .serve_connection(TokioIo::new(stream), service)
        .await
    {
        tracing::error!("Error serving connection: {:?}", err);
    }
}

async fn run_server_loop(
    listener: TcpListener,
    upstream_url: String,
    inject_headers: bool,
    http_client: Arc<Client<HttpConnector, Incoming>>,
    tls_manager: Arc<TlsManager>,
    active_connections: Arc<AtomicUsize>,
    mut sigterm: tokio::signal::unix::Signal,
    mut sigint: tokio::signal::unix::Signal,
) -> Result<(), Error> {
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
            result = listener.accept() => {
                match result {
                    Ok((stream, _)) => {
                        active_connections.fetch_add(1, Ordering::Relaxed);
                        let tls_mgr = Arc::clone(&tls_manager);
                        let upstream = upstream_url.clone();
                        let inject = inject_headers;
                        let client = Arc::clone(&http_client);
                        let counter = Arc::clone(&active_connections);
                        tokio::spawn(async move {
                            handle_connection(stream, tls_mgr, upstream, inject, client).await;
                            counter.fetch_sub(1, Ordering::Relaxed);
                        });
                    }
                    Err(e) => {
                        tracing::error!("Failed to accept connection: {:?}", e);
                    }
                }
            }
        }
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    setup_crypto_provider();
    setup_tracing();
    let config = load_config()?;
    let tls_manager = create_tls_manager(&config).await?;
    start_watcher(Arc::clone(&config), Arc::clone(&tls_manager)).await;
    start_monitoring_server(Arc::clone(&config), Arc::clone(&tls_manager)).await?;
    if let Some(outbound_port) = config.outbound_proxy_port {
        start_outbound_proxy(outbound_port, Arc::clone(&tls_manager)).await?;
    }
    if let Some(inbound_port) = config.tls_listen_port {
        start_inbound_proxy(inbound_port, Arc::clone(&config), Arc::clone(&tls_manager)).await?;
    }
    Ok(())
}

async fn shutdown(active_connections: Arc<AtomicUsize>) {
    tracing::info!("Waiting for in-flight requests to complete...");
    while active_connections.load(Ordering::Relaxed) > 0 {
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
    }
    tracing::info!("Shutdown complete");
}
