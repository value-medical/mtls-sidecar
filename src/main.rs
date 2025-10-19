use anyhow::{Context, Result};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::client::legacy::{connect::HttpConnector, Client};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::signal::unix::{signal, SignalKind};
use tokio_rustls::TlsAcceptor;

use mtls_sidecar::{config, monitoring, proxy_inbound, tls_manager, watcher};

use tls_manager::TlsManager;

#[tokio::main]
async fn main() -> Result<()> {
    rustls::crypto::CryptoProvider::install_default(rustls::crypto::aws_lc_rs::default_provider())
        .expect("Failed to install rustls crypto provider");

    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .json()
        .init();

    // Load config
    let config = config::Config::from_env().context("Failed to load config")?;
    tracing::debug!("config = {:?}", config);
    let config = Arc::new(config);

    // Create TlsManager
    let mut tls_manager = TlsManager::new();
    if config.tls_listen_port.is_some() {
        tls_manager.server_required = true;
    }
    if config.outbound_proxy_port.is_some() {
        tls_manager.client_required = true;
    }
    tls_manager
        .reload(&config)
        .await
        .context("Failed to load TLS config")?;
    tracing::info!("TLS loaded");
    let tls_manager = Arc::new(tls_manager);

    // Create HTTP client
    let client: Arc<Client<HttpConnector, Incoming>> =
        Arc::new(Client::builder(TokioExecutor::new()).build_http());
    tracing::info!("HTTP client created");

    // Start file watcher
    let watcher_config = Arc::clone(&config);
    let watcher_tls_manager = Arc::clone(&tls_manager);
    tokio::spawn(async move {
        if let Err(e) = watcher::start_watcher(
            watcher_config,
            watcher_tls_manager,
        )
        .await
        {
            tracing::error!("Watcher error: {:?}", e);
        }
    });

    // Start monitoring server
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

    // Start outbound proxy server
    if let Some(outbound_port) = config.outbound_proxy_port {
        let outbound_addr = format!("0.0.0.0:{}", outbound_port);
        let outbound_listener = TcpListener::bind(&outbound_addr).await.context(format!(
            "Failed to bind outbound proxy to {}",
            outbound_addr
        ))?;
        tracing::info!("Outbound proxy listening on {}", outbound_addr);
        let tls_manager_outbound = Arc::clone(&tls_manager);
        tokio::spawn(async move {
            loop {
                let (stream, _) = outbound_listener.accept().await.unwrap();
                let tls_manager = Arc::clone(&tls_manager_outbound);
                tokio::spawn(async move {
                    let service = service_fn(move |req| {
                        let tls_mgr = Arc::clone(&tls_manager);
                        async move { mtls_sidecar::proxy_outbound::handler(req, &tls_mgr).await }
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
    }

    // Bind to configured port
    let tls_listen_port = config.tls_listen_port.unwrap_or(8443);
    let addr = format!("0.0.0.0:{}", tls_listen_port);
    let listener = TcpListener::bind(&addr)
        .await
        .context(format!("Failed to bind to {}", addr))?;

    let upstream_url = config.upstream_url.clone();
    let inject_headers = config.inject_client_headers;
    let http_client = Arc::clone(&client);
    let active_connections = Arc::new(AtomicUsize::new(0));

    let mut sigterm =
        signal(SignalKind::terminate()).context("Failed to register SIGTERM handler")?;
    let mut sigint =
        signal(SignalKind::interrupt()).context("Failed to register SIGINT handler")?;

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
                        let tls_manager = Arc::clone(&tls_manager);
                        let upstream = upstream_url.clone();
                        let inject = inject_headers;
                        let client = Arc::clone(&http_client);
                        let counter = Arc::clone(&active_connections);

                        tokio::spawn(async move {
                            let peer_addr = stream.peer_addr().ok();
                            let current_config = tls_manager.server_config.read().await.as_ref().unwrap().clone();
                            let acceptor = TlsAcceptor::from(current_config);

                            let stream = match acceptor.accept(stream).await {
                                Ok(s) => s,
                                Err(e) => {
                                    tracing::error!("TLS handshake failed: {:?}", e);
                                    counter.fetch_sub(1, Ordering::Relaxed);
                                    return;
                                }
                            };
                            tracing::info!("Client connected");

                            let (_, server_conn) = stream.get_ref();
                            let client_cert = server_conn
                                .peer_certificates()
                                .and_then(|certs| certs.first().cloned());

                            let service = service_fn(move |mut req| {
                                if let Some(cert) = &client_cert {
                                    req.extensions_mut().insert(cert.clone());
                                }
                                let up = upstream.clone();
                                let inj = inject;
                                let cli = Arc::clone(&client);
                                async move { proxy_inbound::handler(req, &up, inj, cli, peer_addr).await }
                            });

                            if let Err(err) = auto::Builder::new(TokioExecutor::new())
                                .serve_connection(TokioIo::new(stream), service)
                                .await
                            {
                                tracing::error!("Error serving connection: {:?}", err);
                            }
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

    tracing::info!("Waiting for in-flight requests to complete...");
    while active_connections.load(Ordering::Relaxed) > 0 {
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
    }
    tracing::info!("Shutdown complete");

    Ok(())
}
