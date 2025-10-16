use anyhow::{Context, Result};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::client::legacy::{connect::HttpConnector, Client};
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::signal::unix::{signal, SignalKind};
use tokio_rustls::TlsAcceptor;

use mtls_sidecar::{config, monitoring, proxy, tls_manager, watcher};

use tls_manager::TlsManager;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .json()
        .init();

    // Load config
    let config = config::Config::from_env().context("Failed to load config")?;
    tracing::info!(
        "Config loaded: port={}, upstream={}, cert_dir={}, ca_dir={}",
        config.tls_listen_port,
        config.upstream_url,
        config.cert_dir,
        config.ca_dir
    );

    // Create HTTP client
    let client: Arc<Client<HttpConnector, Incoming>> =
        Arc::new(Client::builder(TokioExecutor::new()).build_http());
    tracing::info!("HTTP client created");

    // Create TlsManager
    let tls_manager = Arc::new(
        TlsManager::new(&config)
            .await
            .context("Failed to load TLS config")?,
    );
    tracing::info!("TLS loaded");

    // Start file watcher
    let cert_dir = config.cert_dir.clone();
    let ca_dir = config.ca_dir.clone();
    let watcher_tls_manager = Arc::clone(&tls_manager);
    tokio::spawn(async move {
        if let Err(e) = watcher::start_watcher(&cert_dir, &ca_dir, watcher_tls_manager).await {
            tracing::error!("Watcher error: {:?}", e);
        }
    });

    // Start monitoring server
    if config.monitor_port != 0 {
        let router = monitoring::create_router(&config);
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

    // Bind to configured port
    let addr = format!("0.0.0.0:{}", config.tls_listen_port);
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
                            let current_config = tls_manager.config.read().await.clone();
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
                                async move { proxy::handler(req, &up, inj, cli).await }
                            });

                            if let Err(err) = http1::Builder::new()
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
