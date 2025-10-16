use anyhow::{Context, Result};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

mod config;
mod proxy;
mod tls_manager;
mod watcher;

use tls_manager::TlsManager;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .json()
        .init();

    // Load config
    let config = config::Config::from_env();
    tracing::info!(
        "Config loaded: port={}, upstream={}, cert_dir={}, ca_dir={}",
        config.tls_listen_port,
        config.upstream_url,
        config.cert_dir,
        config.ca_dir
    );

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

    // Bind to configured port
    let addr = format!("0.0.0.0:{}", config.tls_listen_port);
    let listener = TcpListener::bind(&addr)
        .await
        .context(format!("Failed to bind to {}", addr))?;

    let upstream_url = config.upstream_url.clone();
    let inject_headers = config.inject_client_headers;
    loop {
        let (stream, _) = listener.accept().await?;
        let tls_manager = Arc::clone(&tls_manager);
        let upstream = upstream_url.clone();
        let inject = inject_headers;

        tokio::spawn(async move {
            let current_config = tls_manager.config.read().await.clone();
            let acceptor = TlsAcceptor::from(current_config);

            let stream = acceptor.accept(stream).await.unwrap();
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
                async move { proxy::handler(req, &up, inj).await }
            });

            if let Err(err) = http1::Builder::new()
                .serve_connection(TokioIo::new(stream), service)
                .await
            {
                tracing::error!("Error serving connection: {:?}", err);
            }
        });
    }
}
