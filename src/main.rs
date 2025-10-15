use anyhow::Result;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

mod proxy;
mod tls_manager;

use tls_manager::TlsManager;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .json()
        .init();

    // Create TlsManager
    let tls_manager = Arc::new(TlsManager::new("/etc/certs", "/etc/ca").await?);
    tracing::info!("TLS loaded");

    // Bind to port 8443
    let listener = TcpListener::bind("0.0.0.0:8443").await?;

    loop {
        let (stream, _) = listener.accept().await?;
        let tls_manager = Arc::clone(&tls_manager);

        tokio::spawn(async move {
            let acceptor = TlsAcceptor::from(Arc::clone(&tls_manager.config));

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
                async move { proxy::handler(req).await }
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
