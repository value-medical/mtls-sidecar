use anyhow::Result;
use bytes::Bytes;
use http_body_util::Full;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

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
    let tls_manager = TlsManager::new("/etc/certs", "/etc/ca").await?;
    tracing::info!("TLS loaded");

    // Bind to port 8443
    let listener = TcpListener::bind("0.0.0.0:8443").await?;

    loop {
        let (stream, _) = listener.accept().await?;
        let tls_manager = Arc::clone(&tls_manager.config);

        tokio::spawn(async move {
            let acceptor = TlsAcceptor::from(tls_manager);

            let stream = acceptor.accept(stream).await.unwrap();
            tracing::info!("Client connected");

            let service = service_fn(|_req| async {
                // Simple echo handler: return 200 OK if client cert verified
                // For now, just return OK
                Ok::<_, hyper::Error>(hyper::Response::new(Full::new(Bytes::from("OK"))))
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
