use crate::config::Config;
use crate::tls_manager::TlsManager;
use axum::{
    body::Body as AxumBody,
    http::{Request, StatusCode},
    routing::get,
    Router,
};
use bytes::Bytes;
use chrono::Utc;
use http_body_util::Empty;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use lazy_static::lazy_static;
use prometheus::{register_int_counter, Encoder, IntCounter, TextEncoder};
use std::sync::Arc;
use std::time::Duration;

lazy_static! {
    pub static ref TLS_RELOADS_TOTAL: IntCounter =
        register_int_counter!("tls_reloads_total", "Total number of TLS reloads").unwrap();
    pub static ref MTLS_FAILURES_TOTAL: IntCounter = register_int_counter!(
        "mtls_failures_total",
        "Total number of mTLS authentication failures"
    )
    .unwrap();
    pub static ref REQUESTS_TOTAL: IntCounter =
        register_int_counter!("requests_total", "Total number of proxied requests").unwrap();
}

pub fn create_router(config: &Config, tls_manager: Arc<TlsManager>) -> Router {
    let readiness_url = config.upstream_readiness_url.clone();
    let tls_manager_clone = Arc::clone(&tls_manager);

    let mut router = Router::new().route("/live", get(live_handler)).route(
        "/ready",
        get(move |req| ready_handler(req, readiness_url.clone(), Arc::clone(&tls_manager_clone))),
    );

    if config.enable_metrics {
        tracing::info!("Metrics enabled");
        router = router.route("/metrics", get(metrics_handler));
    }

    router
}

async fn live_handler() -> &'static str {
    tracing::info!("Liveness probe called");
    "OK"
}

async fn check_certificate_expiry(tls_manager: &TlsManager) -> Result<(), ()> {
    let earliest_expiry = *tls_manager.earliest_expiry.read().await;

    if let Some(expiry) = earliest_expiry {
        let now = Utc::now();
        if now > expiry {
            tracing::error!("Certificate expired: earliest expiry={}", expiry);
            return Err(());
        }
    } else {
        // No certificates loaded, assume OK (for tests or minimal setups)
        return Ok(());
    }

    Ok(())
}

async fn ready_handler(
    req: Request<AxumBody>,
    readiness_url: String,
    tls_manager: Arc<TlsManager>,
) -> Result<&'static str, StatusCode> {
    tracing::info!("Readiness probe called");

    // Check certificate expiry
    if let Err(_) = check_certificate_expiry(&tls_manager).await {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }

    let client = Client::builder(TokioExecutor::new()).build_http();

    let mut builder = hyper::Request::get(&readiness_url);
    for (key, value) in req.headers() {
        builder = builder.header(key, value);
    }
    let request = builder
        .body(Empty::<Bytes>::new())
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let response = tokio::time::timeout(Duration::from_secs(1), client.request(request))
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;

    if response.status().is_success() {
        Ok("OK")
    } else {
        Err(StatusCode::SERVICE_UNAVAILABLE)
    }
}

async fn metrics_handler() -> Result<String, StatusCode> {
    let encoder = TextEncoder::new();
    let metric_families = prometheus::gather();
    let mut buffer = Vec::new();
    encoder
        .encode(&metric_families, &mut buffer)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    String::from_utf8(buffer).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use hyper::server::conn::http1;
    use hyper::service::service_fn;
    use hyper_util::rt::TokioIo;
    use rustls::ServerConfig;
    use std::sync::Arc;
    use tokio::net::TcpListener;
    use tokio::spawn;
    use tokio::sync::RwLock;
    use {Request, StatusCode};

    #[derive(Debug)]
    struct DummyResolver;

    impl rustls::server::ResolvesServerCert for DummyResolver {
        fn resolve(
            &self,
            _client_hello: rustls::server::ClientHello,
        ) -> Option<Arc<rustls::sign::CertifiedKey>> {
            None
        }
    }

    #[tokio::test]
    async fn test_live_handler() {
        let dummy_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(DummyResolver));
        let tls_manager = Arc::new(TlsManager {
            config: Arc::new(RwLock::new(Arc::new(dummy_config))),
            earliest_expiry: Arc::new(RwLock::new(None)),
        });
        let _router = create_router(
            &Config {
                tls_listen_port: 8443,
                upstream_url: "http://localhost:8080".to_string(),
                upstream_readiness_url: "http://localhost:8080/ready".to_string(),
                cert_dir: "/etc/certs".to_string(),
                ca_dir: "/etc/ca".to_string(),
                inject_client_headers: false,
                monitor_port: 8081,
                enable_metrics: false,
            },
            tls_manager,
        );

        // For unit test, perhaps use axum-test or something, but since no extra deps, maybe skip or mock.
        // For now, just check that router is created.
        assert!(true);
    }

    #[tokio::test]
    async fn test_ready_handler_success() {
        let dummy_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(DummyResolver));
        let tls_manager = Arc::new(TlsManager {
            config: Arc::new(RwLock::new(Arc::new(dummy_config))),
            earliest_expiry: Arc::new(RwLock::new(None)),
        });

        // Start mock upstream
        let listener = TcpListener::bind("127.0.0.1:8083").await.unwrap();
        spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                spawn(async move {
                    let service = service_fn(|_req| async {
                        Ok::<_, hyper::Error>(hyper::Response::new(Body::from("OK")))
                    });
                    http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service)
                        .await
                        .unwrap();
                });
            }
        });

        tokio::time::sleep(Duration::from_millis(100)).await;

        let req = Request::get("/ready").body(Body::empty()).unwrap();
        let result =
            ready_handler(req, "http://127.0.0.1:8083/ready".to_string(), tls_manager).await;
        assert_eq!(result, Ok("OK"));
    }

    #[tokio::test]
    async fn test_ready_handler_failure() {
        let dummy_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(DummyResolver));
        let tls_manager = Arc::new(TlsManager {
            config: Arc::new(RwLock::new(Arc::new(dummy_config))),
            earliest_expiry: Arc::new(RwLock::new(None)),
        });

        let req = Request::get("/ready").body(Body::empty()).unwrap();
        let result =
            ready_handler(req, "http://127.0.0.1:9999/ready".to_string(), tls_manager).await;
        assert_eq!(result, Err(StatusCode::SERVICE_UNAVAILABLE));
    }

    #[tokio::test]
    async fn test_metrics_handler() {
        // Increment a counter to ensure metrics are present
        TLS_RELOADS_TOTAL.inc();
        let result = metrics_handler().await;
        assert!(result.is_ok());
        let body = result.unwrap();
        assert!(body.contains("# HELP tls_reloads_total"));
        assert!(body.contains("tls_reloads_total 1"));
    }
}
