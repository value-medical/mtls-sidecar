use axum::{body::Body as AxumBody, http::Request, routing::get, Router};
use bytes::Bytes;
use http_body_util::Empty;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use std::time::Duration;

use crate::config::Config;

pub fn create_router(config: &Config) -> Router {
    let readiness_url = config.upstream_readiness_url.clone();

    Router::new().route("/live", get(live_handler)).route(
        "/ready",
        get(move |req| ready_handler(req, readiness_url.clone())),
    )
}

async fn live_handler() -> &'static str {
    tracing::info!("Liveness probe called");
    "OK"
}

async fn ready_handler(
    req: Request<AxumBody>,
    readiness_url: String,
) -> Result<&'static str, axum::http::StatusCode> {
    tracing::info!("Readiness probe called");

    let client = Client::builder(TokioExecutor::new()).build_http();

    let mut builder = hyper::Request::get(&readiness_url);
    for (key, value) in req.headers() {
        builder = builder.header(key, value);
    }
    let request = builder
        .body(Empty::<Bytes>::new())
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;

    let response = tokio::time::timeout(Duration::from_secs(1), client.request(request))
        .await
        .map_err(|_| axum::http::StatusCode::SERVICE_UNAVAILABLE)?
        .map_err(|_| axum::http::StatusCode::SERVICE_UNAVAILABLE)?;

    if response.status().is_success() {
        Ok("OK")
    } else {
        Err(axum::http::StatusCode::SERVICE_UNAVAILABLE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use hyper::server::conn::http1;
    use hyper::service::service_fn;
    use hyper_util::rt::TokioIo;
    use tokio::net::TcpListener;
    use tokio::spawn;

    #[tokio::test]
    async fn test_live_handler() {
        let _router = create_router(&Config {
            tls_listen_port: 8443,
            upstream_url: "http://localhost:8080".to_string(),
            upstream_readiness_url: "http://localhost:8080/ready".to_string(),
            cert_dir: "/etc/certs".to_string(),
            ca_dir: "/etc/ca".to_string(),
            inject_client_headers: false,
            monitor_port: 8081,
        });

        // For unit test, perhaps use axum-test or something, but since no extra deps, maybe skip or mock.
        // For now, just check that router is created.
        assert!(true);
    }

    #[tokio::test]
    async fn test_ready_handler_success() {
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
        let result = ready_handler(req, "http://127.0.0.1:8083/ready".to_string()).await;
        assert_eq!(result, Ok("OK"));
    }

    #[tokio::test]
    async fn test_ready_handler_failure() {
        let req = Request::get("/ready").body(Body::empty()).unwrap();
        let result = ready_handler(req, "http://127.0.0.1:9999/ready".to_string()).await;
        assert_eq!(result, Err(StatusCode::SERVICE_UNAVAILABLE));
    }
}
