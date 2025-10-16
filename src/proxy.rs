use anyhow::Result;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{body::Body, Request, Response, StatusCode};
use hyper_util::client::legacy::{Client, connect::HttpConnector};
use hyper_util::rt::TokioExecutor;
use std::convert::Infallible;
use std::error::Error;
use std::sync::Arc;
use x509_parser::prelude::*;

use crate::monitoring::{MTLS_FAILURES_TOTAL, REQUESTS_TOTAL};

type HttpClient = Client<HttpConnector, hyper::body::Incoming>;

pub async fn handler<B>(
    req: Request<B>,
    upstream_url: &str,
    inject_client_headers: bool,
    client: Arc<HttpClient>,
) -> Result<
    Response<Box<dyn Body<Data = Bytes, Error = Box<dyn Error + Send + Sync>> + Unpin + Send>>,
>
where
    B: Body + Send + Unpin + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn Error + Send + Sync>>,
{
    let (parts, body) = req.into_parts();

    // Extract client cert from extensions
    let client_cert = parts
        .extensions
        .get::<rustls::pki_types::CertificateDer<'static>>();

    if client_cert.is_none() {
        MTLS_FAILURES_TOTAL.inc();
        let body = Full::new(Bytes::from("Unauthorized"))
            .map_err(|e: Infallible| -> Box<dyn Error + Send + Sync> { match e {} });
        return Ok(Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .body(Box::new(body)
                as Box<
                    dyn Body<Data = Bytes, Error = Box<dyn Error + Send + Sync>> + Unpin + Send,
                >)
            .unwrap());
    }

    // Forward to upstream
    let method = parts.method.clone();
    let uri = parts.uri.clone();

    // Build upstream request
    let mut upstream_req_builder = Request::builder()
        .method(method.clone())
        .uri(format!("{}{}", upstream_url, uri));

    // If inject_client_headers, parse cert and add headers
    if inject_client_headers {
        if let Some(cert_der) = client_cert {
            if let Ok((_, cert)) = X509Certificate::from_der(cert_der.as_ref()) {
                let subject = cert.subject().to_string();
                let cn = cert
                    .subject()
                    .iter_common_name()
                    .next()
                    .and_then(|cn| cn.as_str().ok())
                    .unwrap_or("");

                upstream_req_builder = upstream_req_builder
                    .header("X-Client-CN", cn)
                    .header("X-Client-Subject", subject);
                tracing::info!("Injected client headers");
            }
        }
    }

    // Copy headers
    for (key, value) in &parts.headers {
        upstream_req_builder
            .headers_mut()
            .unwrap()
            .insert(key, value.clone());
    }

    // Set host header
    let host_port = upstream_url.strip_prefix("http://").unwrap_or(upstream_url);
    upstream_req_builder
        .headers_mut()
        .unwrap()
        .insert("host", host_port.parse().unwrap());

    let upstream_req = upstream_req_builder.body(body).unwrap();

    let resp = client.request(upstream_req).await?;

    tracing::info!("Proxied request {} {}", method, uri);
    REQUESTS_TOTAL.inc();

    if resp.status().is_server_error() {
        tracing::error!("Upstream error: {}", resp.status());
    }

    // Forward response body without collecting
    let (parts, body) = resp.into_parts();
    let mapped_body = body.map_err(|e| Box::new(e) as Box<dyn Error + Send + Sync>);
    let mut builder = Response::builder().status(parts.status);
    for (k, v) in &parts.headers {
        builder = builder.header(k.clone(), v.clone());
    }
    let response = builder
        .body(Box::new(mapped_body)
            as Box<
                dyn Body<Data = Bytes, Error = Box<dyn Error + Send + Sync>> + Unpin + Send,
            >)
        .unwrap();

    tracing::info!("Response status: {}", parts.status);

    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::Empty;
    use rcgen::{CertificateParams, DnType, KeyPair};

    #[tokio::test]
    async fn test_handler_missing_cert() {
        let client = Arc::new(Client::builder(TokioExecutor::new()).build_http());
        let req = Request::new(Empty::<Bytes>::new());
        let resp = handler(req, "http://localhost:8080", false, client).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_handler_with_cert_no_injection() {
        // Create a mock cert
        let mut params = CertificateParams::new(vec![]).unwrap();
        params
            .distinguished_name
            .push(DnType::CommonName, "test-client");
        params
            .distinguished_name
            .push(DnType::OrganizationName, "Test Org");
        let key_pair = KeyPair::generate().unwrap();
        let cert = params.self_signed(&key_pair).unwrap();
        let cert_der = rustls::pki_types::CertificateDer::from(cert.der().to_vec());

        let mut req = Request::new(Empty::<Bytes>::new());
        req.extensions_mut().insert(cert_der);

        // Since upstream is not running, it will fail, but we can check if it tries to connect
        // For this test, just ensure it doesn't return UNAUTHORIZED
        let client = Arc::new(Client::builder(TokioExecutor::new()).build_http());
        let result = handler(req, "http://localhost:8080", false, client).await;
        // It should try to proxy and fail with connection error, not UNAUTHORIZED
        assert!(result.is_err()); // Since no upstream
    }
}
