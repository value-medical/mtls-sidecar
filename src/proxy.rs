use anyhow::Result;
use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::{body::Body, header::HOST, http::Uri, Request, Response, StatusCode};
use hyper_util::client::legacy::{connect::HttpConnector, Client};
use std::error::Error;
use std::sync::Arc;
use x509_parser::prelude::*;

use crate::monitoring::{MTLS_FAILURES_TOTAL, REQUESTS_TOTAL};

type BodyError = Box<dyn Error + Send + Sync>;

type ProxiedBody = BoxBody<Bytes, BodyError>;

type HttpClient<B> = Client<HttpConnector, B>;

pub async fn handler<B>(
    req: Request<B>,
    upstream_url: &str,
    inject_client_headers: bool,
    client: Arc<HttpClient<B>>,
) -> Result<Response<ProxiedBody>>
where
    B: Body<Data = Bytes> + Send + Unpin + 'static,
    B::Error: Into<BodyError>,
{
    let (parts, body) = req.into_parts();

    // Extract client cert from extensions
    let client_cert = parts
        .extensions
        .get::<rustls::pki_types::CertificateDer<'static>>();

    if client_cert.is_none() {
        // No cert, return 401
        MTLS_FAILURES_TOTAL.inc();
        let unauthorized_full =
            Full::new(Bytes::from("Unauthorized")).map_err(Into::<BodyError>::into);
        let unauthorized_body: ProxiedBody = BoxBody::new(unauthorized_full);
        return Ok(Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .body(unauthorized_body)?);
    }

    // Build upstream URI
    let uri = parts.uri.clone();
    let path_query = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
    let upstream_uri_str = format!("{}{}", upstream_url.trim_end_matches('/'), path_query);
    let upstream_uri = match upstream_uri_str.parse::<Uri>() {
        Err(e) => {
            tracing::error!("Invalid upstream URI: {:?}", e);
            return Err(anyhow::anyhow!(e.to_string()));
        }
        Ok(uri) => uri,
    };

    // Build upstream request
    let mut upstream_req_builder = Request::builder()
        .method(parts.method.clone())
        .uri(upstream_uri.clone());

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

    // Copy headers from original request
    for (key, value) in parts.headers.iter() {
        upstream_req_builder = upstream_req_builder.header(key.clone(), value.clone());
    }

    // Override host header
    let mut host_port = format!("http://{}", upstream_uri.host().unwrap());
    if let Some(port) = upstream_uri.port_u16() {
        host_port = format!("{}:{}", host_port, port);
    }
    upstream_req_builder = upstream_req_builder.header(HOST, host_port);

    // Send request to upstream
    let upstream_req = upstream_req_builder
        .body(body)
        .map_err(|e| anyhow::anyhow!(e))?;
    let resp = match client.request(upstream_req).await {
        Ok(resp) => resp,
        Err(e) => {
            tracing::error!("Upstream request error: {:?}", e);
            return Err(anyhow::anyhow!(e.to_string()));
        }
    };

    tracing::info!("Proxied request {} {}", parts.method.clone(), uri);
    REQUESTS_TOTAL.inc();

    if resp.status().is_server_error() {
        tracing::error!("Upstream error: {}", resp.status());
    }

    // Forward response
    let (parts, body) = resp.into_parts();
    let mapped_body = body.map_err(BodyError::from);
    let proxied_body: ProxiedBody = BoxBody::new(mapped_body);

    let mut builder = Response::builder().status(parts.status);
    for (k, v) in parts.headers.iter() {
        builder = builder.header(k.clone(), v.clone());
    }

    let response = builder.body(proxied_body).map_err(|e| anyhow::anyhow!(e))?;

    tracing::info!("Response status: {}", parts.status);

    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::Empty;
    use hyper_util::rt::TokioExecutor;
    use rcgen::{CertificateParams, DnType, KeyPair};

    #[tokio::test]
    async fn test_handler_missing_cert() {
        let client = Arc::new(Client::builder(TokioExecutor::new()).build_http());
        let req = Request::new(Empty::<Bytes>::new());
        let resp = handler(req, "http://localhost:8080", false, client)
            .await
            .unwrap();
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
