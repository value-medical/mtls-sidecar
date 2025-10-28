use crate::client_cert::HeaderInjector;
use crate::error::{DomainError, DynError};
use crate::header_filter;
use crate::http_client_like::HttpClientLike;
use crate::monitoring::{MTLS_FAILURES_TOTAL, REQUESTS_TOTAL};
use crate::tls_manager::TlsManager;
use crate::utils::adapt_request;
use anyhow::{Error, Result};
use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::header::HOST;
use hyper::{http::Uri, Request, Response, StatusCode};
use hyper_util::client::legacy::{connect::HttpConnector, Client};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use hyper::service::service_fn;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;

pub async fn accept_connection(
    stream: TcpStream,
    tls_manager: Arc<TlsManager>,
    upstream_url: String,
    inject: bool,
    client: Arc<Client<HttpConnector, BoxBody<Bytes, DynError>>>,
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
    let mut inj = HeaderInjector::new();
    if inject {
        if let Some(cert) = server_conn
            .peer_certificates()
            .and_then(|certs| certs.first().cloned())
        {
            inj.parse_client_cert(&cert)
        }
    }
    let inj = Arc::new(inj);

    let service = service_fn(move |req: Request<Incoming>| {
        let up = upstream_url.clone();
        let cli = Arc::clone(&client);
        let inj = Arc::clone(&inj);
        async move { handler(adapt_request(req), &up, cli, peer_addr, inj).await }
    });

    if let Err(err) = auto::Builder::new(TokioExecutor::new())
        .serve_connection(TokioIo::new(stream), service)
        .await
    {
        tracing::error!("Error serving connection: {:?}", err);
    }
}

pub async fn handler<C>(
    req: Request<BoxBody<Bytes, DynError>>,
    upstream_url: &str,
    client: C,
    client_addr: Option<std::net::SocketAddr>,
    injector: Arc<HeaderInjector>,
) -> Result<Response<BoxBody<Bytes, DynError>>, Error>
where
    C: HttpClientLike,
{
    let (parts, body) = req.into_parts();

    // Reject the request if the Upgrade header is present -- currently unsupported.
    if parts.headers.contains_key("upgrade") {
        let bad_request_body =
            BoxBody::new(Full::new(Bytes::from("Bad Request")).map_err(Into::<DynError>::into));
        return Ok(Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(bad_request_body)?);
    }

    // Require client cert
    if !injector.is_valid() {
        tracing::warn!("Missing client certificate");
        // No cert, return 401
        MTLS_FAILURES_TOTAL.inc();
        let unauthorized_body =
            BoxBody::new(Full::new(Bytes::from("Unauthorized")).map_err(Into::<DynError>::into));
        return Ok(Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .body(unauthorized_body)?);
    }

    // Build upstream URI
    let uri = parts.uri;
    let path_query = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
    let upstream_uri_str = format!("{}{}", upstream_url.trim_end_matches('/'), path_query);
    let upstream_uri = match upstream_uri_str.parse::<Uri>() {
        Err(e) => {
            tracing::error!("Invalid upstream URI: {:?}", e);
            return Err(DomainError::from(e).into());
        }
        Ok(uri) => uri,
    };

    // Build upstream request
    let mut upstream_req_builder = Request::builder()
        .method(parts.method.clone())
        .uri(upstream_uri.clone());

    // Copy headers from original request
    for (key, value) in header_filter::filter_headers(&parts.headers, true) {
        upstream_req_builder = upstream_req_builder.header(key, value);
    }

    // If inject_client_headers, parse cert and add headers
    upstream_req_builder = injector.inject(upstream_req_builder);

    // Override host header
    // We only support http upstreams, our purpose is to terminate TLS.
    let mut host_port = upstream_uri.host().unwrap_or("localhost").to_string();
    if let Some(port) = upstream_uri.port_u16() {
        host_port = format!("{}:{}", host_port, port);
    }
    upstream_req_builder = upstream_req_builder.header(HOST, host_port);

    // Set X-Forwarded-Proto, X-Forwarded-For headers
    upstream_req_builder = upstream_req_builder.header("X-Forwarded-Proto", "https");
    if let Some(addr) = client_addr {
        upstream_req_builder =
            upstream_req_builder.header("X-Forwarded-For", addr.ip().to_string());
    }

    // Send request to upstream
    let upstream_req = upstream_req_builder.body(body)?;
    let resp = client
        .request(upstream_req)
        .await
        .map_err(|e| DomainError::from(e))?;

    tracing::info!("Proxied request {} {}", parts.method.clone(), uri);
    REQUESTS_TOTAL.inc();

    if resp.status().is_server_error() {
        tracing::error!("Upstream error: {}", resp.status());
    }

    // Forward response
    let (parts, body) = resp.into_parts();
    let proxied_body = body;

    let mut builder = Response::builder().status(parts.status);
    for (k, v) in parts.headers.iter() {
        builder = builder.header(k, v);
    }

    let response = builder
        .body(proxied_body)
        .map_err(|e| DomainError::from(e))?;

    tracing::info!("Response status: {}", parts.status);

    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http_client_like::ResponseFutureLike;
    use base64;
    use base64::Engine;
    use http_body_util::Empty;
    use rcgen::{CertificateParams, DnType, KeyPair};
    use serde_json::Value;
    use std::pin::Pin;
    use std::sync::{Arc, Mutex};

    #[derive(Clone)]
    struct MockClient;

    impl HttpClientLike for MockClient {
        fn request(
            &self,
            _req: Request<BoxBody<Bytes, DynError>>,
        ) -> Pin<Box<dyn ResponseFutureLike>> {
            Box::pin(std::future::ready({
                let body =
                    BoxBody::new(Full::new(Bytes::from("OK")).map_err(Into::<DynError>::into));
                Ok(Response::builder().status(200).body(body).unwrap())
            }))
        }
    }

    #[derive(Clone)]
    struct CapturingClient {
        captured_headers: Arc<Mutex<Vec<(String, String)>>>,
    }

    impl HttpClientLike for CapturingClient {
        fn request(
            &self,
            req: Request<BoxBody<Bytes, DynError>>,
        ) -> Pin<Box<dyn ResponseFutureLike>> {
            let mut headers = Vec::new();
            for (k, v) in req.headers() {
                headers.push((k.as_str().to_lowercase(), v.to_str().unwrap().to_string()));
            }
            *self.captured_headers.lock().unwrap() = headers;
            Box::pin(std::future::ready({
                let body = Full::new(Bytes::from("OK")).map_err(Into::<DynError>::into);
                let proxied_body = BoxBody::new(body);
                Ok(Response::builder().status(200).body(proxied_body).unwrap())
            }))
        }
    }

    #[tokio::test]
    async fn test_handler_missing_cert() {
        let req = Request::new(BoxBody::new(
            Empty::<Bytes>::new().map_err(Into::<DynError>::into),
        ));

        let resp = handler(req, "http://localhost:8080", MockClient, None, Arc::new(HeaderInjector::new()))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_handler_with_cert_mock() {
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
        let mut inj = HeaderInjector::new();
        inj.parse_client_cert(&cert_der);

        let req = Request::new(BoxBody::new(
            Empty::<Bytes>::new().map_err(Into::<DynError>::into),
        ));
        let result = handler(
            req,
            "http://localhost:8080",
            MockClient,
            None,
            Arc::new(inj),
        )
        .await;
        assert!(result.is_ok());
        let resp = result.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_filter_x_client_headers() {
        let captured = Arc::new(Mutex::new(Vec::new()));
        let client = CapturingClient {
            captured_headers: captured.clone(),
        };

        let mut req = Request::new(BoxBody::new(
            Empty::<Bytes>::new().map_err(Into::<DynError>::into),
        ));
        req.headers_mut()
            .insert("x-client-test", "value".parse().unwrap());
        req.headers_mut()
            .insert("other-header", "keep".parse().unwrap());

        // Add cert
        let mut params = CertificateParams::new(vec![]).unwrap();
        params
            .distinguished_name
            .push(DnType::CommonName, "test-client");
        let key_pair = KeyPair::generate().unwrap();
        let cert = params.self_signed(&key_pair).unwrap();
        let cert_der = rustls::pki_types::CertificateDer::from(cert.der().to_vec());
        let mut inj = HeaderInjector::new();
        inj.parse_client_cert(&cert_der);

        let result = handler(
            req,
            "http://localhost:8080",
            client,
            None,
            Arc::new(inj),
        )
        .await;
        assert!(result.is_ok());

        let captured_headers = captured.lock().unwrap();
        // Check that x-client-test is not present
        assert!(!captured_headers.iter().any(|(k, _)| k == "x-client-test"));
        // Check that other-header is present
        assert!(captured_headers
            .iter()
            .any(|(k, v)| k == "other-header" && v == "keep"));
    }

    #[tokio::test]
    async fn test_inject_x_client_headers() {
        let captured = Arc::new(Mutex::new(Vec::new()));
        let client = CapturingClient {
            captured_headers: captured.clone(),
        };

        let mut req = Request::new(BoxBody::new(
            Empty::<Bytes>::new().map_err(Into::<DynError>::into),
        ));
        req.headers_mut()
            .insert("x-client-test", "value".parse().unwrap());

        // Add cert
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
        let mut inj = HeaderInjector::new();
        inj.parse_client_cert(&cert_der);

        let result = handler(
            req,
            "http://localhost:8080",
            client,
            None,
            Arc::new(inj),
        )
        .await;
        assert!(result.is_ok());

        let captured_headers = captured.lock().unwrap();
        // Check that x-client-test is not present
        assert!(!captured_headers.iter().any(|(k, _)| k == "x-client-test"));
        // Check that injected header is present
        let tls_info_header = captured_headers
            .iter()
            .find(|(k, _)| k == "x-client-tls-info")
            .map(|(_, v)| v);
        assert!(tls_info_header.is_some());
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(tls_info_header.unwrap())
            .unwrap();
        let json_str = String::from_utf8(decoded).unwrap();
        let info: Value = serde_json::from_str(&json_str).unwrap();
        assert_eq!(info["subject"], "CN=test-client, O=Test Org");
        assert!(info["dns_sans"].as_array().unwrap().is_empty());
        assert!(info["uri_sans"].as_array().unwrap().is_empty());
        assert!(info["hash"].as_str().unwrap().starts_with("sha256:"));
        assert!(info["serial"].as_str().unwrap().starts_with("0x"));
    }
}
