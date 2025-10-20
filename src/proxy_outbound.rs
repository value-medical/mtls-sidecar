use crate::header_filter;
use crate::tls_manager::TlsManager;
use anyhow::Result;
use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::header::HOST;
use hyper::{http::uri::Scheme, http::Uri, Request, Response, StatusCode};
use hyper_rustls::HttpsConnector;
use hyper_util::rt::TokioExecutor;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use std::error::Error;

pub async fn handler<B>(
    req: Request<B>,
    tls_manager: &TlsManager,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>>
where
    B: hyper::body::Body + Send + 'static + Unpin,
    B::Data: Send,
    B::Error: Into<Box<dyn Error + Send + Sync>>,
{
    let (parts, body) = req.into_parts();

    // Reject the request if the Upgrade header is present -- currently unsupported.
    if parts.headers.contains_key("upgrade") {
        let bad_request_full = Full::new(Bytes::from("Bad Request")).map_err(|_| unreachable!());
        let bad_request_body: BoxBody<Bytes, hyper::Error> = BoxBody::new(bad_request_full);
        return Ok(Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(bad_request_body)?);
    }

    // Parse the target URI from the request
    let target_uri = parts.uri.clone();
    if target_uri.scheme() != Some(&Scheme::HTTP) {
        let bad_request_full =
            Full::new(Bytes::from("Only HTTP requests supported")).map_err(|_| unreachable!());
        let bad_request_body: BoxBody<Bytes, hyper::Error> = BoxBody::new(bad_request_full);
        return Ok(Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(bad_request_body)?);
    }

    // Build HTTPS URI
    let https_uri_str = format!(
        "https://{}{}",
        target_uri.authority().unwrap(),
        target_uri
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/")
    );
    let https_uri: Uri = https_uri_str
        .parse()
        .map_err(|e| anyhow::anyhow!("Invalid URI: {}", e))?;

    // Create HTTPS connector
    let client_config = tls_manager.client_config.read().await.clone().unwrap();
    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config((*client_config).clone())
        .https_only()
        .enable_http1()
        .enable_http2()
        .build();

    // Create client
    let client: Client<HttpsConnector<HttpConnector>, B> =
        Client::builder(TokioExecutor::new()).build(https);

    // Build upstream request
    let mut upstream_req_builder = Request::builder()
        .method(parts.method.clone())
        .uri(https_uri.clone());

    // Copy headers from original request
    for (key, value) in header_filter::filter_headers(&parts.headers, false) {
        upstream_req_builder = upstream_req_builder.header(key, value);
    }

    // Set host header
    let host = https_uri.host().unwrap_or("localhost");
    let host_header = if let Some(port) = https_uri.port_u16() {
        format!("{}:{}", host, port)
    } else {
        host.to_string()
    };
    upstream_req_builder = upstream_req_builder.header(HOST, host_header);

    // Send request
    let upstream_req = upstream_req_builder
        .body(body)
        .map_err(|e| anyhow::anyhow!(e))?;
    let resp = client.request(upstream_req).await?;

    tracing::info!(
        "Proxied outbound request {} {}",
        parts.method.clone(),
        https_uri
    );

    // Forward response
    let (parts, body) = resp.into_parts();
    let proxied_body = body;

    let mut builder = Response::builder().status(parts.status);
    for (k, v) in parts.headers.iter() {
        builder = builder.header(k, v);
    }

    let response = builder
        .body(BoxBody::new(proxied_body))
        .map_err(|e| anyhow::anyhow!(e))?;

    tracing::info!("Outbound response status: {}", parts.status);

    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::Request;
    use rustls::RootCertStore;
    use std::sync::Arc;

    #[tokio::test]
    async fn test_handler_invalid_scheme() {
        // The outbound proxy should reject non-HTTP requests
        let tls_manager = TlsManager::new();
        tls_manager.set_client_config(Some(Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(RootCertStore::empty())
                .with_no_client_auth(),
        ))).await;

        let req = Request::get("https://example.com")
            .body(http_body_util::Empty::<Bytes>::new())
            .unwrap();
        let result = handler(req, &tls_manager).await;
        assert!(result.is_ok());
        let resp = result.unwrap();
        assert_eq!(resp.status(), 400);
    }
}
