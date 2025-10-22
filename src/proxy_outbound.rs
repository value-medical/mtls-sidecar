use crate::error::DynError;
use crate::header_filter;
use crate::http_client_like::HttpClientLike;
use anyhow::{Error, Result};
use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::header::HOST;
use hyper::http::uri::Scheme;
use hyper::http::{Request, Response, StatusCode, Uri};

pub async fn handler(
    req: Request<BoxBody<Bytes, DynError>>,
    client: impl HttpClientLike,
) -> Result<Response<BoxBody<Bytes, DynError>>> {
    let (parts, body) = req.into_parts();

    if parts.method == hyper::Method::CONNECT {
        // Do we want to handle CONNECT?
        let bad_request_body = BoxBody::new(
            Full::new(Bytes::from("CONNECT method not supported")).map_err(Into::<DynError>::into),
        );
        return Ok(Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(bad_request_body)?);
    }

    // Reject the request if the Upgrade header is present -- currently unsupported.
    if parts.headers.contains_key("upgrade") {
        let bad_request_body =
            BoxBody::new(Full::new(Bytes::from("Bad Request")).map_err(Into::<DynError>::into));
        return Ok(Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(bad_request_body)?);
    }

    // Parse the target URI from the request
    let target_uri = parts.uri.clone();
    if target_uri.scheme() != Some(&Scheme::HTTP) {
        let bad_request_body = BoxBody::new(
            Full::new(Bytes::from("Only HTTP requests supported")).map_err(Into::<DynError>::into),
        );
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
    let resp = client
        .request(upstream_req)
        .await
        .map_err(Error::from_boxed)?;

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
    use http_body_util::Empty;
    use hyper::Request;
    use hyper_util::client::legacy::Client;
    use hyper_util::rt::TokioExecutor;
    use rustls::{ClientConfig, RootCertStore};
    use std::sync::Arc;

    fn new_client() -> Arc<impl HttpClientLike> {
        let client_config = ClientConfig::builder()
            .with_root_certificates(RootCertStore::empty())
            .with_no_client_auth();
        let https = hyper_rustls::HttpsConnectorBuilder::new()
            .with_tls_config(client_config)
            .https_only()
            .enable_http1()
            .build();
        let client = Client::builder(TokioExecutor::new()).build(https);
        Arc::new(client)
    }

    #[tokio::test]
    async fn test_handler_invalid_scheme() {
        // The outbound proxy should reject non-HTTP requests
        let req = Request::get("https://example.com")
            .body(BoxBody::new(
                Empty::<Bytes>::new().map_err(Into::<DynError>::into),
            ))
            .unwrap();
        let client = new_client();
        let result = handler(req, client).await;
        assert!(result.is_ok());
        let resp = result.unwrap();
        assert_eq!(resp.status(), 400);
    }
}
