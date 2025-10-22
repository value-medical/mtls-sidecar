use crate::error::DynError;
use crate::header_filter;
use crate::http_client_like::HttpClientLike;
use anyhow::{Error, Result};
use bytes::Bytes;
use http::header::UPGRADE;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Empty, Full};
use hyper::header::HOST;
use hyper::http::uri::Scheme;
use hyper::http::{Method, Request, Response, StatusCode, Uri};
use hyper_util::rt::TokioIo;
use rustls::ClientConfig;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

pub async fn handler(
    mut req: Request<BoxBody<Bytes, DynError>>,
    client: impl HttpClientLike,
    client_config: Arc<ClientConfig>,
) -> Result<Response<BoxBody<Bytes, DynError>>> {
    if req.method() == Method::CONNECT {
        // Handle CONNECT tunneling
        let uri = req.uri().clone();
        let authority = uri
            .authority()
            .ok_or_else(|| anyhow::anyhow!("CONNECT requires authority"))?;
        let host = authority.host().to_string();
        let port = authority.port_u16().unwrap_or(443);
        let target_addr = format!("{}:{}", host, port);

        // Establish TLS connection to target
        let tcp_stream = TcpStream::connect(&target_addr).await?;
        let connector = TlsConnector::from(client_config);
        let mut tls_stream = connector.connect(host.try_into()?, tcp_stream).await?;

        // Start bidirectional tunnel
        tokio::task::spawn(async move {
            match hyper::upgrade::on(&mut req).await {
                Ok(upgraded) => {
                    let mut client = TokioIo::new(upgraded);
                    match tokio::io::copy_bidirectional(&mut client, &mut tls_stream).await {
                        Ok((up_bytes, down_bytes)) => {
                            tracing::info!(
                                "CONNECT completed, {} bytes sent, {} bytes received",
                                up_bytes,
                                down_bytes
                            )
                        }
                        Err(e) => {
                            tracing::info!("CONNECT completed with error {}", e.to_string())
                        }
                    }
                }
                Err(e) => tracing::error!("Upgrade error: {}", e),
            }
        });

        tracing::info!("CONNECT request to {} accepted", target_addr);
        return Ok(Response::builder()
            .status(StatusCode::OK)
            .body(BoxBody::new(Empty::new().map_err(Into::<DynError>::into)))?);
    }

    if req.headers().contains_key(UPGRADE) {
        // Handle Upgrade request
        let target_uri = req.uri().clone();
        if target_uri.scheme().is_some() && target_uri.scheme() != Some(&Scheme::HTTP) {
            let bad_request_body = BoxBody::new(
                Full::new(Bytes::from("Only HTTP requests supported"))
                    .map_err(Into::<DynError>::into),
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
            .method(req.method().clone())
            .uri(https_uri.clone());

        // Copy headers
        for (key, value) in header_filter::filter_headers(req.headers(), false) {
            upstream_req_builder = upstream_req_builder.header(key, value);
        }

        // Set host
        let host = https_uri.host().unwrap_or("localhost");
        let host_header = if let Some(port) = https_uri.port_u16() {
            format!("{}:{}", host, port)
        } else {
            host.to_string()
        };
        upstream_req_builder = upstream_req_builder.header(HOST, host_header);

        let upstream_req = upstream_req_builder
            .body(BoxBody::new(Empty::new().map_err(Into::<DynError>::into)))?;
        let resp = client
            .request(upstream_req)
            .await
            .map_err(Error::from_boxed)?;
        if resp.status() != StatusCode::SWITCHING_PROTOCOLS {
            return Ok(resp);
        }

        // Handle upgrade
        let (parts, body) = resp.into_parts();
        let response = Response::from_parts(
            parts.clone(),
            BoxBody::new(Empty::new().map_err(Into::<DynError>::into)),
        );
        let resp = Response::from_parts(parts, body);

        tokio::task::spawn(async move {
            // Upgrade the request first
            match hyper::upgrade::on(req).await {
                Ok(upgraded_req) => match hyper::upgrade::on(resp).await {
                    Ok(upgraded_res) => {
                        let mut req_io = TokioIo::new(upgraded_req);
                        let mut res_io = TokioIo::new(upgraded_res);
                        match tokio::io::copy_bidirectional(&mut req_io, &mut res_io).await {
                            Ok((up_bytes, down_bytes)) => {
                                tracing::info!(
                                    "Upgrade completed, {} bytes sent, {} bytes received",
                                    up_bytes,
                                    down_bytes
                                )
                            }
                            Err(e) => {
                                tracing::info!("Upgrade completed with error {}", e.to_string())
                            }
                        }
                    }
                    Err(e) => {
                        tracing::info!("Response upgrade failed with error {}", e.to_string())
                    }
                },
                Err(e) => tracing::info!("Request upgrade failed with error {}", e.to_string()),
            }
        });

        tracing::info!("Upgrade tunnel established for {}", https_uri);
        return Ok(response);
    }

    let (parts, body) = req.into_parts();

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
    use hyper::Request;
    use hyper_util::client::legacy::Client;
    use hyper_util::rt::TokioExecutor;
    use rustls::RootCertStore;
    use std::sync::Arc;

    fn new_client() -> (Arc<impl HttpClientLike>, Arc<ClientConfig>) {
        let client_config = Arc::new(
            ClientConfig::builder()
                .with_root_certificates(RootCertStore::empty())
                .with_no_client_auth(),
        );
        let https = hyper_rustls::HttpsConnectorBuilder::new()
            .with_tls_config((*client_config).clone())
            .https_only()
            .enable_http1()
            .build();
        let client = Client::builder(TokioExecutor::new()).build(https);
        (Arc::new(client), client_config)
    }

    #[tokio::test]
    async fn test_handler_invalid_scheme() {
        // The outbound proxy should reject non-HTTP requests
        let req = Request::get("https://example.com")
            .body(BoxBody::new(
                Empty::<Bytes>::new().map_err(Into::<DynError>::into),
            ))
            .unwrap();
        let (client, config) = new_client();
        let result = handler(req, client, config).await;
        assert!(result.is_ok());
        let resp = result.unwrap();
        assert_eq!(resp.status(), 400);
    }
}
