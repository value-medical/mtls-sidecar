use anyhow::Result;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{body::Body, Request, Response, StatusCode};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;

pub async fn handler<B>(req: Request<B>) -> Result<Response<Full<Bytes>>>
where
    B: Body + Send + Unpin + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let (parts, body) = req.into_parts();

    // Extract client cert from extensions
    let client_cert = parts
        .extensions
        .get::<rustls::pki_types::CertificateDer<'static>>();

    if client_cert.is_none() {
        return Ok(Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .body(Full::new(Bytes::from("Unauthorized")))
            .unwrap());
    }

    // Forward to upstream
    let client = Client::builder(TokioExecutor::new()).build_http();
    let upstream_url = "http://localhost:8080";

    let method = parts.method.clone();
    let uri = parts.uri.clone();

    // Build upstream request
    let mut upstream_req_builder = Request::builder()
        .method(method.clone())
        .uri(format!("{}{}", upstream_url, uri));

    // Copy headers
    for (key, value) in &parts.headers {
        upstream_req_builder
            .headers_mut()
            .unwrap()
            .insert(key, value.clone());
    }

    // Set host header
    upstream_req_builder
        .headers_mut()
        .unwrap()
        .insert("host", "localhost:8080".parse().unwrap());

    let upstream_req = upstream_req_builder.body(body).unwrap();

    let resp = client.request(upstream_req).await?;

    tracing::info!("Proxied request {} {}", method, uri);

    if resp.status().is_server_error() {
        tracing::error!("Upstream error: {}", resp.status());
    }

    // Read response body
    let body_bytes = resp.into_body().collect().await?.to_bytes();

    Ok(Response::new(Full::new(body_bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::Empty;

    #[tokio::test]
    async fn test_handler_missing_cert() {
        let req = Request::new(Empty::<Bytes>::new());
        let resp = handler(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }
}
