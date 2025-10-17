use axum::http::StatusCode;
use axum::routing::get;
use axum::Router;
use base64::Engine;
use tokio::net::TcpListener;

#[derive(serde::Deserialize)]
struct ClientTLSInfo {
    subject: String,
    uri_sans: Vec<String>,
    dns_sans: Vec<String>,
    hash: String,
    not_before: String,
    not_after: String,
    serial: String,
}

async fn root_handler(req: axum::http::Request<axum::body::Body>) -> Result<String, StatusCode> {
    if let Some(h) = req.headers().get("X-Client-TLS-Info") {
        let b64_bytes = base64::engine::general_purpose::STANDARD
            .decode(h.to_str().unwrap())
            .unwrap_or_default();
        let json_str = String::from_utf8_lossy(&b64_bytes);
        let info: ClientTLSInfo = serde_json::from_str(&json_str).unwrap();
        Ok(format!("Client Subject: {}", info.subject))
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}

#[tokio::main]
async fn main() {
    let router = Router::new()
        .route("/", get(root_handler));
    let listener = TcpListener::bind("0.0.0.0:8080").await.unwrap();
    tokio::spawn(async move {
        dbg!(axum::serve(listener, router).await.unwrap());
    });
}
