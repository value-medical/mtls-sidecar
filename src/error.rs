use thiserror::Error;

#[derive(Error, Debug)]
pub enum DomainError {
    #[error("Config error: {0}")]
    Config(String),
    #[error("Certificate error: {0}")]
    Certificate(String),
    #[error("URI error: {0}")]
    Uri(#[from] http::uri::InvalidUri),
    #[error("HTTP error: {0}")]
    Http(#[from] http::Error),
    #[error("Hyper Client error: {0}")]
    HyperClient(#[from] hyper_util::client::legacy::Error),
    #[error("Other error: {0}")]
    Other(String),
}
