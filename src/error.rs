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
    #[error("HTTP error: {0}")]
    Hyper(#[from] hyper::Error),
    #[error("Hyper Client error: {0}")]
    HyperClient(#[from] hyper_util::client::legacy::Error),
    #[error("Dynamic error: {0}")]
    Dynamic(anyhow::Error),
}

pub type DynError = Box<dyn std::error::Error + Send + Sync + 'static>;

impl From<DynError> for DomainError {
    fn from(e: DynError) -> Self {
        let err_ref: &dyn std::error::Error = &*e;
        if let Some(_) = err_ref.downcast_ref::<hyper::Error>() {
            let hyper_err = e.downcast::<hyper::Error>().unwrap();
            DomainError::Hyper(*hyper_err)
        } else if let Some(_) = err_ref.downcast_ref::<http::Error>() {
            let http_err = e.downcast::<http::Error>().unwrap();
            DomainError::Http(*http_err)
        } else if let Some(_) = err_ref.downcast_ref::<hyper_util::client::legacy::Error>() {
            let client_err = e.downcast::<hyper_util::client::legacy::Error>().unwrap();
            DomainError::HyperClient(*client_err)
        } else {
            DomainError::Dynamic(anyhow::Error::from_boxed(e))
        }
    }
}
