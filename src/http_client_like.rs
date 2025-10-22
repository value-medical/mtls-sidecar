use crate::error::DynError;
use bytes::Bytes;
use http::Response;
use http_body_util::combinators::BoxBody;
use http_body_util::BodyExt;
use hyper::Request;
use hyper_util::client::legacy::Client as LegacyClient;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

pub trait ResponseFutureLike:
    Future<Output = Result<Response<BoxBody<Bytes, DynError>>, DynError>> + Send
{
}

impl<T> ResponseFutureLike for T where
    T: Future<Output = Result<Response<BoxBody<Bytes, DynError>>, DynError>> + Send
{
}

pub trait HttpClientLike: Send + Sync + Clone {
    fn request(&self, req: Request<BoxBody<Bytes, DynError>>) -> Pin<Box<dyn ResponseFutureLike>>;
}

impl<C> HttpClientLike for LegacyClient<C, BoxBody<Bytes, DynError>>
where
    C: hyper_util::client::legacy::connect::Connect + Sync + Send + Clone + 'static,
{
    fn request(&self, req: Request<BoxBody<Bytes, DynError>>) -> Pin<Box<dyn ResponseFutureLike>> {
        let client = self.clone();
        Box::pin(async move {
            let resp = <Self>::request(&client, req)
                .await
                .map_err(Into::<DynError>::into)?;
            let (parts, body) = resp.into_parts();
            let mapped_body = body.map_err(Into::<DynError>::into);
            let proxied_body = BoxBody::new(mapped_body);
            Ok(Response::from_parts(parts, proxied_body))
        })
    }
}

impl<C> HttpClientLike for Arc<C>
where
    C: HttpClientLike,
{
    fn request(&self, req: Request<BoxBody<Bytes, DynError>>) -> Pin<Box<dyn ResponseFutureLike>> {
        (**self).request(req)
    }
}
