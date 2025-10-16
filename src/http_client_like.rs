use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::BodyExt;
use hyper::body::Body;
use hyper::{Request, Response};
use hyper_util::client::legacy::{connect::HttpConnector, Client};
use std::error::Error;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

pub type BodyError = Box<dyn Error + Send + Sync>;

pub type ProxiedBody = BoxBody<Bytes, BodyError>;

pub trait HttpClientLike<B>: Send + Sync {
    fn request(
        &self,
        req: Request<B>,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<
                        Response<ProxiedBody>,
                        hyper_util::client::legacy::Error,
                    >,
                > + Send,
        >,
    >;
}

impl<B> HttpClientLike<B> for Client<HttpConnector, B>
where
    B: Body<Data = Bytes> + Send + Unpin + 'static,
    B::Error: Into<BodyError>,
{
    fn request(
        &self,
        req: Request<B>,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<
                        Response<ProxiedBody>,
                        hyper_util::client::legacy::Error,
                    >,
                > + Send,
        >,
    > {
        let client = self.clone();
        Box::pin(async move {
            let resp = Client::request(&client, req).await?;
            let (parts, body) = resp.into_parts();
            let mapped_body = body.map_err(Into::<BodyError>::into);
            let proxied_body = BoxBody::new(mapped_body);
            Ok(Response::from_parts(parts, proxied_body))
        })
    }
}

impl<B> HttpClientLike<B> for Arc<Client<HttpConnector, B>>
where
    B: Body<Data = Bytes> + Send + Unpin + 'static,
    B::Error: Into<BodyError>,
{
    fn request(
        &self,
        req: Request<B>,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<
                        Response<ProxiedBody>,
                        hyper_util::client::legacy::Error,
                    >,
                > + Send,
        >,
    > {
        let client = self.clone();
        Box::pin(async move {
            let resp = Client::request(&*client, req).await?;
            let (parts, body) = resp.into_parts();
            let mapped_body = body.map_err(Into::<BodyError>::into);
            let proxied_body = BoxBody::new(mapped_body);
            Ok(Response::from_parts(parts, proxied_body))
        })
    }
}