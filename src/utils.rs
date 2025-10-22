use bytes::Bytes;
use http::Request;
use http_body_util::BodyExt;
use http_body_util::combinators::BoxBody;
use hyper::body::Incoming;
use crate::error::DynError;

pub fn adapt_request(req: Request<Incoming>) -> Request<BoxBody<Bytes, DynError>> {
    let (parts, body) = req.into_parts();
    let adapted_body = body.map_err(Into::<DynError>::into).boxed();
    Request::from_parts(parts, adapted_body)
}
