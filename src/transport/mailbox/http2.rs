use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use http_body_util::BodyExt as _;
use hyper::client::conn::http2;
use hyper::Error as HyperError;
use tower::Service;
use tracing::{debug, trace};

/// Minimal HTTP/2 client that wraps the underlying hashmail Noise transport.
#[derive(Clone)]
pub struct Http2Channel {
    pub(super) send_request: http2::SendRequest<tonic::body::BoxBody>,
    pub(super) authority: http::uri::Authority,
}

impl Http2Channel {
    pub fn new(
        send_request: http2::SendRequest<tonic::body::BoxBody>,
        authority: http::uri::Authority,
    ) -> Self {
        Self {
            send_request,
            authority,
        }
    }
}

impl Service<http::Request<tonic::body::BoxBody>> for Http2Channel {
    type Response = http::Response<tonic::body::BoxBody>;
    type Error = HyperError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, mut req: http::Request<tonic::body::BoxBody>) -> Self::Future {
        if req.uri().scheme().is_none() || req.uri().authority().is_none() {
            let path_and_query = req
                .uri()
                .path_and_query()
                .cloned()
                .unwrap_or_else(|| http::uri::PathAndQuery::from_static("/"));
            match http::Uri::builder()
                .scheme("http")
                .authority(self.authority.as_str())
                .path_and_query(path_and_query)
                .build()
            {
                Ok(uri) => *req.uri_mut() = uri,
                Err(err) => {
                    debug!(
                        target: "lnd_rs::mailbox::http2",
                        error = %err,
                        "failed to synthesize absolute URI for request"
                    );
                }
            }
        }

        if !req.headers().contains_key(http::header::TE) {
            req.headers_mut()
                .insert(http::header::TE, http::HeaderValue::from_static("trailers"));
        }

        debug!(
            target: "lnd_rs::mailbox::http2",
            method = %req.method(),
            uri = %req.uri(),
            te = ?req.headers().get(http::header::TE),
            content_type = ?req.headers().get(http::header::CONTENT_TYPE),
            "sending request"
        );

        let mut sr = self.send_request.clone();
        Box::pin(async move {
            trace!(
                target: "lnd_rs::mailbox::http2",
                "waiting on send_request.ready()..."
            );
            let t0 = std::time::Instant::now();
            sr.ready().await?;
            trace!(
                target: "lnd_rs::mailbox::http2",
                elapsed = ?t0.elapsed(),
                "send_request.ready() done"
            );

            trace!(
                target: "lnd_rs::mailbox::http2",
                "sending request on ready sender"
            );
            let res = sr.send_request(req).await?;
            let (parts, body) = res.into_parts();
            debug!(
                target: "lnd_rs::mailbox::http2",
                status = %parts.status,
                version = ?parts.version,
                "received response"
            );
            let body = body
                .map_err(|e| tonic::Status::internal(e.to_string()))
                .boxed_unsync();
            Ok(http::Response::from_parts(parts, body))
        })
    }
}
