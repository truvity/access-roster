//! The two services of the driver over [`Index`]: `IndexService` on `index.sock` for the indexer and
//! `IndexReadService` on `index-ro.sock` for the reader. Each method runs on a blocking thread, and
//! each [`Error`] becomes a Connect code with a `Refusal` reason (contracts.md "Errors"). An error
//! names a field, never a value.

#![allow(refining_impl_trait)] // the generated trait returns `impl Encodable`; a concrete type is fine

use connectrpc::error::ErrorCode;
use connectrpc::{ConnectError, RequestContext, Response, ServiceRequest, ServiceResult};
use sluis_kit::refusal;
use sluis_proto::sluis::port::index::v2alpha1::{
    ApplyRequest, ApplyResponse, GetCursorRequest, GetCursorResponse, IndexReadService,
    IndexService, SearchRequest, SearchResponse,
};

use crate::{Error, Index};

/// The write side: the indexer's socket.
#[derive(Clone)]
pub struct Write(pub Index);

/// The read side: the reader's socket. It has no way to write.
#[derive(Clone)]
pub struct Read(pub Index);

/// The Connect error of an [`Error`].
fn refuse(e: &Error) -> ConnectError {
    match e {
        Error::Argument(field) => refusal(ErrorCode::InvalidArgument, "argument", field),
        Error::Version => refusal(ErrorCode::Aborted, "version", "expect_size"),
        Error::Rule => refusal(ErrorCode::PermissionDenied, "rule", "log.kind"),
        Error::Engine(e) => {
            tracing::error!(error = %e, "index database failed");
            refusal(ErrorCode::Unavailable, "engine", "")
        }
    }
}

async fn run<T: Send + 'static>(
    index: &Index,
    f: impl FnOnce(Index) -> Result<T, Error> + Send + 'static,
) -> Result<T, ConnectError> {
    let index = index.clone();
    match tokio::task::spawn_blocking(move || f(index)).await {
        Ok(r) => r.map_err(|e| refuse(&e)),
        Err(_) => Err(refusal(ErrorCode::Internal, "engine", "")),
    }
}

impl IndexService for Write {
    async fn get_cursor(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, GetCursorRequest>,
    ) -> ServiceResult<GetCursorResponse> {
        let req = request.to_owned_message();
        Response::ok(run(&self.0, move |i| i.get_cursor(&req)).await?)
    }

    async fn apply(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, ApplyRequest>,
    ) -> ServiceResult<ApplyResponse> {
        let req = request.to_owned_message();
        Response::ok(run(&self.0, move |i| i.apply(&req)).await?)
    }
}

impl IndexReadService for Read {
    async fn search(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, SearchRequest>,
    ) -> ServiceResult<SearchResponse> {
        let req = request.to_owned_message();
        Response::ok(run(&self.0, move |i| i.search(&req)).await?)
    }
}
