//! The `BlobService` over [`Fs`]: each method runs on a blocking thread, and each [`Error`]
//! becomes a Connect code with a `Refusal` reason (contracts.md "Errors"). An error names a field,
//! never a value.

#![allow(refining_impl_trait)] // the generated trait returns `impl Encodable`; a concrete type is fine

use connectrpc::error::ErrorCode;
use connectrpc::{ConnectError, RequestContext, Response, ServiceRequest, ServiceResult};
use sluis_kit::refusal;
use sluis_proto::sluis::port::blob::v2alpha1::{
    BlobGetRequest, BlobGetResponse, BlobListRequest, BlobListResponse, BlobService, CreateRequest,
    CreateResponse, PutRequest, PutResponse,
};

use crate::{Error, Fs};

/// The blob port of one directory.
#[derive(Clone)]
pub struct Service(pub Fs);

/// The Connect error of an [`Error`]; `field` is the request field at fault.
fn refuse(e: &Error, field: &str) -> ConnectError {
    match e {
        Error::Taken => refusal(ErrorCode::AlreadyExists, "taken", field),
        Error::Absent => refusal(ErrorCode::NotFound, "absent", field),
        Error::Version => refusal(ErrorCode::Aborted, "version", field),
        Error::Rule => refusal(ErrorCode::PermissionDenied, "rule", field),
        Error::Path => refusal(ErrorCode::InvalidArgument, "path", field),
        Error::Io(io) => {
            tracing::error!(error = %io, "blob directory failed");
            refusal(ErrorCode::Unavailable, "engine", "")
        }
    }
}

impl Service {
    async fn run<T: Send + 'static>(
        &self,
        field: &'static str,
        f: impl FnOnce(Fs) -> Result<T, Error> + Send + 'static,
    ) -> Result<T, ConnectError> {
        let fs = self.0.clone();
        match tokio::task::spawn_blocking(move || f(fs)).await {
            Ok(r) => r.map_err(|e| refuse(&e, field)),
            Err(_) => Err(refusal(ErrorCode::Internal, "engine", "")),
        }
    }
}

impl BlobService for Service {
    async fn create(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, CreateRequest>,
    ) -> ServiceResult<CreateResponse> {
        let (path, data) = (request.path.to_owned(), request.data.to_vec());
        let etag = self.run("path", move |fs| fs.create(&path, &data)).await?;
        Response::ok(CreateResponse {
            etag,
            ..CreateResponse::default()
        })
    }

    async fn put(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, PutRequest>,
    ) -> ServiceResult<PutResponse> {
        let (path, data, tag) = (
            request.path.to_owned(),
            request.data.to_vec(),
            request.if_match.to_owned(),
        );
        let etag = self
            .run("path", move |fs| fs.put(&path, &data, &tag))
            .await?;
        Response::ok(PutResponse {
            etag,
            ..PutResponse::default()
        })
    }

    async fn get(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, BlobGetRequest>,
    ) -> ServiceResult<BlobGetResponse> {
        let path = request.path.to_owned();
        let (data, etag) = self.run("path", move |fs| fs.get(&path)).await?;
        Response::ok(BlobGetResponse {
            data,
            etag,
            ..BlobGetResponse::default()
        })
    }

    async fn list(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, BlobListRequest>,
    ) -> ServiceResult<BlobListResponse> {
        let (prefix, token, size) = (
            request.prefix.to_owned(),
            request.page_token.to_owned(),
            request.page_size,
        );
        let (paths, next) = self
            .run("prefix", move |fs| fs.list(&prefix, &token, size))
            .await?;
        Response::ok(BlobListResponse {
            paths,
            next_page_token: next,
            ..BlobListResponse::default()
        })
    }
}
