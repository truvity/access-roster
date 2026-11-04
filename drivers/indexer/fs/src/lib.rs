//! The read-only `fs` blob driver of the indexer and the reader (ADR 0028 "Access": the blob store's own
//! access control, "file permissions per uid on a local file system").
//!
//! The writer's driver (`driver-writer-fs`) answers `writer` alone. This driver is a second process, under
//! its own uid, over the same directory: it serves `Get` and `List` of the blob port and nothing else.
//! `Create` and `Put` are refused with `permission_denied` / `rule`, and the directory is mounted
//! read-only where the deployment can. It reads the writer's files through the group of the writer's
//! driver (files 0640, directories 0750), so it can read what the writer made and change nothing.
//!
//! It serves two sockets, one per caller, each with its own peer check: `blob.sock` answers `indexer`
//! only, and `blob-ro.sock` answers `reader` only (the same pair as `index.sock` and `index-ro.sock` of
//! the index driver).

#![allow(refining_impl_trait)] // the generated trait returns `impl Encodable`; a concrete type is fine

use connectrpc::error::ErrorCode;
use connectrpc::{RequestContext, ServiceRequest, ServiceResult};
use sluis_driver_writer_fs::Fs;
use sluis_driver_writer_fs::service::Service;
use sluis_kit::refusal;
use sluis_proto::sluis::port::blob::v2alpha1::{
    BlobGetRequest, BlobGetResponse, BlobListRequest, BlobListResponse, BlobService, CreateRequest,
    CreateResponse, PutRequest, PutResponse,
};

pub mod suite;

/// The registry name of this driver's user.
pub const NAME: &str = "driver-indexer-fs";
/// The registry name of the writer's driver, whose directory this one reads.
pub const WRITER_DRIVER: &str = "driver-writer-fs";

/// The blob port, read side: [`Fs`] with no way to write.
#[derive(Clone)]
pub struct ReadOnly(pub Fs);

fn no_write<T>() -> ServiceResult<T> {
    Err(refusal(ErrorCode::PermissionDenied, "rule", "path"))
}

impl BlobService for ReadOnly {
    async fn create(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, CreateRequest>,
    ) -> ServiceResult<CreateResponse> {
        no_write()
    }

    async fn put(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, PutRequest>,
    ) -> ServiceResult<PutResponse> {
        no_write()
    }

    async fn get(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, BlobGetRequest>,
    ) -> ServiceResult<BlobGetResponse> {
        Service(self.0.clone()).get(ctx, request).await
    }

    async fn list(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, BlobListRequest>,
    ) -> ServiceResult<BlobListResponse> {
        Service(self.0.clone()).list(ctx, request).await
    }
}
