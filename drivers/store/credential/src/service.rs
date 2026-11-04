//! The `SourceService` over [`Dir`] for secrets. Every [`Error`] becomes a Connect code with a
//! `Refusal` reason, and an error names a field, never a value.

#![allow(refining_impl_trait)] // the generated trait returns `impl Encodable`; a concrete type is fine

use connectrpc::error::ErrorCode;
use connectrpc::{
    ConnectError, RequestContext, Response, ServiceRequest, ServiceResult, ServiceStream,
};
use sluis_kit::refusal;
use sluis_proto::sluis::port::source::v2alpha1::{
    CapabilitiesRequest, CapabilitiesResponse, ReadRequest, ReadResponse, SourceService,
    SourceWatchRequest, SourceWatchResponse, Watch,
};

use crate::{Dir, Error};

/// The secret source of one directory.
#[derive(Clone)]
pub struct Service(pub Dir);

fn refuse(e: &Error) -> ConnectError {
    match e {
        Error::Name => refusal(ErrorCode::InvalidArgument, "schema", "name"),
        Error::Absent => refusal(ErrorCode::NotFound, "absent", "name"),
        Error::Bound => refusal(ErrorCode::FailedPrecondition, "bound", "name"),
        Error::Rule => refusal(ErrorCode::PermissionDenied, "rule", "name"),
        Error::Io(kind) => {
            tracing::error!(?kind, "credentials directory failed");
            refusal(ErrorCode::Unavailable, "engine", "")
        }
    }
}

impl SourceService for Service {
    async fn capabilities(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, CapabilitiesRequest>,
    ) -> ServiceResult<CapabilitiesResponse> {
        Response::ok(CapabilitiesResponse {
            watch: Watch::NONE.into(),
            ..CapabilitiesResponse::default()
        })
    }

    async fn read(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, ReadRequest>,
    ) -> ServiceResult<ReadResponse> {
        let (name, held) = (request.name.to_owned(), request.if_none_match.to_owned());
        let dir = self.0.clone();
        let secret = match tokio::task::spawn_blocking(move || dir.read(&name)).await {
            Ok(r) => r.map_err(|e| refuse(&e))?,
            Err(_) => return Err(refusal(ErrorCode::Internal, "engine", "")),
        };
        if !held.is_empty() && held == secret.version {
            return Response::ok(ReadResponse {
                unchanged: true,
                version: secret.version,
                ..ReadResponse::default()
            });
        }
        Response::ok(ReadResponse {
            data: secret.data,
            version: secret.version,
            ..ReadResponse::default()
        })
    }

    /// A credential does not change under a running service, so there is nothing to watch.
    async fn watch(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, SourceWatchRequest>,
    ) -> ServiceResult<ServiceStream<SourceWatchResponse>> {
        Err(refusal(ErrorCode::Unimplemented, "rule", ""))
    }
}
