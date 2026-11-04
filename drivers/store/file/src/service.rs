//! The `SourceService` over [`Dir`]. Every [`Error`] becomes a Connect code with a `Refusal`
//! reason, and an error names a field, never a value.

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

use crate::{Dir, Error, WATCH_EVERY};

/// The config source of one directory.
#[derive(Clone)]
pub struct Service(pub Dir);

/// The Connect error of an [`Error`]; the field at fault is the request's `name`.
fn refuse(e: &Error) -> ConnectError {
    match e {
        Error::Name => refusal(ErrorCode::InvalidArgument, "schema", "name"),
        Error::Absent => refusal(ErrorCode::NotFound, "absent", "name"),
        Error::Bound => refusal(ErrorCode::FailedPrecondition, "bound", "name"),
        Error::Io(io) => {
            tracing::error!(kind = ?io.kind(), "config directory failed");
            refusal(ErrorCode::Unavailable, "engine", "")
        }
    }
}

async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> Result<T, Error> + Send + 'static,
) -> Result<T, ConnectError> {
    match tokio::task::spawn_blocking(f).await {
        Ok(r) => r.map_err(|e| refuse(&e)),
        Err(_) => Err(refusal(ErrorCode::Internal, "engine", "")),
    }
}

impl SourceService for Service {
    async fn capabilities(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, CapabilitiesRequest>,
    ) -> ServiceResult<CapabilitiesResponse> {
        Response::ok(CapabilitiesResponse {
            watch: Watch::NOTIFY.into(),
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
        let doc = blocking(move || dir.read(&name)).await?;
        if !held.is_empty() && held == doc.version {
            return Response::ok(ReadResponse {
                unchanged: true,
                version: doc.version,
                ..ReadResponse::default()
            });
        }
        Response::ok(ReadResponse {
            data: doc.data,
            version: doc.version,
            ..ReadResponse::default()
        })
    }

    async fn watch(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, SourceWatchRequest>,
    ) -> ServiceResult<ServiceStream<SourceWatchResponse>> {
        let name = request.name.to_owned();
        if !crate::valid_name(&name) {
            return Err(refuse(&Error::Name));
        }
        let dir = self.0.clone();
        // What the watcher was last told. The first look sets it without telling: a watcher asks
        // for the version it holds with `Read`, and `Watch` says what changed after it began.
        let first = {
            let (d, n) = (dir.clone(), name.clone());
            blocking(move || d.version(&n)).await?
        };
        Response::stream_ok(futures::stream::unfold(
            (dir, name, first),
            |(dir, name, seen)| async move {
                loop {
                    tokio::time::sleep(WATCH_EVERY).await;
                    let (d, n) = (dir.clone(), name.clone());
                    let now = match blocking(move || d.version(&n)).await {
                        Ok(v) => v,
                        // A failing look ends the stream with its error; the watcher dials again.
                        Err(e) => return Some((Err(e), (dir, name, seen))),
                    };
                    if now != seen {
                        // An absent document is told as the empty label.
                        let item = SourceWatchResponse {
                            name: name.clone(),
                            version: now.clone().unwrap_or_default(),
                            ..SourceWatchResponse::default()
                        };
                        return Some((Ok(item), (dir, name, now)));
                    }
                }
            },
        ))
    }
}
