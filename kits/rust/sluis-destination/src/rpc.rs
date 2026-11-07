//! The destination port on the wire: [`Service`] serves any [`Destination`] as the Connect `DestinationService`, and
//! [`Client`] is the [`Destination`] that exporter@ calls a driver's socket with.
//!
//! Each [`Error`] becomes a Connect code with a `Refusal` reason (contracts.md "Errors"): `unsupported` is
//! `unimplemented`, an invalid field is `invalid_argument` with the field's path, and an unreachable destination is
//! `unavailable` with the reason `engine`. An error names a field, never a value.

use std::sync::Arc;

use connectrpc::error::ErrorCode;
use connectrpc::{ConnectError, RequestContext, Response, ServiceRequest, ServiceResult};
use sluis_kit::{Client as Dial, Transport, refusal, refusal_reason};
use sluis_proto::sluis::port::destination::v2alpha1::{
    DeleteRequest, DeleteResponse, DestinationService, DestinationServiceClient,
    Document as WireDocument, ListRequest, ListResponse, PurgeRequest, PurgeResponse, PurgeResult,
    PutRequest, PutResponse, ReadBackRequest, ReadBackResponse,
};

use crate::{Destination, Document, Error, Fetched, Listed, Page, Purged, Written, check_document};

/// Any [`Destination`] as a `DestinationService`.
pub struct Service<D>(pub Arc<D>);

impl<D> Clone for Service<D> {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

fn refuse(e: &Error) -> ConnectError {
    match e {
        Error::Unsupported => refusal(ErrorCode::Unimplemented, "unsupported", ""),
        Error::Invalid(field) => refusal(ErrorCode::InvalidArgument, "invalid", field),
        Error::Unavailable(why) => {
            tracing::error!(why = %why, "the destination failed");
            refusal(ErrorCode::Unavailable, "engine", "")
        }
    }
}

impl<D: Destination + 'static> DestinationService for Service<D> {
    async fn put(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, PutRequest>,
    ) -> ServiceResult<PutResponse> {
        let doc = Document {
            address: request.address.to_owned(),
            content_type: request.content_type.to_owned(),
            cache_control: request.cache_control.to_owned(),
            body: request.body.to_vec(),
        };
        let w = self.0.put(doc).await.map_err(|e| refuse(&e))?;
        Response::ok(PutResponse {
            version: w.version,
            sha256: w.sha256,
            ..PutResponse::default()
        })
    }

    async fn delete(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, DeleteRequest>,
    ) -> ServiceResult<DeleteResponse> {
        let removed = self
            .0
            .delete(request.address)
            .await
            .map_err(|e| refuse(&e))?;
        Response::ok(DeleteResponse {
            removed,
            ..DeleteResponse::default()
        })
    }

    async fn list(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, ListRequest>,
    ) -> ServiceResult<ListResponse> {
        let size = usize::try_from(request.page_size).unwrap_or(0);
        let token = request.page_token;
        let page = self
            .0
            .list(request.prefix, (!token.is_empty()).then_some(token), size)
            .await
            .map_err(|e| refuse(&e))?;
        Response::ok(ListResponse {
            documents: page
                .documents
                .into_iter()
                .map(|d| WireDocument {
                    address: d.address,
                    sha256: d.sha256,
                    content_type: d.content_type,
                    cache_control: d.cache_control,
                    size: d.size,
                    ..WireDocument::default()
                })
                .collect(),
            next_page_token: page.next.unwrap_or_default(),
            ..ListResponse::default()
        })
    }

    async fn purge(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, PurgeRequest>,
    ) -> ServiceResult<PurgeResponse> {
        let addresses = request.to_owned_message().addresses;
        let result = match self.0.purge(&addresses).await.map_err(|e| refuse(&e))? {
            Purged::None => PurgeResult::PURGE_RESULT_NONE,
            Purged::Purged => PurgeResult::PURGE_RESULT_PURGED,
        };
        Response::ok(PurgeResponse {
            result: result.into(),
            ..PurgeResponse::default()
        })
    }

    async fn read_back(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, ReadBackRequest>,
    ) -> ServiceResult<ReadBackResponse> {
        let f = self
            .0
            .read_back(request.address)
            .await
            .map_err(|e| refuse(&e))?;
        Response::ok(ReadBackResponse {
            status: u32::from(f.status),
            cache_control: f.cache_control,
            content_type: f.content_type,
            age: f.age,
            cache_state: f.cache_state,
            body: f.body,
            ..ReadBackResponse::default()
        })
    }
}

/// The [`Destination`] behind a driver's socket.
#[derive(Clone)]
pub struct Client {
    inner: DestinationServiceClient<Transport>,
}

impl Client {
    /// A client over the driver's socket (dialled at the first call).
    #[must_use]
    pub fn new(dial: &Dial) -> Self {
        Self {
            inner: DestinationServiceClient::new(dial.transport(), dial.config()),
        }
    }
}

fn error_of(e: &ConnectError) -> Error {
    match e.code {
        ErrorCode::Unimplemented => Error::Unsupported,
        ErrorCode::InvalidArgument => Error::Invalid("remote"),
        _ => Error::Unavailable(format!(
            "{} ({})",
            e.code.as_str(),
            refusal_reason(e).unwrap_or_else(|| "-".into())
        )),
    }
}

impl Destination for Client {
    async fn put(&self, doc: Document) -> Result<Written, Error> {
        // The same rule as the server's, so a document the wire would not take is refused here with its field.
        check_document(&doc)?;
        let r = self
            .inner
            .put(PutRequest {
                address: doc.address,
                content_type: doc.content_type,
                cache_control: doc.cache_control,
                body: doc.body,
                ..PutRequest::default()
            })
            .await
            .map_err(|e| error_of(&e))?
            .into_owned();
        Ok(Written {
            version: r.version,
            sha256: r.sha256,
        })
    }

    async fn delete(&self, address: &str) -> Result<bool, Error> {
        let r = self
            .inner
            .delete(DeleteRequest {
                address: address.to_owned(),
                ..DeleteRequest::default()
            })
            .await
            .map_err(|e| error_of(&e))?
            .into_owned();
        Ok(r.removed)
    }

    async fn list(&self, prefix: &str, page: Option<&str>, size: usize) -> Result<Page, Error> {
        let r = self
            .inner
            .list(ListRequest {
                prefix: prefix.to_owned(),
                page_token: page.unwrap_or_default().to_owned(),
                page_size: i32::try_from(size).unwrap_or(i32::MAX),
                ..ListRequest::default()
            })
            .await
            .map_err(|e| error_of(&e))?
            .into_owned();
        Ok(Page {
            documents: r
                .documents
                .into_iter()
                .map(|d| Listed {
                    address: d.address,
                    sha256: d.sha256,
                    content_type: d.content_type,
                    cache_control: d.cache_control,
                    size: d.size,
                })
                .collect(),
            next: (!r.next_page_token.is_empty()).then_some(r.next_page_token),
        })
    }

    async fn purge(&self, addresses: &[String]) -> Result<Purged, Error> {
        let r = self
            .inner
            .purge(PurgeRequest {
                addresses: addresses.to_vec(),
                ..PurgeRequest::default()
            })
            .await
            .map_err(|e| error_of(&e))?
            .into_owned();
        match r.result.as_known() {
            Some(PurgeResult::PURGE_RESULT_NONE) => Ok(Purged::None),
            Some(PurgeResult::PURGE_RESULT_PURGED) => Ok(Purged::Purged),
            _ => Err(Error::Unavailable("purge: an answer with no result".into())),
        }
    }

    async fn read_back(&self, address: &str) -> Result<Fetched, Error> {
        let r = self
            .inner
            .read_back(ReadBackRequest {
                address: address.to_owned(),
                ..ReadBackRequest::default()
            })
            .await
            .map_err(|e| error_of(&e))?
            .into_owned();
        Ok(Fetched {
            status: u16::try_from(r.status).unwrap_or(0),
            cache_control: r.cache_control,
            content_type: r.content_type,
            age: r.age,
            cache_state: r.cache_state,
            body: r.body,
        })
    }
}
