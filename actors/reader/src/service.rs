//! The `ReaderService`: the contract's one call, with the audit of every call.

#![allow(refining_impl_trait)] // the generated trait returns `impl Encodable`; a concrete type is fine

use connectrpc::error::ErrorCode;
use connectrpc::{ConnectError, RequestContext, Response, ServiceRequest, ServiceResult};
use sluis_audit::Emitter;
use sluis_kit::{refusal, refusal_reason};
use sluis_proto::sluis::reader::v2alpha1::{ReaderService, SearchRequest, SearchResponse};

use crate::audit::{self, Outcome};
use crate::search::{Decision, Searcher};

/// The reader's service over a [`Searcher`] and an emitter.
pub struct Service {
    searcher: Searcher,
    audit: Emitter,
}

impl Service {
    #[must_use]
    pub fn new(searcher: Searcher, audit: Emitter) -> Self {
        Self { searcher, audit }
    }

    /// The reason to write in the audit record of a refusal: the closed word of its `Refusal` detail.
    fn reason(e: &ConnectError) -> String {
        refusal_reason(e).unwrap_or_else(|| e.code.as_str().to_owned())
    }
}

impl ReaderService for Service {
    async fn search(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, SearchRequest>,
    ) -> ServiceResult<SearchResponse> {
        let q = request.to_owned_message();
        // A request that does not fit the contract is audited without its tenants: they are the caller's words.
        let tenants: &[String] = if crate::search::validate(&q).is_ok() {
            &q.tenants
        } else {
            &[]
        };
        let mut seen: Vec<Decision> = Vec::new();
        let result = self.searcher.run(&q, &mut seen).await;
        match result {
            Ok(res) => {
                let ev = audit::search(&Outcome {
                    tenants,
                    decisions: &seen,
                    hits: res.hits.len(),
                    status_code: "",
                });
                // No record leaves before its read is durable in the audit transport: a read that cannot be
                // audited is not made (0029 "Sealing": a blocking emit returns when the message is durable).
                if let Err(e) = self.audit.emit_blocking(ev).await {
                    tracing::error!(code = e.code.as_str(), "the search could not be audited");
                    return Err(refusal(ErrorCode::Unavailable, "engine", "audit"));
                }
                Response::ok(res)
            }
            Err(e) => {
                let reason = Self::reason(&e);
                let ev = audit::search(&Outcome {
                    tenants,
                    decisions: &seen,
                    hits: 0,
                    status_code: &reason,
                });
                if let Err(a) = self.audit.emit(ev).await {
                    tracing::warn!(
                        code = a.code.as_str(),
                        "a refused search could not be audited"
                    );
                }
                Err(e)
            }
        }
    }
}
