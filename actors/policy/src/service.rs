//! `sluis.policy.v2alpha1.PolicyService`: the decision, and the sealed grant of an allow.
//!
//! The caller is the peer the kit named from the transport; no request field says who it is. A
//! decision is made against the engine in force at that moment, sealed at key@ when it is an
//! allow, and audited once. Anything that goes wrong after Cedar said allow, a key@ that does not
//! seal or an audit fact that is not durable, ends as a deny: policy cannot decide, so it denies.

use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use connectrpc::error::ErrorCode;
use connectrpc::{ConnectError, RequestContext, Response, ServiceRequest, ServiceResult};
use sluis_audit::{Decision, Emitter, new_uuid_v7};
use sluis_kit::{Peer, Transport, refusal};
use sluis_proto::sluis::key::v2alpha1::{KeyServiceClient, SealGrantRequest};
use sluis_proto::sluis::policy::v2alpha1::{
    DecideRequest, DecideResponse, Decision as WireDecision, PolicyService, Reason as WireReason,
};

use crate::audit::{self, Outcome};
use crate::decide::{Refused, Verdict};
use crate::engine::Engine;
use crate::grant::{self, KEY_OPS, STORE_VERBS};

/// What the service is made of.
pub struct Deps {
    pub engine: Engine,
    pub keys: KeyServiceClient<Transport>,
    pub audit: Emitter,
    /// The clock; a test sets one.
    pub clock: fn() -> SystemTime,
}

/// The service. The engine in force is swapped whole by a reload.
pub struct Service {
    engine: RwLock<Arc<Engine>>,
    keys: KeyServiceClient<Transport>,
    audit: Emitter,
    clock: fn() -> SystemTime,
}

impl Service {
    #[must_use]
    pub fn new(d: Deps) -> Self {
        Self {
            engine: RwLock::new(Arc::new(d.engine)),
            keys: d.keys,
            audit: d.audit,
            clock: d.clock,
        }
    }

    /// The engine in force.
    #[must_use]
    pub fn engine(&self) -> Arc<Engine> {
        Arc::clone(
            &self
                .engine
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        )
    }

    /// Puts a new engine in force. The old one answers the calls that already started.
    pub fn swap(&self, next: Engine) {
        *self
            .engine
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Arc::new(next);
    }

    /// The emitter, for the facts of the process itself (start, reload).
    #[must_use]
    pub fn emitter(&self) -> &Emitter {
        &self.audit
    }
}

fn unix_ms(t: SystemTime) -> i64 {
    t.duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_millis()).ok())
        .unwrap_or(0)
}

fn wire_reasons(v: &Verdict) -> Vec<WireReason> {
    v.reasons
        .iter()
        .map(|r| WireReason {
            policy_id: r.policy_id.clone(),
            layer: r.layer.clone(),
            annotations: r.annotations.clone().into_iter().collect(),
            ..WireReason::default()
        })
        .collect()
}

/// The store verbs and key operations of a grant: what the asker asked for, cut to what its action
/// may ever allow and to what the registry gives the asker at all. Narrow, never widen.
fn narrowed(
    caller: &str,
    action: &str,
    req: &DecideRequest,
) -> Result<(Vec<String>, Vec<String>), Refused> {
    let (cap_verbs, cap_ops) = grant::caps(action).ok_or(Refused::schema("action"))?;
    let (verbs, ops) = grant::ceiling(caller);
    let verbs: Vec<&'static str> = verbs
        .into_iter()
        .filter(|v| cap_verbs.contains(v))
        .collect();
    let ops: Vec<&'static str> = ops.into_iter().filter(|o| cap_ops.contains(o)).collect();
    Ok((
        grant::narrow(&req.grant_store_verbs, &STORE_VERBS, &verbs)
            .map_err(|_| Refused::schema("grant_store_verbs"))?,
        grant::narrow(&req.grant_key_ops, &KEY_OPS, &ops)
            .map_err(|_| Refused::schema("grant_key_ops"))?,
    ))
}

impl Service {
    /// Audits a question that was not one, and builds its error.
    async fn refuse(
        &self,
        who: &Peer,
        req: &DecideRequest,
        r: Refused,
        decision_id: &str,
        digest: &str,
    ) -> ConnectError {
        let principal = req.principal.as_option().map(|p| p.r#type.as_str());
        // What the asker wrote is not recorded unless it is a word of ours.
        let action = if grant::caps(&req.action).is_some() {
            req.action.as_str()
        } else {
            "unknown"
        };
        let event = audit::decide(&Outcome {
            decision_id,
            digest,
            asker: who.name,
            principal_type: principal
                .filter(|t| matches!(*t, "Person" | "Actor"))
                .unwrap_or("unknown"),
            subject: None,
            action,
            tenant: "",
            reasons: &[],
            grant_count: 0,
            errors: 0,
            status_code: r.reason,
            path: r.path,
            decision: None,
        });
        if let Err(e) = self.audit.emit(event).await {
            tracing::error!(code = e.code.as_str(), "a refusal could not be audited");
        }
        refusal(r.code, r.reason, r.path)
    }

    async fn decide_inner(&self, who: &Peer, req: DecideRequest) -> ServiceResult<DecideResponse> {
        let engine = self.engine();
        let now = (self.clock)();
        let decision_id = new_uuid_v7(unix_ms(now));
        let digest = engine.digest().to_owned();
        // Cedar recurses: the evaluation runs on a thread with a stack of its own (stack.rs).
        let (asker, held) = (who.name, Arc::clone(&engine));
        let decided = crate::stack::run(move || {
            let verdict = held.decide(asker, &req);
            (req, verdict)
        })
        .await;
        let Ok((req, verdict)) = decided else {
            tracing::error!("the evaluation thread ended without a result");
            return Err(refusal(ErrorCode::Internal, "internal", ""));
        };
        let verdict = match verdict {
            Ok(v) => v,
            Err(r) => return Err(self.refuse(who, &req, r, &decision_id, &digest).await),
        };
        // The verbs and operations are checked before anything is recorded as allowed.
        let wanted = if verdict.allow {
            match narrowed(who.name, verdict.action, &req) {
                Ok(w) => Some(w),
                Err(r) => return Err(self.refuse(who, &req, r, &decision_id, &digest).await),
            }
        } else {
            None
        };
        let is_person = req
            .principal
            .as_option()
            .is_some_and(|p| p.r#type == "Person");
        let subject = req
            .person
            .as_option()
            .map(|p| p.subject.as_str())
            .filter(|s| is_person && !s.is_empty());
        let principal_type = if req
            .principal
            .as_option()
            .is_some_and(|p| p.r#type == "Person")
        {
            "Person"
        } else {
            "Actor"
        };
        let event = audit::decide(&Outcome {
            decision_id: &decision_id,
            digest: &digest,
            asker: who.name,
            principal_type,
            subject,
            action: verdict.action,
            tenant: &verdict.tenant,
            reasons: &verdict.reasons,
            grant_count: verdict.grant_names.len(),
            errors: verdict.errors,
            status_code: verdict.why,
            path: "",
            decision: Some(if verdict.allow {
                Decision::Allowed
            } else {
                Decision::Denied
            }),
        });

        let Some((store_verbs, key_ops)) = wanted else {
            // A denial hands out nothing, so its fact need not hold the answer.
            if let Err(e) = self.audit.emit(event).await {
                tracing::error!(code = e.code.as_str(), "a denial could not be audited");
            }
            return Ok(Response::new(DecideResponse {
                decision: WireDecision::DENY.into(),
                // A denial by a forbid names it: `session` reads `@step_up` from it.
                reasons: wire_reasons(&verdict),
                digest,
                decision_id,
                ..DecideResponse::default()
            }));
        };

        // Audit first: a grant is a power, so its fact is durable before the grant exists. When the
        // fact cannot be made the caller is told so, and there is no grant to withdraw.
        if let Err(e) = self.audit.emit_blocking(event).await {
            tracing::error!(code = e.code.as_str(), "the allow could not be audited");
            return Err(refusal(ErrorCode::Unavailable, "audit", ""));
        }
        let g = grant::build(grant::Parts {
            boundary: &engine.boundary,
            holder: who.name,
            tenant: &verdict.tenant,
            store_verbs,
            key_ops,
            decision_id: &decision_id,
            action: verdict.action,
            now,
        });
        let sealed = match self
            .keys
            .seal_grant(SealGrantRequest {
                grant: g.into(),
                ..SealGrantRequest::default()
            })
            .await
        {
            Ok(r) => r.into_owned().sealed_grant,
            Err(e) => {
                tracing::warn!(code = e.code.as_str(), "key@ did not seal the grant");
                Vec::new()
            }
        };
        if sealed.is_empty() {
            return Err(refusal(ErrorCode::Unavailable, "keys", ""));
        }
        Ok(Response::new(DecideResponse {
            decision: WireDecision::ALLOW.into(),
            reasons: wire_reasons(&verdict),
            grant_names: verdict.grant_names.clone(),
            digest,
            sealed_grant: sealed,
            decision_id,
            ..DecideResponse::default()
        }))
    }
}

#[allow(refining_impl_trait)] // the generated trait returns `impl Encodable`; the concrete type is fine
impl PolicyService for Service {
    async fn decide(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, DecideRequest>,
    ) -> ServiceResult<DecideResponse> {
        // The guard of the kit named the caller before the message was decoded; a call without one
        // never reaches here.
        let Some(who) = sluis_kit::peer(ctx.extensions()).cloned() else {
            return Err(refusal(ErrorCode::PermissionDenied, "caller", ""));
        };
        self.decide_inner(&who, request.to_owned_message()).await
    }
}
