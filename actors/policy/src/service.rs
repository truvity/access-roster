//! `sluis.policy.v2alpha1.PolicyService`: the decision, and the sealed grant of an allow.
//!
//! The caller is the peer the kit named from the transport; no request field says who it is. A
//! decision is made against the engine in force at that moment, sealed at key@ when it is an
//! allow, and audited once. Anything that goes wrong after Cedar said allow, a key@ that does not
//! seal or an audit fact that is not durable, ends as a deny: policy cannot decide, so it denies.

use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use connectrpc::error::ErrorCode;
use connectrpc::{RequestContext, Response, ServiceRequest, ServiceResult};
use sluis_audit::{Emitter, new_uuid_v7};
use sluis_kit::{Peer, Transport, refusal};
use sluis_proto::sluis::key::v2alpha1::{KeyServiceClient, SealGrantRequest};
use sluis_proto::sluis::policy::v2alpha1::{
    DecideRequest, DecideResponse, Decision, PolicyService, Reason as WireReason,
};

use crate::audit::{self, Outcome};
use crate::decide::Verdict;
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

impl Service {
    /// Seals the grant of an allow. `Err` carries the closed reason the allow is withdrawn for.
    async fn seal(
        &self,
        engine: &Engine,
        caller: &str,
        req: &DecideRequest,
        v: &Verdict,
        decision_id: &str,
        now: SystemTime,
    ) -> Result<Vec<u8>, &'static str> {
        let (verbs, ops) = grant::ceiling(caller);
        // Narrow, never widen: what was asked, cut to what the caller can do at all.
        let store_verbs =
            grant::narrow(&req.grant_store_verbs, &STORE_VERBS, &verbs).map_err(|_| "grant")?;
        let key_ops = grant::narrow(&req.grant_key_ops, &KEY_OPS, &ops).map_err(|_| "grant")?;
        let g = grant::build(grant::Parts {
            boundary: &engine.boundary,
            holder: caller,
            tenant: &v.tenant,
            store_verbs,
            key_ops,
            decision_id,
            action: v.action,
            now,
        });
        match self
            .keys
            .seal_grant(SealGrantRequest {
                grant: g.into(),
                ..SealGrantRequest::default()
            })
            .await
        {
            Ok(r) => {
                let sealed = r.into_owned().sealed_grant;
                if sealed.is_empty() {
                    Err("keys")
                } else {
                    Ok(sealed)
                }
            }
            Err(e) => {
                tracing::warn!(code = e.code.as_str(), "key@ did not seal the grant");
                Err("keys")
            }
        }
    }

    async fn decide_inner(&self, who: &Peer, req: DecideRequest) -> DecideResponse {
        let engine = self.engine();
        let now = (self.clock)();
        let decision_id = new_uuid_v7(unix_ms(now));
        let verdict = engine.decide(who.name, &req);
        let digest = engine.digest().to_owned();

        let mut allowed = verdict.allow;
        let mut why = verdict.why;
        let mut sealed = Vec::new();
        if allowed {
            match self
                .seal(&engine, who.name, &req, &verdict, &decision_id, now)
                .await
            {
                Ok(s) => sealed = s,
                Err(w) => (allowed, why) = (false, w),
            }
        }
        let principal = req.principal.as_option();
        let principal_type = principal
            .map(|p| p.r#type.as_str())
            .filter(|t| matches!(*t, "Person" | "Actor"))
            .unwrap_or("unknown");
        let subject = (principal_type == "Person")
            .then(|| req.person.as_option().map(|p| p.subject.as_str()))
            .flatten()
            .filter(|s| !s.is_empty());
        let event = audit::decide(&Outcome {
            verdict: &verdict,
            decision_id: &decision_id,
            digest: &digest,
            asker: who.name,
            principal_type,
            subject,
            allowed,
            why,
        });
        // A grant is a power, so an allow leaves its audit fact durable before it is handed out
        // (the rule key@ keeps for a signature). A denial hands out nothing, so its fact need not
        // hold the answer.
        if allowed {
            if let Err(e) = self.audit.emit_blocking(event).await {
                tracing::error!(
                    code = e.code.as_str(),
                    "the allow could not be audited; withdrawn"
                );
                // The grant was sealed and is dropped here; it expires unused.
                allowed = false;
                sealed.clear();
                self.emit_withdrawn(
                    &verdict,
                    &decision_id,
                    &digest,
                    who.name,
                    principal_type,
                    subject,
                )
                .await;
            }
        } else if let Err(e) = self.audit.emit(event).await {
            tracing::error!(code = e.code.as_str(), "a denial could not be audited");
        }
        if allowed {
            DecideResponse {
                decision: Decision::ALLOW.into(),
                reasons: wire_reasons(&verdict),
                grant_names: verdict.grant_names.clone(),
                digest,
                sealed_grant: sealed,
                decision_id,
                ..DecideResponse::default()
            }
        } else {
            DecideResponse {
                decision: Decision::DENY.into(),
                // A denial by a forbid names it: `session` reads `@step_up` from it. A denial that
                // was not Cedar's names nothing.
                reasons: if why.is_empty() {
                    wire_reasons(&verdict)
                } else {
                    Vec::new()
                },
                digest,
                decision_id,
                ..DecideResponse::default()
            }
        }
    }

    /// The fact that an allow was withdrawn because its own audit fact was not durable: one more
    /// record, best effort, so the log shows the decision id that was never handed out.
    async fn emit_withdrawn(
        &self,
        verdict: &Verdict,
        decision_id: &str,
        digest: &str,
        asker: &str,
        principal_type: &str,
        subject: Option<&str>,
    ) {
        let event = audit::decide(&Outcome {
            verdict,
            decision_id,
            digest,
            asker,
            principal_type,
            subject,
            allowed: false,
            why: "audit",
        });
        let _ = self.audit.emit(event).await;
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
        Response::ok(self.decide_inner(&who, request.to_owned_message()).await)
    }
}
