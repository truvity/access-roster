//! `Search`: the grant is the filter, the log is the source (ADR 0028 "The reader", "Access").
//!
//! One call:
//!
//! 1. The request is checked against the contract: at most 16 tenants, or `*` alone, each a tenant id.
//! 2. `policy` is asked for an `audit.read` grant for each tenant named. A denial refuses the call, and a
//!    tenant that was not granted is never read.
//! 3. The index is asked for the logs of the boundary's `AuditLog`, for those tenants and the request's
//!    filters. This is the grant as a mandatory filter (T-16). A row of a tenant that no grant names is dropped
//!    again here, whatever the index answered.
//! 4. Each row is looked up in the log: the entry at its `seq` must be the record the row stands for. It is
//!    opened at key@ with the grant of its tenant. key@ is the second check, and it does not read the first's
//!    answer. The bytes it returns must hash to the row's `hash`, or the call fails: the index is derived data
//!    and is never trusted over the log.

use std::collections::BTreeSet;

use aws_lc_rs::digest;
use connectrpc::ConnectError;
use connectrpc::error::ErrorCode;
use sluis_kit::refusal;
use sluis_proto::sluis::policy::v2alpha1::{
    ActorFacts, DecideRequest, Decision as Verdict, EntityRef,
};
use sluis_proto::sluis::port::index::v2alpha1::{Partition, Row, SearchRequest as IndexSearch};
use sluis_proto::sluis::reader::v2alpha1::{Hit, SearchRequest, SearchResponse};

use crate::config::{Config, Log};
use crate::open::{Bundles, OPEN_BATCH, Opener};
use crate::ports::{CALL, Ports, down, passed};

/// The name policy knows the reader by (decision D-6: the audit pieces are principals).
const PRINCIPAL: &str = "reader";
/// The action of the grant.
const ACTION: &str = "audit.read";
/// The most tenants one call names.
pub const TENANTS_MAX: usize = 16;
/// The most records one page holds.
pub const PAGE_MAX: i32 = 200;
/// The longest filter or word list, in bytes.
const TEXT_MAX: usize = 256;
/// The longest page token, in bytes.
const TOKEN_MAX: usize = 1024;

/// One decision of policy that took part in a call, for the audit record of the call.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Decision {
    /// The tenant the question was about.
    pub tenant: String,
    /// `ALLOW` or not.
    pub allowed: bool,
    /// The decision id (UUIDv7).
    pub id: String,
    /// The digest of the policy set that decided.
    pub digest: String,
    /// The policies that determined it.
    pub policy_ids: Vec<String>,
}

/// A grant, with the tenant it names.
struct Granted {
    tenant: String,
    sealed: Vec<u8>,
}

/// A tenant id, or `*`: the part rule of store-api.md "Address encoding", as policy checks it.
fn tenant_ok(t: &str) -> bool {
    t == "*"
        || ((1..=128).contains(&t.len())
            && t != "-"
            && t != "."
            && t != ".."
            && t.bytes()
                .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.')))
}

fn invalid(path: &str) -> ConnectError {
    refusal(ErrorCode::InvalidArgument, "schema", path)
}

/// Checks a request against the contract.
///
/// # Errors
///
/// `invalid_argument` / `schema` or `bound`, with the path of the field; never a value.
pub fn validate(q: &SearchRequest) -> Result<(), ConnectError> {
    if q.tenants.is_empty() || q.tenants.iter().any(|t| !tenant_ok(t)) {
        return Err(invalid("tenants"));
    }
    if q.tenants.len() > TENANTS_MAX {
        return Err(refusal(ErrorCode::InvalidArgument, "bound", "tenants"));
    }
    let distinct: BTreeSet<&String> = q.tenants.iter().collect();
    if distinct.len() != q.tenants.len()
        || (q.tenants.len() > 1 && distinct.contains(&"*".to_owned()))
    {
        return Err(invalid("tenants"));
    }
    for (path, v) in [
        ("project", &q.project),
        ("q", &q.q),
        ("action", &q.action),
        ("status_code", &q.status_code),
        ("actor_uid", &q.actor_uid),
        ("trace_id", &q.trace_id),
        ("record_id", &q.record_id),
    ] {
        if v.len() > TEXT_MAX || v.chars().any(char::is_control) {
            return Err(refusal(ErrorCode::InvalidArgument, "bound", path));
        }
    }
    if q.from_ms < 0 || q.to_ms < 0 || (q.to_ms != 0 && q.from_ms > q.to_ms) {
        return Err(invalid("from_ms"));
    }
    if !(0..=PAGE_MAX).contains(&q.page_size) {
        return Err(refusal(ErrorCode::InvalidArgument, "bound", "page_size"));
    }
    if q.page_token.len() > TOKEN_MAX {
        return Err(refusal(ErrorCode::InvalidArgument, "bound", "page_token"));
    }
    Ok(())
}

/// The search, over the ports.
pub struct Searcher {
    boundary: String,
    ports: Ports,
    config: Config,
    opener: Opener,
}

impl Searcher {
    #[must_use]
    pub fn new(boundary: &str, ports: Ports, config: Config) -> Self {
        Self {
            boundary: boundary.to_owned(),
            opener: Opener::new(ports.clone()),
            ports,
            config,
        }
    }

    /// Asks policy for the grant of one tenant. The decision is pushed to `seen` whether or not it allows, so
    /// that the audit record of the call names it.
    async fn grant(&self, tenant: &str, seen: &mut Vec<Decision>) -> Result<Granted, ConnectError> {
        let req = DecideRequest {
            action: ACTION.into(),
            principal: ::buffa::MessageField::some(EntityRef {
                r#type: "Actor".into(),
                id: PRINCIPAL.into(),
                ..EntityRef::default()
            }),
            resource: ::buffa::MessageField::some(EntityRef {
                r#type: "Boundary".into(),
                id: self.boundary.clone(),
                ..EntityRef::default()
            }),
            tenant: tenant.to_owned(),
            actor: ::buffa::MessageField::some(ActorFacts {
                name: PRINCIPAL.into(),
                ..ActorFacts::default()
            }),
            grant_key_ops: vec!["open".into()],
            ..DecideRequest::default()
        };
        let res = tokio::time::timeout(CALL, self.ports.policy.decide(req))
            .await
            .map_err(|_| down("policy"))?
            .map_err(|e| passed("policy", &e))?
            .into_owned();
        let allowed = res.decision == Verdict::ALLOW && !res.sealed_grant.is_empty();
        seen.push(Decision {
            tenant: tenant.to_owned(),
            allowed,
            id: res.decision_id.clone(),
            digest: res.digest.clone(),
            policy_ids: res.reasons.iter().map(|r| r.policy_id.clone()).collect(),
        });
        if !allowed {
            return Err(refusal(ErrorCode::PermissionDenied, "grant", "tenants"));
        }
        Ok(Granted {
            tenant: tenant.to_owned(),
            sealed: res.sealed_grant,
        })
    }

    /// Runs one call. `seen` collects the decisions of policy, also when the call fails.
    ///
    /// # Errors
    ///
    /// See [`validate`]; `permission_denied` / `grant` when policy denies or key@ refuses; `unavailable` /
    /// `engine` when a dependency is down; `internal` / `integrity` when the index and the log disagree.
    pub async fn run(
        &self,
        q: &SearchRequest,
        seen: &mut Vec<Decision>,
    ) -> Result<SearchResponse, ConnectError> {
        validate(q)?;
        let logs: Vec<Log> = self
            .config
            .logs()
            .await?
            .into_iter()
            .filter(|l| q.project.is_empty() || l.project == q.project)
            .collect();
        let mut grants = Vec::new();
        for t in &q.tenants {
            grants.push(self.grant(t, seen).await?);
        }
        if logs.is_empty() {
            return Ok(SearchResponse::default());
        }

        let mut partitions: Vec<Partition> = Vec::new();
        for l in &logs {
            let p = Partition {
                project: l.project.clone(),
                kind: l.kind.clone(),
                ..Partition::default()
            };
            if !partitions.contains(&p) {
                partitions.push(p);
            }
        }
        let page = tokio::time::timeout(
            CALL,
            self.ports.index.search(IndexSearch {
                partitions,
                // The grant is the filter: the tenants that were granted, no others.
                tenants: grants.iter().map(|g| g.tenant.clone()).collect(),
                q: q.q.clone(),
                action: q.action.clone(),
                status_code: q.status_code.clone(),
                status_id: q.status_id,
                actor_uid: q.actor_uid.clone(),
                trace_id: q.trace_id.clone(),
                record_id: q.record_id.clone(),
                from_ms: q.from_ms,
                to_ms: q.to_ms,
                page_size: q.page_size,
                page_token: q.page_token.clone(),
                ..IndexSearch::default()
            }),
        )
        .await
        .map_err(|_| down("index"))?
        .map_err(|e| match e.code {
            ErrorCode::InvalidArgument => invalid("page_token"),
            _ => passed("index", &e),
        })?
        .into_owned();

        // The second look at the grant: whatever the index answered, a row of a tenant no grant names goes.
        let rows: Vec<&Row> = page
            .rows
            .iter()
            .filter(|r| {
                grants
                    .iter()
                    .any(|g| g.tenant == "*" || g.tenant == r.tenant)
                    && logs
                        .iter()
                        .any(|l| (&l.project, &l.kind, &l.id) == (&r.project, &r.kind, &r.log))
            })
            .collect();
        let hits = self.records(&logs, &grants, &rows).await?;
        Ok(SearchResponse {
            hits,
            next_page_token: page.next_page_token,
            ..SearchResponse::default()
        })
    }

    /// The records the rows stand for, opened at key@, in the order of the rows.
    async fn records(
        &self,
        logs: &[Log],
        grants: &[Granted],
        rows: &[&Row],
    ) -> Result<Vec<Hit>, ConnectError> {
        let mut cache = Bundles::default();
        let mut found = Vec::with_capacity(rows.len());
        for r in rows {
            let log = logs
                .iter()
                .find(|l| (&l.project, &l.kind, &l.id) == (&r.project, &r.kind, &r.log))
                .ok_or_else(|| refusal(ErrorCode::Internal, "integrity", "row"))?;
            let seq = u64::try_from(r.seq)
                .map_err(|_| refusal(ErrorCode::Internal, "integrity", "row"))?;
            let e = self.opener.entry(log, seq, &mut cache).await?;
            // The entry must be the record the row stands for: the same record id, in the same tenant.
            if e.uid != r.record_id || e.tenant != r.tenant {
                return Err(refusal(ErrorCode::Internal, "integrity", "row"));
            }
            found.push((*r, log, e));
        }

        // Open with the grant of the row's tenant, in batches key@ takes.
        let mut plain: Vec<Option<Vec<u8>>> = vec![None; found.len()];
        for g in grants {
            let mine: Vec<usize> = (0..found.len())
                .filter(|i| g.tenant == "*" || found[*i].0.tenant == g.tenant)
                .collect();
            for chunk in mine.chunks(OPEN_BATCH) {
                // Rows of one log open in one call; the address carries the log.
                for log in logs {
                    let of_log: Vec<usize> = chunk
                        .iter()
                        .copied()
                        .filter(|i| std::ptr::eq(found[*i].1, log))
                        .collect();
                    if of_log.is_empty() {
                        continue;
                    }
                    let records: Vec<_> = of_log.iter().map(|i| &found[*i].2).collect();
                    let opened = self.opener.open(log, &records, &g.sealed).await?;
                    for (i, p) in of_log.into_iter().zip(opened) {
                        plain[i] = Some(p);
                    }
                }
            }
        }

        let mut hits = Vec::with_capacity(found.len());
        for ((row, log, _), p) in found.iter().zip(plain) {
            let p = p.ok_or_else(|| refusal(ErrorCode::Internal, "integrity", "row"))?;
            // The index is derived data: the record it points at must be the one it indexed.
            if digest::digest(&digest::SHA384, &p).as_ref() != row.hash.as_slice() {
                return Err(refusal(ErrorCode::Internal, "integrity", "row"));
            }
            let record = String::from_utf8(p)
                .map_err(|_| refusal(ErrorCode::Internal, "integrity", "record"))?;
            hits.push(Hit {
                tenant: row.tenant.clone(),
                project: log.project.clone(),
                kind: log.kind.clone(),
                log: log.id.clone(),
                seq: row.seq,
                time_ms: row.time_ms,
                recorded_ms: row.recorded_ms,
                action: row.action.clone(),
                status_code: row.status_code.clone(),
                actor_uid: row.actor_uid.clone(),
                trace_id: row.trace_id.clone(),
                record_id: row.record_id.clone(),
                record,
                ..Hit::default()
            });
        }
        Ok(hits)
    }
}
