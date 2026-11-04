//! `sluis.store.v2alpha1.StoreService`: the rules on every call (ADR 0005 "Rules"), then the
//! engine. The caller is the peer the kit named from the transport; no request field says who it
//! is, and a request names no boundary.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use aws_lc_rs::digest;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use buffa_types::google::protobuf::Duration as PbDuration;
use connectrpc::error::ErrorCode;
use connectrpc::{
    ConnectError, RequestContext, Response, ServiceRequest, ServiceResult, ServiceStream,
};
use sluis_kit::{Peer, refusal};
use sluis_proto::sluis::port::item::v2alpha1::{
    Condition, Delete, DriverItem, Put, QueryRequest, TransactRequest, condition::Expect,
};
use sluis_proto::sluis::store::v2alpha1::{
    Consistency, GetRequest, GetResponse, Item, ListRequest, ListResponse, StoreService, Verb,
    WatchRequest, WatchResponse, WriteRequest, WriteResponse,
};
use sluis_proto::sluis::r#type::v2alpha1::{Address, IndexEntry};
use sluis_registry::{Class, Kind, Scope};

use crate::address::{self, valid_part};
use crate::audit::{AuditEvent, AuditSink, Auditor};
use crate::config::ConfigSnapshot;
use crate::engine::{EngineError, ItemEngine};
use crate::grant::{self, GrantCache, GrantOpener, OpenError, from_system_time, to_system_time};
use crate::messages;

/// A write batch holds at most this many operations (store-api.md "Write").
pub const BATCH_MAX: usize = 64;
/// The default and the largest page of a `List` (the driver's page is at most 500).
const PAGE_DEFAULT: i32 = 100;
const PAGE_MAX: i32 = 500;
/// A page token is good for this long.
const PAGE_TOKEN_TTL: Duration = Duration::from_secs(300);
const PAGE_TOKEN_VERSION: u8 = 1;
/// The purposes of a `DataKeyWrap` id, by whether the wrap has a tenant (kinds.yaml: `purposes`).
const WRAP_PURPOSES_TENANT: [&str; 4] = ["data", "pseudonym", "pairwise", "evidence"];
const WRAP_PURPOSES_BOUNDARY: [&str; 4] = ["grant", "cookie", "mac", "data"];

/// The clock of the store. Production passes `SystemTime::now`.
pub type Clock = Arc<dyn Fn() -> SystemTime + Send + Sync>;

/// Everything the service needs from outside.
pub struct Deps<E, G, A> {
    pub boundary: String,
    pub durable: E,
    pub temp: E,
    pub grants: G,
    pub config: Arc<dyn ConfigSnapshot>,
    pub audit: A,
    pub clock: Clock,
}

/// The store service.
pub struct Service<E, G, A> {
    boundary: String,
    durable: E,
    temp: E,
    grants: GrantCache<G>,
    config: Arc<dyn ConfigSnapshot>,
    audit: Auditor<A>,
    now: Clock,
}

impl<E: ItemEngine, G: GrantOpener, A: AuditSink> Service<E, G, A> {
    #[must_use]
    pub fn new(d: Deps<E, G, A>) -> Self {
        Self {
            boundary: d.boundary,
            durable: d.durable,
            temp: d.temp,
            grants: GrantCache::new(d.grants),
            config: d.config,
            audit: Auditor::new(d.audit),
            now: d.clock,
        }
    }

    /// The facts the audit log could not take since start.
    #[must_use]
    pub fn audit_failures(&self) -> u64 {
        self.audit.failed()
    }

    /// Tells the audit log that store@ started.
    pub async fn announce_start(&self, drivers: Vec<(&'static str, String)>) {
        let mut fields = vec![("boundary", self.boundary.clone())];
        fields.extend(drivers);
        self.audit
            .emit(AuditEvent {
                action: "store.start",
                failure: false,
                reason: String::new(),
                fields,
            })
            .await;
    }
}

/// A refusal in the making: the Connect code, the reason of store-api.md "Refusals" and the path
/// of the field at fault (never its value).
#[derive(Debug)]
struct Refuse {
    code: ErrorCode,
    reason: &'static str,
    path: String,
    /// The kind, when the call got as far as naming one.
    kind: Option<&'static str>,
    verb: &'static str,
    /// The operation of a batch a transaction refusal is about.
    op: Option<usize>,
}

fn refuse(code: ErrorCode, reason: &'static str, path: impl Into<String>) -> Refuse {
    Refuse {
        code,
        reason,
        path: path.into(),
        kind: None,
        verb: "",
        op: None,
    }
}

fn engine_down() -> Refuse {
    refuse(ErrorCode::Unavailable, "engine", "")
}

impl From<EngineError> for Refuse {
    fn from(_: EngineError) -> Self {
        // An aborted condition is mapped where the operations are known; anything that gets here
        // is the engine failing closed.
        engine_down()
    }
}

type Res<T> = Result<T, Refuse>;

/// The address of a call, checked.
struct Target {
    kind: &'static Kind,
    /// The wire tenant: empty for none.
    tenant: String,
    id: String,
}

fn verb_name(v: Verb) -> Option<&'static str> {
    match v {
        Verb::CREATE => Some("create"),
        Verb::UPDATE => Some("update"),
        Verb::DELETE => Some("delete"),
        Verb::APPLY => Some("apply"),
        Verb::VERB_UNSPECIFIED => None,
    }
}

impl<E: ItemEngine, G: GrantOpener, A: AuditSink> Service<E, G, A> {
    fn now(&self) -> SystemTime {
        (self.now)()
    }

    fn engine(&self, class: Class) -> &E {
        if class == Class::Temp {
            &self.temp
        } else {
            &self.durable
        }
    }

    // ---- the checks that come before data ----

    /// The kind of a segment, and the tenant against the kind's scope (store-api.md "Refused by
    /// the store: the kind's scope").
    fn kind_and_tenant(&self, field: &str, segment: &str, tenant: &str) -> Res<&'static Kind> {
        if !valid_part(segment) {
            return Err(refuse(
                ErrorCode::InvalidArgument,
                "address",
                format!("{field}.kind"),
            ));
        }
        let kind = sluis_registry::kind_by_segment(segment).ok_or_else(|| {
            refuse(
                ErrorCode::InvalidArgument,
                "address",
                format!("{field}.kind"),
            )
        })?;
        let bad = |kind: &'static Kind| {
            let mut r = refuse(
                ErrorCode::InvalidArgument,
                "address",
                format!("{field}.tenant"),
            );
            r.kind = Some(kind.name);
            r
        };
        match kind.scope {
            Scope::Boundary if !tenant.is_empty() => return Err(bad(kind)),
            Scope::BoundaryTenant if tenant.is_empty() => {
                // The boundary's own wraps are a `DataKeyWrap` at no tenant (kinds.yaml, notes).
                if kind.name != "DataKeyWrap" {
                    return Err(bad(kind));
                }
            }
            Scope::BoundaryTenant if tenant == "-" || !valid_part(tenant) => return Err(bad(kind)),
            _ => {}
        }
        Ok(kind)
    }

    fn target(&self, field: &str, a: &Address) -> Res<Target> {
        let kind = self.kind_and_tenant(field, &a.kind, &a.tenant)?;
        let at = |path: String| {
            let mut r = refuse(ErrorCode::InvalidArgument, "address", path);
            r.kind = Some(kind.name);
            r
        };
        if let Some(i) = address::invalid_id_part(&a.id) {
            return Err(at(format!("{field}.id[{i}]")));
        }
        if !address::within_limit(&self.boundary, &a.tenant, kind.segment, &a.id) {
            return Err(at(field.to_owned()));
        }
        if kind.name == "DataKeyWrap" {
            let purpose = a.id.split('/').next().unwrap_or("");
            let set = if a.tenant.is_empty() {
                &WRAP_PURPOSES_BOUNDARY
            } else {
                &WRAP_PURPOSES_TENANT
            };
            if !set.contains(&purpose) {
                return Err(at(format!("{field}.id[0]")));
            }
        }
        Ok(Target {
            kind,
            tenant: a.tenant.clone(),
            id: a.id.clone(),
        })
    }

    /// The rule of the actor, kind and verb; the kind's one writer for a write; and the id of a
    /// self-scoped rule (ADR 0005 "Rules"). `id` is None for a listing.
    fn authorise(
        &self,
        caller: &str,
        kind: &'static Kind,
        verb: &'static str,
        id: Option<&str>,
    ) -> Res<()> {
        let denied = |reason: &'static str| {
            let mut r = refuse(ErrorCode::PermissionDenied, reason, "");
            r.kind = Some(kind.name);
            r.verb = verb;
            r
        };
        if !sluis_registry::store_allows(caller, kind.segment, verb) {
            return Err(denied("rule"));
        }
        let write = matches!(verb, "create" | "update" | "delete" | "apply");
        if write && !sluis_registry::is_writer(caller, kind.segment) {
            return Err(denied("writer"));
        }
        if let Some(id) = id
            && sluis_registry::store_self_scoped_for(caller, kind.segment, verb)
            && !id.strip_prefix(caller).is_some_and(|r| r.starts_with('/'))
        {
            return Err(denied("writer"));
        }
        Ok(())
    }

    fn expired(&self, item: &DriverItem) -> bool {
        item.expires_at
            .as_option()
            .and_then(to_system_time)
            .is_some_and(|e| e <= self.now())
    }

    /// A driver item as the store service returns it.
    fn wire_item(&self, address: Address, item: &DriverItem) -> Item {
        Item {
            address: address.into(),
            version: item.version,
            value: item.value.clone(),
            expires_at: item.expires_at.as_option().cloned().into(),
            indexes: item.indexes.clone(),
            ..Item::default()
        }
    }

    /// The address of a key the driver returned: it must be this boundary's, under `prefix`.
    fn address_of(&self, key: &[u8], prefix: &[u8]) -> Res<Address> {
        let text = std::str::from_utf8(key).map_err(|_| engine_down())?;
        if !key.starts_with(prefix) {
            return Err(engine_down());
        }
        let mut it = text.splitn(4, '/');
        let (Some(b), Some(t), Some(k), Some(id)) = (it.next(), it.next(), it.next(), it.next())
        else {
            return Err(engine_down());
        };
        if b != self.boundary {
            return Err(engine_down());
        }
        Ok(Address {
            kind: k.to_owned(),
            tenant: if t == "-" {
                String::new()
            } else {
                t.to_owned()
            },
            id: id.to_owned(),
            ..Address::default()
        })
    }

    // ---- Get ----

    async fn get_inner(&self, caller: &str, req: GetRequest) -> Res<GetResponse> {
        let addr = req.address.as_option().cloned().unwrap_or_default();
        let t = self.target("address", &addr)?;
        self.authorise(caller, t.kind, "get", Some(&t.id))?;
        let blame = |mut r: Refuse| {
            r.kind = Some(t.kind.name);
            r.verb = "get";
            r
        };
        let item = match t.kind.class {
            Class::Config => {
                // The snapshot of the document, never an engine. A kind with no loaded document is
                // unavailable, not empty.
                let version = self
                    .config
                    .version(t.kind.segment)
                    .ok_or_else(|| blame(engine_down()))?;
                let bytes = self
                    .config
                    .get(t.kind.segment, &t.id)
                    .ok_or_else(|| blame(refuse(ErrorCode::NotFound, "absent", "address")))?;
                DriverItem {
                    version,
                    value: bytes,
                    ..DriverItem::default()
                }
            }
            Class::Secret => return Err(blame(unimplemented_secret())),
            Class::Durable | Class::Temp => {
                let key = address::key(&self.boundary, &t.tenant, t.kind.segment, &t.id);
                let linearizable = req.consistency.as_known() != Some(Consistency::FOLLOWER);
                let found = self
                    .engine(t.kind.class)
                    .get(key, linearizable)
                    .await
                    .map_err(|e| blame(e.into()))?;
                match found {
                    Some(i) if !self.expired(&i) => i,
                    _ => return Err(blame(refuse(ErrorCode::NotFound, "absent", "address"))),
                }
            }
        };
        if req.if_none_match != 0 && item.version == req.if_none_match {
            return Ok(GetResponse {
                unchanged: true,
                ..GetResponse::default()
            });
        }
        Ok(GetResponse {
            item: self.wire_item(addr, &item).into(),
            ..GetResponse::default()
        })
    }

    // ---- List ----

    fn query_binding(caller: &str, r: &ListRequest) -> [u8; 16] {
        let mut ctx = digest::Context::new(&digest::SHA384);
        for part in [
            caller.as_bytes(),
            r.kind.as_bytes(),
            r.tenant.as_bytes(),
            r.index.as_bytes(),
            &r.index_value,
        ] {
            // Length-prefixed, so two queries cannot collide by moving a byte across a boundary.
            ctx.update(&(part.len() as u64).to_be_bytes());
            ctx.update(part);
        }
        let mut out = [0u8; 16];
        out.copy_from_slice(&ctx.finish().as_ref()[..16]);
        out
    }

    /// An opaque page token, bound to the query and the caller, with an expiry.
    fn seal_token(&self, binding: [u8; 16], inner: &[u8]) -> String {
        let expires = self
            .now()
            .checked_add(PAGE_TOKEN_TTL)
            .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
            .map_or(0, |d| d.as_secs());
        let mut raw = vec![PAGE_TOKEN_VERSION];
        raw.extend_from_slice(&expires.to_be_bytes());
        raw.extend_from_slice(&binding);
        raw.extend_from_slice(inner);
        URL_SAFE_NO_PAD.encode(raw)
    }

    fn open_token(&self, binding: [u8; 16], token: &str) -> Res<Vec<u8>> {
        let bad = || refuse(ErrorCode::InvalidArgument, "schema", "page_token");
        if token.is_empty() {
            return Ok(Vec::new());
        }
        let raw = URL_SAFE_NO_PAD.decode(token).map_err(|_| bad())?;
        if raw.len() < 25 || raw[0] != PAGE_TOKEN_VERSION {
            return Err(bad());
        }
        let expires = u64::from_be_bytes(raw[1..9].try_into().map_err(|_| bad())?);
        let now = self
            .now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        if expires <= now || raw[9..25] != binding {
            return Err(bad());
        }
        Ok(raw[25..].to_vec())
    }

    async fn list_inner(&self, caller: &str, req: ListRequest) -> Res<ListResponse> {
        let kind = self.kind_and_tenant("kind", &req.kind, &req.tenant)?;
        let blame = |mut r: Refuse| {
            r.kind = Some(kind.name);
            r.verb = "list";
            r
        };
        self.authorise(caller, kind, "list", None)?;
        if req.page_size < 0 {
            return Err(blame(refuse(
                ErrorCode::InvalidArgument,
                "schema",
                "page_size",
            )));
        }
        let page_size = if req.page_size == 0 {
            PAGE_DEFAULT
        } else {
            req.page_size.min(PAGE_MAX)
        };
        if !req.index.is_empty() && !kind.indexes.contains(&req.index.as_str()) {
            return Err(blame(refuse(ErrorCode::InvalidArgument, "index", "index")));
        }
        // A rule bound to the caller's own ids lists only those.
        let own = sluis_registry::store_self_scoped_for(caller, kind.segment, "list");
        if own && !req.index.is_empty() {
            // An index cannot be narrowed to a prefix of ids.
            return Err(blame(refuse(
                ErrorCode::PermissionDenied,
                "writer",
                "index",
            )));
        }
        let id_prefix = if own {
            format!("{caller}/")
        } else {
            String::new()
        };
        let binding = Self::query_binding(caller, &req);
        let inner = self.open_token(binding, &req.page_token).map_err(blame)?;

        match kind.class {
            Class::Config => {
                self.config
                    .version(kind.segment)
                    .ok_or_else(|| blame(engine_down()))?;
                let version = self.config.version(kind.segment).unwrap_or(0);
                // Sorted by id; the token is the last id of the previous page.
                let after = String::from_utf8(inner).map_err(|_| {
                    blame(refuse(ErrorCode::InvalidArgument, "schema", "page_token"))
                })?;
                let mut rest = self
                    .config
                    .list(kind.segment)
                    .into_iter()
                    .filter(|(id, _)| {
                        id.starts_with(&id_prefix) && (after.is_empty() || *id > after)
                    });
                let page: Vec<_> = rest.by_ref().take(page_size as usize).collect();
                let more = rest.next().is_some();
                let next = match (more, page.last()) {
                    (true, Some((id, _))) => self.seal_token(binding, id.as_bytes()),
                    _ => String::new(),
                };
                let items = page
                    .into_iter()
                    .map(|(id, bytes)| {
                        let a = Address {
                            kind: kind.segment.to_owned(),
                            id,
                            ..Address::default()
                        };
                        self.wire_item(
                            a,
                            &DriverItem {
                                version,
                                value: bytes,
                                ..DriverItem::default()
                            },
                        )
                    })
                    .collect();
                Ok(ListResponse {
                    items,
                    next_page_token: next,
                    ..ListResponse::default()
                })
            }
            Class::Secret => Err(blame(unimplemented_secret())),
            Class::Durable | Class::Temp => {
                let prefix = address::prefix(&self.boundary, &req.tenant, kind.segment, &id_prefix);
                let q = QueryRequest {
                    prefix: prefix.clone(),
                    index: req.index.clone(),
                    index_value: req.index_value.clone(),
                    page_size,
                    page_token: inner,
                    ..QueryRequest::default()
                };
                let resp = self
                    .engine(kind.class)
                    .query(q)
                    .await
                    .map_err(|e| blame(e.into()))?;
                let mut items = Vec::with_capacity(resp.items.len());
                for it in &resp.items {
                    let a = self.address_of(&it.key, &prefix).map_err(blame)?;
                    if !self.expired(it) {
                        items.push(self.wire_item(a, it));
                    }
                }
                let next = if resp.next_page_token.is_empty() {
                    String::new()
                } else {
                    self.seal_token(binding, &resp.next_page_token)
                };
                Ok(ListResponse {
                    items,
                    next_page_token: next,
                    ..ListResponse::default()
                })
            }
        }
    }

    // ---- Write ----

    /// The TTL of an operation: the request's, else the kind's default; within the kind's maximum.
    /// None for a kind with no TTL (ADR 0005 "Time to live").
    fn ttl_of(kind: &Kind, given: Option<Duration>) -> Result<Option<Duration>, ()> {
        let max = if kind.ttl_max.is_zero() {
            kind.ttl_default
        } else {
            kind.ttl_max
        };
        let temp = kind.class == Class::Temp;
        if max.is_zero() {
            return if given.is_some() || temp {
                Err(())
            } else {
                Ok(None)
            };
        }
        match given.unwrap_or(kind.ttl_default) {
            d if d.is_zero() && given.is_none() && !temp => Ok(None),
            d if d.is_zero() || d > max => Err(()),
            d => Ok(Some(d)),
        }
    }

    async fn write_inner(&self, caller: &str, req: WriteRequest) -> Res<WriteResponse> {
        let ops = &req.operations;
        if ops.is_empty() || ops.len() > BATCH_MAX {
            return Err(refuse(ErrorCode::InvalidArgument, "batch", "operations"));
        }

        // 1. Who may do what to which kind, for every operation, before anything else.
        let mut planned = Vec::with_capacity(ops.len());
        let mut keys = HashSet::new();
        for (i, op) in ops.iter().enumerate() {
            let field = format!("operations[{i}].address");
            let addr = op.address.as_option().cloned().unwrap_or_default();
            let t = self.target(&field, &addr)?;
            let blame = |mut r: Refuse| {
                r.kind = Some(t.kind.name);
                r
            };
            let Some(verb) = op.verb.as_known().and_then(verb_name) else {
                return Err(blame(refuse(
                    ErrorCode::InvalidArgument,
                    "batch",
                    format!("operations[{i}].verb"),
                )));
            };
            if matches!(t.kind.class, Class::Config | Class::Secret) {
                // Config and secret kinds are read-only to sluis.
                let mut r = refuse(ErrorCode::PermissionDenied, "rule", "");
                r.kind = Some(t.kind.name);
                r.verb = verb;
                return Err(r);
            }
            self.authorise(caller, t.kind, verb, Some(&t.id))?;
            let key = address::key(&self.boundary, &t.tenant, t.kind.segment, &t.id);
            if !keys.insert(key.clone()) {
                let mut r = refuse(
                    ErrorCode::InvalidArgument,
                    "batch",
                    format!("operations[{i}].address"),
                );
                r.kind = Some(t.kind.name);
                r.verb = verb;
                return Err(r);
            }
            planned.push((i, op, t, verb, key));
        }
        // One engine takes the whole batch: all or none holds inside one engine only.
        let class = planned[0].2.kind.class;
        if let Some((i, _, t, verb, _)) = planned.iter().find(|p| p.2.kind.class != class) {
            let mut r = refuse(
                ErrorCode::InvalidArgument,
                "batch",
                format!("operations[{i}].address"),
            );
            r.kind = Some(t.kind.name);
            r.verb = verb;
            return Err(r);
        }

        // 2. The grant, for every operation on a tenant-scoped address, except key@'s own writes
        // of `DataKeyWrap`: key@ is the other check there (ADR 0005 "Rules").
        let needs_grant = |t: &Target| {
            t.kind.scope == Scope::BoundaryTenant
                && !(caller == "key" && t.kind.name == "DataKeyWrap")
        };
        if planned.iter().any(|p| needs_grant(&p.2)) {
            let denied = |t: &Target, verb: &'static str| {
                let mut r = refuse(ErrorCode::PermissionDenied, "grant", "grant");
                r.kind = Some(t.kind.name);
                r.verb = verb;
                r
            };
            let first = planned
                .iter()
                .find(|p| needs_grant(&p.2))
                .map(|p| (&p.2, p.3));
            let Some((ft, fv)) = first else {
                return Err(engine_down());
            };
            if req.grant.is_empty() {
                return Err(denied(ft, fv));
            }
            let now = self.now();
            let opened = match self.grants.open(&req.grant, now).await {
                Ok(g) => g,
                Err(OpenError::Refused) => return Err(denied(ft, fv)),
                Err(OpenError::Unavailable) => {
                    let mut r = engine_down();
                    r.kind = Some(ft.kind.name);
                    r.verb = fv;
                    return Err(r);
                }
            };
            for (_, _, t, verb, _) in planned.iter().filter(|p| needs_grant(&p.2)) {
                if !grant::allows(&opened, &self.boundary, caller, &t.tenant, verb, now) {
                    return Err(denied(t, verb));
                }
            }
        }

        // 3. The shape of each write, and the engine's transaction.
        let now = self.now();
        let mut conditions = Vec::new();
        let mut condition_ops = Vec::new(); // the operation each condition belongs to
        let (mut puts, mut deletes) = (Vec::new(), Vec::new());
        let mut put_ops = Vec::new(); // (operation index, key, address, expiry shown to the writer)
        for (i, op, t, verb, key) in &planned {
            let blame = |mut r: Refuse| {
                r.kind = Some(t.kind.name);
                r.verb = verb;
                r
            };
            let watched = t.kind.watched || t.kind.exportable;
            let expect = match *verb {
                "create" => Some(Expect::Absent(true)),
                "update" if op.if_version == 0 => {
                    return Err(blame(refuse(
                        ErrorCode::Aborted,
                        "version",
                        format!("operations[{i}].if_version"),
                    )));
                }
                "update" => Some(Expect::Version(op.if_version)),
                "delete" if op.if_version != 0 => Some(Expect::Version(op.if_version)),
                _ => None,
            };
            if let Some(expect) = expect {
                conditions.push(Condition {
                    key: key.clone(),
                    expect: Some(expect),
                    ..Condition::default()
                });
                condition_ops.push(*i);
            }
            if *verb == "delete" {
                deletes.push(Delete {
                    key: key.clone(),
                    log: watched,
                    ..Delete::default()
                });
                continue;
            }

            // The TTL: store@ computes the expiry itself (ADR 0005: store@ sets every timestamp).
            let given = op
                .ttl
                .as_option()
                .map(|d| {
                    pb_duration(d).ok_or_else(|| {
                        blame(refuse(
                            ErrorCode::InvalidArgument,
                            "ttl",
                            format!("operations[{i}].ttl"),
                        ))
                    })
                })
                .transpose()?;
            let ttl = Self::ttl_of(t.kind, given).map_err(|()| {
                blame(refuse(
                    ErrorCode::InvalidArgument,
                    "ttl",
                    format!("operations[{i}].ttl"),
                ))
            })?;
            let expires = ttl.and_then(|d| now.checked_add(d));
            // A lease is never swept: its expiry is kept in its value and the engine gets none
            // (ADR 0005 "Leases"), so a taken-over lease keeps its item and its version grows.
            // planned: the `Lease` message of sluis-proto carries the expiry; until it exists the
            // holder writes it, and the time shown back to the writer is informational.
            let engine_expiry = if t.kind.name == "Lease" {
                None
            } else {
                expires
            };

            let mut indexes = Vec::with_capacity(op.indexes.len());
            for (j, ix) in op.indexes.iter().enumerate() {
                if !t.kind.indexes.contains(&ix.name.as_str()) {
                    return Err(blame(refuse(
                        ErrorCode::InvalidArgument,
                        "index",
                        format!("operations[{i}].indexes[{j}]"),
                    )));
                }
                indexes.push(IndexEntry {
                    name: ix.name.clone(),
                    value: ix.value.clone(),
                    ..IndexEntry::default()
                });
            }

            let value_path = format!("operations[{i}].value");
            let schema = || {
                blame(refuse(
                    ErrorCode::InvalidArgument,
                    "schema",
                    value_path.clone(),
                ))
            };
            if t.kind.treatment == "sealed" {
                // The envelope only: store@ never opens it.
                if !messages::envelope_ok(&op.value) {
                    return Err(schema());
                }
            } else if messages::decodes(t.kind.segment, &op.value) == Some(false) {
                return Err(schema());
            }

            puts.push(Put {
                key: key.clone(),
                value: op.value.clone(),
                expires_at: engine_expiry.map(from_system_time).into(),
                indexes,
                log: watched,
                ..Put::default()
            });
            put_ops.push((*i, key.clone(), addr_of(t, &self.boundary), expires));
        }

        let tx = TransactRequest {
            conditions,
            puts,
            deletes,
            ..TransactRequest::default()
        };
        let verbs: Vec<&'static str> = planned.iter().map(|p| p.3).collect();
        let done = self
            .transact(class, tx, &condition_ops, &verbs)
            .await
            .map_err(|mut r| {
                if let Some(p) = planned.iter().find(|p| Some(p.0) == r.op) {
                    r.kind = Some(p.2.kind.name);
                    r.verb = p.3;
                }
                r
            })?;

        let mut items = Vec::with_capacity(put_ops.len());
        for (_, key, address, expires) in put_ops {
            let written = done
                .items
                .iter()
                .find(|i| i.key == key)
                .ok_or_else(engine_down)?;
            let mut item = self.wire_item(address, written);
            if item.expires_at.as_option().is_none() {
                item.expires_at = expires.map(from_system_time).into();
            }
            items.push(item);
        }
        Ok(WriteResponse {
            items,
            ..WriteResponse::default()
        })
    }
}

/// The address of a planned operation, as the writer gets it back.
fn addr_of(t: &Target, _boundary: &str) -> Address {
    Address {
        kind: t.kind.segment.to_owned(),
        tenant: t.tenant.clone(),
        id: t.id.clone(),
        ..Address::default()
    }
}

fn pb_duration(d: &PbDuration) -> Option<Duration> {
    let secs = u64::try_from(d.seconds).ok()?;
    let nanos = u32::try_from(d.nanos).ok().filter(|n| *n < 1_000_000_000)?;
    Some(Duration::new(secs, nanos))
}

fn unimplemented_secret() -> Refuse {
    // A secret kind is read from the secret source, which WP-11 wires. Not a refusal with a
    // reason of the closed list: the method exists, the source does not.
    refuse(ErrorCode::Unimplemented, "", "")
}

// ---- the transaction, with its retry over an expired item ----

impl<E: ItemEngine, G: GrantOpener, A: AuditSink> Service<E, G, A> {
    /// Runs the transaction. A failed condition is `already_exists`/`taken` for a create and
    /// `aborted`/`version` for the rest. A create over an item that is past its expiry is allowed
    /// again (ADR 0005 "Time to live"): it is retried once against the version the engine holds.
    async fn transact(
        &self,
        class: Class,
        mut tx: TransactRequest,
        condition_ops: &[usize],
        verbs: &[&'static str],
    ) -> Res<sluis_proto::sluis::port::item::v2alpha1::TransactResponse> {
        let engine = self.engine(class);
        let mut retried = false;
        loop {
            match engine.transact(tx.clone()).await {
                Ok(r) => return Ok(r),
                Err(EngineError::Unavailable) => return Err(engine_down()),
                Err(EngineError::Aborted(idx)) => {
                    // Without the index, the first condition is the best answer the driver left.
                    let c = idx.unwrap_or(0).min(tx.conditions.len().saturating_sub(1));
                    let op = condition_ops.get(c).copied().unwrap_or(0);
                    let create = matches!(
                        tx.conditions.get(c).and_then(|c| c.expect.as_ref()),
                        Some(Expect::Absent(_))
                    );
                    if create && !retried {
                        retried = true;
                        let key = tx.conditions[c].key.clone();
                        if let Some(held) = engine.get(key, true).await?
                            && self.expired(&held)
                        {
                            tx.conditions[c].expect = Some(Expect::Version(held.version));
                            continue;
                        }
                    }
                    let mut r = if verbs.get(op).copied() == Some("create") {
                        refuse(
                            ErrorCode::AlreadyExists,
                            "taken",
                            format!("operations[{op}].address"),
                        )
                    } else {
                        refuse(
                            ErrorCode::Aborted,
                            "version",
                            format!("operations[{op}].if_version"),
                        )
                    };
                    r.op = Some(op);
                    return Err(r);
                }
            }
        }
    }

    // ---- answering ----

    /// Turns a refusal into the Connect error with its `Refusal` detail, and tells the audit log
    /// about the ones that are the rules speaking (not a missing item or a moved version).
    async fn fail(&self, caller: &str, r: Refuse) -> ConnectError {
        if r.code == ErrorCode::Unimplemented {
            return ConnectError::new(ErrorCode::Unimplemented, "not served yet");
        }
        let audited = matches!(
            r.code,
            ErrorCode::InvalidArgument
                | ErrorCode::PermissionDenied
                | ErrorCode::FailedPrecondition
                | ErrorCode::Unavailable
        );
        if audited {
            let mut fields = vec![("caller", caller.to_owned())];
            if let Some(k) = r.kind {
                fields.push(("kind", k.to_owned()));
            }
            if !r.verb.is_empty() {
                fields.push(("verb", r.verb.to_owned()));
            }
            self.audit
                .emit(AuditEvent {
                    action: "store.refused",
                    failure: true,
                    reason: r.reason.to_owned(),
                    fields,
                })
                .await;
        }
        refusal(r.code, r.reason, &r.path)
    }

    async fn answer<T>(&self, caller: &Peer, r: Res<T>) -> ServiceResult<T>
    where
        T: buffa::Message + Send + 'static,
    {
        match r {
            Ok(v) => Response::ok(v),
            Err(e) => Err(self.fail(caller.name, e).await),
        }
    }
}

/// The caller, from the transport. The guard of the kit set it before the message was decoded; a
/// call without one never reaches here, and is refused if it somehow does.
fn caller(ctx: &RequestContext) -> Result<Peer, ConnectError> {
    sluis_kit::peer(ctx.extensions())
        .cloned()
        .ok_or_else(|| refusal(ErrorCode::PermissionDenied, "rule", ""))
}

#[allow(refining_impl_trait)] // the generated trait returns `impl Encodable`; the concrete type is fine
impl<E: ItemEngine, G: GrantOpener, A: AuditSink> StoreService for Service<E, G, A> {
    async fn get(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, GetRequest>,
    ) -> ServiceResult<GetResponse> {
        let who = caller(&ctx)?;
        let r = self.get_inner(who.name, request.to_owned_message()).await;
        self.answer(&who, r).await
    }

    async fn list(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, ListRequest>,
    ) -> ServiceResult<ListResponse> {
        let who = caller(&ctx)?;
        let r = self.list_inner(who.name, request.to_owned_message()).await;
        self.answer(&who, r).await
    }

    async fn write(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, WriteRequest>,
    ) -> ServiceResult<WriteResponse> {
        let who = caller(&ctx)?;
        let r = self.write_inner(who.name, request.to_owned_message()).await;
        self.answer(&who, r).await
    }

    async fn watch(
        &self,
        ctx: RequestContext,
        _request: ServiceRequest<'_, WatchRequest>,
    ) -> ServiceResult<ServiceStream<WatchResponse>> {
        // The change log and the stream wait for the first watcher (D-18, #1204).
        let _ = caller(&ctx)?;
        Err(ConnectError::new(
            ErrorCode::Unimplemented,
            "watch is not served yet",
        ))
    }
}
