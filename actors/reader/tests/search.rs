//! The reader over real Unix sockets: a log made as the writer makes it, indexed by the real indexer into the
//! real `sqlite` index driver, and stand-ins for the blob driver, key@, policy, store@ and the audit transport.
//! The reader reaches all of them with the kit's clients, and the test reaches the reader through its own
//! Connect service. The stand-ins are test code: key@'s checks the tenant of the grant as the real one does.

#![allow(refining_impl_trait)]
#![allow(clippy::unwrap_used, clippy::expect_used)] // a failed unwrap in a test is the failure
#![allow(dead_code)]

#[path = "../../indexer/tests/common/mod.rs"]
mod common;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use aws_lc_rs::aead::{Aad, Nonce, RandomizedNonceKey};
use buffa::Message as _;
use common::{BOUNDARY, Env, LOG, PROJECT, Rec};
use connectrpc::error::ErrorCode;
use connectrpc::{RequestContext, Response, Router, ServiceRequest, ServiceResult};
use indexer::run::Runner;
use reader::config::Config;
use reader::ports::{Ports, Sockets};
use reader::search::Searcher;
use reader::service::Service;
use serde_json::Value;
use sluis_audit::Emitter;
use sluis_driver_indexer_sqlite::service::Read;
use sluis_kit::{Allow, Identities, ServerConfig, dial, refusal, refusal_reason};
use sluis_proto::sluis::config::v2alpha1::{AuditLog, LogDecl};
use sluis_proto::sluis::key::v2alpha1::{
    KeyService, KeyServiceExt, MacRequest, MacResponse, OpenGrantRequest, OpenGrantResponse,
    OpenRequest, OpenResponse, PublicKeyRequest, PublicKeyResponse, SealGrantRequest,
    SealGrantResponse, SealRequest, SealResponse, SignRequest, SignResponse,
};
use sluis_proto::sluis::policy::v2alpha1::{
    DecideRequest, DecideResponse, Decision, PolicyService, PolicyServiceExt, Reason,
};
use sluis_proto::sluis::port::blob::v2alpha1::{
    BlobGetRequest, BlobGetResponse, BlobListRequest, BlobListResponse, BlobService,
    BlobServiceExt, CreateRequest, CreateResponse, PutRequest, PutResponse,
};
use sluis_proto::sluis::port::index::v2alpha1::IndexReadServiceExt;
use sluis_proto::sluis::port::transport::v2alpha1::{
    AckRequest, AckResponse, EmitRequest, EmitResponse, ReceiveRequest, ReceiveResponse,
    TransportService, TransportServiceExt,
};
use sluis_proto::sluis::reader::v2alpha1::{
    ReaderServiceClient, ReaderServiceExt, SearchRequest, SearchResponse,
};
use sluis_proto::sluis::store::v2alpha1::{
    GetRequest, GetResponse, Item, ListRequest, ListResponse, StoreService, StoreServiceExt,
    WatchRequest, WatchResponse, WriteRequest, WriteResponse,
};
use sluis_proto::sluis::r#type::v2alpha1::Address;
use tokio::sync::oneshot;

fn identities(me_is: &'static str) -> Identities {
    let me = rustix::process::geteuid().as_raw();
    Identities::with(0, move |uid| (uid == me).then_some((me_is, 0)))
}

fn serve(
    socket: &Path,
    actor: &'static str,
    router: Router,
    allow: Allow,
    me_is: &'static str,
) -> oneshot::Sender<()> {
    let cfg = ServerConfig {
        actor,
        boundary: BOUNDARY.into(),
        socket: socket.to_path_buf(),
        mode: 0o600,
        socket_gid: None,
        allow,
        default_deadline: std::time::Duration::from_secs(20),
    };
    let (tx, rx) = oneshot::channel::<()>();
    tokio::spawn(sluis_kit::serve_with(
        cfg,
        router,
        async move {
            let _ = rx.await;
        },
        identities(me_is),
    ));
    tx
}

async fn up(socket: &Path) {
    for _ in 0..500 {
        if socket.exists() {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("no socket {}", socket.display());
}

fn unimplemented<T>() -> ServiceResult<T> {
    Err(refusal(ErrorCode::Unimplemented, "unsupported", ""))
}

// ---------------------------------------------------------------- the stand-ins

/// The blob port over the directory the log was written to, Get and List only. It counts the reads.
struct BlobSvc(PathBuf, Arc<std::sync::atomic::AtomicUsize>);

impl BlobService for BlobSvc {
    async fn create(
        &self,
        _: RequestContext,
        _: ServiceRequest<'_, CreateRequest>,
    ) -> ServiceResult<CreateResponse> {
        Err(refusal(ErrorCode::PermissionDenied, "rule", "path"))
    }
    async fn put(
        &self,
        _: RequestContext,
        _: ServiceRequest<'_, PutRequest>,
    ) -> ServiceResult<PutResponse> {
        Err(refusal(ErrorCode::PermissionDenied, "rule", "path"))
    }
    async fn get(
        &self,
        _: RequestContext,
        r: ServiceRequest<'_, BlobGetRequest>,
    ) -> ServiceResult<BlobGetResponse> {
        let path = r.path.to_string();
        assert!(!path.contains(".."), "the reader asked for {path}");
        self.1.fetch_add(1, Ordering::SeqCst);
        match std::fs::read(self.0.join(&path)) {
            Ok(data) => Response::ok(BlobGetResponse {
                data,
                etag: "x".into(),
                ..BlobGetResponse::default()
            }),
            Err(_) => Err(refusal(ErrorCode::NotFound, "absent", "path")),
        }
    }
    async fn list(
        &self,
        _: RequestContext,
        r: ServiceRequest<'_, BlobListRequest>,
    ) -> ServiceResult<BlobListResponse> {
        let prefix = r.prefix.to_string();
        let mut paths = Vec::new();
        walk(&self.0, &self.0, &mut paths);
        paths.retain(|p| p.starts_with(&prefix));
        paths.sort();
        Response::ok(BlobListResponse {
            paths,
            ..BlobListResponse::default()
        })
    }
}

fn walk(root: &Path, dir: &Path, out: &mut Vec<String>) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            walk(root, &p, out);
        } else {
            out.push(p.strip_prefix(root).unwrap().to_string_lossy().into_owned());
        }
    }
}

#[derive(Default)]
struct Control {
    /// What policy was asked: (action, principal type, principal id, tenant).
    decides: Mutex<Vec<(String, String, String, String)>>,
    /// policy denies this tenant.
    deny: Mutex<Vec<String>>,
    /// key@ is down.
    key_down: AtomicBool,
    /// policy is down.
    policy_down: AtomicBool,
    /// The tenants of the addresses key@ opened.
    opened: Mutex<Vec<String>>,
    /// The records the transport took: (blocking, record).
    emitted: Mutex<Vec<(bool, Value)>>,
    /// The transport is down.
    transport_down: AtomicBool,
    /// policy answers for this tenant with a grant for the other one (a bug of policy, which key@ must catch).
    grant_for_other: Mutex<Option<(String, String)>>,
}

struct PolicySvc(Arc<Control>);

impl PolicyService for PolicySvc {
    async fn decide(
        &self,
        _: RequestContext,
        r: ServiceRequest<'_, DecideRequest>,
    ) -> ServiceResult<DecideResponse> {
        let req = r.to_owned_message();
        let p = req.principal.as_option().cloned().unwrap_or_default();
        self.0.decides.lock().unwrap().push((
            req.action.clone(),
            p.r#type,
            p.id,
            req.tenant.clone(),
        ));
        if self.0.policy_down.load(Ordering::SeqCst) {
            return Err(refusal(ErrorCode::Unavailable, "engine", ""));
        }
        if self.0.deny.lock().unwrap().contains(&req.tenant) {
            return Response::ok(DecideResponse {
                decision: Decision::DENY.into(),
                decision_id: format!("deny-{}", req.tenant),
                ..DecideResponse::default()
            });
        }
        let named = match self.0.grant_for_other.lock().unwrap().as_ref() {
            Some((asked, other)) if *asked == req.tenant => other.clone(),
            _ => req.tenant.clone(),
        };
        Response::ok(DecideResponse {
            decision: Decision::ALLOW.into(),
            sealed_grant: format!("grant:{named}").into_bytes(),
            decision_id: format!("decision-{}", req.tenant),
            digest: "digest".into(),
            reasons: vec![Reason {
                policy_id: "bind-reader".into(),
                layer: "config".into(),
                ..Reason::default()
            }],
            ..DecideResponse::default()
        })
    }
}

struct KeySvc {
    c: Arc<Control>,
    seal: Arc<RandomizedNonceKey>,
}

fn aad(tenant: &str, kind: &str, id: &str) -> Vec<u8> {
    format!("{tenant}|{kind}|{id}").into_bytes()
}

impl KeyService for KeySvc {
    async fn open(
        &self,
        _: RequestContext,
        r: ServiceRequest<'_, OpenRequest>,
    ) -> ServiceResult<OpenResponse> {
        let req = r.to_owned_message();
        if self.c.key_down.load(Ordering::SeqCst) {
            return Err(refusal(ErrorCode::Unavailable, "engine", ""));
        }
        // key@ checks the tenant of every address against the tenants the grant names (ADR 0007).
        let Some(tenant) = req
            .grant
            .strip_prefix(b"grant:")
            .and_then(|t| std::str::from_utf8(t).ok())
        else {
            return Err(refusal(ErrorCode::PermissionDenied, "grant", "grant"));
        };
        if req.items.is_empty() || req.items.len() > 64 {
            return Err(refusal(ErrorCode::InvalidArgument, "bound", "items"));
        }
        let mut plaintexts = Vec::new();
        for it in &req.items {
            let a = it.address.as_option().cloned().unwrap_or_default();
            if it.purpose != "evidence" || a.kind != indexer::entry::SEAL_KIND {
                return Err(refusal(ErrorCode::InvalidArgument, "purpose", "items"));
            }
            if tenant != "*" && tenant != a.tenant {
                return Err(refusal(ErrorCode::PermissionDenied, "grant", "grant"));
            }
            let (nonce, ct) = it.envelope.split_at(12.min(it.envelope.len()));
            let mut buf = ct.to_vec();
            let opened = Nonce::try_assume_unique_for_key(nonce).ok().and_then(|n| {
                self.seal
                    .open_in_place(n, Aad::from(aad(&a.tenant, &a.kind, &a.id)), &mut buf)
                    .ok()
                    .map(|p| p.to_vec())
            });
            match opened {
                Some(p) => plaintexts.push(p),
                None => return Err(refusal(ErrorCode::PermissionDenied, "open", "")),
            }
            self.c.opened.lock().unwrap().push(a.tenant);
        }
        Response::ok(OpenResponse {
            plaintexts,
            ..OpenResponse::default()
        })
    }
    async fn seal(
        &self,
        _: RequestContext,
        _: ServiceRequest<'_, SealRequest>,
    ) -> ServiceResult<SealResponse> {
        unimplemented()
    }
    async fn seal_grant(
        &self,
        _: RequestContext,
        _: ServiceRequest<'_, SealGrantRequest>,
    ) -> ServiceResult<SealGrantResponse> {
        unimplemented()
    }
    async fn open_grant(
        &self,
        _: RequestContext,
        _: ServiceRequest<'_, OpenGrantRequest>,
    ) -> ServiceResult<OpenGrantResponse> {
        unimplemented()
    }
    async fn sign(
        &self,
        _: RequestContext,
        _: ServiceRequest<'_, SignRequest>,
    ) -> ServiceResult<SignResponse> {
        unimplemented()
    }
    async fn mac(
        &self,
        _: RequestContext,
        _: ServiceRequest<'_, MacRequest>,
    ) -> ServiceResult<MacResponse> {
        unimplemented()
    }
    async fn public_key(
        &self,
        _: RequestContext,
        _: ServiceRequest<'_, PublicKeyRequest>,
    ) -> ServiceResult<PublicKeyResponse> {
        unimplemented()
    }
}

struct StoreSvc(Vec<u8>);

impl StoreService for StoreSvc {
    async fn get(
        &self,
        _: RequestContext,
        r: ServiceRequest<'_, GetRequest>,
    ) -> ServiceResult<GetResponse> {
        if r.address.kind != "audit-log" || r.address.id != "default" {
            return Err(refusal(ErrorCode::NotFound, "absent", ""));
        }
        Response::ok(GetResponse {
            item: Some(Item {
                address: Some(Address {
                    kind: "audit-log".into(),
                    id: "default".into(),
                    ..Address::default()
                })
                .into(),
                version: 1,
                value: self.0.clone(),
                ..Item::default()
            })
            .into(),
            ..GetResponse::default()
        })
    }
    async fn list(
        &self,
        _: RequestContext,
        _: ServiceRequest<'_, ListRequest>,
    ) -> ServiceResult<ListResponse> {
        unimplemented()
    }
    async fn write(
        &self,
        _: RequestContext,
        _: ServiceRequest<'_, WriteRequest>,
    ) -> ServiceResult<WriteResponse> {
        unimplemented()
    }
    async fn watch(
        &self,
        _: RequestContext,
        _: ServiceRequest<'_, WatchRequest>,
    ) -> ServiceResult<connectrpc::ServiceStream<WatchResponse>> {
        unimplemented()
    }
}

/// The audit transport: it keeps what it is handed.
struct TransportSvc(Arc<Control>);

impl TransportService for TransportSvc {
    async fn emit(
        &self,
        _: RequestContext,
        r: ServiceRequest<'_, EmitRequest>,
    ) -> ServiceResult<EmitResponse> {
        if self.0.transport_down.load(Ordering::SeqCst) {
            return Err(refusal(ErrorCode::Unavailable, "engine", ""));
        }
        let req = r.to_owned_message();
        let rec: Value =
            serde_json::from_slice(&req.message.as_option().cloned().unwrap_or_default().record)
                .unwrap();
        self.0.emitted.lock().unwrap().push((req.blocking, rec));
        Response::ok(EmitResponse::default())
    }
    async fn receive(
        &self,
        _: RequestContext,
        _: ServiceRequest<'_, ReceiveRequest>,
    ) -> ServiceResult<connectrpc::ServiceStream<ReceiveResponse>> {
        unimplemented()
    }
    async fn ack(
        &self,
        _: RequestContext,
        _: ServiceRequest<'_, AckRequest>,
    ) -> ServiceResult<AckResponse> {
        unimplemented()
    }
}

// ---------------------------------------------------------------- the environment

struct Rd {
    /// The indexer's environment: the log, the index and the indexer's own stand-ins.
    env: Env,
    control: Arc<Control>,
    blob_reads: Arc<std::sync::atomic::AtomicUsize>,
    /// The reader's service, called as `entry` would call it.
    client: ReaderServiceClient<sluis_kit::Transport>,
    _stops: Vec<oneshot::Sender<()>>,
    _dir: tempfile::TempDir,
}

impl Rd {
    /// 600 records over three batches: tenants acme (2 of 3) and globex (1 of 3); actions alternate.
    async fn new() -> Self {
        let mut env = Env::new().await;
        for batch in [recs(0..250), recs(250..420), recs(420..600)] {
            env.log.append_records(&batch);
        }
        let r = Runner::new(&env.settings).unwrap().round().await;
        assert_eq!((r.transient, r.halted), (0, 0), "{r:?}");
        Self::over(env).await
    }

    async fn over(env: Env) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let s = dir.path();
        let control = Arc::new(Control::default());
        let reads = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let sockets = Sockets {
            blob: s.join("blob-ro.sock"),
            key: s.join("key.sock"),
            policy: s.join("policy.sock"),
            index: s.join("index-ro.sock"),
            store: s.join("store.sock"),
            audit: s.join("emit.sock"),
        };
        let doc = AuditLog {
            project: PROJECT.into(),
            logs: vec![
                LogDecl {
                    kind: "audit".into(),
                    id: LOG.into(),
                    origin: common::ORIGIN.into(),
                    ..LogDecl::default()
                },
                LogDecl {
                    kind: "usage".into(),
                    id: LOG.into(),
                    origin: "x/usage".into(),
                    ..LogDecl::default()
                },
            ],
            lock_mode: "none".into(),
            ..AuditLog::default()
        };
        let blob_root = env.log.root.clone();
        let mut stops = vec![
            serve(
                &sockets.blob,
                "driver-indexer-fs",
                Arc::new(BlobSvc(blob_root, reads.clone())).register(Router::new()),
                Allow::Exact("reader"),
                "reader",
            ),
            serve(
                &sockets.key,
                "key",
                Arc::new(KeySvc {
                    c: control.clone(),
                    seal: env.log.seal.clone(),
                })
                .register(Router::new()),
                Allow::Exact("reader"),
                "reader",
            ),
            serve(
                &sockets.policy,
                "policy",
                Arc::new(PolicySvc(control.clone())).register(Router::new()),
                Allow::Exact("reader"),
                "reader",
            ),
            serve(
                &sockets.store,
                "store",
                Arc::new(StoreSvc(doc.encode_to_vec())).register(Router::new()),
                Allow::Exact("reader"),
                "reader",
            ),
            serve(
                &sockets.audit,
                "driver-writer-spool",
                Arc::new(TransportSvc(control.clone())).register(Router::new()),
                Allow::Exact("reader"),
                "reader",
            ),
            // The real index driver's read side, on a socket of this test.
            serve(
                &sockets.index,
                "driver-indexer-sqlite",
                Arc::new(Read(env.index.clone())).register(Router::new()),
                Allow::Exact("reader"),
                "reader",
            ),
        ];
        for p in [
            &sockets.blob,
            &sockets.key,
            &sockets.policy,
            &sockets.store,
            &sockets.audit,
            &sockets.index,
        ] {
            up(p).await;
        }
        let audit = Emitter::new(sluis_audit::Config {
            actor: "reader".into(),
            boundary: BOUNDARY.into(),
            release: "0.0.0".into(),
            transport_socket: sockets.audit.clone(),
            key_socket: None,
            now: None,
        })
        .unwrap();
        let searcher = Searcher::new(
            BOUNDARY,
            Ports::new(&sockets),
            Config::new(&dial(&sockets.store)).unwrap(),
        );
        // The reader's service, served as the reader serves it, to the caller `entry`.
        let own = s.join("reader.sock");
        stops.push(serve(
            &own,
            "reader",
            Arc::new(Service::new(searcher, audit)).register(Router::new()),
            Allow::Exact("entry"),
            "entry",
        ));
        up(&own).await;
        let c = dial(&own);
        Self {
            env,
            control,
            blob_reads: reads,
            client: ReaderServiceClient::new(c.transport(), c.config()),
            _stops: stops,
            _dir: dir,
        }
    }

    async fn search(&self, req: SearchRequest) -> Result<SearchResponse, connectrpc::ConnectError> {
        self.client.search(req).await.map(|r| r.into_owned())
    }

    /// Every page of a query.
    async fn all(&self, mut req: SearchRequest) -> Vec<sluis_proto::sluis::reader::v2alpha1::Hit> {
        let mut out = Vec::new();
        loop {
            let page = self.search(req.clone()).await.unwrap();
            out.extend(page.hits);
            if page.next_page_token.is_empty() {
                return out;
            }
            req.page_token = page.next_page_token;
        }
    }
}

fn recs(range: std::ops::Range<u32>) -> Vec<Rec> {
    range
        .map(|n| {
            let tenant = if n % 3 == 0 { "globex" } else { "acme" };
            let action = if n % 2 == 0 {
                "token.exchange"
            } else {
                "key.sign"
            };
            Rec::new(n, tenant, action)
        })
        .collect()
}

fn q(tenants: &[&str]) -> SearchRequest {
    SearchRequest {
        tenants: tenants.iter().map(|t| (*t).into()).collect(),
        page_size: 200,
        ..SearchRequest::default()
    }
}

fn record(h: &sluis_proto::sluis::reader::v2alpha1::Hit) -> Value {
    serde_json::from_str(&h.record).unwrap()
}

// ---------------------------------------------------------------- the tests

#[tokio::test]
async fn a_grant_for_one_tenant_returns_its_records_opened_from_the_log() {
    let rd = Rd::new().await;
    let hits = rd.all(q(&["acme"])).await;
    assert_eq!(hits.len(), 400);
    assert!(hits.iter().all(|h| h.tenant == "acme"));
    // Newest first, and each hit is the record the emitter made, byte for byte as the index took it.
    assert!(hits.windows(2).all(|w| w[0].time_ms >= w[1].time_ms));
    let want = Rec::new(7, "acme", "key.sign");
    let one = hits.iter().find(|h| h.record_id == want.uid).unwrap();
    assert_eq!(one.record.as_bytes(), want.bytes());
    assert_eq!(
        (
            one.action.as_str(),
            one.trace_id.as_str(),
            one.project.as_str()
        ),
        ("key.sign", "trace-7", PROJECT)
    );
    assert_eq!(record(one)["metadata"]["tenant_uid"], "acme");
    // The records were opened at key@, from the log, and only for the tenant that was granted.
    let opened = rd.control.opened.lock().unwrap();
    assert_eq!(opened.len(), 400);
    assert!(opened.iter().all(|t| t == "acme"));
    // policy was asked for audit.read as the reader, for that tenant alone.
    let asked = rd.control.decides.lock().unwrap().clone();
    assert!(!asked.is_empty());
    assert!(asked.iter().all(|d| *d
        == (
            "audit.read".to_owned(),
            "Actor".to_owned(),
            "reader".to_owned(),
            "acme".to_owned()
        )));
}

#[tokio::test]
async fn a_grant_for_another_tenant_returns_nothing_of_the_first() {
    let rd = Rd::new().await;
    // A tenant the log has no records of: an empty answer, as for a tenant that does not exist.
    let none = rd.search(q(&["initech"])).await.unwrap();
    assert!(none.hits.is_empty() && none.next_page_token.is_empty());
    // Two tenants each see their own, and the union is not a third set.
    let globex = rd.all(q(&["globex"])).await;
    assert_eq!(globex.len(), 200);
    assert!(globex.iter().all(|h| h.tenant == "globex"));
    let both = rd.all(q(&["acme", "globex"])).await;
    assert_eq!(both.len(), 600);
    // Nothing of acme was opened under globex's grant: key@ would refuse it, and the reader never asks.
    let opened = rd.control.opened.lock().unwrap().clone();
    assert_eq!(opened.iter().filter(|t| *t == "acme").count(), 400);
}

#[tokio::test]
async fn key_at_refuses_a_record_of_a_tenant_the_grant_does_not_name_even_if_policy_and_the_index_agree_on_it()
 {
    let rd = Rd::new().await;
    // Policy (wrongly) seals a grant for globex when acme is asked: the first check passes, the second must not.
    *rd.control.grant_for_other.lock().unwrap() = Some(("acme".into(), "globex".into()));
    let e = rd.search(q(&["acme"])).await.unwrap_err();
    assert_eq!(
        (e.code, refusal_reason(&e).as_deref()),
        (ErrorCode::PermissionDenied, Some("grant"))
    );
    assert!(
        rd.control.opened.lock().unwrap().is_empty(),
        "key@ opened something under the wrong grant"
    );
}

#[tokio::test]
async fn a_denial_by_policy_refuses_the_call_and_reads_nothing() {
    let rd = Rd::new().await;
    rd.control.deny.lock().unwrap().push("globex".into());
    let e = rd.search(q(&["acme", "globex"])).await.unwrap_err();
    assert_eq!(
        (e.code, refusal_reason(&e).as_deref()),
        (ErrorCode::PermissionDenied, Some("grant"))
    );
    assert!(rd.control.opened.lock().unwrap().is_empty());
    assert_eq!(
        rd.blob_reads.load(Ordering::SeqCst),
        0,
        "a denied call read the log"
    );
    // The refusal is audited, with the decision that denied it.
    let emitted = rd.control.emitted.lock().unwrap();
    let last = &emitted.last().unwrap().1;
    assert_eq!(last["metadata"]["event_code"], "reader.search");
    assert_eq!(last["status_id"], 2);
    assert_eq!(last["status_code"], "grant");
    assert!(
        last["unmapped"]["sluis"]["decisions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|d| d == "deny-globex")
    );
}

#[tokio::test]
async fn filters_words_and_pages_are_applied_under_the_grant() {
    let rd = Rd::new().await;
    // A filter by action, and the same by word.
    let mut r = q(&["acme"]);
    r.action = "token.exchange".into();
    let by_action = rd.all(r).await;
    assert!(
        !by_action.is_empty()
            && by_action
                .iter()
                .all(|h| h.action == "token.exchange" && h.tenant == "acme")
    );
    let mut r = q(&["acme"]);
    r.q = "key.sign".into();
    let by_word = rd.all(r).await;
    assert!(!by_word.is_empty() && by_word.iter().all(|h| h.action == "key.sign"));
    // A record id is one hit; the same id under another tenant's grant is none.
    let want = Rec::new(8, "acme", "token.exchange");
    let mut r = q(&["acme"]);
    r.record_id = want.uid.clone();
    assert_eq!(rd.all(r.clone()).await.len(), 1);
    r.tenants = vec!["globex".into()];
    assert!(rd.all(r).await.is_empty());
    // Pages: small pages give the same set as one big page.
    let mut r = q(&["acme"]);
    r.page_size = 7;
    let paged = rd.all(r).await;
    let ids: Vec<&str> = paged.iter().map(|h| h.record_id.as_str()).collect();
    assert_eq!(ids.len(), 400);
    assert_eq!(
        ids.iter().collect::<std::collections::BTreeSet<_>>().len(),
        400
    );
}

#[tokio::test]
async fn the_wildcard_is_one_grant_for_every_tenant_and_stands_alone() {
    let rd = Rd::new().await;
    let all = rd.all(q(&["*"])).await;
    assert_eq!(all.len(), 600);
    let asked: Vec<String> = rd
        .control
        .decides
        .lock()
        .unwrap()
        .iter()
        .map(|d| d.3.clone())
        .collect();
    assert!(asked.iter().all(|t| t == "*"));
    for bad in [
        vec!["*", "acme"],
        vec![],
        vec!["Acme"],
        vec!["a/b"],
        vec!["acme", "acme"],
    ] {
        let e = rd.search(q(&bad)).await.unwrap_err();
        assert_eq!(
            (e.code, refusal_reason(&e).as_deref()),
            (ErrorCode::InvalidArgument, Some("schema")),
            "{bad:?}"
        );
    }
}

#[tokio::test]
async fn a_request_outside_the_contract_is_refused_with_the_field_path_and_audited_without_its_words()
 {
    let rd = Rd::new().await;
    let mut r = q(&["acme"]);
    r.page_size = 201;
    let e = rd.search(r).await.unwrap_err();
    assert_eq!(
        (e.code, refusal_reason(&e).as_deref()),
        (ErrorCode::InvalidArgument, Some("bound"))
    );
    let mut r = q(&["secret-looking-tenant!"]);
    r.q = "secret words".into();
    assert!(rd.search(r).await.is_err());
    // Nothing of the second request is in the audit record.
    let emitted = rd.control.emitted.lock().unwrap();
    let text = serde_json::to_string(&*emitted.iter().map(|e| &e.1).collect::<Vec<_>>()).unwrap();
    assert!(
        !text.contains("secret"),
        "a word of the request is in the audit record"
    );
}

#[tokio::test]
async fn every_search_is_audited_before_its_records_are_returned() {
    let rd = Rd::new().await;
    let mut r = q(&["acme"]);
    r.page_size = 3;
    let page = rd.search(r).await.unwrap();
    assert_eq!(page.hits.len(), 3);
    let emitted = rd.control.emitted.lock().unwrap();
    let (blocking, rec) = emitted.last().unwrap();
    assert!(
        *blocking,
        "a read must be durable in the transport before it returns"
    );
    assert_eq!(rec["metadata"]["event_code"], "reader.search");
    assert_eq!(rec["status_id"], 1);
    assert_eq!(rec["unmapped"]["sluis"]["hits"], 3);
    assert_eq!(
        rec["unmapped"]["sluis"]["tenants"],
        serde_json::json!(["acme"])
    );
    assert_eq!(rec["actor"]["user"]["uid"], "reader@dev");
}

#[tokio::test]
async fn a_read_that_cannot_be_audited_returns_no_record() {
    let rd = Rd::new().await;
    rd.control.transport_down.store(true, Ordering::SeqCst);
    let e = rd.search(q(&["acme"])).await.unwrap_err();
    assert_eq!(
        (e.code, refusal_reason(&e).as_deref()),
        (ErrorCode::Unavailable, Some("engine"))
    );
}

#[tokio::test]
async fn a_dependency_that_is_down_fails_closed() {
    let rd = Rd::new().await;
    rd.control.key_down.store(true, Ordering::SeqCst);
    let e = rd.search(q(&["acme"])).await.unwrap_err();
    assert_eq!(e.code, ErrorCode::Unavailable);
    rd.control.key_down.store(false, Ordering::SeqCst);
    rd.control.policy_down.store(true, Ordering::SeqCst);
    let before = rd.blob_reads.load(Ordering::SeqCst);
    let e = rd.search(q(&["acme"])).await.unwrap_err();
    assert_eq!(e.code, ErrorCode::Unavailable);
    assert_eq!(
        rd.blob_reads.load(Ordering::SeqCst),
        before,
        "the log was read without a grant"
    );
}

#[tokio::test]
async fn an_index_row_that_is_not_the_record_in_the_log_fails_the_call() {
    use sluis_proto::sluis::port::index::v2alpha1::{ApplyRequest, Cursor, LogRef};
    let rd = Rd::new().await;
    // Make the index lie: a row for seq 0 of the log with the record id of another record.
    let rows = rd.env.search(&["acme"], "").await;
    let mut liar = rows.last().unwrap().clone();
    liar.record_id = "0194d000-0000-7000-8000-999999999999".into();
    liar.hash = vec![7; 48];
    let size = rd.env.cursor_size();
    rd.env
        .index
        .apply(&ApplyRequest {
            log: ::buffa::MessageField::some(LogRef {
                project: PROJECT.into(),
                kind: "audit".into(),
                log: LOG.into(),
                ..LogRef::default()
            }),
            expect_size: size,
            next: ::buffa::MessageField::some(Cursor {
                size: size + 1,
                root: vec![1; 32],
                state: vec![],
                ..Cursor::default()
            }),
            rows: vec![liar],
            ..ApplyRequest::default()
        })
        .unwrap();
    let mut r = q(&["acme"]);
    r.record_id = "0194d000-0000-7000-8000-999999999999".into();
    let e = rd.search(r).await.unwrap_err();
    assert_eq!(
        (e.code, refusal_reason(&e).as_deref()),
        (ErrorCode::Internal, Some("integrity"))
    );
}

#[tokio::test]
async fn records_in_partial_and_full_bundles_are_found() {
    let rd = Rd::new().await;
    // 603 entries: bundles 0 and 1 are full, bundle 2 is partial (603 - 512 = 91). Search reaches the last record.
    let last = Rec::new(597, "globex", "key.sign");
    let mut r = q(&["globex"]);
    r.record_id = last.uid.clone();
    let hits = rd.all(r).await;
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].record.as_bytes(), last.bytes());
    assert!(hits[0].seq >= 512);
}
