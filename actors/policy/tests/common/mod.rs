#![allow(refining_impl_trait)] // the generated traits return `impl Encodable`; a concrete type is fine
#![allow(clippy::unwrap_used, clippy::expect_used)] // a failed unwrap in a test is the failure
#![allow(dead_code)] // each test file uses part of the rig
//! The rig of the tests of `policy`: the service under test on a Unix socket of the kit, with fake
//! `key@`, fake audit transport and fake `store@`, each a real server of its contract over the
//! kit's transport. The test process is every actor in turn: each server has its own table that
//! names the process's uid.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use buffa::Message as _;
use connectrpc::error::ErrorCode;
use connectrpc::{RequestContext, Response, Router, ServiceRequest, ServiceResult, ServiceStream};
use policy::engine::{Engine, Inputs, PolicyDoc};
use policy::service::{Deps, Service};
use serde_json::Value;
use sluis_audit::{Config as AuditConfig, Emitter};
use sluis_kit::{Allow, Identities, ServerConfig, dial, refusal};
use sluis_proto::sluis::config::v2alpha1 as cfg;
use sluis_proto::sluis::key::v2alpha1::{
    KeyService, KeyServiceClient, KeyServiceExt, MacRequest, MacResponse, OpenGrantRequest,
    OpenGrantResponse, OpenRequest, OpenResponse, PublicKeyRequest, PublicKeyResponse,
    SealGrantRequest, SealGrantResponse, SealRequest, SealResponse, SignRequest, SignResponse,
};
use sluis_proto::sluis::policy::v2alpha1::{
    ActorFacts, Authentication, ClientFacts, DecideRequest, EntityRef, PersonFacts,
    PolicyServiceClient, PolicyServiceExt as _,
};
use sluis_proto::sluis::port::transport::v2alpha1::{
    AckRequest, AckResponse, EmitRequest, EmitResponse, ReceiveRequest, ReceiveResponse,
    TransportService, TransportServiceExt,
};
use sluis_proto::sluis::store::v2alpha1::{
    GetRequest, GetResponse, Item, ListRequest, ListResponse, StoreService, StoreServiceExt,
    WatchRequest, WatchResponse, WriteRequest, WriteResponse,
};
use sluis_proto::sluis::r#type::v2alpha1::{Address, Grant};

/// 2026-11-04T00:00:00Z.
pub fn now() -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_millis(1_793_750_400_000)
}

pub fn local(file: &str) -> String {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/installations/local/policy")
        .join(file);
    std::fs::read_to_string(p).unwrap()
}

/// The local installation's inputs: `local.cedar` and its vocabulary, no links.
pub fn local_inputs() -> Inputs {
    Inputs {
        boundary: "dev".into(),
        policies: vec![PolicyDoc {
            file: "local".into(),
            cedar: local("local.cedar"),
        }],
        vocabulary: local("vocabulary.yaml").into_bytes(),
        links: Vec::new(),
    }
}

// ---- the audit transport ----------------------------------------------------------------

#[derive(Default)]
pub struct Spool {
    pub reqs: Mutex<Vec<EmitRequest>>,
    pub fail: Mutex<Option<ErrorCode>>,
}

impl Spool {
    /// The records received, decoded, with whether each was a blocking emit.
    pub fn records(&self) -> Vec<(Value, bool)> {
        self.reqs
            .lock()
            .unwrap()
            .iter()
            .map(|r| {
                (
                    serde_json::from_slice(&r.message.record).unwrap(),
                    r.blocking,
                )
            })
            .collect()
    }

    /// The records of one action.
    pub fn of(&self, event_code: &str) -> Vec<(Value, bool)> {
        self.records()
            .into_iter()
            .filter(|(r, _)| r["metadata"]["event_code"] == event_code)
            .collect()
    }
}

impl TransportService for Spool {
    async fn emit(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, EmitRequest>,
    ) -> ServiceResult<EmitResponse> {
        if let Some(code) = *self.fail.lock().unwrap() {
            return Err(refusal(code, "engine", ""));
        }
        self.reqs.lock().unwrap().push(request.to_owned_message());
        Response::ok(EmitResponse::default())
    }
    async fn receive(
        &self,
        _: RequestContext,
        _: ServiceRequest<'_, ReceiveRequest>,
    ) -> ServiceResult<ServiceStream<ReceiveResponse>> {
        Err(refusal(ErrorCode::Unimplemented, "unsupported", ""))
    }
    async fn ack(
        &self,
        _: RequestContext,
        _: ServiceRequest<'_, AckRequest>,
    ) -> ServiceResult<AckResponse> {
        Err(refusal(ErrorCode::Unimplemented, "unsupported", ""))
    }
}

// ---- key@ -------------------------------------------------------------------------------

/// A fake key@: it seals a grant as `u16 length | decision_id | grant`, the wire form of the real
/// one without the encryption, and keeps what it was asked.
#[derive(Default)]
pub struct Keys {
    pub sealed: Mutex<Vec<Grant>>,
    pub fail: Mutex<bool>,
}

fn unsupported<T>() -> ServiceResult<T> {
    Err(refusal(ErrorCode::Unimplemented, "unsupported", ""))
}

/// The grant inside a grant sealed by the fake.
pub fn open_sealed(sealed: &[u8]) -> Grant {
    let n = usize::from(u16::from_be_bytes([sealed[0], sealed[1]]));
    Grant::decode_from_slice(&sealed[2 + n..]).unwrap()
}

impl KeyService for Keys {
    async fn seal_grant(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, SealGrantRequest>,
    ) -> ServiceResult<SealGrantResponse> {
        if *self.fail.lock().unwrap() {
            return Err(refusal(ErrorCode::Unavailable, "driver", ""));
        }
        let req = request.to_owned_message();
        let g = req.grant.into_option().unwrap();
        let id = g.decision_id.clone();
        let mut out = u16::try_from(id.len()).unwrap().to_be_bytes().to_vec();
        out.extend_from_slice(id.as_bytes());
        out.extend_from_slice(&g.encode_to_vec());
        self.sealed.lock().unwrap().push(g);
        Response::ok(SealGrantResponse {
            sealed_grant: out,
            ..SealGrantResponse::default()
        })
    }
    async fn mac(
        &self,
        _: RequestContext,
        _: ServiceRequest<'_, MacRequest>,
    ) -> ServiceResult<MacResponse> {
        Response::ok(MacResponse {
            mac: (0..48).collect(),
            ..MacResponse::default()
        })
    }
    async fn seal(
        &self,
        _: RequestContext,
        _: ServiceRequest<'_, SealRequest>,
    ) -> ServiceResult<SealResponse> {
        unsupported()
    }
    async fn open(
        &self,
        _: RequestContext,
        _: ServiceRequest<'_, OpenRequest>,
    ) -> ServiceResult<OpenResponse> {
        unsupported()
    }
    async fn open_grant(
        &self,
        _: RequestContext,
        _: ServiceRequest<'_, OpenGrantRequest>,
    ) -> ServiceResult<OpenGrantResponse> {
        unsupported()
    }
    async fn sign(
        &self,
        _: RequestContext,
        _: ServiceRequest<'_, SignRequest>,
    ) -> ServiceResult<SignResponse> {
        unsupported()
    }
    async fn public_key(
        &self,
        _: RequestContext,
        _: ServiceRequest<'_, PublicKeyRequest>,
    ) -> ServiceResult<PublicKeyResponse> {
        unsupported()
    }
}

// ---- store@ -----------------------------------------------------------------------------

/// A fake store@ that serves the two config kinds `policy` reads.
#[derive(Default)]
pub struct Store {
    pub vocabulary: Mutex<Vec<u8>>,
    /// `(file id, Cedar text)`.
    pub policies: Mutex<Vec<(String, String)>>,
    pub down: Mutex<bool>,
}

impl Store {
    pub fn set(&self, inputs: &Inputs) {
        *self.vocabulary.lock().unwrap() = inputs.vocabulary.clone();
        *self.policies.lock().unwrap() = inputs
            .policies
            .iter()
            .map(|d| (d.file.clone(), d.cedar.clone()))
            .collect();
    }
}

fn item(kind: &str, id: &str, value: Vec<u8>) -> Item {
    Item {
        address: Address {
            kind: kind.into(),
            id: id.into(),
            ..Address::default()
        }
        .into(),
        version: 1,
        value,
        ..Item::default()
    }
}

impl StoreService for Store {
    async fn get(
        &self,
        _: RequestContext,
        request: ServiceRequest<'_, GetRequest>,
    ) -> ServiceResult<GetResponse> {
        if *self.down.lock().unwrap() {
            return Err(refusal(ErrorCode::Unavailable, "engine", ""));
        }
        let req = request.to_owned_message();
        let a = req.address.into_option().unwrap();
        if a.kind != "grant-vocabulary" || a.id != "default" {
            return Err(refusal(ErrorCode::NotFound, "absent", ""));
        }
        let value = cfg::GrantVocabulary {
            document: self.vocabulary.lock().unwrap().clone(),
            ..cfg::GrantVocabulary::default()
        };
        Response::ok(GetResponse {
            item: item("grant-vocabulary", "default", value.encode_to_vec()).into(),
            ..GetResponse::default()
        })
    }
    async fn list(
        &self,
        _: RequestContext,
        request: ServiceRequest<'_, ListRequest>,
    ) -> ServiceResult<ListResponse> {
        if *self.down.lock().unwrap() {
            return Err(refusal(ErrorCode::Unavailable, "engine", ""));
        }
        let req = request.to_owned_message();
        if req.kind != "policy" {
            return Err(refusal(ErrorCode::NotFound, "absent", ""));
        }
        let items = self
            .policies
            .lock()
            .unwrap()
            .iter()
            .map(|(id, cedar)| {
                let v = cfg::Policy {
                    id: id.clone(),
                    cedar: cedar.clone(),
                    ..cfg::Policy::default()
                };
                item("policy", id, v.encode_to_vec())
            })
            .collect();
        Response::ok(ListResponse {
            items,
            ..ListResponse::default()
        })
    }
    async fn write(
        &self,
        _: RequestContext,
        _: ServiceRequest<'_, WriteRequest>,
    ) -> ServiceResult<WriteResponse> {
        unsupported()
    }
    async fn watch(
        &self,
        _: RequestContext,
        _: ServiceRequest<'_, WatchRequest>,
    ) -> ServiceResult<ServiceStream<WatchResponse>> {
        unsupported()
    }
}

// ---- serving ----------------------------------------------------------------------------

/// Serves `router` on a socket of `dir`, for the test process named `as_` by that server's own
/// table, and only for it.
pub async fn serve(
    dir: &Path,
    name: &str,
    actor: &'static str,
    allow: Allow,
    as_: &'static str,
    router: Router,
    stop: &mut Vec<tokio::sync::oneshot::Sender<()>>,
) -> PathBuf {
    let socket = dir.join(name);
    let me = rustix::process::geteuid().as_raw();
    let ids = Identities::with(0, move |u| (u == me).then_some((as_, 0)));
    let cfg = ServerConfig {
        actor,
        boundary: "dev".into(),
        socket: socket.clone(),
        mode: 0o660,
        socket_gid: None,
        allow,
        default_deadline: Duration::from_secs(10),
    };
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    stop.push(tx);
    tokio::spawn(sluis_kit::serve_with(
        cfg,
        router,
        async move {
            let _ = rx.await;
        },
        ids,
    ));
    for _ in 0..300 {
        if socket.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    socket
}

/// Everything around the service: the fakes and their sockets. `policy` is "policy" to each.
pub struct Around {
    pub dir: tempfile::TempDir,
    pub spool: Arc<Spool>,
    pub keys: Arc<Keys>,
    pub store: Arc<Store>,
    pub emit_socket: PathBuf,
    pub key_socket: PathBuf,
    pub store_socket: PathBuf,
    pub stop: Vec<tokio::sync::oneshot::Sender<()>>,
}

impl Around {
    pub async fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let (spool, keys, store) = (
            Arc::new(Spool::default()),
            Arc::new(Keys::default()),
            Arc::new(Store::default()),
        );
        let mut stop = Vec::new();
        let emit_socket = serve(
            dir.path(),
            "emit.sock",
            "transport",
            Allow::Exact("policy"),
            "policy",
            Arc::clone(&spool).register(Router::new()),
            &mut stop,
        )
        .await;
        let key_socket = serve(
            dir.path(),
            "key.sock",
            "key",
            Allow::Exact("policy"),
            "policy",
            Arc::clone(&keys).register(Router::new()),
            &mut stop,
        )
        .await;
        let store_socket = serve(
            dir.path(),
            "store.sock",
            "store",
            Allow::Exact("policy"),
            "policy",
            Arc::clone(&store).register(Router::new()),
            &mut stop,
        )
        .await;
        Self {
            dir,
            spool,
            keys,
            store,
            emit_socket,
            key_socket,
            store_socket,
            stop,
        }
    }

    pub fn emitter(&self) -> Emitter {
        Emitter::new(AuditConfig {
            actor: "policy".into(),
            boundary: "dev".into(),
            release: "0.0.0-test".into(),
            transport_socket: self.emit_socket.clone(),
            key_socket: Some(self.key_socket.clone()),
            now: Some(now),
        })
        .unwrap()
    }

    pub fn service(&self, inputs: &Inputs) -> Arc<Service> {
        let key = dial(&self.key_socket);
        Arc::new(Service::new(Deps {
            engine: Engine::build(inputs).unwrap(),
            keys: KeyServiceClient::new(key.transport(), key.config()),
            audit: self.emitter(),
            clock: now,
        }))
    }
}

/// The service under test, served for a process that the kit names `caller`.
pub struct Rig {
    pub around: Around,
    pub service: Arc<Service>,
    pub client: PolicyServiceClient<sluis_kit::Transport>,
}

impl Rig {
    pub async fn new(caller: &'static str) -> Self {
        Self::with(caller, &local_inputs()).await
    }

    pub async fn with(caller: &'static str, inputs: &Inputs) -> Self {
        let mut around = Around::new().await;
        let service = around.service(inputs);
        let socket = serve(
            around.dir.path(),
            "policy.sock",
            "policy",
            Allow::CallGraph,
            caller,
            Arc::clone(&service).register(Router::new()),
            &mut around.stop,
        )
        .await;
        let c = dial(&socket);
        let client = PolicyServiceClient::new(c.transport(), c.config());
        Self {
            around,
            service,
            client,
        }
    }
}

// ---- requests ---------------------------------------------------------------------------

pub fn entity(ty: &str, id: &str) -> EntityRef {
    EntityRef {
        r#type: ty.into(),
        id: id.into(),
        ..EntityRef::default()
    }
}

/// How a person signed in: multi-factor, fresh.
pub fn fresh_mfa() -> Authentication {
    Authentication {
        acr: Some("urn:example:acr:mfa".into()),
        amr: vec!["pwd".into(), "mfa".into()],
        amr_present: true,
        auth_age: Some(300),
        ..Authentication::default()
    }
}

/// A person asks for a token for the client `example-app`, which requires the user role of `dev`
/// or of `acme`.
pub fn token(
    action: &str,
    accounts: &[&str],
    state: &str,
    context: Authentication,
) -> DecideRequest {
    DecideRequest {
        action: action.into(),
        principal: entity("Person", "p-1").into(),
        resource: entity("Client", "example-app").into(),
        tenant: "acme".into(),
        context: context.into(),
        person: PersonFacts {
            subject: "p-1".into(),
            accounts: accounts.iter().map(|s| (*s).to_owned()).collect(),
            state: state.into(),
            org: "acme".into(),
            ..PersonFacts::default()
        }
        .into(),
        client: ClientFacts {
            id: "example-app".into(),
            requires: vec![
                "dev:example-app:user".into(),
                "acme:example-app:user".into(),
            ],
            kind: "confidential".into(),
            ..ClientFacts::default()
        }
        .into(),
        grant_store_verbs: vec!["get".into(), "create".into()],
        grant_key_ops: vec!["seal".into(), "open".into()],
        ..DecideRequest::default()
    }
}

/// An actor asks for a grant for itself.
pub fn audit(action: &str, actor: &str, tenant: &str) -> DecideRequest {
    DecideRequest {
        action: action.into(),
        principal: entity("Actor", actor).into(),
        resource: entity("Boundary", "dev").into(),
        tenant: tenant.into(),
        actor: ActorFacts {
            name: actor.into(),
            ..ActorFacts::default()
        }
        .into(),
        grant_key_ops: vec!["seal".into(), "open".into()],
        ..DecideRequest::default()
    }
}

// ---- edits of a request (the message fields do not deref mutably) ------------------------

pub fn requires(mut r: DecideRequest, names: &[&str]) -> DecideRequest {
    let mut c = r.client.as_option().unwrap().clone();
    c.requires = names.iter().map(|s| (*s).to_owned()).collect();
    r.client = c.into();
    r
}

pub fn subject(mut r: DecideRequest, s: &str) -> DecideRequest {
    let mut p = r.person.as_option().unwrap().clone();
    p.subject = s.into();
    r.person = p.into();
    r
}

pub fn accounts(mut r: DecideRequest, a: &[&str]) -> DecideRequest {
    let mut p = r.person.as_option().unwrap().clone();
    p.accounts = a.iter().map(|s| (*s).to_owned()).collect();
    r.person = p.into();
    r
}

pub fn auth_age(mut r: DecideRequest, age: i64) -> DecideRequest {
    let mut c = r.context.as_option().unwrap().clone();
    c.auth_age = Some(age);
    r.context = c.into();
    r
}

pub fn org(mut r: DecideRequest, o: &str) -> DecideRequest {
    let mut p = r.person.as_option().unwrap().clone();
    p.org = o.into();
    r.person = p.into();
    r
}

pub fn kind(mut r: DecideRequest, k: &str) -> DecideRequest {
    let mut c = r.client.as_option().unwrap().clone();
    c.kind = k.into();
    r.client = c.into();
    r
}
