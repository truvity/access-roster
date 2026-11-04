#![allow(refining_impl_trait)] // the generated trait returns `impl Encodable`; a concrete type is fine
#![allow(clippy::unwrap_used, clippy::expect_used)] // a failed unwrap in a test is the failure
//! `entry` over its real Unix socket, with in-process fake `session`, `exchange`, `store@` and
//! audit transport servers (test code only; every call between them is Connect over `proto/`).
//! The fakes name the test process as the caller `entry` through the kit's test identities.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use buffa::Message as _;
use connectrpc::error::ErrorCode;
use connectrpc::{RequestContext, Response, Router, ServiceRequest, ServiceResult, ServiceStream};
use entry::{Config, Front, Sockets};
use serde_json::Value;
use sluis_kit::{Allow, Identities, ServerConfig, refusal};
use sluis_proto::sluis::config::v2alpha1::Boundary;
use sluis_proto::sluis::exchange::v2alpha1::{
    ExchangeService, ExchangeServiceExt, TokenExchangeRequest,
};
use sluis_proto::sluis::port::transport::v2alpha1::{
    AckRequest, AckResponse, EmitRequest, EmitResponse, ReceiveRequest, ReceiveResponse,
    TransportService, TransportServiceExt,
};
use sluis_proto::sluis::reader::v2alpha1::{
    Hit, ReaderService, ReaderServiceExt, SearchRequest, SearchResponse,
};
use sluis_proto::sluis::session::v2alpha1::{
    AuthorizeRequest, CallbackRequest, SessionService, SessionServiceExt, TokenRequest,
};
use sluis_proto::sluis::signer::v2alpha1::{SigningKey, SigningRing};
use sluis_proto::sluis::store::v2alpha1::{
    GetRequest, GetResponse, Item, ListRequest, ListResponse, StoreService, StoreServiceExt,
    WatchRequest, WatchResponse, WriteRequest, WriteResponse,
};
use sluis_proto::sluis::r#type::v2alpha1::{Address, Header, HttpReply};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const ISSUER: &str = "https://sluis.dev.local.test";

// ---------------------------------------------------------------- the fakes

#[derive(Default)]
struct Calls {
    authorize: Vec<AuthorizeRequest>,
    callback: Vec<CallbackRequest>,
    token: Vec<TokenRequest>,
    exchange: Vec<TokenExchangeRequest>,
    search: Vec<SearchRequest>,
}

#[derive(Default)]
struct Fake {
    calls: Mutex<Calls>,
    /// The reply of the next call; `None` is a plain 200.
    reply: Mutex<Option<HttpReply>>,
    /// The error of the next call.
    error: Mutex<Option<(ErrorCode, &'static str)>>,
    store_fails: Mutex<bool>,
    store_gets: Mutex<usize>,
    emitted: Mutex<Vec<Value>>,
}

impl Fake {
    fn answer(&self) -> ServiceResult<HttpReply> {
        if let Some((code, reason)) = *self.error.lock().unwrap() {
            return Err(refusal(code, reason, "secret.field.path"));
        }
        let r = self.reply.lock().unwrap().clone().unwrap_or(HttpReply {
            status: 200,
            body: b"ok".to_vec(),
            ..HttpReply::default()
        });
        Response::ok(r)
    }
}

struct FakeSession(Arc<Fake>);
impl SessionService for FakeSession {
    async fn authorize(
        &self,
        _: RequestContext,
        r: ServiceRequest<'_, AuthorizeRequest>,
    ) -> ServiceResult<HttpReply> {
        self.0
            .calls
            .lock()
            .unwrap()
            .authorize
            .push(r.to_owned_message());
        self.0.answer()
    }
    async fn callback(
        &self,
        _: RequestContext,
        r: ServiceRequest<'_, CallbackRequest>,
    ) -> ServiceResult<HttpReply> {
        self.0
            .calls
            .lock()
            .unwrap()
            .callback
            .push(r.to_owned_message());
        self.0.answer()
    }
    async fn token(
        &self,
        _: RequestContext,
        r: ServiceRequest<'_, TokenRequest>,
    ) -> ServiceResult<HttpReply> {
        self.0
            .calls
            .lock()
            .unwrap()
            .token
            .push(r.to_owned_message());
        self.0.answer()
    }
}

struct FakeReader(Arc<Fake>);
impl ReaderService for FakeReader {
    async fn search(
        &self,
        _: RequestContext,
        r: ServiceRequest<'_, SearchRequest>,
    ) -> ServiceResult<SearchResponse> {
        self.0
            .calls
            .lock()
            .unwrap()
            .search
            .push(r.to_owned_message());
        if let Some((code, reason)) = *self.0.error.lock().unwrap() {
            return Err(refusal(code, reason, "secret.field.path"));
        }
        Response::ok(SearchResponse {
            hits: vec![Hit {
                tenant: "acme".into(),
                seq: 7,
                time_ms: 1_700_000_000_000,
                action: "signer.sign".into(),
                record: "{\"a\":1}".into(),
                ..Hit::default()
            }],
            next_page_token: vec![9, 9],
            ..SearchResponse::default()
        })
    }
}

struct FakeExchange(Arc<Fake>);
impl ExchangeService for FakeExchange {
    async fn token(
        &self,
        _: RequestContext,
        r: ServiceRequest<'_, TokenExchangeRequest>,
    ) -> ServiceResult<HttpReply> {
        self.0
            .calls
            .lock()
            .unwrap()
            .exchange
            .push(r.to_owned_message());
        self.0.answer()
    }
}

/// A P-384 SubjectPublicKeyInfo with made-up coordinates (a test key, not a real one).
fn spki() -> Vec<u8> {
    let mut v = vec![
        0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05,
        0x2b, 0x81, 0x04, 0x00, 0x22, 0x03, 0x62, 0x00, 0x04,
    ];
    v.extend(std::iter::repeat_n(7u8, 48));
    v.extend(std::iter::repeat_n(9u8, 48));
    v
}

struct FakeStore(Arc<Fake>);
impl StoreService for FakeStore {
    async fn get(
        &self,
        _: RequestContext,
        r: ServiceRequest<'_, GetRequest>,
    ) -> ServiceResult<GetResponse> {
        *self.0.store_gets.lock().unwrap() += 1;
        if *self.0.store_fails.lock().unwrap() {
            return Err(refusal(ErrorCode::Unavailable, "engine", ""));
        }
        let kind = r.address.kind.to_string();
        let value = match kind.as_str() {
            "boundary" => Boundary {
                issuer: ISSUER.into(),
                ..Boundary::default()
            }
            .encode_to_vec(),
            "signing-ring" => SigningRing {
                keys: vec![
                    SigningKey {
                        key_id: "kid-1".into(),
                        algorithm: "ES384".into(),
                        state: "active".into(),
                        spki_der: spki(),
                        ..SigningKey::default()
                    },
                    SigningKey {
                        key_id: "kid-revoked".into(),
                        algorithm: "ES384".into(),
                        state: "revoked".into(),
                        spki_der: spki(),
                        ..SigningKey::default()
                    },
                ],
                ..SigningRing::default()
            }
            .encode_to_vec(),
            _ => return Err(refusal(ErrorCode::NotFound, "absent", "")),
        };
        Response::ok(GetResponse {
            item: Some(Item {
                address: Some(Address {
                    kind,
                    id: "default".into(),
                    ..Address::default()
                })
                .into(),
                version: 1,
                value,
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
        Err(refusal(ErrorCode::Unimplemented, "unsupported", ""))
    }
    async fn write(
        &self,
        _: RequestContext,
        _: ServiceRequest<'_, WriteRequest>,
    ) -> ServiceResult<WriteResponse> {
        Err(refusal(ErrorCode::Unimplemented, "unsupported", ""))
    }
    async fn watch(
        &self,
        _: RequestContext,
        _: ServiceRequest<'_, WatchRequest>,
    ) -> ServiceResult<ServiceStream<WatchResponse>> {
        Err(refusal(ErrorCode::Unimplemented, "unsupported", ""))
    }
}

struct FakeSpool(Arc<Fake>);
impl TransportService for FakeSpool {
    async fn emit(
        &self,
        _: RequestContext,
        r: ServiceRequest<'_, EmitRequest>,
    ) -> ServiceResult<EmitResponse> {
        let rec: Value = serde_json::from_slice(r.message.record).unwrap();
        self.0.emitted.lock().unwrap().push(rec);
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

// ---------------------------------------------------------------- the harness

struct Up {
    _dir: tempfile::TempDir,
    fake: Arc<Fake>,
    socket: PathBuf,
    _stop: Vec<tokio::sync::oneshot::Sender<()>>,
}

async fn wait_for(path: &Path) {
    for _ in 0..300 {
        if path.exists() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("socket {} did not appear", path.display());
}

fn fake_server(
    socket: &Path,
    actor: &'static str,
    router: Router,
    stop: &mut Vec<tokio::sync::oneshot::Sender<()>>,
) {
    let me = rustix::process::geteuid().as_raw();
    let ids = Identities::with(0, move |u| (u == me).then_some(("entry", 0)));
    let cfg = ServerConfig {
        actor,
        boundary: "dev".into(),
        socket: socket.to_path_buf(),
        mode: 0o660,
        socket_gid: None,
        allow: Allow::Exact("entry"),
        default_deadline: Duration::from_secs(5),
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
}

/// The uid table of a test: this process is `name` in uid block `block`.
type Table = Box<dyn Fn(u32) -> Option<(&'static str, u32)> + Send + Sync>;

fn me_as(name: &'static str, block: u32) -> Table {
    let me = rustix::process::geteuid().as_raw();
    Box::new(move |u| (u == me).then_some((name, block)))
}

async fn up() -> Up {
    up_as(me_as("harness-forwarder", 0)).await
}

async fn up_as(table: Table) -> Up {
    up_front(table, Front::Identity).await
}

async fn up_front(table: Table, front: Front) -> Up {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let fake = Arc::new(Fake::default());
    let mut stop = Vec::new();
    let sockets = Sockets {
        session: d.join("session.sock"),
        exchange: d.join("exchange.sock"),
        store: d.join("store.sock"),
        audit: d.join("emit.sock"),
        reader: d.join("reader.sock"),
    };
    fake_server(
        &sockets.reader,
        "reader",
        Arc::new(FakeReader(fake.clone())).register(Router::new()),
        &mut stop,
    );
    fake_server(
        &sockets.session,
        "session",
        Arc::new(FakeSession(fake.clone())).register(Router::new()),
        &mut stop,
    );
    fake_server(
        &sockets.exchange,
        "exchange",
        Arc::new(FakeExchange(fake.clone())).register(Router::new()),
        &mut stop,
    );
    fake_server(
        &sockets.store,
        "store",
        Arc::new(FakeStore(fake.clone())).register(Router::new()),
        &mut stop,
    );
    fake_server(
        &sockets.audit,
        "transport",
        Arc::new(FakeSpool(fake.clone())).register(Router::new()),
        &mut stop,
    );
    let socket = d.join("entry.sock");
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    stop.push(tx);
    let mut cfg = config(&socket, &sockets, 0o600);
    cfg.front = front;
    tokio::spawn(entry::serve_with(
        cfg,
        async move {
            let _ = rx.await;
        },
        0,
        table,
    ));
    for s in [
        &sockets.reader,
        &sockets.session,
        &sockets.exchange,
        &sockets.store,
        &sockets.audit,
        &socket,
    ] {
        wait_for(s).await;
    }
    Up {
        _dir: dir,
        fake,
        socket,
        _stop: stop,
    }
}

fn config(socket: &Path, sockets: &Sockets, mode: u32) -> Config {
    Config {
        boundary: "dev".into(),
        front: Front::Identity,
        socket: socket.to_path_buf(),
        socket_mode: mode,
        socket_gid: None,
        sockets: sockets.clone(),
        release: "0.0.0-test".into(),
    }
}

struct Resp {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Resp {
    fn h(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }
    fn all(&self, name: &str) -> Vec<&str> {
        self.headers
            .iter()
            .filter(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
            .collect()
    }
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

/// One HTTP/1.1 request over the socket, then the whole answer.
async fn http(up: &Up, method: &str, target: &str, headers: &[(&str, &str)], body: &[u8]) -> Resp {
    let mut s = tokio::net::UnixStream::connect(&up.socket).await.unwrap();
    let mut req = format!(
        "{method} {target} HTTP/1.1\r\nHost: sluis.dev.local.test\r\nConnection: close\r\n"
    );
    for (k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    if !body.is_empty() {
        req.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    req.push_str("\r\n");
    s.write_all(req.as_bytes()).await.unwrap();
    s.write_all(body).await.unwrap();
    let mut raw = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(10), s.read_to_end(&mut raw))
        .await
        .unwrap();
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("a complete head");
    let head = String::from_utf8_lossy(&raw[..split]).into_owned();
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .unwrap()
        .split(' ')
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    let headers = lines
        .map(|l| {
            let (k, v) = l.split_once(':').unwrap();
            (k.to_ascii_lowercase(), v.trim().to_owned())
        })
        .collect();
    Resp {
        status,
        headers,
        body: raw[split + 4..].to_vec(),
    }
}

const FORM: (&str, &str) = ("Content-Type", "application/x-www-form-urlencoded");

async fn post_token(up: &Up, body: &str) -> Resp {
    http(up, "POST", "/token", &[FORM], body.as_bytes()).await
}

fn reply(status: i32, headers: &[(&str, &str)]) -> HttpReply {
    HttpReply {
        status,
        headers: headers
            .iter()
            .map(|(n, v)| Header {
                name: (*n).into(),
                value: (*v).into(),
                ..Header::default()
            })
            .collect(),
        body: b"{}".to_vec(),
        ..HttpReply::default()
    }
}

const AUTHORIZE_Q: &str = "response_type=code&client_id=sluis-cli&redirect_uri=http%3A%2F%2F127.0.0.1%3A9%2Fcb&scope=openid+groups&state=st&nonce=no&code_challenge=cc&code_challenge_method=S256";

// ---------------------------------------------------------------- the tests

#[tokio::test]
async fn authorize_is_routed_to_session_with_every_field_of_its_closed_list() {
    let up = up().await;
    *up.fake.reply.lock().unwrap() = Some(reply(
        302,
        &[
            ("Location", "https://idp.example.com/auth"),
            ("Set-Cookie", "a=1; Secure"),
            ("set-cookie", "b=2; Secure"),
        ],
    ));
    let r = http(
        &up,
        "GET",
        &format!("/authorize?{AUTHORIZE_Q}&prompt=login&max_age=0"),
        &[],
        b"",
    )
    .await;
    assert_eq!(r.status, 302);
    assert_eq!(r.h("location"), Some("https://idp.example.com/auth"));
    assert_eq!(r.all("set-cookie"), ["a=1; Secure", "b=2; Secure"]);
    let calls = up.fake.calls.lock().unwrap();
    let a = &calls.authorize[0];
    assert_eq!(
        (
            a.client_id.as_str(),
            a.scope.as_str(),
            a.code_challenge_method.as_str(),
            a.prompt.as_str(),
            a.max_age.as_str()
        ),
        ("sluis-cli", "openid groups", "S256", "login", "0")
    );
    assert_eq!(a.redirect_uri, "http://127.0.0.1:9/cb");
}

#[tokio::test]
async fn every_response_has_the_security_headers_and_a_fresh_correlation_id() {
    let up = up().await;
    let a = http(
        &up,
        "GET",
        &format!("/authorize?{AUTHORIZE_Q}"),
        &[("Sluis-Correlation-Id", "chosen-by-client")],
        b"",
    )
    .await;
    let b = http(&up, "GET", "/nope", &[], b"").await;
    for r in [&a, &b] {
        assert!(
            r.h("content-security-policy")
                .unwrap()
                .contains("frame-ancestors 'none'")
        );
        assert_eq!(r.h("x-frame-options"), Some("DENY"));
        assert_eq!(r.h("referrer-policy"), Some("no-referrer"));
        assert_eq!(r.h("x-content-type-options"), Some("nosniff"));
        assert!(
            r.h("strict-transport-security")
                .unwrap()
                .starts_with("max-age=")
        );
        assert_eq!(r.h("cache-control"), Some("no-store"));
        assert!(
            r.all("set-cookie").is_empty(),
            "entry sets no cookie of its own"
        );
    }
    let (ia, ib) = (
        a.h("sluis-correlation-id").unwrap(),
        b.h("sluis-correlation-id").unwrap(),
    );
    assert_ne!(ia, "chosen-by-client");
    assert_ne!(ia, ib);
    assert_eq!(ia.len(), 36);
}

#[tokio::test]
async fn an_unknown_or_repeated_parameter_is_refused_before_any_actor_is_called() {
    let up = up().await;
    let unknown = http(
        &up,
        "GET",
        &format!("/authorize?{AUTHORIZE_Q}&extra=1"),
        &[],
        b"",
    )
    .await;
    let dup = http(
        &up,
        "GET",
        &format!("/authorize?{AUTHORIZE_Q}&state=again"),
        &[],
        b"",
    )
    .await;
    let bad = http(&up, "GET", "/authorize?state=%zz", &[], b"").await;
    let case = http(&up, "GET", "/authorize?State=x", &[], b"").await;
    let cb = http(&up, "GET", "/callback?code=1&cookie=injected", &[], b"").await;
    for r in [&unknown, &dup, &bad, &case, &cb] {
        assert_eq!(r.status, 400);
    }
    // The same body for every refusal of a status, whatever the reason.
    assert_eq!(unknown.body, dup.body);
    assert_eq!(unknown.body, bad.body);
    let text = unknown.text();
    assert!(!text.contains("extra") && !text.contains("state"), "{text}");
    let calls = up.fake.calls.lock().unwrap();
    assert!(calls.authorize.is_empty() && calls.callback.is_empty());
}

#[tokio::test]
async fn an_error_from_an_actor_shows_nothing_of_its_reason() {
    let up = up().await;
    *up.fake.error.lock().unwrap() = Some((ErrorCode::PermissionDenied, "audience-globex-refused"));
    let denied = http(&up, "GET", &format!("/authorize?{AUTHORIZE_Q}"), &[], b"").await;
    assert_eq!(denied.status, 403);
    let text = denied.text();
    assert!(
        !text.contains("globex") && !text.contains("secret") && !text.contains("refused"),
        "{text}"
    );
    *up.fake.error.lock().unwrap() = Some((ErrorCode::Unavailable, "x"));
    assert_eq!(
        http(&up, "GET", &format!("/authorize?{AUTHORIZE_Q}"), &[], b"")
            .await
            .status,
        503
    );
    *up.fake.error.lock().unwrap() = Some((ErrorCode::Internal, "x"));
    let internal = http(&up, "GET", &format!("/authorize?{AUTHORIZE_Q}"), &[], b"").await;
    assert_eq!(internal.status, 500);
    // A refusal of entry's own and one from inside have the same body for the same status.
    let own = http(&up, "GET", "/authorize?a=1", &[], b"").await;
    *up.fake.error.lock().unwrap() = Some((ErrorCode::InvalidArgument, "bound"));
    let inner = http(&up, "GET", &format!("/authorize?{AUTHORIZE_Q}"), &[], b"").await;
    assert_eq!((own.status, inner.status), (400, 400));
    assert_eq!(own.body, inner.body);
}

#[tokio::test]
async fn a_reply_entry_cannot_relay_exactly_is_a_server_error() {
    let up = up().await;
    for bad in [
        reply(302, &[("X-Internal", "leak")]),
        reply(302, &[("Content-Security-Policy", "default-src *")]),
        reply(99, &[]),
        reply(700, &[]),
        reply(200, &[("Content-Type", "a"), ("content-type", "b")]),
        reply(200, &[("Location", "bad\r\nvalue")]),
    ] {
        *up.fake.reply.lock().unwrap() = Some(bad);
        let r = http(&up, "GET", &format!("/authorize?{AUTHORIZE_Q}"), &[], b"").await;
        assert_eq!(r.status, 500);
        assert!(!r.text().contains("leak"));
        assert!(r.h("x-internal").is_none());
    }
}

#[tokio::test]
async fn methods_and_paths_are_closed() {
    let up = up().await;
    let r = http(&up, "POST", "/authorize", &[FORM], b"a=1").await;
    assert_eq!((r.status, r.h("allow")), (405, Some("GET")));
    let r = http(&up, "GET", "/token", &[], b"").await;
    assert_eq!((r.status, r.h("allow")), (405, Some("POST")));
    assert_eq!(http(&up, "DELETE", "/jwks", &[], b"").await.status, 405);
    assert_eq!(http(&up, "OPTIONS", "/token", &[], b"").await.status, 405);
    for path in [
        "/",
        "/jwks/",
        "/JWKS",
        "/authorize/",
        "//authorize",
        "/sluis.session.v2alpha1.SessionService/Token",
        "/sluis.store.v2alpha1.StoreService/Get",
        "/userinfo",
    ] {
        assert_eq!(http(&up, "GET", path, &[], b"").await.status, 404, "{path}");
    }
    let c = up.fake.calls.lock().unwrap();
    assert!(c.authorize.is_empty() && c.token.is_empty());
}

#[tokio::test]
async fn token_is_dispatched_by_grant_type() {
    let up = up().await;
    let r = post_token(&up, "grant_type=authorization_code&code=c1&redirect_uri=http%3A%2F%2F127.0.0.1%3A9%2Fcb&code_verifier=v&client_id=sluis-cli").await;
    assert_eq!(r.status, 200);
    let r = post_token(&up, "grant_type=refresh_token&refresh_token=r1&scope=openid&client_id=sluis-cli&client_secret=s").await;
    assert_eq!(r.status, 200);
    let ex = "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange&subject_token=jwt&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token&audience=example-app&client_id=sluis-cli";
    assert_eq!(post_token(&up, ex).await.status, 200);
    let c = up.fake.calls.lock().unwrap();
    assert_eq!(c.token.len(), 2);
    assert_eq!(
        (c.token[0].code.as_str(), c.token[0].code_verifier.as_str()),
        ("c1", "v")
    );
    assert_eq!(
        (
            c.token[1].refresh_token.as_str(),
            c.token[1].client_secret.as_str()
        ),
        ("r1", "s")
    );
    assert_eq!(c.exchange.len(), 1);
    assert_eq!(
        (
            c.exchange[0].audience.as_str(),
            c.exchange[0].subject_token.as_str()
        ),
        ("example-app", "jwt")
    );
}

#[tokio::test]
async fn token_refuses_what_its_grant_does_not_list() {
    let up = up().await;
    for body in [
        "",
        "grant_type=password&username=a&password=b",
        "grant_type=",
        "grant_type=authorization_code&grant_type=refresh_token",
        "grant_type=authorization_code&code=c&unknown=1",
        // a field of another grant
        "grant_type=authorization_code&code=c&refresh_token=r",
        "grant_type=refresh_token&refresh_token=r&code=c",
        "grant_type=refresh_token&refresh_token=r&audience=a",
        "code=c",
    ] {
        let r = post_token(&up, body).await;
        assert_eq!(r.status, 400, "{body}");
        assert!(!r.text().contains("password"));
    }
    // An unserved grant is `unsupported_grant_type`; a missing one is `invalid_request`.
    for body in [
        "grant_type=password&username=a",
        "grant_type=",
        "grant_type=authorization_codes",
    ] {
        let r = post_token(&up, body).await;
        assert_eq!(r.status, 400);
        assert!(r.text().contains("\"unsupported_grant_type\""), "{body}");
    }
    let missing = post_token(&up, "code=c").await;
    assert!(missing.text().contains("\"invalid_request\""));
    let ex_with_code = "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange&subject_token=t&code=c";
    assert_eq!(post_token(&up, ex_with_code).await.status, 400);
    // the query string takes no parameter on the token endpoint
    assert_eq!(
        http(
            &up,
            "POST",
            "/token?grant_type=refresh_token",
            &[FORM],
            b"grant_type=refresh_token&refresh_token=r"
        )
        .await
        .status,
        400
    );
    let c = up.fake.calls.lock().unwrap();
    assert!(c.token.is_empty() && c.exchange.is_empty());
}

#[tokio::test]
async fn token_checks_the_media_type_and_the_size() {
    let up = up().await;
    let body = "grant_type=refresh_token&refresh_token=r";
    assert_eq!(
        http(
            &up,
            "POST",
            "/token",
            &[("Content-Type", "application/json")],
            body.as_bytes()
        )
        .await
        .status,
        415
    );
    assert_eq!(
        http(&up, "POST", "/token", &[], body.as_bytes())
            .await
            .status,
        415
    );
    assert_eq!(
        http(
            &up,
            "POST",
            "/token",
            &[(
                "Content-Type",
                "application/x-www-form-urlencoded; charset=latin1"
            )],
            body.as_bytes()
        )
        .await
        .status,
        415
    );
    assert_eq!(
        http(
            &up,
            "POST",
            "/token",
            &[(
                "content-type",
                "Application/X-WWW-Form-Urlencoded; charset=UTF-8"
            )],
            body.as_bytes()
        )
        .await
        .status,
        200
    );
    let big = format!(
        "grant_type=refresh_token&refresh_token={}",
        "a".repeat(40_000)
    );
    assert_eq!(post_token(&up, &big).await.status, 413);
    // a value at the per-value bound is read
    let many = format!("grant_type=refresh_token&scope={}", "b".repeat(8192));
    assert_eq!(post_token(&up, &many).await.status, 200);
    assert_eq!(up.fake.calls.lock().unwrap().token.len(), 2);
}

#[tokio::test]
async fn client_authentication_by_header_reaches_session_and_never_exchange() {
    let up = up().await;
    let r = http(
        &up,
        "POST",
        "/token",
        &[FORM, ("Authorization", "Basic Zm9vOmJhcg==")],
        b"grant_type=authorization_code&code=c",
    )
    .await;
    assert_eq!(r.status, 200);
    assert_eq!(
        up.fake.calls.lock().unwrap().token[0].authorization,
        "Basic Zm9vOmJhcg=="
    );
    let ex = "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange&subject_token=t";
    let r = http(
        &up,
        "POST",
        "/token",
        &[FORM, ("Authorization", "Basic Zm9vOmJhcg==")],
        ex.as_bytes(),
    )
    .await;
    assert_eq!(r.status, 401);
    assert_eq!(r.h("www-authenticate"), Some("Basic realm=\"sluis\""));
    assert!(r.text().contains("invalid_client"));
    assert!(up.fake.calls.lock().unwrap().exchange.is_empty());
}

#[tokio::test]
async fn callback_passes_the_signin_cookie_and_only_that_cookie() {
    let up = up().await;
    let r = http(
        &up,
        "GET",
        "/callback?code=abc&state=st&iss=https%3A%2F%2Fidp.example.com",
        &[("Cookie", "other=1; __Host-sluis_signin=cv123; more=2")],
        b"",
    )
    .await;
    assert_eq!(r.status, 200);
    let r = http(
        &up,
        "GET",
        "/callback?error=access_denied&state=st",
        &[],
        b"",
    )
    .await;
    assert_eq!(r.status, 200);
    let dup = http(
        &up,
        "GET",
        "/callback?code=abc",
        &[("Cookie", "__Host-sluis_signin=a; __Host-sluis_signin=b")],
        b"",
    )
    .await;
    assert_eq!(dup.status, 400);
    let c = up.fake.calls.lock().unwrap();
    assert_eq!(c.callback.len(), 2);
    assert_eq!(
        (
            c.callback[0].cookie.as_str(),
            c.callback[0].code.as_str(),
            c.callback[0].iss.as_str()
        ),
        ("cv123", "abc", "https://idp.example.com")
    );
    assert_eq!(
        (c.callback[1].cookie.as_str(), c.callback[1].error.as_str()),
        ("", "access_denied")
    );
}

#[tokio::test]
async fn discovery_and_the_key_set_are_built_from_the_store_and_cacheable() {
    let up = up().await;
    let d = http(&up, "GET", "/.well-known/openid-configuration", &[], b"").await;
    assert_eq!(d.status, 200);
    assert_eq!(d.h("cache-control"), Some("public, max-age=300"));
    assert_eq!(d.h("content-type"), Some("application/json"));
    let doc: Value = serde_json::from_slice(&d.body).unwrap();
    assert_eq!(doc["issuer"], ISSUER);
    assert_eq!(doc["jwks_uri"], format!("{ISSUER}/jwks"));
    assert_eq!(
        doc["token_endpoint_auth_methods_supported"],
        serde_json::json!(["none"])
    );
    let k = http(&up, "GET", "/jwks", &[], b"").await;
    assert_eq!(k.status, 200);
    assert_eq!(k.h("cache-control"), Some("public, max-age=300"));
    let set: Value = serde_json::from_slice(&k.body).unwrap();
    assert_eq!(
        set["keys"].as_array().unwrap().len(),
        1,
        "a revoked key is not published"
    );
    assert_eq!(set["keys"][0]["kid"], "kid-1");
    assert_eq!(set["keys"][0]["crv"], "P-384");
    assert_eq!(set["keys"][0]["alg"], "ES384");
    // HEAD is answered like GET without a body; a parameter is refused; a repeat reads the store once.
    let h = http(&up, "HEAD", "/jwks", &[], b"").await;
    assert_eq!((h.status, h.body.len()), (200, 0));
    assert_eq!(http(&up, "GET", "/jwks?x=1", &[], b"").await.status, 400);
    assert_eq!(
        *up.fake.store_gets.lock().unwrap(),
        2,
        "one Boundary and one SigningRing read"
    );
}

#[tokio::test]
async fn without_the_store_the_documents_fail_closed() {
    let up = up().await;
    *up.fake.store_fails.lock().unwrap() = true;
    for p in ["/jwks", "/.well-known/openid-configuration"] {
        let r = http(&up, "GET", p, &[], b"").await;
        assert_eq!(r.status, 503);
        assert!(r.h("cache-control") != Some("public, max-age=300"));
        assert!(!r.text().contains("engine"));
    }
}

#[tokio::test]
async fn every_request_is_audited_without_repeating_what_the_caller_sent() {
    let up = up().await;
    let secret = "s3cr3t-value-123";
    let ok = post_token(
        &up,
        &format!("grant_type=refresh_token&refresh_token={secret}"),
    )
    .await;
    let refused = http(&up, "GET", &format!("/authorize?{secret}=1"), &[], b"").await;
    let missing = http(&up, "GET", "/no/such/path", &[], b"").await;
    let recs = up.fake.emitted.lock().unwrap().clone();
    assert_eq!(recs.len(), 3, "{recs:?}");
    let find = |code: &str| {
        recs.iter()
            .find(|r| r["metadata"]["event_code"] == code)
            .unwrap_or_else(|| panic!("{code}"))
    };
    let t = find("entry.token");
    assert_eq!(
        t["metadata"]["correlation_uid"].as_str(),
        ok.h("sluis-correlation-id")
    );
    assert_eq!(t["unmapped"]["sluis"]["grant_type"], "refresh_token");
    assert_eq!(t["unmapped"]["sluis"]["http_status"], 200);
    assert_eq!(t["class_uid"], 6003);
    let a = find("entry.authorize");
    assert_eq!(a["status_code"], "unknown_parameter");
    assert_eq!(a["status_id"], 2);
    assert_eq!(
        a["metadata"]["correlation_uid"].as_str(),
        refused.h("sluis-correlation-id")
    );
    let u = find("entry.unrouted");
    assert_eq!(u["status_code"], "route");
    assert_eq!(
        u["metadata"]["correlation_uid"].as_str(),
        missing.h("sluis-correlation-id")
    );
    let all = serde_json::to_string(&recs).unwrap();
    assert!(
        !all.contains(secret) && !all.contains("/no/such/path"),
        "{all}"
    );
}

#[tokio::test]
async fn the_socket_has_the_asked_for_mode() {
    use std::os::unix::fs::PermissionsExt;
    let up = up().await;
    let mode = std::fs::metadata(&up.socket).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
}

#[tokio::test]
async fn only_the_forwarder_of_this_boundary_is_served() {
    for (name, block) in [("session", 0), ("entry", 0), ("harness-forwarder", 1)] {
        let up = up_as(me_as(name, block)).await;
        let mut s = tokio::net::UnixStream::connect(&up.socket).await.unwrap();
        let _ = s
            .write_all(b"GET /jwks HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
            .await;
        let mut raw = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut raw)).await;
        assert!(raw.is_empty(), "{name}@{block} got an answer");
        // The refusal is audited, with no value of the connection.
        for _ in 0..200 {
            if !up.fake.emitted.lock().unwrap().is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let recs = up.fake.emitted.lock().unwrap().clone();
        assert_eq!(recs.len(), 1, "{name}@{block}");
        assert_eq!(recs[0]["metadata"]["event_code"], "entry.connection");
        assert_eq!(recs[0]["status_code"], "peer");
        assert_eq!(recs[0]["status_id"], 2);
        assert_eq!(
            *up.fake.store_gets.lock().unwrap(),
            0,
            "no actor was called"
        );
    }
    // The right peer is served.
    let up = up().await;
    assert_eq!(http(&up, "GET", "/jwks", &[], b"").await.status, 200);
}

#[tokio::test]
async fn a_socket_mode_that_gives_anything_to_others_is_refused_at_start() {
    let dir = tempfile::tempdir().unwrap();
    let sockets = Sockets::under(dir.path(), "dev");
    for mode in [0o666, 0o662, 0o601, 0o777, 0o4660, 0o1660] {
        let socket = dir.path().join(format!("e{mode:o}.sock"));
        let err = entry::serve_with(
            config(&socket, &sockets, mode),
            std::future::pending(),
            0,
            me_as("harness-forwarder", 0),
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("socket mode"), "{mode:o}: {err}");
        assert!(!socket.exists(), "{mode:o}");
    }
    let mut cfg = config(&dir.path().join("g0.sock"), &sockets, 0o660);
    cfg.socket_gid = Some(0);
    let err = entry::serve_with(
        cfg,
        std::future::pending(),
        0,
        me_as("harness-forwarder", 0),
    )
    .await
    .unwrap_err();
    assert!(err.to_string().contains("group 0"), "{err}");
}

#[tokio::test]
async fn a_form_post_page_gets_the_relaxed_policy_and_nothing_else_does() {
    let up = up().await;
    let page = |ct: &str| reply(200, &[("Content-Type", ct)]);
    *up.fake.reply.lock().unwrap() = Some(page("text/html; charset=utf-8"));
    let q = format!("/authorize?{AUTHORIZE_Q}&response_mode=form_post");
    let r = http(&up, "GET", &q, &[], b"").await;
    let csp = r.h("content-security-policy").unwrap();
    assert!(
        csp.contains("script-src 'unsafe-inline'") && !csp.contains("form-action"),
        "{csp}"
    );
    assert!(csp.contains("frame-ancestors 'none'"));
    let r = http(&up, "GET", "/callback?code=c", &[], b"").await;
    assert!(
        !r.h("content-security-policy")
            .unwrap()
            .contains("form-action")
    );
    // JSON on the same route, an error page, and HTML on the token route keep the strict policy.
    *up.fake.reply.lock().unwrap() = Some(page("application/json"));
    let r = http(&up, "GET", &q, &[], b"").await;
    assert!(
        r.h("content-security-policy")
            .unwrap()
            .contains("form-action 'self'")
    );
    *up.fake.reply.lock().unwrap() = Some(reply(400, &[("Content-Type", "text/html")]));
    let r = http(&up, "GET", &q, &[], b"").await;
    assert!(
        r.h("content-security-policy")
            .unwrap()
            .contains("form-action 'self'")
    );
    *up.fake.reply.lock().unwrap() = Some(page("text/html"));
    let r = post_token(&up, "grant_type=refresh_token&refresh_token=r").await;
    assert!(
        r.h("content-security-policy")
            .unwrap()
            .contains("form-action 'self'")
    );
}

// ---------------------------------------------------------------- the audit front

const JSON: (&str, &str) = ("Content-Type", "application/json");
const SEARCH: &str = "/sluis.reader.v2alpha1.ReaderService/Search";

async fn audit_front() -> Up {
    up_front(me_as("harness-forwarder", 0), Front::Audit).await
}

#[tokio::test]
async fn the_audit_front_routes_search_to_the_reader_and_nothing_else() {
    let up = audit_front().await;
    let body =
        br#"{"tenants":["acme"],"action":"signer.sign","from_ms":"1700000000000","page_size":5}"#;
    let r = http(&up, "POST", SEARCH, &[JSON], body).await;
    assert_eq!(r.status, 200, "{}", r.text());
    assert_eq!(r.h("content-type"), Some("application/json"));
    assert_eq!(r.h("cache-control"), Some("no-store"));
    let v: Value = serde_json::from_slice(&r.body).unwrap();
    assert_eq!(v["hits"][0]["tenant"], "acme");
    assert_eq!(v["hits"][0]["seq"], "7");
    assert_eq!(v["hits"][0]["timeMs"], "1700000000000");
    assert_eq!(v["nextPageToken"], "CQk=");
    // The reader got the typed request, with the 64-bit integer read from its string.
    let seen = up.fake.calls.lock().unwrap().search.clone();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].tenants, ["acme"]);
    assert_eq!(
        (seen[0].action.as_str(), seen[0].from_ms, seen[0].page_size),
        ("signer.sign", 1_700_000_000_000, 5)
    );
    // The call is audited as the route `search`.
    let emitted = up.fake.emitted.lock().unwrap().clone();
    assert!(
        emitted
            .iter()
            .any(|e| e["metadata"]["event_code"] == "entry.search")
    );
    // The identity front's routes do not exist here, and this route does not exist there.
    for path in [
        "/authorize",
        "/token",
        "/jwks",
        "/.well-known/openid-configuration",
        "/search",
    ] {
        assert_eq!(http(&up, "GET", path, &[], b"").await.status, 404, "{path}");
    }
    let identity = up_as(me_as("harness-forwarder", 0)).await;
    assert_eq!(
        http(&identity, "POST", SEARCH, &[JSON], body).await.status,
        404
    );
    assert!(identity.fake.calls.lock().unwrap().search.is_empty());
}

#[tokio::test]
async fn the_audit_front_refuses_what_the_contract_does_not_have() {
    let up = audit_front().await;
    type Case<'a> = (&'a str, &'a str, &'a [(&'a str, &'a str)], &'a [u8], u16);
    let cases: [Case; 8] = [
        ("GET", SEARCH, &[], b"", 405),
        ("POST", SEARCH, &[FORM], b"tenants=acme", 415),
        ("POST", SEARCH, &[JSON], br#"{"tenant":"acme"}"#, 400),
        ("POST", SEARCH, &[JSON], br#"{"tenants":"acme"}"#, 400),
        ("POST", SEARCH, &[JSON], b"[]", 400),
        ("POST", SEARCH, &[JSON], b"{", 400),
        (
            "POST",
            "/sluis.reader.v2alpha1.ReaderService/Search?x=1",
            &[JSON],
            b"{}",
            400,
        ),
        (
            "POST",
            "/sluis.reader.v2alpha1.ReaderService/Export",
            &[JSON],
            b"{}",
            404,
        ),
    ];
    for (m, path, h, body, want) in cases {
        let r = http(&up, m, path, h, body).await;
        assert_eq!(r.status, want, "{m} {path}: {}", r.text());
    }
    assert!(
        up.fake.calls.lock().unwrap().search.is_empty(),
        "a refused request reached the reader"
    );
    let big = vec![b' '; 20_000];
    assert_eq!(http(&up, "POST", SEARCH, &[JSON], &big).await.status, 413);
}

#[tokio::test]
async fn an_error_from_the_reader_shows_nothing_of_its_reason() {
    let up = audit_front().await;
    *up.fake.error.lock().unwrap() = Some((ErrorCode::PermissionDenied, "grant"));
    let r = http(&up, "POST", SEARCH, &[JSON], br#"{"tenants":["acme"]}"#).await;
    assert_eq!(r.status, 403);
    assert!(
        !r.text().contains("grant") && !r.text().contains("secret"),
        "{}",
        r.text()
    );
    *up.fake.error.lock().unwrap() = Some((ErrorCode::Unavailable, "engine"));
    assert_eq!(
        http(&up, "POST", SEARCH, &[JSON], br#"{"tenants":["acme"]}"#)
            .await
            .status,
        503
    );
}
