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
use sluis_proto::sluis::key::v2alpha1::KeyRevocation;
use sluis_proto::sluis::port::transport::v2alpha1::{
    AckRequest, AckResponse, EmitRequest, EmitResponse, ReceiveRequest, ReceiveResponse,
    TransportService, TransportServiceExt,
};
use sluis_proto::sluis::reader::v2alpha1::{
    Hit, ReaderService, ReaderServiceExt, SearchRequest, SearchResponse,
};
use sluis_proto::sluis::session::v2alpha1::{
    AuthorizeRequest, CallbackRequest, RevokeRequest, SessionService, SessionServiceExt,
    TokenRequest, UserInfoRequest,
};
use sluis_proto::sluis::signer::v2alpha1::{SigningKey, SigningRing};
use sluis_proto::sluis::store::v2alpha1::{
    GetRequest, GetResponse, GetSignedConfigRequest, GetSignedConfigResponse, Item, ListRequest,
    ListResponse, StoreService, StoreServiceExt, WatchRequest, WatchResponse, WriteRequest,
    WriteResponse,
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
    userinfo: Vec<UserInfoRequest>,
    revoke: Vec<RevokeRequest>,
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
    /// The kids `KeyRevocation` lists, and whether reading the kind fails.
    revoked: Mutex<Vec<String>>,
    revocations_fail: Mutex<bool>,
    store_gets: Mutex<usize>,
    /// A key that the ring lists in addition, once a test has written it.
    extra_kid: Mutex<Option<String>>,
    /// An RS256 key of the ring: its kid and its state. `None` is a ring with none.
    rsa: Mutex<Option<(String, String)>>,
    /// The issuer of the `Boundary` that store@ holds; `None` is [`ISSUER`].
    issuer: Mutex<Option<String>>,
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
    async fn user_info(
        &self,
        _: RequestContext,
        r: ServiceRequest<'_, UserInfoRequest>,
    ) -> ServiceResult<HttpReply> {
        self.0
            .calls
            .lock()
            .unwrap()
            .userinfo
            .push(r.to_owned_message());
        self.0.answer()
    }
    async fn revoke(
        &self,
        _: RequestContext,
        r: ServiceRequest<'_, RevokeRequest>,
    ) -> ServiceResult<HttpReply> {
        self.0
            .calls
            .lock()
            .unwrap()
            .revoke
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
/// The SubjectPublicKeyInfo of an RSA-2048 key with the exponent 65537 whose modulus is 256 bytes of `fill` (top bit set).
fn rsa_spki(fill: u8) -> Vec<u8> {
    let mut v = vec![
        0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01,
        0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00, 0x30, 0x82, 0x01, 0x0a, 0x02, 0x82,
        0x01, 0x01, 0x00,
    ];
    v.extend(std::iter::repeat_n(fill, 256));
    v.extend([0x02, 0x03, 0x01, 0x00, 0x01]);
    v
}

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
                issuer: self
                    .0
                    .issuer
                    .lock()
                    .unwrap()
                    .clone()
                    .unwrap_or_else(|| ISSUER.into()),
                ..Boundary::default()
            }
            .encode_to_vec(),
            "signing-ring" => {
                let mut keys = vec![
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
                ];
                if let Some(kid) = self.0.extra_kid.lock().unwrap().clone() {
                    keys.push(SigningKey {
                        key_id: kid,
                        algorithm: "ES384".into(),
                        state: "active".into(),
                        spki_der: spki(),
                        ..SigningKey::default()
                    });
                }
                if let Some((kid, state)) = self.0.rsa.lock().unwrap().clone() {
                    keys.push(SigningKey {
                        key_id: kid,
                        algorithm: "RS256".into(),
                        state,
                        spki_der: rsa_spki(0xC3),
                        // A chain in the ring is for the ES384 key: the RSA entry must not carry it.
                        x5c: vec![vec![1, 2, 3]],
                        ..SigningKey::default()
                    });
                }
                SigningRing {
                    keys,
                    ..SigningRing::default()
                }
                .encode_to_vec()
            }
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
        r: ServiceRequest<'_, ListRequest>,
    ) -> ServiceResult<ListResponse> {
        if r.kind != "key-revocation" {
            return Err(refusal(ErrorCode::Unimplemented, "unsupported", ""));
        }
        if *self.0.store_fails.lock().unwrap() || *self.0.revocations_fail.lock().unwrap() {
            return Err(refusal(ErrorCode::Unavailable, "engine", ""));
        }
        let items = self
            .0
            .revoked
            .lock()
            .unwrap()
            .iter()
            .enumerate()
            .map(|(i, kid)| Item {
                address: Some(Address {
                    kind: "key-revocation".into(),
                    id: format!("kid/{i}"),
                    ..Address::default()
                })
                .into(),
                version: 1,
                value: KeyRevocation {
                    target_kind: "kid".into(),
                    target: kid.clone(),
                    reason_code: "compromise".into(),
                    ..KeyRevocation::default()
                }
                .encode_to_vec(),
                ..Item::default()
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
        Err(refusal(ErrorCode::Unimplemented, "unsupported", ""))
    }
    async fn get_signed_config(
        &self,
        _: RequestContext,
        _: ServiceRequest<'_, GetSignedConfigRequest>,
    ) -> ServiceResult<GetSignedConfigResponse> {
        Err(connectrpc::ConnectError::new(
            connectrpc::error::ErrorCode::Unimplemented,
            "not served by this fake",
        ))
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

/// An `id_token_hint` is a parameter of `/authorize` and reaches `session` as it was sent; a repeat is refused. What it means
/// is `session`'s (its tests hold the sign-in to the hint's person).
#[tokio::test]
async fn id_token_hint_reaches_session_and_is_not_repeated() {
    let up = up().await;
    let hint = "eyJhbGciOiJFUzM4NCJ9.eyJzdWIiOiJzIn0.c2ln";
    let q = http(
        &up,
        "GET",
        &format!("/authorize?{AUTHORIZE_Q}&id_token_hint={hint}"),
        &[],
        b"",
    )
    .await;
    assert_eq!(q.status, 200);
    assert_eq!(
        up.fake.calls.lock().unwrap().authorize[0].id_token_hint,
        hint
    );
    let r = http(
        &up,
        "GET",
        &format!("/authorize?{AUTHORIZE_Q}&id_token_hint={hint}&id_token_hint={hint}"),
        &[],
        b"",
    )
    .await;
    assert_eq!(r.status, 400);
    assert_eq!(up.fake.calls.lock().unwrap().authorize.len(), 1);
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

/// Every kind of response `entry` sends has the headers of a page, once each and with their values: a restrictive content
/// security policy (nothing inline but the form_post page's one script, by its hash; framing, `base-uri` and `object-src`
/// refused), HSTS of a year with `includeSubDomains`, no referrer, no sniffing and no framing. The kinds are an error page
/// and a redirect from `session`, the form_post page, a token and its refusal, the two public documents, the health probe,
/// every refusal of `entry` itself and of an actor behind it, a reply `entry` cannot relay (an actor cannot set a security
/// header: it is a 500 that has them), and the audit front. A header an actor asks for does not change one.
///
/// verifies: REQ-SEC-004
#[tokio::test]
async fn every_kind_of_response_has_the_headers_of_a_page() {
    let up = up().await;
    let authorize = format!("/authorize?{AUTHORIZE_Q}");
    let mut seen: Vec<(String, Resp)> = Vec::new();
    let mut take = |what: &str, r: Resp| seen.push((what.to_owned(), r));

    let set = |r: Option<HttpReply>| *up.fake.reply.lock().unwrap() = r;
    set(Some(reply(
        400,
        &[("Content-Type", "text/html; charset=utf-8")],
    )));
    take(
        "an error page",
        http(&up, "GET", &authorize, &[], b"").await,
    );
    set(Some(reply(
        302,
        &[("Location", "http://127.0.0.1:9/cb?code=c")],
    )));
    take("a redirect", http(&up, "GET", &authorize, &[], b"").await);
    set(Some(form_post_page("https://app.example.test")));
    take(
        "a form_post page",
        http(&up, "GET", &authorize, &[], b"").await,
    );
    set(Some(reply(200, &[("Content-Type", "application/json")])));
    take(
        "a token",
        post_token(&up, "grant_type=refresh_token&refresh_token=r").await,
    );
    set(Some(reply(
        401,
        &[
            ("Content-Type", "application/json"),
            ("WWW-Authenticate", "Basic realm=\"sluis\""),
        ],
    )));
    take(
        "a token refusal",
        post_token(&up, "grant_type=refresh_token&refresh_token=r").await,
    );
    // An actor that asks for a header of the page, or for one that is not on the list, gets a 500 that carries the page's.
    set(Some(reply(
        200,
        &[("Content-Security-Policy", "default-src *")],
    )));
    take(
        "a hostile reply",
        http(&up, "GET", &authorize, &[], b"").await,
    );
    set(None);
    for (what, code) in [
        ("an actor's refusal", ErrorCode::PermissionDenied),
        ("an actor that is unavailable", ErrorCode::Unavailable),
        ("an actor that is late", ErrorCode::DeadlineExceeded),
        ("an actor that fails", ErrorCode::Internal),
    ] {
        *up.fake.error.lock().unwrap() = Some((code, "x"));
        take(what, http(&up, "GET", &authorize, &[], b"").await);
    }
    *up.fake.error.lock().unwrap() = None;
    for (what, method, target, headers, body) in [
        (
            "discovery",
            "GET",
            "/.well-known/openid-configuration",
            vec![],
            &b""[..],
        ),
        ("the key set", "GET", "/jwks", vec![], &b""[..]),
        (
            "the OAuth discovery name",
            "GET",
            "/.well-known/oauth-authorization-server",
            vec![],
            &b""[..],
        ),
        ("a health probe", "GET", "/healthz", vec![], &b""[..]),
        ("a head request", "HEAD", "/jwks", vec![], &b""[..]),
        (
            "an unknown parameter",
            "GET",
            "/authorize?a=1",
            vec![],
            &b""[..],
        ),
        ("no route", "GET", "/nope", vec![], &b""[..]),
        ("a wrong method", "DELETE", "/jwks", vec![], &b""[..]),
        (
            "a wrong media type",
            "POST",
            "/token",
            vec![("Content-Type", "text/plain")],
            &b"a"[..],
        ),
    ] {
        take(what, http(&up, method, target, &headers, body).await);
    }
    *up.fake.store_fails.lock().unwrap() = true;
    take(
        "a store that fails",
        http(&up, "GET", "/jwks", &[], b"").await,
    );
    let audit = audit_front().await;
    take(
        "an audit search",
        http(
            &audit,
            "POST",
            SEARCH,
            &[JSON],
            br#"{"tenants":["acme"],"page_size":5}"#,
        )
        .await,
    );
    take(
        "an audit refusal",
        http(&audit, "GET", "/authorize", &[], b"").await,
    );

    assert!(seen.len() >= 22, "{}", seen.len());
    let mut statuses: Vec<u16> = seen.iter().map(|(_, r)| r.status).collect();
    statuses.sort_unstable();
    statuses.dedup();
    for want in [200, 302, 400, 401, 403, 404, 405, 415, 500, 503, 504] {
        assert!(
            statuses.contains(&want),
            "no response of status {want}: {statuses:?}"
        );
    }
    for (what, r) in &seen {
        let one = |name: &str| {
            let v = r.all(name);
            assert_eq!(v.len(), 1, "{what}: {name} is sent {} times", v.len());
            v[0].to_owned()
        };
        let csp = one("content-security-policy");
        assert!(csp.contains("frame-ancestors 'none'"), "{what}: {csp}");
        assert!(csp.contains("base-uri 'none'"), "{what}: {csp}");
        assert!(
            csp.contains("object-src 'none'") || csp.contains("default-src 'none'"),
            "{what}: {csp}"
        );
        assert!(
            csp.starts_with("default-src 'self'") || csp.starts_with("default-src 'none'"),
            "{what}: {csp}"
        );
        for weak in ["unsafe-eval", "script-src 'unsafe-inline'", " *", "http:"] {
            assert!(!csp.contains(weak), "{what}: {csp} holds {weak}");
        }
        // The only inline script a policy allows is a hash: the form_post page's.
        if let Some(at) = csp.find("script-src") {
            assert!(
                csp[at..].starts_with("script-src 'sha256-"),
                "{what}: {csp}"
            );
            assert_eq!(what, "a form_post page", "{what} may not carry a script");
        }
        let hsts = one("strict-transport-security");
        assert_eq!(hsts, "max-age=31536000; includeSubDomains", "{what}");
        assert_eq!(one("referrer-policy"), "no-referrer", "{what}");
        assert_eq!(one("x-content-type-options"), "nosniff", "{what}");
        assert_eq!(one("x-frame-options"), "DENY", "{what}");
        assert!(!one("cache-control").is_empty(), "{what}");
        assert!(r.all("access-control-allow-origin").len() <= 1, "{what}");
    }
}

/// A repeated, badly escaped or oversized parameter is refused before any actor is called, whether its name is one of
/// the list or not (`Params::read` is the same for every name). A name off the list is not one of these: it is ignored
/// (`an_unknown_parameter_is_ignored_and_counted`).
///
/// verifies: REQ-AUTHN-037
#[tokio::test]
async fn a_repeated_parameter_is_refused_before_any_actor_is_called() {
    let up = up().await;
    let dup = http(
        &up,
        "GET",
        &format!("/authorize?{AUTHORIZE_Q}&state=again"),
        &[],
        b"",
    )
    .await;
    // The repeat of a name that the route ignores is refused as well, even when the two spellings differ.
    let dup_ignored = http(
        &up,
        "GET",
        &format!("/authorize?{AUTHORIZE_Q}&extra=1&%65xtra=2"),
        &[],
        b"",
    )
    .await;
    let bad = http(&up, "GET", "/authorize?state=%zz", &[], b"").await;
    let bad_ignored = http(
        &up,
        "GET",
        &format!("/authorize?{AUTHORIZE_Q}&extra=%zz"),
        &[],
        b"",
    )
    .await;
    let control = http(
        &up,
        "GET",
        &format!("/authorize?{AUTHORIZE_Q}&extra=a%0ab"),
        &[],
        b"",
    )
    .await;
    let long = http(
        &up,
        "GET",
        &format!("/authorize?{AUTHORIZE_Q}&extra={}", "a".repeat(9000)),
        &[],
        b"",
    )
    .await;
    for r in [&dup, &dup_ignored, &bad, &bad_ignored, &control, &long] {
        assert_eq!(r.status, 400);
    }
    // The same body for every refusal of a status, whatever the reason.
    assert_eq!(dup.body, bad.body);
    assert_eq!(dup.body, dup_ignored.body);
    let text = dup_ignored.text();
    assert!(!text.contains("extra") && !text.contains("state"), "{text}");
    let calls = up.fake.calls.lock().unwrap();
    assert!(calls.authorize.is_empty() && calls.callback.is_empty());
    drop(calls);
    let reasons: Vec<String> = up
        .fake
        .emitted
        .lock()
        .unwrap()
        .iter()
        .map(|r| r["status_code"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(
        reasons,
        [
            "duplicate_parameter",
            "duplicate_parameter",
            "parameter_syntax",
            "parameter_syntax",
            "parameter_syntax",
            "parameter_size"
        ]
    );
}

/// The OpenID Foundation's module `oidcc-ensure-request-with-unknown-parameter-succeeds` adds `extra=foobar` to the
/// request and expects the sign-in to complete (RFC 6749 section 3.1). `oidcc-claims-essential` adds a `claims` JSON
/// object. Both succeed, in a query and in a form, session gets the request without them, and the audit record holds
/// their number and no name or value.
///
/// verifies: REQ-AUTHN-012, REQ-AUTHN-011
#[tokio::test]
async fn an_unknown_parameter_is_ignored_and_counted() {
    let up = up().await;
    let claims = "claims=%7B%22userinfo%22%3A%7B%22name%22%3A%7B%22essential%22%3Atrue%7D%7D%7D";
    let name = "x-unlikely-name-7f3a9c";
    let value = "unlikely-value-5be1d2";
    let extra = format!("extra=foobar&{claims}&display=page&{name}={value}");
    let plain = http(&up, "GET", &format!("/authorize?{AUTHORIZE_Q}"), &[], b"").await;
    let query = http(
        &up,
        "GET",
        &format!("/authorize?{AUTHORIZE_Q}&{extra}"),
        &[],
        b"",
    )
    .await;
    let form = http(
        &up,
        "POST",
        "/authorize",
        &[FORM],
        format!("{AUTHORIZE_Q}&{extra}").as_bytes(),
    )
    .await;
    assert_eq!((plain.status, query.status, form.status), (200, 200, 200));
    {
        let c = up.fake.calls.lock().unwrap();
        assert_eq!(c.authorize.len(), 3);
        assert_eq!(c.authorize[0], c.authorize[1]);
        assert_eq!(c.authorize[0], c.authorize[2]);
    }
    let recs = up.fake.emitted.lock().unwrap().clone();
    assert_eq!(recs.len(), 3, "{recs:?}");
    let counts: Vec<u64> = recs
        .iter()
        .map(|r| {
            r["unmapped"]["sluis"]["ignored_parameters"]
                .as_u64()
                .unwrap()
        })
        .collect();
    assert_eq!(counts, [0, 4, 4]);
    let all = serde_json::to_string(&recs).unwrap();
    for secret in [
        "extra",
        "foobar",
        name,
        value,
        "claims",
        "display",
        "essential",
    ] {
        assert!(
            !all.contains(secret),
            "{secret} is in the audit record: {all}"
        );
    }
}

/// No name in a request turns on the nonce option: `pkce=nonce` and the names a client might guess are not on the list, so
/// session gets the request as it gets one without them, in a query and in a form, and the setting is read from the
/// client's declaration alone.
///
/// verifies: REQ-AUTHN-109
#[tokio::test]
async fn no_parameter_of_a_request_can_turn_on_the_nonce_option() {
    let up = up().await;
    let guess =
        "pkce=nonce&skip_pkce=true&require_pkce=false&code_verifier_required=0&pkce_mode=nonce";
    http(&up, "GET", &format!("/authorize?{AUTHORIZE_Q}"), &[], b"").await;
    let query = http(
        &up,
        "GET",
        &format!("/authorize?{AUTHORIZE_Q}&{guess}"),
        &[],
        b"",
    )
    .await;
    let form = http(
        &up,
        "POST",
        "/authorize",
        &[FORM],
        format!("{AUTHORIZE_Q}&{guess}").as_bytes(),
    )
    .await;
    assert_eq!((query.status, form.status), (200, 200));
    let c = up.fake.calls.lock().unwrap();
    assert_eq!(c.authorize.len(), 3);
    assert_eq!(c.authorize[0], c.authorize[1]);
    assert_eq!(c.authorize[0], c.authorize[2]);
}

/// verifies: REQ-AUTHN-078
#[tokio::test]
async fn callback_drops_unknown_parameters_and_still_refuses_a_repeated_known_one() {
    // The upstream answers sluis as a client: RFC 6749 section 4.1.2 says to ignore a response
    // parameter that is not recognised (Keycloak sends session_state). Requests to sluis keep
    // their closed lists (REQ-AUTHN-012).
    let up = up().await;
    let ok = http(
        &up,
        "GET",
        "/callback?code=abc&state=st&session_state=sess9&iss=https%3A%2F%2Fidp.example.com\
         &error_uri=https%3A%2F%2Fidp.example.com%2Fe&arbitrary_extra=zz&cookie=injected",
        &[("Cookie", "__Host-sluis_signin=cv123")],
        b"",
    )
    .await;
    assert_eq!(ok.status, 200);
    for q in [
        "/callback?code=a&code=b&state=st",
        "/callback?code=a&state=s&state=t",
        "/callback?code=a&state=s&error_uri=x&error_uri=y",
        "/callback?code=a&session_state=%zz",
    ] {
        let r = http(&up, "GET", q, &[], b"").await;
        assert_eq!(r.status, 400, "{q}");
        let text = r.text();
        assert!(!text.contains("code") && !text.contains("state"), "{text}");
    }
    let authorize = http(
        &up,
        "GET",
        &format!("/authorize?{AUTHORIZE_Q}&session_state=x&session_state=x"),
        &[],
        b"",
    )
    .await;
    // `/authorize` ignores a name it does not know, as the callback does, but it does not skip the check of a repeat.
    assert_eq!(authorize.status, 400);
    let c = up.fake.calls.lock().unwrap();
    assert!(c.authorize.is_empty());
    // Only the contract's fields arrive, and the cookie is the header's, never a parameter's.
    assert_eq!(c.callback.len(), 1);
    let r = &c.callback[0];
    assert_eq!(
        (
            r.code.as_str(),
            r.state.as_str(),
            r.iss.as_str(),
            r.cookie.as_str()
        ),
        ("abc", "st", "https://idp.example.com", "cv123")
    );
}

/// No online certificate status responder is served: the paths an OCSP client would use (RFC 6960, appendix A.1) and the
/// usual status paths are unrouted, until a decision to run one is recorded.
///
/// verifies: REQ-PKI-008
#[tokio::test]
async fn there_is_no_certificate_status_responder() {
    let up = up().await;
    let ocsp = ("Content-Type", "application/ocsp-request");
    for (method, path) in [
        ("POST", "/"),
        ("POST", "/ocsp"),
        ("GET", "/ocsp/MEgwRjBEMEIwQDAJBgUrDgMCGgUA"),
        ("GET", "/status"),
        ("GET", "/ca/status"),
    ] {
        let r = http(&up, method, path, &[ocsp], b"\x30\x00").await;
        assert_ne!(r.status, 200, "{method} {path}");
        if path != "/" {
            assert_eq!(r.status, 404, "{method} {path}");
        }
    }
}

/// A resource indicator (RFC 8707) is a parameter of the token exchange only. On the sign-in it is refused although the
/// route ignores other names, because ignoring it would issue a token for another audience than the one asked; on the
/// code and refresh grants it is an unknown parameter. The request is refused before session sees it, so it cannot reach
/// the audience of an ID token.
///
/// verifies: REQ-TOKEN-004
#[tokio::test]
async fn a_resource_indicator_is_refused_where_an_id_token_is_made() {
    let up = up().await;
    let authorize = http(
        &up,
        "GET",
        &format!("/authorize?{AUTHORIZE_Q}&resource=https%3A%2F%2Frs.example.com"),
        &[],
        b"",
    )
    .await;
    assert_eq!(authorize.status, 400, "{}", authorize.text());
    for grant in [
        "grant_type=authorization_code&code=c&redirect_uri=u&code_verifier=v&client_id=sluis-cli",
        "grant_type=refresh_token&refresh_token=r",
    ] {
        let r = post_token(
            &up,
            &format!("{grant}&resource=https%3A%2F%2Frs.example.com"),
        )
        .await;
        assert_eq!(r.status, 400, "{grant}: {}", r.text());
        assert!(!r.text().contains("rs.example.com"));
    }
    let recs = up.fake.emitted.lock().unwrap().clone();
    assert_eq!(recs.len(), 3, "{recs:?}");
    let reasons: Vec<&str> = recs
        .iter()
        .map(|r| r["status_code"].as_str().unwrap())
        .collect();
    assert_eq!(
        reasons,
        [
            "refused_parameter",
            "unknown_parameter",
            "unknown_parameter"
        ]
    );
    // A refused request has no count: it is not read further.
    assert!(
        recs[0]["unmapped"]["sluis"]
            .get("ignored_parameters")
            .is_none()
    );
}

/// The UserInfo route hands the `Authorization` header to session and nothing else of the request, for a GET and for a POST
/// (OpenID Connect Core section 5.3.1), and relays the answer with its `WWW-Authenticate` challenge (RFC 6750 section 3), which
/// entry does not make: an answer made here would not carry one.
///
/// verifies: REQ-TOKEN-008
#[tokio::test]
async fn userinfo_hands_the_bearer_header_to_session_and_relays_its_answer() {
    let up = up().await;
    for method in ["GET", "POST"] {
        let r = http(
            &up,
            method,
            "/userinfo",
            &[("Authorization", "Bearer abc.def-ghi")],
            b"",
        )
        .await;
        assert_eq!(r.status, 200, "{method}");
    }
    {
        let c = up.fake.calls.lock().unwrap();
        assert_eq!(c.userinfo.len(), 2);
        assert!(
            c.userinfo
                .iter()
                .all(|u| u.authorization == "Bearer abc.def-ghi")
        );
    }
    *up.fake.reply.lock().unwrap() = Some(reply(
        401,
        &[
            ("Content-Type", "application/json"),
            (
                "WWW-Authenticate",
                "Bearer realm=\"sluis\", error=\"invalid_token\"",
            ),
        ],
    ));
    let r = http(
        &up,
        "GET",
        "/userinfo",
        &[("Authorization", "Bearer x")],
        b"",
    )
    .await;
    assert_eq!(r.status, 401);
    assert_eq!(
        r.h("www-authenticate"),
        Some("Bearer realm=\"sluis\", error=\"invalid_token\"")
    );
    assert_eq!(r.h("cache-control"), Some("no-store"));
    // A request with no header is session's to answer (a 401 with a challenge and no error), and entry passes on an empty one.
    *up.fake.reply.lock().unwrap() = None;
    assert_eq!(http(&up, "GET", "/userinfo", &[], b"").await.status, 200);
    assert_eq!(up.fake.calls.lock().unwrap().userinfo[3].authorization, "");
}

/// The access token is in the header and nowhere else. A token in the query (RFC 6750 section 2.3 allows it and says it
/// SHOULD NOT be used: a URL is logged), a body of any kind (section 2.2 takes a form body, which is not served), another
/// parameter, two `Authorization` headers and a method other than GET and POST are refused before session is asked, and each
/// refusal is audited as the UserInfo route with a closed reason that holds no part of the token.
///
/// verifies: REQ-SEC-038
#[tokio::test]
async fn userinfo_takes_the_token_from_the_header_alone() {
    let up = up().await;
    let auth = ("Authorization", "Bearer secret-token-value");
    #[allow(clippy::type_complexity)]
    let cases: Vec<(&str, &str, Vec<(&str, &str)>, &[u8], u16, &str)> = vec![
        (
            "a token in the query",
            "GET",
            vec![],
            &b""[..],
            400,
            "unknown_parameter",
        ),
        (
            "a token in a form body",
            "POST",
            vec![FORM],
            &b"access_token=secret-token-value"[..],
            400,
            "body",
        ),
        (
            "two headers",
            "GET",
            vec![auth, auth],
            &b""[..],
            400,
            "authorization",
        ),
        ("a method", "PUT", vec![auth], &b""[..], 405, "method"),
    ];
    for (what, method, headers, body, status, reason) in cases {
        let target = if what == "a token in the query" {
            "/userinfo?access_token=secret-token-value"
        } else {
            "/userinfo"
        };
        let before = up.fake.emitted.lock().unwrap().len();
        let r = http(&up, method, target, &headers, body).await;
        assert_eq!(r.status, status, "{what}");
        if status == 405 {
            assert_eq!(r.h("allow"), Some("GET, POST"));
        }
        let recs = up.fake.emitted.lock().unwrap().clone();
        assert_eq!(recs.len(), before + 1, "{what}: one record");
        let rec = recs.last().unwrap();
        assert_eq!(rec["status_code"], reason, "{what}");
        assert!(
            !rec.to_string().contains("secret-token-value"),
            "{what}: {rec}"
        );
        assert!(!r.text().contains("secret-token-value"), "{what}");
    }
    assert!(
        up.fake.calls.lock().unwrap().userinfo.is_empty(),
        "session was asked"
    );
}

/// The revocation route takes a form post and nothing else: the parameters of RFC 7009 and the client's authentication go to
/// session as they came, and its answer comes back as it is, so a 200 for a token session did not revoke is the same 200 as for
/// one it did. A query (a token in a URL is logged), a GET, another media type, a parameter off the list, a repeated one and a
/// second `Authorization` header are refused before session is asked, with a closed reason that holds no part of the token.
///
/// verifies: REQ-TOKEN-009
#[tokio::test]
async fn revoke_takes_a_form_post_and_hands_it_to_session() {
    let up = up().await;
    let body =
        "token=the-token&token_type_hint=refresh_token&client_id=app&client_secret=s3%2Bcret";
    let r = http(
        &up,
        "POST",
        "/revoke",
        &[FORM, ("Authorization", "Basic Zm9vOmJhcg==")],
        body.as_bytes(),
    )
    .await;
    assert_eq!(r.status, 200);
    {
        let c = up.fake.calls.lock().unwrap();
        let q = &c.revoke[0];
        assert_eq!(
            (
                q.token.as_str(),
                q.token_type_hint.as_str(),
                q.client_id.as_str(),
                q.client_secret.as_str(),
                q.authorization.as_str()
            ),
            (
                "the-token",
                "refresh_token",
                "app",
                "s3+cret",
                "Basic Zm9vOmJhcg=="
            )
        );
    }
    assert_eq!(r.h("cache-control"), Some("no-store"));
    #[allow(clippy::type_complexity)]
    let refused: Vec<(&str, &str, &str, Vec<(&str, &str)>, &[u8], u16, &str)> = vec![
        ("a GET", "GET", "/revoke", vec![], &b""[..], 405, "method"),
        (
            "a token in the query",
            "POST",
            "/revoke?token=the-token",
            vec![FORM],
            &b"client_id=app"[..],
            400,
            "unknown_parameter",
        ),
        (
            "another media type",
            "POST",
            "/revoke",
            vec![("Content-Type", "application/json")],
            &b"{\"token\":\"the-token\"}"[..],
            415,
            "content_type",
        ),
        (
            "a parameter off the list",
            "POST",
            "/revoke",
            vec![FORM],
            &b"token=the-token&resource=x"[..],
            400,
            "unknown_parameter",
        ),
        (
            "a repeated token",
            "POST",
            "/revoke",
            vec![FORM],
            &b"token=the-token&token=another"[..],
            400,
            "duplicate_parameter",
        ),
        (
            "two authorizations",
            "POST",
            "/revoke",
            vec![
                FORM,
                ("Authorization", "Basic YQ=="),
                ("Authorization", "Basic Yg=="),
            ],
            &b"token=the-token"[..],
            400,
            "authorization",
        ),
    ];
    for (what, method, target, headers, body, status, reason) in refused {
        let before = up.fake.emitted.lock().unwrap().len();
        let r = http(&up, method, target, &headers, body).await;
        assert_eq!(r.status, status, "{what}");
        let recs = up.fake.emitted.lock().unwrap().clone();
        assert_eq!(recs.len(), before + 1, "{what}: one record");
        let rec = recs.last().unwrap();
        assert_eq!(rec["status_code"], reason, "{what}");
        assert!(!rec.to_string().contains("the-token"), "{what}: {rec}");
        assert!(!r.text().contains("the-token"), "{what}");
    }
    assert_eq!(up.fake.calls.lock().unwrap().revoke.len(), 1);
}

/// There is no introspection endpoint: a token of any installation sent to `/introspect` is answered as an unrouted
/// path, and the refusal is audited as a route that does not exist.
///
/// verifies: REQ-SEC-011
#[tokio::test]
async fn there_is_no_introspection_endpoint() {
    let up = up().await;
    for method in ["GET", "POST"] {
        let r = http(&up, method, "/introspect", &[FORM], b"token=abc").await;
        assert_eq!(r.status, 404, "{method}");
    }
    let recs = up.fake.emitted.lock().unwrap().clone();
    assert_eq!(recs.len(), 2, "{recs:?}");
    assert!(
        recs.iter()
            .all(|r| r["metadata"]["event_code"] == "entry.unrouted" && r["status_code"] == "route")
    );
}

/// verifies: REQ-UX-006
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
    // The reason is in the audit record of the refusal, under the same correlation id, and nowhere in the body.
    let recs = up.fake.emitted.lock().unwrap().clone();
    let rec = recs
        .iter()
        .find(|r| r["metadata"]["correlation_uid"].as_str() == denied.h("sluis-correlation-id"))
        .expect("the audit record of the refusal");
    assert_eq!(rec["status_code"], "rpc_permission_denied");
    assert!(
        !text.contains("rpc_permission_denied"),
        "the body names the reason: {text}"
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
    let own = http(&up, "GET", "/authorize?state=%zz", &[], b"").await;
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
    let r = http(&up, "PUT", "/authorize", &[FORM], b"a=1").await;
    assert_eq!((r.status, r.h("allow")), (405, Some("GET, POST")));
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
    ] {
        assert_eq!(http(&up, "GET", path, &[], b"").await.status, 404, "{path}");
    }
    let c = up.fake.calls.lock().unwrap();
    assert!(c.authorize.is_empty() && c.token.is_empty());
}

/// The authorization endpoint takes its parameters in the query of a GET or in the form body of a POST, and the request
/// that session gets is the same (OpenID Connect Core section 3.1.2.1). A POST with a query has two sources and is refused,
/// like a GET with a body; the media type, the size and the syntax of the body are checked as the token endpoint checks its
/// own, and the list of names is the same closed list.
#[tokio::test]
async fn authorize_takes_a_form_post_as_it_takes_a_query() {
    let up = up().await;
    let got = http(&up, "GET", &format!("/authorize?{AUTHORIZE_Q}"), &[], b"").await;
    let posted = http(&up, "POST", "/authorize", &[FORM], AUTHORIZE_Q.as_bytes()).await;
    assert_eq!((got.status, posted.status), (200, 200));
    {
        let c = up.fake.calls.lock().unwrap();
        assert_eq!(c.authorize.len(), 2);
        assert_eq!(c.authorize[0], c.authorize[1], "a POST is the same request");
    }
    let charset = (
        "Content-Type",
        "application/x-www-form-urlencoded; charset=utf-8",
    );
    #[allow(clippy::type_complexity)]
    let refused: [(&str, &str, &[(&str, &str)], Vec<u8>, u16); 11] = [
        (
            "a POST with a query",
            "/authorize?state=x",
            &[FORM],
            AUTHORIZE_Q.into(),
            400,
        ),
        ("a GET with a body", "", &[FORM], AUTHORIZE_Q.into(), 400),
        (
            "the wrong media type",
            "/authorize",
            &[("Content-Type", "text/plain")],
            AUTHORIZE_Q.into(),
            415,
        ),
        ("no media type", "/authorize", &[], AUTHORIZE_Q.into(), 415),
        (
            "JSON",
            "/authorize",
            &[("Content-Type", "application/json")],
            b"{}".to_vec(),
            415,
        ),
        (
            "a resource indicator",
            "/authorize",
            &[FORM],
            format!("{AUTHORIZE_Q}&resource=https%3A%2F%2Frs.example.test").into(),
            400,
        ),
        (
            "a repeated parameter",
            "/authorize",
            &[FORM],
            format!("{AUTHORIZE_Q}&state=again").into(),
            400,
        ),
        (
            "a bad escape",
            "/authorize",
            &[FORM],
            b"state=%zz".to_vec(),
            400,
        ),
        (
            "bytes that are not UTF-8",
            "/authorize",
            &[FORM],
            b"state=%ff&a=\xff".to_vec(),
            400,
        ),
        (
            "a body over the limit",
            "/authorize",
            &[FORM],
            format!("state={}", "a".repeat(40_000)).into(),
            413,
        ),
        (
            "a charset it does not know",
            "/authorize",
            &[(
                "Content-Type",
                "application/x-www-form-urlencoded; charset=latin-1",
            )],
            AUTHORIZE_Q.into(),
            415,
        ),
    ];
    for (what, target, headers, body, want) in refused {
        let (method, target) = if what == "a GET with a body" {
            ("GET", format!("/authorize?{AUTHORIZE_Q}"))
        } else {
            ("POST", target.to_owned())
        };
        let r = http(&up, method, &target, headers, &body).await;
        assert_eq!(r.status, want, "{what}");
    }
    let r = http(
        &up,
        "POST",
        "/authorize",
        &[charset],
        AUTHORIZE_Q.as_bytes(),
    )
    .await;
    assert_eq!(
        r.status, 200,
        "charset=utf-8 is the one charset of the format"
    );
    assert_eq!(
        up.fake.calls.lock().unwrap().authorize.len(),
        3,
        "a refused request reached session"
    );
}

/// `display`, `ui_locales`, `claims_locales`, `login_hint` and `claims` are parameters of OpenID Connect Core section
/// 3.1.2.1 and 5.5 that an OP may ignore (discovery says `claims_parameter_supported` is false). `/authorize` ignores
/// them, in a query and in a form, and session gets the request without them; a repeat is refused as for any parameter.
/// The parameters that narrow or bind what is issued are refused (`resource`, `audience`, `authorization_details`,
/// `dpop_jkt`), in a query and in a form. (`request`,
/// `request_uri` and `registration` are answered by `session` with the errors of section 3.1.2.6.)
///
/// verifies: REQ-AUTHN-036
#[tokio::test]
async fn authorize_ignores_the_hints_and_refuses_what_it_cannot_ignore() {
    let up = up().await;
    let hints = "display=page&ui_locales=de+en&claims_locales=de&login_hint=alice%40example.test&claims=%7B%7D";
    let plain = http(&up, "GET", &format!("/authorize?{AUTHORIZE_Q}"), &[], b"").await;
    let query = http(
        &up,
        "GET",
        &format!("/authorize?{AUTHORIZE_Q}&{hints}"),
        &[],
        b"",
    )
    .await;
    let form = http(
        &up,
        "POST",
        "/authorize",
        &[FORM],
        format!("{AUTHORIZE_Q}&{hints}").as_bytes(),
    )
    .await;
    assert_eq!((plain.status, query.status, form.status), (200, 200, 200));
    {
        let c = up.fake.calls.lock().unwrap();
        assert_eq!(c.authorize.len(), 3);
        assert_eq!(c.authorize[0], c.authorize[1]);
        assert_eq!(c.authorize[0], c.authorize[2]);
    }
    for name in [
        "display",
        "ui_locales",
        "claims_locales",
        "login_hint",
        "claims",
    ] {
        let r = http(
            &up,
            "GET",
            &format!("/authorize?{AUTHORIZE_Q}&{name}=a&{name}=a"),
            &[],
            b"",
        )
        .await;
        assert_eq!(r.status, 400, "a repeated {name}");
    }
    // The parameters that narrow or bind what is issued are refused, in a query and in a form, each of them.
    let refused = [
        "resource=https%3A%2F%2Fapi.example.test",
        "audience=api-example-test",
        "authorization_details=%5B%7B%22type%22%3A%22payment-example%22%7D%5D",
        "dpop_jkt=0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I",
    ];
    for param in refused {
        for (method, target, body) in [
            (
                "GET",
                format!("/authorize?{AUTHORIZE_Q}&{param}"),
                String::new(),
            ),
            (
                "POST",
                "/authorize".to_owned(),
                format!("{AUTHORIZE_Q}&{param}"),
            ),
        ] {
            let headers: &[(&str, &str)] = if method == "POST" { &[FORM] } else { &[] };
            let r = http(&up, method, &target, headers, body.as_bytes()).await;
            assert_eq!(r.status, 400, "{method} {param}");
            let value = param.split_once('=').unwrap().1;
            assert!(!r.text().contains(value), "{method} {param}");
        }
    }
    {
        let recs = up.fake.emitted.lock().unwrap().clone();
        let n = recs
            .iter()
            .filter(|r| r["status_code"] == "refused_parameter")
            .count();
        assert_eq!(n, 2 * refused.len(), "{recs:?}");
    }
    assert_eq!(up.fake.calls.lock().unwrap().authorize.len(), 3);
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

/// verifies: REQ-AUTHN-036, REQ-AUTHN-015, REQ-AUTHN-012
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
async fn client_authentication_by_header_or_form_reaches_session_and_exchange() {
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
    // Exchange takes the header (client_secret_basic) ...
    let ex = "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange&subject_token=t";
    let r = http(
        &up,
        "POST",
        "/token",
        &[FORM, ("Authorization", "Basic Zm9vOmJhcg==")],
        ex.as_bytes(),
    )
    .await;
    assert_eq!(r.status, 200);
    // ... or the form field (client_secret_post).
    let post = format!("{ex}&client_id=app&client_secret=s3cret%2B%3D");
    assert_eq!(post_token(&up, &post).await.status, 200);
    let c = up.fake.calls.lock().unwrap();
    assert_eq!(c.exchange.len(), 2);
    assert_eq!(c.exchange[0].authorization, "Basic Zm9vOmJhcg==");
    assert_eq!(c.exchange[0].client_secret, "");
    assert_eq!(c.exchange[1].authorization, "");
    assert_eq!(
        (
            c.exchange[1].client_id.as_str(),
            c.exchange[1].client_secret.as_str()
        ),
        ("app", "s3cret+=")
    );
}

#[tokio::test]
async fn every_advertised_client_authentication_method_is_accepted_by_a_grant() {
    // RFC 8414 lists the methods of the endpoint, not of a grant: `none` is what a public client uses for
    // authorization_code and refresh_token, the secret methods are what a confidential client uses for those two and
    // for the token-exchange grant. A method that discovery advertises and no grant takes would be a lie, and a method
    // that is added needs a case.
    let up = up().await;
    let d = http(&up, "GET", "/.well-known/openid-configuration", &[], b"").await;
    let doc: Value = serde_json::from_slice(&d.body).unwrap();
    let methods: Vec<String> = doc["token_endpoint_auth_methods_supported"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m.as_str().unwrap().to_owned())
        .collect();
    let ex = "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange&subject_token=t";
    for m in &methods {
        match m.as_str() {
            "none" => {
                let code = "grant_type=authorization_code&code=c&client_id=app";
                assert_eq!(post_token(&up, code).await.status, 200);
                let refresh = "grant_type=refresh_token&refresh_token=r&client_id=app";
                assert_eq!(post_token(&up, refresh).await.status, 200);
                let c = up.fake.calls.lock().unwrap();
                assert_eq!(c.token.len(), 2);
                for t in &c.token {
                    assert_eq!(
                        (t.authorization.as_str(), t.client_secret.as_str()),
                        ("", "")
                    );
                }
            }
            "client_secret_basic" => {
                let r = http(
                    &up,
                    "POST",
                    "/token",
                    &[FORM, ("Authorization", "Basic Zm9vOmJhcg==")],
                    ex.as_bytes(),
                )
                .await;
                assert_eq!(r.status, 200);
                {
                    let c = up.fake.calls.lock().unwrap();
                    assert_eq!(
                        c.exchange.last().unwrap().authorization,
                        "Basic Zm9vOmJhcg=="
                    );
                }
                // The code and the refresh grants hand the header to session as it came.
                let code = "grant_type=authorization_code&code=c";
                let refresh = "grant_type=refresh_token&refresh_token=r";
                for body in [code, refresh] {
                    let r = http(
                        &up,
                        "POST",
                        "/token",
                        &[FORM, ("Authorization", "Basic Zm9vOmJhcg==")],
                        body.as_bytes(),
                    )
                    .await;
                    assert_eq!(r.status, 200, "{body}");
                }
                let c = up.fake.calls.lock().unwrap();
                for t in c.token.iter().rev().take(2) {
                    assert_eq!(t.authorization, "Basic Zm9vOmJhcg==");
                    assert_eq!(t.client_secret, "");
                }
            }
            "client_secret_post" => {
                let post = format!("{ex}&client_id=app&client_secret=s");
                assert_eq!(post_token(&up, &post).await.status, 200);
                {
                    let c = up.fake.calls.lock().unwrap();
                    assert_eq!(c.exchange.last().unwrap().client_secret, "s");
                }
                let code = "grant_type=authorization_code&code=c&client_id=app&client_secret=s";
                let refresh =
                    "grant_type=refresh_token&refresh_token=r&client_id=app&client_secret=s";
                for body in [code, refresh] {
                    assert_eq!(post_token(&up, body).await.status, 200, "{body}");
                }
                let c = up.fake.calls.lock().unwrap();
                for t in c.token.iter().rev().take(2) {
                    assert_eq!(
                        (
                            t.client_id.as_str(),
                            t.client_secret.as_str(),
                            t.authorization.as_str()
                        ),
                        ("app", "s", "")
                    );
                }
            }
            other => {
                panic!("discovery advertises {other}, and no case shows a grant that accepts it")
            }
        }
    }
    assert_eq!(methods.len(), 3);
}

#[tokio::test]
async fn an_authorization_header_that_is_present_and_empty_is_refused() {
    // An empty header must not read as "no authentication": it would hide a second method beside client_secret.
    let up = up().await;
    let ex = "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange&subject_token=t&client_id=sluis-cli";
    for form in [ex.to_owned(), format!("{ex}&client_secret=s")] {
        let r = http(
            &up,
            "POST",
            "/token",
            &[FORM, ("Authorization", "")],
            form.as_bytes(),
        )
        .await;
        assert_eq!(r.status, 400);
        assert!(r.text().contains("invalid_request"));
    }
    assert!(up.fake.calls.lock().unwrap().exchange.is_empty());
}

#[tokio::test]
async fn two_client_authentication_methods_in_one_exchange_are_refused_at_the_edge() {
    // RFC 6749 section 2.3: a client uses one method per request. Even an empty secret is a second method.
    let up = up().await;
    let ex = "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange&subject_token=t";
    for form in [
        format!("{ex}&client_secret=s"),
        format!("{ex}&client_secret="),
    ] {
        let r = http(
            &up,
            "POST",
            "/token",
            &[FORM, ("Authorization", "Basic Zm9vOmJhcg==")],
            form.as_bytes(),
        )
        .await;
        assert_eq!(r.status, 400);
        assert!(r.text().contains("invalid_request"));
        assert!(!r.text().contains("Zm9v") && !r.text().contains("=s"));
    }
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

/// verifies: REQ-AUTHN-012, REQ-KEYS-016
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
        serde_json::json!(["none", "client_secret_basic", "client_secret_post"])
    );
    // The revocation endpoint authenticates the client as the token endpoint does (REQ-TOKEN-009).
    assert_eq!(
        doc["revocation_endpoint_auth_methods_supported"],
        doc["token_endpoint_auth_methods_supported"]
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

/// The discovery document that `entry` serves lists what `entry` serves. It is the golden file, with the issuer of this
/// test; every endpoint in it is a route that reaches the actor behind (and no other endpoint field is in it); each
/// grant it lists is dispatched to its actor and a grant it does not list is refused; and `/authorize` hands `request`,
/// `request_uri` and `registration` to `session` to be answered as not supported, as `request_uri_parameter_supported: false`
/// says. What the document says of the behaviour of `session` (response types and modes, PKCE, `iss`, subject type, ID token
/// algorithm, scopes) is held to the same file by `session`'s tests.
///
/// verifies: REQ-AUTHN-006
#[tokio::test]
async fn the_served_discovery_document_lists_what_entry_serves_and_no_more() {
    let up = up().await;
    let d = http(&up, "GET", "/.well-known/openid-configuration", &[], b"").await;
    assert_eq!(d.status, 200);
    let doc: Value = serde_json::from_slice(&d.body).unwrap();
    let golden: Value = serde_json::from_str(
        &include_str!("testdata/discovery.json").replace("https://sluis.example.test", ISSUER),
    )
    .unwrap();
    assert_eq!(doc, golden, "the served document is the golden file");
    // The OAuth name serves the same document, so what the golden says is true at both locations.
    let oauth = http(
        &up,
        "GET",
        "/.well-known/oauth-authorization-server",
        &[],
        b"",
    )
    .await;
    assert_eq!((oauth.status, &oauth.body), (200, &d.body));

    // The endpoint fields are exactly the four routes, and each URL is the issuer and the path of a route that answers.
    let urls: Vec<(&str, &str)> = doc
        .as_object()
        .unwrap()
        .iter()
        .filter(|(k, _)| k.ends_with("_endpoint") || k.ends_with("_uri"))
        .filter(|(k, _)| !k.ends_with("_supported"))
        .map(|(k, v)| (k.as_str(), v.as_str().unwrap()))
        .collect();
    // Sorted: the member order of a parsed object depends on the features of the workspace build.
    let mut names: Vec<&str> = urls.iter().map(|(k, _)| *k).collect();
    names.sort_unstable();
    assert_eq!(
        names,
        [
            "authorization_endpoint",
            "jwks_uri",
            "revocation_endpoint",
            "token_endpoint",
            "userinfo_endpoint"
        ],
        "an endpoint field without a route behind it (or the reverse) is an untruth"
    );
    let path = |url: &str| url.strip_prefix(ISSUER).unwrap().to_owned();
    for (name, url) in urls {
        let path = path(url);
        match name {
            "authorization_endpoint" => {
                let r = http(&up, "GET", &format!("{path}?{AUTHORIZE_Q}"), &[], b"").await;
                assert_eq!(r.status, 200, "{name}");
                assert_eq!(up.fake.calls.lock().unwrap().authorize.len(), 1);
            }
            "token_endpoint" => {
                let r = post_token(&up, "grant_type=refresh_token&refresh_token=r").await;
                assert_eq!((r.status, path.as_str()), (200, "/token"), "{name}");
            }
            "jwks_uri" => {
                let r = http(&up, "GET", &path, &[], b"").await;
                assert_eq!(r.status, 200, "{name}");
                assert!(serde_json::from_slice::<Value>(&r.body).unwrap()["keys"].is_array());
            }
            "userinfo_endpoint" => {
                let r = http(&up, "GET", &path, &[("Authorization", "Bearer t")], b"").await;
                assert_eq!((r.status, path.as_str()), (200, "/userinfo"), "{name}");
                assert_eq!(up.fake.calls.lock().unwrap().userinfo.len(), 1);
            }
            "revocation_endpoint" => {
                let r = http(&up, "POST", &path, &[FORM], b"token=t&client_id=app").await;
                assert_eq!((r.status, path.as_str()), (200, "/revoke"), "{name}");
                assert_eq!(up.fake.calls.lock().unwrap().revoke.len(), 1);
            }
            other => panic!("{other} is listed and no case shows the route behind it"),
        }
    }
    // What other providers list and this one does not serve is not in the document and not routed.
    for (field, route) in [
        ("introspection_endpoint", "/introspect"),
        ("registration_endpoint", "/register"),
        ("pushed_authorization_request_endpoint", "/par"),
        ("device_authorization_endpoint", "/device_authorization"),
        ("end_session_endpoint", "/logout"),
    ] {
        assert!(doc.get(field).is_none(), "{field}");
        for method in ["GET", "POST"] {
            let r = http(&up, method, route, &[FORM], b"token=t").await;
            assert_eq!(r.status, 404, "{method} {route}");
        }
    }

    // Each grant the document lists reaches its actor; each that it does not list is refused before any actor.
    let before = {
        let c = up.fake.calls.lock().unwrap();
        (c.token.len(), c.exchange.len())
    };
    let listed: Vec<&str> = doc["grant_types_supported"]
        .as_array()
        .unwrap()
        .iter()
        .map(|g| g.as_str().unwrap())
        .collect();
    for (n, grant) in listed.iter().enumerate() {
        let enc = grant.replace(':', "%3A");
        let body = match *grant {
            "authorization_code" => format!("grant_type={enc}&code=c&client_id=app"),
            "refresh_token" => format!("grant_type={enc}&refresh_token=r&client_id=app"),
            "urn:ietf:params:oauth:grant-type:token-exchange" => {
                format!("grant_type={enc}&subject_token=t&client_id=app")
            }
            other => panic!("{other} is listed and no case shows a request that reaches its actor"),
        };
        assert_eq!(post_token(&up, &body).await.status, 200, "{grant}");
        let c = up.fake.calls.lock().unwrap();
        assert_eq!(
            (c.token.len() - before.0, c.exchange.len() - before.1),
            match n {
                0 => (1, 0),
                1 => (2, 0),
                _ => (2, 1),
            },
            "{grant}"
        );
    }
    assert_eq!(listed.len(), 3);
    for grant in [
        "client_credentials",
        "password",
        "implicit",
        "urn:ietf:params:oauth:grant-type:device_code",
        "urn:ietf:params:oauth:grant-type:jwt-bearer",
        "urn:ietf:params:oauth:grant-type:saml2-bearer",
    ] {
        assert!(!listed.contains(&grant), "{grant}");
        let r = post_token(&up, &format!("grant_type={}", grant.replace(':', "%3A"))).await;
        assert_eq!(r.status, 400, "{grant}");
        assert!(r.text().contains("\"unsupported_grant_type\""), "{grant}");
    }
    {
        let c = up.fake.calls.lock().unwrap();
        assert_eq!(
            (c.token.len(), c.exchange.len()),
            (before.0 + 2, before.1 + 1)
        );
    }

    // request_uri_parameter_supported is false because /authorize serves no request_uri: entry passes the parameter to
    // session, which answers request_uri_not_supported at the client's redirect (its test holds that side).
    assert_eq!(doc["request_uri_parameter_supported"], false);
    for (param, sent, want) in [
        (
            "request_uri",
            "https%3A%2F%2Frp.example.test%2Fr",
            "https://rp.example.test/r",
        ),
        ("request", "eyJ", "eyJ"),
        ("registration", "%7B%7D", "{}"),
    ] {
        let before = up.fake.calls.lock().unwrap().authorize.len();
        let r = http(
            &up,
            "GET",
            &format!("/authorize?{AUTHORIZE_Q}&{param}={sent}"),
            &[],
            b"",
        )
        .await;
        assert_eq!(r.status, 200, "{param}");
        let c = up.fake.calls.lock().unwrap();
        assert_eq!(c.authorize.len(), before + 1, "{param}");
        let a = &c.authorize[before];
        let got = [&a.request, &a.request_uri, &a.registration];
        // Exactly the parameter that was sent arrived, with its decoded value, and in its own field.
        let at = ["request", "request_uri", "registration"]
            .iter()
            .position(|n| *n == param)
            .unwrap();
        for (i, v) in got.iter().enumerate() {
            assert_eq!(**v, if i == at { want } else { "" }, "{param}: field {i}");
        }
    }
    // The list of scopes is the document's: only what carries something today (session's test holds it to the scopes it grants).
    assert_eq!(doc["scopes_supported"], serde_json::json!(["openid"]));
}

/// The discovery document is served at the OpenID name and at the OAuth name (OpenID Connect Discovery 1.0 section 4,
/// RFC 8414 section 3), and at the path-inserted form of each for an issuer that has a path (RFC 8414 section 3.1:
/// the name goes between the host and the path). The path must be the issuer's own, byte for byte: an issuer with no
/// path has no inserted location, and the path of another issuer, a prefix of it, a longer one, another case and a
/// trailing slash are not found. Every location answers as the first does: GET and HEAD, public, no parameter.
///
/// verifies: REQ-AUTHN-029
#[tokio::test]
async fn discovery_is_served_at_both_well_known_names_and_the_path_inserted_ones() {
    const NAMES: [&str; 2] = [
        "/.well-known/openid-configuration",
        "/.well-known/oauth-authorization-server",
    ];
    // (issuer, the path after the well-known name that is served, paths that are not)
    let issuers: [(&str, &str, &[&str]); 4] = [
        (
            ISSUER,
            "",
            &["/", "/tenant-a", "/tenant-a/v2", "/.well-known", "x"],
        ),
        (
            "https://sluis.example.test:8443/tenant-a/v2",
            "/tenant-a/v2",
            &[
                "/",
                "/tenant-a",
                "/tenant-a/",
                "/tenant-a/v2/",
                "/tenant-a/v2/x",
                "/tenant-a/v3",
                "/Tenant-a/v2",
                "/v2",
                "//tenant-a/v2",
            ],
        ),
        (
            "https://sluis.example.test/Tenant%2FA/%7e",
            "/Tenant%2FA/%7e",
            &["/Tenant/A/~", "/tenant%2fa/%7e", "/Tenant%2FA/~"],
        ),
        (
            "https://Sluis.Example.TEST:443/a",
            "/a",
            &["/A", "/a/", "/a/b"],
        ),
    ];
    for (issuer, path, wrong) in issuers {
        let up = up().await;
        *up.fake.issuer.lock().unwrap() = Some(issuer.into());
        let first = http(&up, "GET", NAMES[0], &[], b"").await;
        assert_eq!(first.status, 200, "{issuer}");
        for name in NAMES {
            // Without a path (the name itself) and with the issuer's path inserted, when it has one.
            let mut served = vec![name.to_owned()];
            if !path.is_empty() {
                served.push(format!("{name}{path}"));
            }
            for target in served {
                let r = http(&up, "GET", &target, &[], b"").await;
                assert_eq!(r.status, 200, "{issuer} {target}");
                assert_eq!(r.body, first.body, "{issuer} {target}: the same document");
                assert_eq!(r.h("cache-control"), Some("public, max-age=300"));
                assert_eq!(r.h("access-control-allow-origin"), Some("*"));
                assert_eq!(r.h("content-type"), Some("application/json"));
                let h = http(&up, "HEAD", &target, &[], b"").await;
                assert_eq!((h.status, h.body.len()), (200, 0), "{target}");
                // The document, as for the first name: a parameter, a body and another method are refused.
                assert_eq!(
                    http(&up, "GET", &format!("{target}?x=1"), &[], b"")
                        .await
                        .status,
                    400,
                    "{target}"
                );
                let p = http(&up, "POST", &target, &[FORM], b"a=b").await;
                assert_eq!(
                    (p.status, p.h("allow")),
                    (405, Some("GET, HEAD")),
                    "{target}"
                );
            }
            for suffix in wrong {
                let target = format!("{name}{suffix}");
                let r = http(&up, "GET", &target, &[], b"").await;
                assert_eq!(r.status, 404, "{issuer} {target}");
                assert!(!r.text().contains("tenant") && !r.text().contains("issuer"));
            }
        }
        // Another name that starts like a well-known name is not one.
        for target in [
            "/.well-known/openid-configurationx",
            "/.well-known/oauth-authorization-serverx",
            "/.well-known/oauth-protected-resource",
            "/.well-known/openid-configuration.json",
        ] {
            assert_eq!(
                http(&up, "GET", target, &[], b"").await.status,
                404,
                "{target}"
            );
        }
    }
    // The audit front serves neither name.
    let audit = up_front(me_as("harness-forwarder", 0), Front::Audit).await;
    for name in NAMES {
        assert_eq!(
            http(&audit, "GET", name, &[], b"").await.status,
            404,
            "{name}"
        );
    }
}

/// The issuer in the discovery document is the boundary's issuer as written, whatever its form (a port, a path, capitals,
/// an escape), and an issuer that cannot be one is refused, not repaired. `session` and `exchange` put the same string in
/// `iss`; `session`'s test holds that side for the same issuers.
///
/// verifies: REQ-AUTHN-030
#[tokio::test]
async fn the_served_issuer_is_the_boundarys_issuer_byte_for_byte() {
    const ISSUERS: [&str; 3] = [
        "https://Sluis.Example.TEST:8443/tenant-a/v2",
        "https://sluis.example.test:443",
        "https://sluis.example.test/Tenant%2FA/%7e",
    ];
    for iss in ISSUERS {
        let up = up().await;
        *up.fake.issuer.lock().unwrap() = Some(iss.into());
        let d = http(&up, "GET", "/.well-known/openid-configuration", &[], b"").await;
        assert_eq!(d.status, 200, "{iss}");
        let doc: Value = serde_json::from_slice(&d.body).unwrap();
        assert_eq!(doc["issuer"].as_str().unwrap().as_bytes(), iss.as_bytes());
        assert!(
            d.text().contains(&format!("\"issuer\":\"{iss}\"")),
            "{}",
            d.text()
        );
        for endpoint in [
            "authorization_endpoint",
            "token_endpoint",
            "jwks_uri",
            "revocation_endpoint",
        ] {
            assert!(
                doc[endpoint]
                    .as_str()
                    .unwrap()
                    .starts_with(&format!("{iss}/")),
                "{endpoint}"
            );
        }
    }
    for bad in ["https://sluis.example.test/", "http://sluis.example.test"] {
        let up = up().await;
        *up.fake.issuer.lock().unwrap() = Some(bad.into());
        let d = http(&up, "GET", "/.well-known/openid-configuration", &[], b"").await;
        assert_eq!(d.status, 503, "{bad}: the issuer is not made right");
        assert!(!d.text().contains("sluis.example.test"));
    }
}

/// Every entry of the key set that `entry` serves carries `kid`, `kty`, `alg` and `use`, with the key's own value in
/// each, for every published key and not only the first.
///
/// verifies: REQ-KEYS-006
#[tokio::test]
async fn every_entry_of_the_served_key_set_carries_kid_kty_alg_use() {
    let up = up().await;
    *up.fake.extra_kid.lock().unwrap() = Some("kid-2".into());
    let r = http(&up, "GET", "/jwks", &[], b"").await;
    assert_eq!(r.status, 200);
    let set: Value = serde_json::from_slice(&r.body).unwrap();
    let keys = set["keys"].as_array().unwrap();
    assert_eq!(keys.len(), 2, "{set}");
    for (entry, kid) in keys.iter().zip(["kid-1", "kid-2"]) {
        assert_eq!(
            (
                entry["kid"].as_str(),
                entry["kty"].as_str(),
                entry["alg"].as_str(),
                entry["use"].as_str()
            ),
            (Some(kid), Some("EC"), Some("ES384"), Some("sig")),
            "{entry}"
        );
    }
}

/// verifies: REQ-KEYS-107
#[tokio::test]
async fn a_revoked_kid_is_not_in_the_published_key_set() {
    let up = up().await;
    // The ring lists `kid-1` as active; a person has revoked it. The set that is served lacks it, and the
    // discovery document is unchanged.
    up.fake.revoked.lock().unwrap().push("kid-1".into());
    let k = http(&up, "GET", "/jwks", &[], b"").await;
    assert_eq!(k.status, 200);
    let set: Value = serde_json::from_slice(&k.body).unwrap();
    assert_eq!(set, serde_json::json!({ "keys": [] }));
    let d = http(&up, "GET", "/.well-known/openid-configuration", &[], b"").await;
    assert_eq!(d.status, 200);
}

/// verifies: REQ-KEYS-089
#[tokio::test]
async fn a_key_written_to_the_ring_is_in_the_key_set_within_the_shared_cache_time() {
    // `signer` holds back the first token of a key that skipped the lead time for this long (plus a
    // margin), because `entry` serves the key set it built for this long.
    let up = up().await;
    let kids = |body: &[u8]| -> Vec<String> {
        let v: Value = serde_json::from_slice(body).unwrap();
        v["keys"]
            .as_array()
            .unwrap()
            .iter()
            .map(|k| k["kid"].as_str().unwrap().to_owned())
            .collect()
    };
    assert_eq!(
        kids(&http(&up, "GET", "/jwks", &[], b"").await.body),
        ["kid-1"]
    );
    *up.fake.extra_kid.lock().unwrap() = Some("kid-new".into());
    assert_eq!(
        kids(&http(&up, "GET", "/jwks", &[], b"").await.body),
        ["kid-1"],
        "the built set is kept, so the key is not listed yet"
    );
    tokio::time::sleep(sluis_store::KEY_SET_CACHE + Duration::from_millis(200)).await;
    assert_eq!(
        kids(&http(&up, "GET", "/jwks", &[], b"").await.body),
        ["kid-1", "kid-new"]
    );
}

/// verifies: REQ-KEYS-107
#[tokio::test]
async fn a_key_revocation_that_cannot_be_read_fails_the_key_set_closed() {
    let up = up().await;
    *up.fake.revocations_fail.lock().unwrap() = true;
    let r = http(&up, "GET", "/jwks", &[], b"").await;
    assert_eq!(r.status, 503);
    assert!(r.h("cache-control") != Some("public, max-age=300"));
    // The discovery document names no key, so it is served.
    let d = http(&up, "GET", "/.well-known/openid-configuration", &[], b"").await;
    assert_eq!(d.status, 200);
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
    let refused = http(
        &up,
        "GET",
        &format!("/authorize?{secret}=1&{secret}=2"),
        &[],
        b"",
    )
    .await;
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
    // The route is the operation, and the only peer `entry` serves is the source: the address of the person behind the forwarder
    // is not known to it and not recorded (ADR 0030, "The OCSF attributes a class requires").
    assert_eq!(t["api"], serde_json::json!({"operation": "token"}));
    assert_eq!(
        t["src_endpoint"],
        serde_json::json!({"name": "harness-forwarder"})
    );
    let a = find("entry.authorize");
    assert_eq!(a["status_code"], "duplicate_parameter");
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

/// S-3 (ADR 0030): an answered health probe writes no audit record, however often it comes and whatever was audited
/// before it; every other request writes exactly one, whether it succeeds, is refused here, is refused by the actor
/// behind, or finds no route; and a health request that is refused is not a probe and is audited.
///
/// verifies: REQ-AUDIT-161
#[tokio::test]
async fn a_health_probe_is_not_audited_and_a_real_call_is() {
    let up = up().await;
    let records = |up: &Up| up.fake.emitted.lock().unwrap().len();
    let probe = async |up: &Up| {
        for method in ["GET", "HEAD"] {
            let r = http(up, method, "/healthz", &[], b"").await;
            assert_eq!(r.status, 200, "{method}");
            assert!(r.h("sluis-correlation-id").is_some());
        }
    };
    for _ in 0..3 {
        probe(&up).await;
    }
    assert!(
        up.fake.emitted.lock().unwrap().is_empty(),
        "{:?}",
        up.fake.emitted.lock().unwrap()
    );

    // Every other request is audited once, the order of the probes among them changing nothing.
    let code = "grant_type=authorization_code&code=c&client_id=app";
    let authorize = format!("/authorize?{AUTHORIZE_Q}");
    #[allow(clippy::type_complexity)]
    let calls: [(&str, &str, &str, &[(&str, &str)], &[u8], u16); 13] = [
        ("answered", "GET", "/jwks", &[], b"", 200),
        (
            "discovery",
            "GET",
            "/.well-known/openid-configuration",
            &[],
            b"",
            200,
        ),
        (
            "discovery",
            "GET",
            "/.well-known/oauth-authorization-server",
            &[],
            b"",
            200,
        ),
        ("authorize", "GET", authorize.as_str(), &[], b"", 200),
        ("callback", "GET", "/callback?code=c&state=s", &[], b"", 200),
        ("token", "POST", "/token", &[FORM], code.as_bytes(), 200),
        ("an unknown parameter", "GET", "/jwks?x=1", &[], b"", 400),
        ("a wrong method", "DELETE", "/jwks", &[], b"", 405),
        ("no route", "GET", "/no/such/path", &[], b"", 404),
        (
            "a readiness path is no route",
            "GET",
            "/readyz",
            &[],
            b"",
            404,
        ),
        (
            "a wrong media type",
            "POST",
            "/token",
            &[],
            code.as_bytes(),
            415,
        ),
        (
            "a refused health request: method",
            "POST",
            "/healthz",
            &[],
            b"",
            405,
        ),
        (
            "a refused health request: query",
            "GET",
            "/healthz?x=1",
            &[],
            b"",
            400,
        ),
    ];
    for (n, (what, method, path, headers, body, status)) in calls.into_iter().enumerate() {
        let before = records(&up);
        let r = http(&up, method, path, headers, body).await;
        assert_eq!(r.status, status, "{what}");
        assert_eq!(records(&up), before + 1, "{what}: one record");
        let rec = up.fake.emitted.lock().unwrap().last().unwrap().clone();
        assert_eq!(
            rec["metadata"]["correlation_uid"].as_str(),
            r.h("sluis-correlation-id"),
            "{what}: the record is of this request ({n})"
        );
        probe(&up).await;
        assert_eq!(
            records(&up),
            before + 1,
            "{what}: the probes after it add none"
        );
    }
    // A health request with a body is refused and audited too; so is a call that the actor behind refuses.
    let before = records(&up);
    assert_eq!(http(&up, "GET", "/healthz", &[], b"x=1").await.status, 400);
    *up.fake.error.lock().unwrap() = Some((ErrorCode::Internal, "x"));
    assert_eq!(http(&up, "GET", &authorize, &[], b"").await.status, 500);
    assert_eq!(records(&up), before + 2);
    let recs = up.fake.emitted.lock().unwrap().clone();
    let health: Vec<&Value> = recs
        .iter()
        .filter(|r| r["metadata"]["event_code"] == "entry.health")
        .collect();
    assert_eq!(health.len(), 3, "{health:?}");
    assert!(health.iter().all(|r| r["status_id"] == 2));
}

#[tokio::test]
async fn the_socket_has_the_asked_for_mode() {
    use std::os::unix::fs::PermissionsExt;
    let up = up().await;
    let mode = std::fs::metadata(&up.socket).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
}

/// verifies: REQ-AUDIT-188
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
        // A connection from a peer that is not the forwarder names the peer by its registry name, `unknown` for a uid the
        // registry does not know, and never an address.
        assert_eq!(recs[0]["api"]["operation"], "connection");
        let who = recs[0]["src_endpoint"]["name"].as_str().unwrap();
        assert!(who == name || who == "unknown", "{who} for {name}@{block}");
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

/// A form_post page as `session` makes it: an HTML 200 that names the web origin of the redirect_uri it posts to.
fn form_post_page(origin: &str) -> HttpReply {
    HttpReply {
        form_post_origin: origin.into(),
        ..reply(200, &[("Content-Type", "text/html; charset=utf-8")])
    }
}

/// The page that posts a code to the client gets a policy that allows its one script by the script's hash, and a
/// `form-action` of the origin of the redirect_uri of that response, which differs from one response to the next.
/// Nothing else gets the relaxed policy: not HTML with no origin, not another status, type or route. An origin that is
/// more than an origin is a server error, and the answer is the same fixed body.
///
/// verifies: REQ-AUTHN-059, REQ-AUTHN-079
#[tokio::test]
async fn a_form_post_page_gets_a_form_action_of_its_own_origin_and_nothing_else_does() {
    let up = up().await;
    let q = format!("/authorize?{AUTHORIZE_Q}&response_mode=form_post");
    for (origin, route) in [
        ("https://app.example.test", q.as_str()),
        ("http://127.0.0.1:43210", "/callback?code=c"),
        ("https://[2001:db8::7]:8443", q.as_str()),
    ] {
        *up.fake.reply.lock().unwrap() = Some(form_post_page(origin));
        let r = http(&up, "GET", route, &[], b"").await;
        assert_eq!(r.status, 200, "{origin}");
        let csp = r.h("content-security-policy").unwrap();
        assert!(
            csp.contains("script-src 'sha256-") && !csp.contains("unsafe-inline"),
            "{csp}"
        );
        assert!(csp.contains("frame-ancestors 'none'"), "{csp}");
        assert!(csp.contains("default-src 'none'"), "{csp}");
        assert!(
            csp.ends_with(&format!("; form-action {origin}")),
            "{origin}: {csp}"
        );
        assert_eq!(csp.matches("form-action").count(), 1, "{csp}");
        assert!(!csp.contains("'self'"), "{csp}");
    }
    let strict = |r: &Resp| {
        let csp = r.h("content-security-policy").unwrap();
        assert!(
            csp.contains("form-action 'self'") && !csp.contains("script-src"),
            "{csp}"
        );
    };
    // HTML with no origin, JSON on the same route, an error page, and HTML on the token route keep the strict policy.
    let page = |ct: &str| reply(200, &[("Content-Type", ct)]);
    *up.fake.reply.lock().unwrap() = Some(page("text/html; charset=utf-8"));
    strict(&http(&up, "GET", &q, &[], b"").await);
    *up.fake.reply.lock().unwrap() = Some(HttpReply {
        form_post_origin: "https://app.example.test".into(),
        ..page("application/json")
    });
    strict(&http(&up, "GET", &q, &[], b"").await);
    *up.fake.reply.lock().unwrap() = Some(HttpReply {
        form_post_origin: "https://app.example.test".into(),
        ..reply(400, &[("Content-Type", "text/html")])
    });
    strict(&http(&up, "GET", &q, &[], b"").await);
    *up.fake.reply.lock().unwrap() = Some(form_post_page("https://app.example.test"));
    strict(&post_token(&up, "grant_type=refresh_token&refresh_token=r").await);
    // An origin that is more than an origin is not repaired.
    let hostile = [
        "https://app.example.test; script-src *",
        "https://app.example.test/cb",
        "https://app.example.test https://evil.example.test",
        "*",
    ];
    let mut bodies = Vec::new();
    for origin in hostile {
        *up.fake.reply.lock().unwrap() = Some(form_post_page(origin));
        let r = http(&up, "GET", &q, &[], b"").await;
        assert_eq!(r.status, 500, "{origin}");
        assert!(!r.text().contains("evil"), "{origin}");
        strict(&r);
        bodies.push(r.body);
    }
    assert!(bodies.windows(2).all(|w| w[0] == w[1]));
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

/// Discovery lists RS256 in `id_token_signing_alg_values_supported` only while the ring holds an active RS256 key that
/// `KeyRevocation` does not list, and the key set lists the RSA key in every published state, as an RSA entry with `n` and
/// `e` and no `x5c`. With no RSA key, a pre-published, a retiring or a revoked one, the document says ES384 alone.
///
/// verifies: REQ-AUTHN-108
#[tokio::test]
async fn discovery_lists_rs256_only_while_an_rs256_key_is_active() {
    let alg_values = |doc: &Value| -> Vec<String> {
        doc["id_token_signing_alg_values_supported"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_owned())
            .collect()
    };
    // (state of the RSA key, revoked, listed in discovery, in the key set)
    for (state, revoked, listed, in_set) in [
        (None, false, false, false),
        (Some("pre-published"), false, false, true),
        (Some("active"), false, true, true),
        (Some("retiring"), false, false, true),
        (Some("dropped"), false, false, false),
        (Some("active"), true, false, false),
    ] {
        let up = up().await;
        if let Some(state) = state {
            *up.fake.rsa.lock().unwrap() = Some(("-rsa-kid".into(), state.into()));
        }
        if revoked {
            up.fake.revoked.lock().unwrap().push("-rsa-kid".into());
        }
        let d = http(&up, "GET", "/.well-known/openid-configuration", &[], b"").await;
        assert_eq!(d.status, 200);
        let doc: Value = serde_json::from_slice(&d.body).unwrap();
        let want: Vec<String> = if listed {
            vec!["ES384".into(), "RS256".into()]
        } else {
            vec!["ES384".into()]
        };
        assert_eq!(alg_values(&doc), want, "state {state:?}, revoked {revoked}");
        let k = http(&up, "GET", "/jwks", &[], b"").await;
        let set: Value = serde_json::from_slice(&k.body).unwrap();
        let rsa: Vec<&Value> = set["keys"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|k| k["kty"] == "RSA")
            .collect();
        assert_eq!(
            !rsa.is_empty(),
            in_set,
            "state {state:?}, revoked {revoked}"
        );
        for k in rsa {
            assert_eq!(
                (k["kid"].as_str(), k["alg"].as_str(), k["e"].as_str()),
                (Some("-rsa-kid"), Some("RS256"), Some("AQAB"))
            );
            assert!(k.get("x5c").is_none(), "{k}");
            assert_eq!(k["n"].as_str().map(str::len), Some(342));
        }
        // The EC key is in every one of them, whatever the RSA key does.
        assert_eq!(set["keys"][0]["kid"], "kid-1");
    }
    // Revocations that cannot be read: the key set is withheld, and the document does not promise RS256.
    let up = up().await;
    *up.fake.rsa.lock().unwrap() = Some(("-rsa-kid".into(), "active".into()));
    *up.fake.revocations_fail.lock().unwrap() = true;
    let d = http(&up, "GET", "/.well-known/openid-configuration", &[], b"").await;
    let doc: Value = serde_json::from_slice(&d.body).unwrap();
    assert_eq!(alg_values(&doc), ["ES384"]);
    assert_eq!(http(&up, "GET", "/jwks", &[], b"").await.status, 503);
}
