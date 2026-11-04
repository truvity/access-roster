#![allow(refining_impl_trait)] // the generated trait returns `impl Encodable`; a concrete type is fine
#![allow(clippy::unwrap_used, clippy::expect_used)] // a failed unwrap in a test is the failure
//! The typed client against an in-memory `StoreService` over a Unix socket, and the address
//! vectors of store-api.md "Address encoding".

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use connectrpc::error::ErrorCode;
use connectrpc::{RequestContext, Response, Router, ServiceRequest, ServiceResult, ServiceStream};
use sluis_kit::{Allow, Identities, ServerConfig, dial, refusal};
use sluis_proto::sluis::store::v2alpha1::Provenance;
use sluis_proto::sluis::store::v2alpha1::{
    GetRequest, GetResponse, Item as WireItem, ListRequest, ListResponse, StoreService,
    StoreServiceExt, Verb, WatchRequest, WatchResponse, WriteRequest, WriteResponse,
};
use sluis_store::{Error, Kind, Store, WriteOpts, segment_of, validate_address, validate_id};

/// A tenant-scoped kind, with any message as its value.
struct Person;
impl Kind for Person {
    type Id = String;
    type Value = Provenance;
    const NAME: &'static str = "Person";
}

/// A kind with no tenant.
struct Lease;
impl Kind for Lease {
    type Id = String;
    type Value = Provenance;
    const NAME: &'static str = "Lease";
}

struct Nope;
impl Kind for Nope {
    type Id = String;
    type Value = Provenance;
    const NAME: &'static str = "NotInTheRegistry";
}

type Key = (String, String, String);

#[derive(Default)]
struct Mem {
    items: Mutex<BTreeMap<Key, (u64, Vec<u8>)>>,
    last_grant: Mutex<Vec<u8>>,
}

fn key(a: &sluis_proto::sluis::r#type::v2alpha1::Address) -> Key {
    (a.kind.clone(), a.tenant.clone(), a.id.clone())
}

fn wire(k: &Key, v: u64, value: &[u8]) -> WireItem {
    WireItem {
        address: sluis_proto::sluis::r#type::v2alpha1::Address {
            kind: k.0.clone(),
            tenant: k.1.clone(),
            id: k.2.clone(),
            ..Default::default()
        }
        .into(),
        version: v,
        value: value.to_vec(),
        ..WireItem::default()
    }
}

impl StoreService for Mem {
    async fn get(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, GetRequest>,
    ) -> ServiceResult<GetResponse> {
        let k = key(&request.to_owned_message().address);
        let items = self.items.lock().unwrap();
        match items.get(&k) {
            Some((v, bytes)) => Response::ok(GetResponse {
                item: wire(&k, *v, bytes).into(),
                ..Default::default()
            }),
            None => Err(refusal(ErrorCode::NotFound, "absent", "address")),
        }
    }

    async fn list(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, ListRequest>,
    ) -> ServiceResult<ListResponse> {
        let r = request.to_owned_message();
        let from: usize = r.page_token.parse().unwrap_or(0);
        let items = self.items.lock().unwrap();
        let all: Vec<_> = items
            .iter()
            .filter(|(k, _)| k.0 == r.kind && k.1 == r.tenant)
            .map(|(k, (v, b))| wire(k, *v, b))
            .collect();
        let page: Vec<_> = all.iter().skip(from).take(2).cloned().collect();
        let next = if from + 2 < all.len() {
            (from + 2).to_string()
        } else {
            String::new()
        };
        Response::ok(ListResponse {
            items: page,
            next_page_token: next,
            ..Default::default()
        })
    }

    async fn write(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, WriteRequest>,
    ) -> ServiceResult<WriteResponse> {
        let r = request.to_owned_message();
        *self.last_grant.lock().unwrap() = r.grant.clone();
        let mut items = self.items.lock().unwrap();
        let mut out = Vec::new();
        for op in &r.operations {
            let k = key(&op.address);
            let cur = items.get(&k).map(|(v, _)| *v);
            match op.verb.as_known() {
                Some(Verb::CREATE) => {
                    if cur.is_some() {
                        return Err(refusal(ErrorCode::AlreadyExists, "taken", "address"));
                    }
                    items.insert(k.clone(), (1, op.value.clone()));
                    out.push(wire(&k, 1, &op.value));
                }
                Some(Verb::UPDATE) => {
                    if cur != Some(op.if_version) {
                        return Err(refusal(
                            ErrorCode::Aborted,
                            "version",
                            "operations[0].if_version",
                        ));
                    }
                    let v = op.if_version + 1;
                    items.insert(k.clone(), (v, op.value.clone()));
                    out.push(wire(&k, v, &op.value));
                }
                Some(Verb::APPLY) => {
                    let v = cur.unwrap_or(0) + 1;
                    items.insert(k.clone(), (v, op.value.clone()));
                    out.push(wire(&k, v, &op.value));
                }
                Some(Verb::DELETE) => {
                    if op.if_version != 0 && cur != Some(op.if_version) {
                        return Err(refusal(
                            ErrorCode::Aborted,
                            "version",
                            "operations[0].if_version",
                        ));
                    }
                    items.remove(&k);
                }
                _ => {
                    return Err(refusal(
                        ErrorCode::InvalidArgument,
                        "batch",
                        "operations[0].verb",
                    ));
                }
            }
        }
        Response::ok(WriteResponse {
            items: out,
            ..Default::default()
        })
    }

    async fn watch(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, WatchRequest>,
    ) -> ServiceResult<ServiceStream<WatchResponse>> {
        Err(refusal(ErrorCode::Unimplemented, "unsupported", ""))
    }
}

struct Up {
    mem: Arc<Mem>,
    client: sluis_kit::Client,
    stop: tokio::sync::oneshot::Sender<()>,
    done: tokio::task::JoinHandle<anyhow::Result<()>>,
}

async fn up(dir: &Path) -> Up {
    let socket = dir.join("store.sock");
    let mem = Arc::new(Mem::default());
    let router = Arc::clone(&mem).register(Router::new());
    let me = rustix::process::geteuid().as_raw();
    let ids = Identities::with(0, move |u| (u == me).then_some(("session", 0)));
    let cfg = ServerConfig {
        actor: "store",
        boundary: "dev".into(),
        socket: socket.clone(),
        mode: 0o660,
        socket_gid: None,
        allow: Allow::Exact("session"),
        default_deadline: Duration::from_secs(5),
    };
    let (stop, rx) = tokio::sync::oneshot::channel::<()>();
    let done = tokio::spawn(sluis_kit::serve_with(
        cfg,
        router,
        async move {
            let _ = rx.await;
        },
        ids,
    ));
    for _ in 0..200 {
        if socket.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    Up {
        mem,
        client: dial(&socket),
        stop,
        done,
    }
}

fn prov(path: &str) -> Provenance {
    Provenance {
        field_path: path.into(),
        version: 3,
        ..Default::default()
    }
}

#[tokio::test]
async fn create_get_update_apply_delete_and_the_refusals() {
    let dir = tempfile::tempdir().unwrap();
    let up = up(dir.path()).await;
    let s = Store::<Person>::new(up.client.clone()).unwrap();

    let made = s
        .create("acme", "q7x2m5nt", &prov("a"), WriteOpts::default())
        .await
        .unwrap();
    assert_eq!(
        (made.version, made.tenant.as_str(), made.id.as_str()),
        (1, "acme", "q7x2m5nt")
    );
    assert_eq!(made.value, prov("a"));

    assert!(matches!(
        s.create("acme", "q7x2m5nt", &prov("b"), WriteOpts::default())
            .await,
        Err(Error::Exists)
    ));

    let got = s.get("acme", "q7x2m5nt").await.unwrap();
    assert_eq!(got.value, prov("a"));
    assert!(matches!(
        s.get("acme", "missing").await,
        Err(Error::NotFound)
    ));

    let upd = s
        .update("acme", "q7x2m5nt", &prov("c"), 1, WriteOpts::default())
        .await
        .unwrap();
    assert_eq!(upd.version, 2);
    assert!(matches!(
        s.update("acme", "q7x2m5nt", &prov("d"), 1, WriteOpts::default())
            .await,
        Err(Error::Version)
    ));

    let applied = s
        .apply("acme", "other", &prov("e"), WriteOpts::default())
        .await
        .unwrap();
    assert_eq!(applied.version, 1);
    assert_eq!(
        s.apply("acme", "other", &prov("f"), WriteOpts::default())
            .await
            .unwrap()
            .version,
        2
    );

    assert!(matches!(
        s.delete("acme", "other", Some(1), WriteOpts::default())
            .await,
        Err(Error::Version)
    ));
    s.delete("acme", "other", Some(2), WriteOpts::default())
        .await
        .unwrap();
    assert!(matches!(s.get("acme", "other").await, Err(Error::NotFound)));
    s.delete("acme", "q7x2m5nt", None, WriteOpts::default())
        .await
        .unwrap();

    // The grant travels with the write.
    let w = WriteOpts {
        grant: Some(vec![1, 2, 3]),
        ..WriteOpts::default()
    };
    s.create("acme", "g", &prov("g"), w).await.unwrap();
    assert_eq!(*up.mem.last_grant.lock().unwrap(), vec![1, 2, 3]);

    drop(up.client);
    let _ = up.stop.send(());
    up.done.await.unwrap().unwrap();
}

#[tokio::test]
async fn list_pages_and_the_tenant_rules() {
    let dir = tempfile::tempdir().unwrap();
    let up = up(dir.path()).await;
    let p = Store::<Person>::new(up.client.clone()).unwrap();
    for i in 0..5 {
        p.create("acme", &format!("id-{i}"), &prov("x"), WriteOpts::default())
            .await
            .unwrap();
    }
    let (first, next) = p.list("acme", None).await.unwrap();
    assert_eq!(first.len(), 2);
    let mut all = first;
    let mut token = next;
    while let Some(t) = token {
        let (page, next) = p.list("acme", Some(t)).await.unwrap();
        all.extend(page);
        token = next;
    }
    let ids: Vec<_> = all.iter().map(|i| i.id.as_str()).collect();
    assert_eq!(ids, ["id-0", "id-1", "id-2", "id-3", "id-4"]);

    // A kind with a tenant needs one; a kind with none refuses one; "-" is never a tenant id.
    assert!(matches!(p.get("", "x").await, Err(Error::Address(f)) if f == "tenant"));
    assert!(matches!(p.get("-", "x").await, Err(Error::Address(f)) if f == "tenant"));
    let l = Store::<Lease>::new(up.client.clone()).unwrap();
    assert!(
        matches!(l.get("acme", "adapter-github/sync").await, Err(Error::Address(f)) if f == "tenant")
    );
    assert!(matches!(l.get("-", "x").await, Err(Error::Address(f)) if f == "tenant"));
    l.create("", "adapter-github/sync", &prov("l"), WriteOpts::default())
        .await
        .unwrap();
    // The tenant of a kind with none is empty on the wire.
    assert_eq!(l.get("", "adapter-github/sync").await.unwrap().tenant, "");

    // A bad id never reaches the wire.
    assert!(matches!(p.get("acme", "Bad").await, Err(Error::Address(f)) if f == "id[0]"));
    assert!(matches!(
        Store::<Nope>::new(up.client.clone()),
        Err(Error::UnknownKind("NotInTheRegistry"))
    ));

    let _ = up.stop.send(());
    up.done.await.unwrap().unwrap();
}

/// The language-neutral vectors both kits read (`kits/conformance/kit/store-address-vectors.json`).
fn vectors() -> serde_json::Value {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../conformance/kit/store-address-vectors.json");
    serde_json::from_slice(&std::fs::read(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display())))
        .unwrap()
}

#[test]
fn the_shared_vectors_hold() {
    let v = vectors();
    let valid = v["valid"].as_array().unwrap();
    let invalid = v["invalid"].as_array().unwrap();
    let segments = v["segments"].as_array().unwrap();
    assert!(
        !valid.is_empty() && !invalid.is_empty() && !segments.is_empty(),
        "an empty sweep proves nothing"
    );
    for a in valid {
        let a = a.as_str().unwrap();
        validate_address(a).unwrap_or_else(|e| panic!("{a}: {e}"));
    }
    for c in invalid {
        let a = c["address"].as_str().unwrap();
        assert!(
            validate_address(a).is_err(),
            "{a:?} must be refused: {}",
            c["why"]
        );
    }
    for s in segments {
        assert_eq!(
            segment_of(s["kind"].as_str().unwrap()),
            s["segment"].as_str().unwrap()
        );
    }
}

#[test]
fn id_vectors_of_store_api_address_encoding() {
    for ok in [
        "q7x2m5nt4kz3c6vdp9ba8hwrfe",
        "data/1/board-a",
        "adapter-github/sync",
        "a.b_c-d",
        &"a".repeat(128),
    ] {
        validate_id(ok).unwrap_or_else(|e| panic!("{ok}: {e}"));
    }
    for bad in [
        "",
        "Acme",
        "../x",
        "a/../x",
        "a//x",
        "a/",
        "/a",
        "a b",
        ".",
        "..",
        "a/.",
        "é",
        &"a".repeat(129),
    ] {
        assert!(validate_id(bad).is_err(), "{bad:?} must be refused");
    }
    // The error names a path, never the value.
    let Err(Error::Address(path)) = validate_id("ok/Bad Value") else {
        panic!("must be refused")
    };
    assert_eq!(path, "id[1]");
    assert!(!path.contains("Bad"));
}

#[test]
fn address_vectors_of_store_api_address_encoding() {
    for ok in [
        "prod/acme/session-chain/q7x2m5nt4kz3c6vdp9ba8hwrfe",
        "prod/acme/data-key-wrap/data/1/board-a",
        "prod/-/lease/adapter-github/sync",
    ] {
        validate_address(ok).unwrap_or_else(|e| panic!("{ok}: {e}"));
    }
    for bad in [
        "prod/Acme/person/x",
        "prod/acme/person/../x",
        "prod/acme/person//x",
        "prod/acme/person/x/",
        "prod/acme/person/a b",
        "prod/acme/person",
        &format!("prod/acme/person/{}", "a".repeat(129)),
        // 300 bytes is the limit (below); 301 is refused.
        &format!(
            "prod/acme/person/{}",
            ["a".repeat(100), "a".repeat(100), "a".repeat(82)].join("/")
        ),
    ] {
        assert!(validate_address(bad).is_err(), "{bad:?} must be refused");
    }
    let exactly_300 = format!(
        "prod/acme/person/{}",
        ["a".repeat(100), "a".repeat(100), "a".repeat(81)].join("/")
    );
    assert_eq!(exactly_300.len(), 300);
    validate_address(&exactly_300).expect("300 bytes is the limit");
}

#[test]
fn segments_follow_the_rule_and_equal_the_registry_for_every_kind() {
    assert_eq!(segment_of("DataKeyWrap"), "data-key-wrap");
    assert_eq!(segment_of("SessionChain"), "session-chain");
    assert_eq!(segment_of("Lease"), "lease");
    assert_eq!(
        segment_of("PredefinedPolicyLinkTemporary"),
        "predefined-policy-link-temporary"
    );
    let kinds = sluis_registry::kinds();
    assert!(!kinds.is_empty(), "an empty sweep proves nothing");
    for k in kinds {
        assert_eq!(segment_of(k.name), k.segment, "segment of {}", k.name);
    }
}
