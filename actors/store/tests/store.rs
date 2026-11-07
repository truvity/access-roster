#![allow(clippy::unwrap_used, clippy::expect_used)] // a failed unwrap in a test is the failure
//! The rules of store@ on every call, over the kit's transport: the address vectors of
//! store-api.md, the scope refusals, each refusal reason, the grant check, TTL, batches, versions,
//! expiry and the config class.

mod common;

use std::sync::atomic::Ordering;

use common::*;
use connectrpc::error::ErrorCode;
use sluis_proto::sluis::store::v2alpha1::{
    Consistency, GetRequest, GetResponse, ListRequest, Verb,
};

const WRITES: [&str; 4] = ["create", "update", "delete", "apply"];

fn g(f: &F) -> Vec<u8> {
    f.grant("session", &["acme"], &WRITES, 60)
}

// ---- address and scope ----

/// verifies: REQ-DATA-001
/// A kind that the registry does not declare is refused by every call that names one: a read, a listing, a write and
/// a watch, with the reason `address` and the path of the kind.
#[tokio::test]
async fn a_kind_the_registry_does_not_declare_is_refused_by_every_call() {
    let f = F::new().await;
    f.as_("session");
    let e = f.get("no-such-kind", "acme", "x").await.unwrap_err();
    assert_eq!(
        (e.code, reason(&e)),
        (ErrorCode::InvalidArgument, "address".into())
    );
    assert_eq!(common::refusal_path(&e), "address.kind");
    let e = f
        .list(ListRequest {
            kind: "no-such-kind".into(),
            ..ListRequest::default()
        })
        .await
        .unwrap_err();
    assert_eq!(
        (e.code, reason(&e)),
        (ErrorCode::InvalidArgument, "address".into())
    );
    let e = f
        .write(
            vec![op(Verb::CREATE, "no-such-kind", "acme", "x", b"v")],
            &g(&f),
        )
        .await
        .unwrap_err();
    assert_eq!(
        (e.code, reason(&e)),
        (ErrorCode::InvalidArgument, "address".into())
    );
    f.as_("key");
    let e = f.watch("no-such-kind", "", 0).await.err().unwrap();
    assert_eq!(
        (e.code, reason(&e)),
        (ErrorCode::InvalidArgument, "address".into())
    );
}

#[tokio::test]
async fn the_address_vectors_are_refused_with_the_path_of_the_part() {
    let f = F::new().await;
    f.as_("session");
    for (tenant, id, path) in [
        ("Acme", "x", "address.tenant"),
        ("acme", "a b", "address.id[0]"),
        ("acme", "..", "address.id[0]"),
        ("acme", "x/../y", "address.id[1]"),
        ("acme", "x//y", "address.id[1]"),
        ("acme", "x/", "address.id[1]"),
        ("acme", "", "address.id[0]"),
        ("acme", &"a".repeat(129), "address.id[0]"),
        // 301 bytes: each part valid, the whole too long
        (
            "acme",
            &format!("{}/{}/{}", "a".repeat(128), "b".repeat(128), "c".repeat(40)),
            "address",
        ),
    ] {
        let e = f.get("person", tenant, id).await.unwrap_err();
        assert_eq!(
            (e.code, reason(&e)),
            (ErrorCode::InvalidArgument, "address".into()),
            "{tenant} {id:.10}"
        );
        let detail = common::refusal_path(&e);
        assert_eq!(detail, path, "{tenant} {id:.10}");
        // An error never shows a value.
        assert!(!e.to_string().contains("a b"), "{e}");
    }
    // The valid ones of the table reach the engine and are absent.
    for id in [
        "q7x2m5nt4kz3c6vdp9ba8hwrfe",
        "data/1/board-a",
        "adapter-github/sync",
    ] {
        refused(
            f.get("person", "acme", id).await,
            ErrorCode::NotFound,
            "absent",
        );
    }
    // An unknown kind and a malformed segment.
    refused(
        f.get("no-such-kind", "acme", "x").await,
        ErrorCode::InvalidArgument,
        "address",
    );
    refused(
        f.get("Person", "acme", "x").await,
        ErrorCode::InvalidArgument,
        "address",
    );
}

#[tokio::test]
async fn the_kinds_scope_is_enforced_both_ways() {
    let f = F::new().await;
    f.as_("session");
    // A tenant-scoped kind with the tenant `-` or none, a boundary kind with a tenant.
    refused(
        f.get("person", "-", "x").await,
        ErrorCode::InvalidArgument,
        "address",
    );
    refused(
        f.get("person", "", "x").await,
        ErrorCode::InvalidArgument,
        "address",
    );
    f.as_("exchange");
    refused(
        f.get("lease", "acme", "exchange/x").await,
        ErrorCode::InvalidArgument,
        "address",
    );
    refused(
        f.get("lease", "-", "exchange/x").await,
        ErrorCode::InvalidArgument,
        "address",
    );
    // The same rule on a write and on a list.
    f.as_("session");
    refused(
        f.write(vec![op(Verb::CREATE, "person", "", "x", &sealed())], &[])
            .await,
        ErrorCode::InvalidArgument,
        "address",
    );
    let e = f
        .list(ListRequest {
            kind: "person".into(),
            tenant: "-".into(),
            ..ListRequest::default()
        })
        .await;
    refused(e, ErrorCode::InvalidArgument, "address");
}

// ---- rules and writers ----

/// verifies: REQ-DATA-047
#[tokio::test]
async fn no_rule_means_denied_and_the_refusal_is_audited_without_the_id() {
    let f = F::new().await;
    // exporter reads Person but never writes it.
    f.as_("exporter");
    refused(
        f.write(
            vec![op(
                Verb::CREATE,
                "person",
                "acme",
                "secret-looking-id",
                &sealed(),
            )],
            &g(&f),
        )
        .await,
        ErrorCode::PermissionDenied,
        "rule",
    );
    // An actor with no rule on the kind at all.
    f.as_("quota");
    refused(
        f.get("person", "acme", "x").await,
        ErrorCode::PermissionDenied,
        "rule",
    );
    let events = f.audit();
    assert_eq!(events.len(), 2, "{events:?}");
    let e = &events[0];
    assert_eq!(
        (e.action, e.failure, e.reason.as_str()),
        ("store.refused", true, "rule")
    );
    assert_eq!(
        e.fields,
        vec![
            ("caller", "exporter".to_owned()),
            ("kind", "Person".to_owned()),
            ("verb", "create".to_owned()),
            ("code", "permission_denied".to_owned())
        ]
    );
    assert!(!format!("{events:?}").contains("secret-looking-id"));
}

/// verifies: REQ-DATA-005
#[tokio::test]
async fn a_self_scoped_kind_takes_only_ids_under_the_callers_name() {
    let f = F::new().await;
    f.as_("exchange");
    // ReplayGuard is self-scoped: the id starts with the writing actor.
    let ok = with_ttl(
        op(Verb::CREATE, "replay-guard", "", "exchange/jti-1", b"h"),
        60,
    );
    f.write(vec![ok], &[]).await.unwrap();
    for id in ["session/jti-1", "exchangex/jti", "exchange", "jti-1"] {
        let bad = with_ttl(op(Verb::CREATE, "replay-guard", "", id, b"h"), 60);
        refused(
            f.write(vec![bad], &[]).await,
            ErrorCode::PermissionDenied,
            "writer",
        );
    }
    // Reads are bound the same way.
    refused(
        f.get("replay-guard", "", "session/jti-1").await,
        ErrorCode::PermissionDenied,
        "writer",
    );
    assert!(f.get("replay-guard", "", "exchange/jti-1").await.is_ok());
    // A spent grant is tenant-scoped and self-scoped: both rules apply.
    let spent = with_ttl(
        op(Verb::CREATE, "spent-grant", "acme", "session/g1", b"h"),
        60,
    );
    refused(
        f.write(vec![spent], &g(&f)).await,
        ErrorCode::PermissionDenied,
        "writer",
    );
}

// ---- the grant ----

/// verifies: REQ-DATA-026, REQ-DATA-027
#[tokio::test]
async fn a_tenant_write_without_a_good_grant_is_refused() {
    let f = F::new().await;
    f.as_("session");
    let one = |t: &str| vec![op(Verb::CREATE, "person", t, "p1", &sealed())];

    // missing
    refused(
        f.write(one("acme"), &[]).await,
        ErrorCode::PermissionDenied,
        "grant",
    );
    // not a grant key@ opens
    refused(
        f.write(one("acme"), b"garbage").await,
        ErrorCode::PermissionDenied,
        "grant",
    );
    // for another tenant
    let other = f.grant("session", &["globex"], &WRITES, 60);
    refused(
        f.write(one("acme"), &other).await,
        ErrorCode::PermissionDenied,
        "grant",
    );
    // made for another actor
    let held = f.grant("exchange", &["acme"], &WRITES, 60);
    refused(
        f.write(one("acme"), &held).await,
        ErrorCode::PermissionDenied,
        "grant",
    );
    // another boundary
    let b = f.grant_with(|g| g.boundary = "prod".into());
    refused(
        f.write(one("acme"), &b).await,
        ErrorCode::PermissionDenied,
        "grant",
    );
    // not allowing the verb
    let v = f.grant("session", &["acme"], &["update", "delete", "apply"], 60);
    refused(
        f.write(one("acme"), &v).await,
        ErrorCode::PermissionDenied,
        "grant",
    );
    // every tenant is for audit reads; a write never accepts it
    let star = f.grant("session", &["*"], &WRITES, 60);
    refused(
        f.write(one("acme"), &star).await,
        ErrorCode::PermissionDenied,
        "grant",
    );
    let star_and = f.grant("session", &["acme", "*"], &WRITES, 60);
    refused(
        f.write(one("acme"), &star_and).await,
        ErrorCode::PermissionDenied,
        "grant",
    );
    // no expiry at all
    let none = f.grant_with(|g| g.expires_at = Default::default());
    refused(
        f.write(one("acme"), &none).await,
        ErrorCode::PermissionDenied,
        "grant",
    );
    // expired
    let old = f.grant("session", &["acme"], &WRITES, -1);
    refused(
        f.write(one("acme"), &old).await,
        ErrorCode::PermissionDenied,
        "grant",
    );
    // nothing was written by any of them
    assert!(f.durable.keys().is_empty());

    // a good one
    let ok = g(&f);
    f.write(one("acme"), &ok).await.unwrap();
    assert_eq!(f.durable.keys(), ["dev/acme/person/p1"]);
}

#[tokio::test]
async fn a_grant_expiring_between_two_requests_is_not_served_from_the_cache() {
    let f = F::new().await;
    f.as_("session");
    let grant = f.grant("session", &["acme"], &WRITES, 30);
    f.write(
        vec![op(Verb::CREATE, "person", "acme", "p1", &sealed())],
        &grant,
    )
    .await
    .unwrap();
    f.advance(31);
    refused(
        f.write(
            vec![op(Verb::CREATE, "person", "acme", "p2", &sealed())],
            &grant,
        )
        .await,
        ErrorCode::PermissionDenied,
        "grant",
    );
}

#[tokio::test]
async fn a_batch_costs_one_open_of_the_grant() {
    let f = F::new().await;
    f.as_("session");
    let grant = g(&f);
    let ops = vec![
        op(Verb::CREATE, "person", "acme", "p1", &sealed()),
        op(Verb::CREATE, "person", "acme", "p2", &sealed()),
        op(Verb::CREATE, "person", "acme", "p3", &sealed()),
    ];
    f.write(ops, &grant).await.unwrap();
    assert_eq!(f.key.opens.load(Ordering::SeqCst), 1);
    // The next write of the same request is served from the cache until the grant expires.
    f.write(
        vec![op(Verb::CREATE, "person", "acme", "p4", &sealed())],
        &grant,
    )
    .await
    .unwrap();
    assert_eq!(f.key.opens.load(Ordering::SeqCst), 1);
}

/// verifies: REQ-DATA-026
#[tokio::test]
async fn one_operation_for_another_tenant_refuses_the_whole_batch() {
    let f = F::new().await;
    f.as_("session");
    let ops = vec![
        op(Verb::CREATE, "person", "acme", "p1", &sealed()),
        op(Verb::CREATE, "person", "globex", "p2", &sealed()),
    ];
    refused(
        f.write(ops, &g(&f)).await,
        ErrorCode::PermissionDenied,
        "grant",
    );
    assert!(f.durable.keys().is_empty());
}

#[tokio::test]
async fn key_unreachable_fails_closed() {
    let f = F::new().await;
    f.as_("session");
    f.key.down.store(true, Ordering::SeqCst);
    refused(
        f.write(
            vec![op(Verb::CREATE, "person", "acme", "p1", &sealed())],
            &g(&f),
        )
        .await,
        ErrorCode::Unavailable,
        "engine",
    );
    assert!(f.durable.keys().is_empty());
}

/// verifies: REQ-DATA-027
#[tokio::test]
async fn a_boundary_scoped_write_needs_no_grant() {
    let f = F::new().await;
    f.as_("exchange");
    f.write(
        vec![with_ttl(
            op(Verb::CREATE, "replay-guard", "", "exchange/a", b"h"),
            60,
        )],
        &[],
    )
    .await
    .unwrap();
    assert_eq!(f.key.opens.load(Ordering::SeqCst), 0);
}

// ---- key@'s DataKeyWrap ----

#[tokio::test]
async fn key_writes_its_wraps_without_a_grant_at_a_tenant_and_at_the_boundary() {
    let f = F::new().await;
    f.as_("key");
    // A tenant's wrap, and the boundary's own wraps at no tenant: one atomic batch.
    let ops = vec![
        op(
            Verb::CREATE,
            "data-key-wrap",
            "acme",
            "data/1/node-1-aaaa",
            b"wrap-1",
        ),
        op(
            Verb::CREATE,
            "data-key-wrap",
            "acme",
            "data/1/node-2-bbbb",
            b"wrap-2",
        ),
        op(
            Verb::CREATE,
            "data-key-wrap",
            "",
            "grant/1/node-1-aaaa",
            b"wrap-3",
        ),
        op(
            Verb::CREATE,
            "data-key-wrap",
            "",
            "cookie/1/node-1-aaaa",
            b"wrap-4",
        ),
        op(
            Verb::CREATE,
            "data-key-wrap",
            "acme",
            "chain/1/node-1-aaaa",
            b"wrap-5",
        ),
    ];
    let done = f.write(ops, &[]).await.unwrap();
    assert_eq!(done.items.len(), 5);
    assert_eq!(done.items[2].address.tenant, "");
    assert_eq!(done.items[4].address.tenant, "acme");
    assert_eq!(
        f.durable.keys(),
        [
            "dev/-/data-key-wrap/cookie/1/node-1-aaaa",
            "dev/-/data-key-wrap/grant/1/node-1-aaaa",
            "dev/acme/data-key-wrap/chain/1/node-1-aaaa",
            "dev/acme/data-key-wrap/data/1/node-1-aaaa",
            "dev/acme/data-key-wrap/data/1/node-2-bbbb",
        ]
    );
    assert_eq!(
        f.key.opens.load(Ordering::SeqCst),
        0,
        "no grant was asked for"
    );
    // One transaction, and the kind is watched, so every put asks for its change-log row.
    let txs = f.durable.transactions();
    assert_eq!(txs.len(), 1);
    assert!(txs[0].puts.iter().all(|p| p.log));
    assert!(
        txs[0]
            .puts
            .iter()
            .all(|p| p.expires_at.as_option().is_none())
    );

    // The boundary purposes are at no tenant and the tenant purposes at a tenant.
    refused(
        f.write(
            vec![op(
                Verb::CREATE,
                "data-key-wrap",
                "",
                "pseudonym/202611/node-1-aaaa",
                b"w",
            )],
            &[],
        )
        .await,
        ErrorCode::InvalidArgument,
        "address",
    );
    refused(
        f.write(
            vec![op(
                Verb::CREATE,
                "data-key-wrap",
                "acme",
                "grant/1/node-1-aaaa",
                b"w",
            )],
            &[],
        )
        .await,
        ErrorCode::InvalidArgument,
        "address",
    );
    // The chain purpose is a tenant's: the boundary has none.
    refused(
        f.write(
            vec![op(
                Verb::CREATE,
                "data-key-wrap",
                "",
                "chain/1/node-1-aaaa",
                b"w",
            )],
            &[],
        )
        .await,
        ErrorCode::InvalidArgument,
        "address",
    );
    // A batch with one taken wrap is refused whole.
    let ops = vec![
        op(
            Verb::CREATE,
            "data-key-wrap",
            "acme",
            "data/2/node-1-aaaa",
            b"w",
        ),
        op(
            Verb::CREATE,
            "data-key-wrap",
            "acme",
            "data/1/node-1-aaaa",
            b"w",
        ),
    ];
    refused(f.write(ops, &[]).await, ErrorCode::AlreadyExists, "taken");
    assert_eq!(f.durable.keys().len(), 5);

    // The exporter may read the wraps and nothing else.
    f.as_("exporter");
    assert!(
        f.get("data-key-wrap", "", "grant/1/node-1-aaaa")
            .await
            .is_ok()
    );
    let l = f
        .list(ListRequest {
            kind: "data-key-wrap".into(),
            tenant: "acme".into(),
            ..ListRequest::default()
        })
        .await
        .unwrap();
    assert_eq!(l.items.len(), 3);
    refused(
        f.write(
            vec![op(
                Verb::DELETE,
                "data-key-wrap",
                "acme",
                "data/1/node-1-aaaa",
                b"",
            )],
            &g(&f),
        )
        .await,
        ErrorCode::PermissionDenied,
        "rule",
    );
    // Another actor does not get the exemption: it has no rule on the kind.
    f.as_("session");
    refused(
        f.write(
            vec![op(Verb::CREATE, "data-key-wrap", "acme", "data/3/x", b"w")],
            &[],
        )
        .await,
        ErrorCode::PermissionDenied,
        "rule",
    );
}

// ---- schema ----

/// verifies: REQ-DATA-020
#[tokio::test]
async fn a_sealed_value_is_checked_for_its_envelope_and_never_opened() {
    let f = F::new().await;
    f.as_("session");
    let grant = g(&f);
    let create = |v: &[u8]| vec![op(Verb::CREATE, "person", "acme", "p1", v)];
    refused(
        f.write(create(&[1, 1, 0]), &grant).await,
        ErrorCode::InvalidArgument,
        "schema",
    );
    refused(
        f.write(create(&[]), &grant).await,
        ErrorCode::InvalidArgument,
        "schema",
    );
    let mut wrong_version = sealed();
    wrong_version[0] = 2;
    refused(
        f.write(create(&wrong_version), &grant).await,
        ErrorCode::InvalidArgument,
        "schema",
    );
    let mut wrong_purpose = sealed();
    wrong_purpose[1] = 2;
    refused(
        f.write(create(&wrong_purpose), &grant).await,
        ErrorCode::InvalidArgument,
        "schema",
    );
    let mut exactly_34 = sealed();
    exactly_34.truncate(34);
    let done = f.write(create(&exactly_34), &grant).await.unwrap();
    // What went in comes out as it was: store@ keeps the envelope's bytes.
    assert_eq!(
        f.get("person", "acme", "p1").await.unwrap().item.value,
        exactly_34
    );
    assert_eq!(done.items[0].value, exactly_34);
}

#[tokio::test]
async fn an_unmapped_plain_kind_passes_its_bytes() {
    let f = F::new().await;
    f.as_("exchange");
    f.write(
        vec![op(Verb::CREATE, "lease", "", "exchange/job", &[0xff, 0xfe])],
        &[],
    )
    .await
    .unwrap();
    assert_eq!(
        f.get("lease", "", "exchange/job").await.unwrap().item.value,
        [0xff, 0xfe]
    );
}

// ---- TTL ----

/// verifies: REQ-DATA-061
#[tokio::test]
async fn ttl_default_max_and_the_expiry_store_computes() {
    let f = F::new().await;
    f.as_("exchange");
    // ReplayGuard: no default, a maximum of one hour.
    let rg = |id: &str| op(Verb::CREATE, "replay-guard", "", id, b"h");
    refused(
        f.write(vec![rg("exchange/a")], &[]).await,
        ErrorCode::InvalidArgument,
        "ttl",
    );
    refused(
        f.write(vec![with_ttl(rg("exchange/a"), 3601)], &[]).await,
        ErrorCode::InvalidArgument,
        "ttl",
    );
    refused(
        f.write(vec![with_ttl(rg("exchange/a"), 0)], &[]).await,
        ErrorCode::InvalidArgument,
        "ttl",
    );
    refused(
        f.write(vec![with_ttl(rg("exchange/a"), -5)], &[]).await,
        ErrorCode::InvalidArgument,
        "ttl",
    );
    let done = f
        .write(vec![with_ttl(rg("exchange/a"), 3600)], &[])
        .await
        .unwrap();
    let want = i64::try_from(T0).unwrap() + 3600;
    assert_eq!(done.items[0].expires_at.seconds, want);
    assert_eq!(
        f.temp
            .item("dev/-/replay-guard/exchange/a")
            .unwrap()
            .expires_at
            .seconds,
        want
    );

    // A kind with a default takes it: SessionChain, 24 h by default, 90 d at most.
    f.as_("session");
    let grant = g(&f);
    let sc = |id: &str| op(Verb::CREATE, "session-chain", "acme", id, b"h");
    let done = f.write(vec![sc("c1")], &grant).await.unwrap();
    assert_eq!(
        done.items[0].expires_at.seconds,
        i64::try_from(T0).unwrap() + 86_400
    );
    refused(
        f.write(vec![with_ttl(sc("c2"), 7_776_001)], &grant).await,
        ErrorCode::InvalidArgument,
        "ttl",
    );
    f.write(vec![with_ttl(sc("c2"), 7_776_000)], &grant)
        .await
        .unwrap();

    // A kind with no TTL takes none.
    refused(
        f.write(
            vec![with_ttl(
                op(Verb::CREATE, "person", "acme", "p1", &sealed()),
                60,
            )],
            &grant,
        )
        .await,
        ErrorCode::InvalidArgument,
        "ttl",
    );
}

/// verifies: REQ-DATA-064
#[tokio::test]
async fn a_lease_gets_no_engine_expiry_and_is_taken_over_by_a_conditional_update() {
    let f = F::new().await;
    f.as_("exchange");
    let lease = |verb, v| with_version(op(verb, "lease", "", "exchange/job", b"holder-a"), v);
    // 30 s by default, 10 min at most.
    let done = f.write(vec![lease(Verb::CREATE, 0)], &[]).await.unwrap();
    assert_eq!(
        done.items[0].expires_at.seconds,
        i64::try_from(T0).unwrap() + 30
    );
    assert!(
        f.temp
            .item("dev/-/lease/exchange/job")
            .unwrap()
            .expires_at
            .as_option()
            .is_none()
    );
    refused(
        f.write(vec![with_ttl(lease(Verb::UPDATE, 1), 601)], &[])
            .await,
        ErrorCode::InvalidArgument,
        "ttl",
    );

    // Long after the lease ran out it is still there, and a conditional update takes it over.
    f.advance(10_000);
    assert_eq!(
        f.get("lease", "", "exchange/job")
            .await
            .unwrap()
            .item
            .version,
        1
    );
    let taken = f.write(vec![lease(Verb::UPDATE, 1)], &[]).await.unwrap();
    assert_eq!(taken.items[0].version, 2);
    // A create finds the lease taken for ever.
    refused(
        f.write(vec![lease(Verb::CREATE, 0)], &[]).await,
        ErrorCode::AlreadyExists,
        "taken",
    );
}

/// verifies: REQ-DATA-097
#[tokio::test]
async fn a_leases_version_only_grows_and_a_stale_holder_loses() {
    let f = F::new().await;
    f.as_("exchange");
    let lease = |verb, v, who: &[u8]| with_version(op(verb, "lease", "", "exchange/job", who), v);

    let a = f
        .write(vec![lease(Verb::CREATE, 0, b"a")], &[])
        .await
        .unwrap()
        .items[0]
        .version;
    assert_eq!(a, 1);
    // B reads version 1 and takes the lease over; A, still holding 1, now loses.
    let b = f
        .write(vec![lease(Verb::UPDATE, 1, b"b")], &[])
        .await
        .unwrap()
        .items[0]
        .version;
    assert_eq!(b, 2);
    refused(
        f.write(vec![lease(Verb::UPDATE, 1, b"a")], &[]).await,
        ErrorCode::Aborted,
        "version",
    );
    assert_eq!(
        f.get("lease", "", "exchange/job").await.unwrap().item.value,
        b"b"
    );
    // A takes it back at the version it reads now, and the token goes on growing.
    let c = f
        .write(vec![lease(Verb::UPDATE, 2, b"a")], &[])
        .await
        .unwrap()
        .items[0]
        .version;
    assert_eq!(c, 3);

    // A delete followed by a create would start over at 1: a lease is never deleted.
    refused(
        f.write(vec![lease(Verb::DELETE, 0, b"")], &[]).await,
        ErrorCode::PermissionDenied,
        "rule",
    );
    refused(
        f.write(vec![lease(Verb::DELETE, 3, b"")], &[]).await,
        ErrorCode::PermissionDenied,
        "rule",
    );
    // An apply would take the lease without naming the version it read.
    refused(
        f.write(vec![lease(Verb::APPLY, 0, b"z")], &[]).await,
        ErrorCode::PermissionDenied,
        "rule",
    );
    refused(
        f.write(vec![lease(Verb::CREATE, 0, b"z")], &[]).await,
        ErrorCode::AlreadyExists,
        "taken",
    );
    // An update that names no version (0) can never match.
    refused(
        f.write(vec![lease(Verb::UPDATE, 0, b"z")], &[]).await,
        ErrorCode::Aborted,
        "version",
    );
    // A refused batch applies none of it.
    let batch = vec![lease(Verb::UPDATE, 3, b"d"), lease(Verb::DELETE, 0, b"")];
    refused(
        f.write(batch, &[]).await,
        ErrorCode::PermissionDenied,
        "rule",
    );

    let held = f.get("lease", "", "exchange/job").await.unwrap().item;
    assert_eq!(
        (held.version, held.value.clone()),
        (3, b"a".to_vec()),
        "nothing moved the lease backwards"
    );
    // The refusals are audit facts with the kind and the verb.
    assert!(
        f.audit()
            .iter()
            .any(|e| e.reason == "rule" && e.fields.contains(&("verb", "delete".to_owned())))
    );
}

/// verifies: REQ-DATA-060
#[tokio::test]
async fn an_expired_item_reads_as_absent_whatever_the_engine_holds() {
    let f = F::new().await;
    f.as_("session");
    let grant = f.grant("session", &["acme"], &WRITES, 600);
    let sc = |id: &str| with_ttl(op(Verb::CREATE, "session-chain", "acme", id, b"h"), 60);
    f.write(vec![sc("c1"), sc("c2")], &grant).await.unwrap();
    assert!(f.get("session-chain", "acme", "c1").await.is_ok());
    f.advance(61);
    // The engine still holds both rows.
    assert_eq!(f.temp.keys().len(), 2);
    refused(
        f.get("session-chain", "acme", "c1").await,
        ErrorCode::NotFound,
        "absent",
    );
    let l = f
        .list(ListRequest {
            kind: "session-chain".into(),
            tenant: "acme".into(),
            ..ListRequest::default()
        })
        .await
        .unwrap();
    assert!(l.items.is_empty());
    // A create may write it again, though the engine still holds the old row: the expired item
    // does not exist for the condition, and the new item starts at version 1.
    let again = f.write(vec![sc("c1")], &grant).await.unwrap();
    assert_eq!(again.items[0].version, 1);
    // An update at the version of the expired item loses.
    f.advance(61);
    let stale = with_version(op(Verb::UPDATE, "session-chain", "acme", "c1", b"h"), 1);
    refused(
        f.write(vec![stale], &grant).await,
        ErrorCode::Aborted,
        "version",
    );
    let again = f.write(vec![sc("c1")], &grant).await.unwrap();
    assert_eq!(again.items[0].version, 1);
    assert!(f.get("session-chain", "acme", "c1").await.is_ok());
    // An item that is not expired is still taken.
    refused(
        f.write(vec![sc("c1")], &grant).await,
        ErrorCode::AlreadyExists,
        "taken",
    );
}

// ---- indexes ----

/// verifies: REQ-DATA-010
#[tokio::test]
async fn only_declared_indexes_are_taken_and_listed_by() {
    let f = F::new().await;
    f.as_("session");
    let grant = g(&f);
    let sc = |id: &str| with_ttl(op(Verb::CREATE, "session-chain", "acme", id, b"h"), 600);
    refused(
        f.write(vec![with_index(sc("c1"), "by_colour", b"red")], &grant)
            .await,
        ErrorCode::InvalidArgument,
        "index",
    );
    f.write(vec![with_index(sc("c1"), "by_subject", b"s1")], &grant)
        .await
        .unwrap();
    f.write(vec![with_index(sc("c2"), "by_subject", b"s2")], &grant)
        .await
        .unwrap();
    let list = |index: &str, value: &[u8]| ListRequest {
        kind: "session-chain".into(),
        tenant: "acme".into(),
        index: index.into(),
        index_value: value.to_vec(),
        ..ListRequest::default()
    };
    let hit = f.list(list("by_subject", b"s2")).await.unwrap();
    assert_eq!(hit.items.len(), 1);
    assert_eq!(hit.items[0].address.id, "c2");
    refused(
        f.list(list("by_colour", b"red")).await,
        ErrorCode::InvalidArgument,
        "index",
    );
    assert_eq!(f.list(list("", b"")).await.unwrap().items.len(), 2);
}

// ---- batches and versions ----

/// verifies: REQ-DATA-049
#[tokio::test]
async fn a_batch_of_65_is_refused_and_a_batch_of_2_is_all_or_none() {
    let f = F::new().await;
    f.as_("session");
    let grant = g(&f);
    let many: Vec<_> = (0..65)
        .map(|i| op(Verb::CREATE, "person", "acme", &format!("p{i}"), &sealed()))
        .collect();
    refused(
        f.write(many, &grant).await,
        ErrorCode::InvalidArgument,
        "batch",
    );
    let many: Vec<_> = (0..64)
        .map(|i| op(Verb::CREATE, "person", "acme", &format!("p{i}"), &sealed()))
        .collect();
    assert_eq!(f.write(many, &grant).await.unwrap().items.len(), 64);
    refused(
        f.write(vec![], &grant).await,
        ErrorCode::InvalidArgument,
        "batch",
    );

    // Two operations, the second fails: neither is applied.
    let ops = vec![
        op(Verb::CREATE, "person", "acme", "new", &sealed()),
        op(Verb::CREATE, "person", "acme", "p0", &sealed()),
    ];
    refused(
        f.write(ops, &grant).await,
        ErrorCode::AlreadyExists,
        "taken",
    );
    assert!(f.durable.item("dev/acme/person/new").is_none());
    // Two that hold are both applied, in one transaction.
    let before = f.durable.transactions().len();
    let ops = vec![
        op(Verb::CREATE, "person", "acme", "x1", &sealed()),
        op(Verb::CREATE, "person", "acme", "x2", &sealed()),
    ];
    f.write(ops, &grant).await.unwrap();
    assert_eq!(f.durable.transactions().len(), before + 1);
    assert!(
        f.durable.item("dev/acme/person/x1").is_some()
            && f.durable.item("dev/acme/person/x2").is_some()
    );
}

#[tokio::test]
async fn a_batch_names_one_item_once_and_one_engine() {
    let f = F::new().await;
    f.as_("session");
    let grant = g(&f);
    let twice = vec![
        op(Verb::CREATE, "person", "acme", "p1", &sealed()),
        op(Verb::APPLY, "person", "acme", "p1", &sealed()),
    ];
    refused(
        f.write(twice, &grant).await,
        ErrorCode::InvalidArgument,
        "batch",
    );
    // A durable and a temp kind cannot be applied all or none: they are two engines.
    let mixed = vec![
        op(Verb::CREATE, "person", "acme", "p1", &sealed()),
        with_ttl(op(Verb::CREATE, "session-chain", "acme", "c1", b"h"), 60),
    ];
    refused(
        f.write(mixed, &grant).await,
        ErrorCode::InvalidArgument,
        "batch",
    );
    refused(
        f.write(
            vec![op(
                Verb::VERB_UNSPECIFIED,
                "person",
                "acme",
                "p1",
                &sealed(),
            )],
            &grant,
        )
        .await,
        ErrorCode::InvalidArgument,
        "batch",
    );
}

/// verifies: REQ-DATA-050
#[tokio::test]
async fn versions_come_from_the_engine_and_conflicts_have_their_reasons() {
    let f = F::new().await;
    f.as_("session");
    let grant = g(&f);
    let p = |verb, v| with_version(op(verb, "person", "acme", "p1", &sealed()), v);

    assert_eq!(
        f.write(vec![p(Verb::CREATE, 0)], &grant)
            .await
            .unwrap()
            .items[0]
            .version,
        1
    );
    refused(
        f.write(vec![p(Verb::CREATE, 0)], &grant).await,
        ErrorCode::AlreadyExists,
        "taken",
    );
    assert_eq!(
        f.write(vec![p(Verb::UPDATE, 1)], &grant)
            .await
            .unwrap()
            .items[0]
            .version,
        2
    );
    refused(
        f.write(vec![p(Verb::UPDATE, 1)], &grant).await,
        ErrorCode::Aborted,
        "version",
    );
    refused(
        f.write(vec![p(Verb::UPDATE, 0)], &grant).await,
        ErrorCode::Aborted,
        "version",
    );
    // An update of an item that is not there.
    let missing = with_version(op(Verb::UPDATE, "person", "acme", "none", &sealed()), 1);
    refused(
        f.write(vec![missing], &grant).await,
        ErrorCode::Aborted,
        "version",
    );
    // Apply is never refused for a version.
    assert_eq!(
        f.write(vec![p(Verb::APPLY, 0)], &grant)
            .await
            .unwrap()
            .items[0]
            .version,
        3
    );
    // Delete at a version, and without one.
    refused(
        f.write(vec![p(Verb::DELETE, 1)], &grant).await,
        ErrorCode::Aborted,
        "version",
    );
    f.write(vec![p(Verb::DELETE, 3)], &grant).await.unwrap();
    refused(
        f.get("person", "acme", "p1").await,
        ErrorCode::NotFound,
        "absent",
    );
    f.write(vec![p(Verb::APPLY, 0)], &grant).await.unwrap();
    f.write(vec![p(Verb::DELETE, 0)], &grant).await.unwrap();
    assert!(f.durable.keys().is_empty());
}

/// verifies: REQ-DATA-056
#[tokio::test]
async fn the_change_log_is_asked_for_only_on_watched_kinds() {
    let f = F::new().await;
    f.as_("session");
    f.write(
        vec![op(Verb::CREATE, "person", "acme", "p1", &sealed())],
        &g(&f),
    )
    .await
    .unwrap();
    let txs = f.durable.transactions();
    assert!(!txs[0].puts[0].log, "Person is watched by nobody");
    f.as_("key");
    f.write(
        vec![op(
            Verb::CREATE,
            "data-key-wrap",
            "acme",
            "data/1/n-1",
            b"w",
        )],
        &[],
    )
    .await
    .unwrap();
    assert!(f.durable.transactions()[1].puts[0].log);
    f.write(
        vec![op(Verb::DELETE, "data-key-wrap", "acme", "data/1/n-1", b"")],
        &[],
    )
    .await
    .unwrap();
    assert!(f.durable.transactions()[2].deletes[0].log);
}

// ---- Get and List ----

#[tokio::test]
async fn get_answers_unchanged_for_the_version_the_caller_holds() {
    let f = F::new().await;
    f.as_("session");
    f.write(
        vec![op(Verb::CREATE, "person", "acme", "p1", &sealed())],
        &g(&f),
    )
    .await
    .unwrap();
    let req = |v| GetRequest {
        address: addr("person", "acme", "p1").into(),
        if_none_match: v,
        consistency: Consistency::FOLLOWER.into(),
        ..GetRequest::default()
    };
    let same = f.get_req(req(1)).await.unwrap();
    assert!(same.unchanged && same.item.as_option().is_none());
    let moved = f.get_req(req(7)).await.unwrap();
    assert!(!moved.unchanged);
    assert_eq!(moved.item.version, 1);
}

#[tokio::test]
async fn list_pages_are_bound_to_the_query_the_caller_and_the_clock() {
    let f = F::new().await;
    f.as_("session");
    let grant = g(&f);
    for i in 0..5 {
        f.write(
            vec![op(
                Verb::CREATE,
                "person",
                "acme",
                &format!("p{i}"),
                &sealed(),
            )],
            &grant,
        )
        .await
        .unwrap();
    }
    f.write(
        vec![op(Verb::CREATE, "person", "globex", "other", &sealed())],
        &f.grant("session", &["globex"], &WRITES, 60),
    )
    .await
    .unwrap();
    let page = |tenant: &str, token: &str| ListRequest {
        kind: "person".into(),
        tenant: tenant.into(),
        page_size: 2,
        page_token: token.into(),
        ..ListRequest::default()
    };
    let (mut ids, mut token) = (Vec::new(), String::new());
    for _ in 0..3 {
        let r = f.list(page("acme", &token)).await.unwrap();
        ids.extend(r.items.iter().map(|i| i.address.id.clone()));
        token = r.next_page_token;
    }
    assert_eq!(ids, ["p0", "p1", "p2", "p3", "p4"]);
    assert!(token.is_empty(), "the last page has no token");

    let first = f.list(page("acme", "")).await.unwrap().next_page_token;
    // Another tenant, another caller, a garbage token, a token after its time.
    refused(
        f.list(page("globex", &first)).await,
        ErrorCode::InvalidArgument,
        "schema",
    );
    refused(
        f.list(page("acme", "not-a-token")).await,
        ErrorCode::InvalidArgument,
        "schema",
    );
    f.as_("exporter");
    refused(
        f.list(page("acme", &first)).await,
        ErrorCode::InvalidArgument,
        "schema",
    );
    f.as_("session");
    assert!(f.list(page("acme", &first)).await.is_ok());
    f.advance(301);
    refused(
        f.list(page("acme", &first)).await,
        ErrorCode::InvalidArgument,
        "schema",
    );
    // A page size above the maximum is cut, a negative one refused.
    let mut big = page("acme", "");
    big.page_size = 100_000;
    assert_eq!(f.list(big).await.unwrap().items.len(), 5);
    let mut neg = page("acme", "");
    neg.page_size = -1;
    refused(f.list(neg).await, ErrorCode::InvalidArgument, "schema");
}

#[tokio::test]
async fn a_self_scoped_list_shows_the_callers_own_ids_only() {
    let f = F::new().await;
    for who in ["exchange", "session"] {
        f.as_(who);
        for i in 0..2 {
            f.write(
                vec![with_ttl(
                    op(
                        Verb::CREATE,
                        "replay-guard",
                        "",
                        &format!("{who}/j{i}"),
                        b"h",
                    ),
                    60,
                )],
                &[],
            )
            .await
            .unwrap();
        }
    }
    f.as_("exchange");
    let l = f
        .list(ListRequest {
            kind: "replay-guard".into(),
            ..ListRequest::default()
        })
        .await
        .unwrap();
    let ids: Vec<_> = l.items.iter().map(|i| i.address.id.as_str()).collect();
    assert_eq!(ids, ["exchange/j0", "exchange/j1"]);
}

// ---- the engine down ----

#[tokio::test]
async fn an_engine_that_is_down_is_unavailable_and_nothing_is_guessed() {
    let f = F::new().await;
    f.as_("session");
    let grant = g(&f);
    f.durable.set_down(true);
    refused(
        f.get("person", "acme", "p1").await,
        ErrorCode::Unavailable,
        "engine",
    );
    refused(
        f.list(ListRequest {
            kind: "person".into(),
            tenant: "acme".into(),
            ..ListRequest::default()
        })
        .await,
        ErrorCode::Unavailable,
        "engine",
    );
    refused(
        f.write(
            vec![op(Verb::CREATE, "person", "acme", "p1", &sealed())],
            &grant,
        )
        .await,
        ErrorCode::Unavailable,
        "engine",
    );
    // The temp engine is a different port.
    f.as_("exchange");
    f.write(
        vec![with_ttl(
            op(Verb::CREATE, "replay-guard", "", "exchange/a", b"h"),
            60,
        )],
        &[],
    )
    .await
    .unwrap();
    f.temp.set_down(true);
    refused(
        f.get("replay-guard", "", "exchange/a").await,
        ErrorCode::Unavailable,
        "engine",
    );
    f.durable.set_down(false);
    f.as_("session");
    refused(
        f.get("person", "acme", "p1").await,
        ErrorCode::NotFound,
        "absent",
    );
}

// ---- config and secret kinds ----

#[tokio::test]
async fn a_config_kind_is_read_from_the_snapshot_and_never_written() {
    let f = F::new().await;
    f.as_("key");
    // No document loaded: unavailable, never an empty kind.
    refused(
        f.get("key-plan", "", "default").await,
        ErrorCode::Unavailable,
        "engine",
    );
    refused(
        f.list(ListRequest {
            kind: "key-plan".into(),
            ..ListRequest::default()
        })
        .await,
        ErrorCode::Unavailable,
        "engine",
    );
    f.docs.versions.lock().unwrap().insert("key-plan".into(), 7);
    f.docs
        .items
        .lock()
        .unwrap()
        .insert(("key-plan".into(), "default".into()), b"plan".to_vec());
    let got = f.get("key-plan", "", "default").await.unwrap();
    assert_eq!(
        (got.item.version, got.item.value.clone()),
        (7, b"plan".to_vec())
    );
    refused(
        f.get("key-plan", "", "other").await,
        ErrorCode::NotFound,
        "absent",
    );
    assert_eq!(
        f.list(ListRequest {
            kind: "key-plan".into(),
            ..ListRequest::default()
        })
        .await
        .unwrap()
        .items
        .len(),
        1
    );
    // An actor with no rule on it.
    f.as_("session");
    refused(
        f.get("key-plan", "", "default").await,
        ErrorCode::PermissionDenied,
        "rule",
    );
    // Config is read-only to sluis, whoever asks.
    f.as_("key");
    refused(
        f.write(vec![op(Verb::CREATE, "key-plan", "", "default", b"x")], &[])
            .await,
        ErrorCode::PermissionDenied,
        "rule",
    );
    assert!(f.durable.transactions().is_empty() && f.temp.transactions().is_empty());
}

/// verifies: REQ-DATA-099
/// the signed document of a config kind is returned exactly as the source gave it, to the
/// readers of the kind and to nobody else; the answer is a read of the kind, so every refusal of a read applies.
#[tokio::test]
async fn req_data_099_the_signed_document_of_a_config_kind_goes_to_its_readers_only() {
    let f = F::new().await;
    f.as_("key");
    // No document loaded: unavailable, never an empty document.
    refused(
        f.get_signed_config("key-plan").await,
        ErrorCode::Unavailable,
        "engine",
    );
    let jws: &[u8] = b"{\"payload\":\"AAAA\",\"signatures\":[]}";
    f.docs
        .signed
        .lock()
        .unwrap()
        .insert("key-plan".into(), jws.to_vec());
    assert_eq!(f.get_signed_config("key-plan").await.unwrap().document, jws);
    // Another reader of the kind gets it too.
    f.as_("signer");
    assert_eq!(f.get_signed_config("key-plan").await.unwrap().document, jws);
    // An actor with no read rule on the kind does not, and the refusal is the one a read makes.
    f.as_("session");
    refused(
        f.get_signed_config("key-plan").await,
        ErrorCode::PermissionDenied,
        "rule",
    );
    assert!(
        f.audit()
            .iter()
            .any(|e| e.action == "store.refused" && e.reason == "rule"),
        "a refused read is an audit fact"
    );
    // Only a config kind has a signed document: a durable kind, an unknown segment and a bad one are refused.
    f.as_("key");
    for kind in ["data-key-wrap", "no-such-kind", "Bad/Kind", ""] {
        let e = f.get_signed_config(kind).await.unwrap_err();
        assert_eq!(e.code, ErrorCode::InvalidArgument, "{kind}");
        assert_eq!(refusal_path(&e), "kind", "{kind}");
    }
}

/// verifies: REQ-DATA-099
/// a self-scoped kind has no signed document for any caller. The document holds every actor's items, and
/// an actor may read its own only, so the call is refused even to an actor that may read its own items.
#[tokio::test]
async fn req_data_099_a_self_scoped_kind_has_no_signed_document_for_anyone() {
    let f = F::new().await;
    let jws: &[u8] = b"{\"payload\":\"AAAA\",\"signatures\":[]}";
    for (actor, kind) in [
        ("adapter-github", "integration"),
        ("adapter-slack", "integration"),
        ("key", "tunables"),
        ("session", "tunables"),
        ("key", "log-settings"),
    ] {
        f.docs
            .signed
            .lock()
            .unwrap()
            .insert(kind.into(), jws.to_vec());
        f.docs.versions.lock().unwrap().insert(kind.into(), 1);
        f.as_(actor);
        // The same actor reads its own item.
        f.docs
            .items
            .lock()
            .unwrap()
            .insert((kind.into(), format!("{actor}/x")), b"t".to_vec());
        assert!(
            f.get(kind, "", &format!("{actor}/x")).await.is_ok(),
            "{actor} reads its own item of {kind}"
        );
        refused(
            f.get_signed_config(kind).await,
            ErrorCode::PermissionDenied,
            "rule",
        );
    }
}

#[tokio::test]
async fn a_self_scoped_config_kind_is_read_under_the_callers_name_only() {
    let f = F::new().await;
    f.docs.versions.lock().unwrap().insert("tunables".into(), 1);
    for id in ["key/limits", "session/limits"] {
        f.docs
            .items
            .lock()
            .unwrap()
            .insert(("tunables".into(), id.into()), b"t".to_vec());
    }
    f.as_("key");
    assert!(f.get("tunables", "", "key/limits").await.is_ok());
    refused(
        f.get("tunables", "", "session/limits").await,
        ErrorCode::PermissionDenied,
        "writer",
    );
    let l = f
        .list(ListRequest {
            kind: "tunables".into(),
            ..ListRequest::default()
        })
        .await
        .unwrap();
    assert_eq!(l.items.len(), 1);
    assert_eq!(l.items[0].address.id, "key/limits");
}

#[tokio::test]
async fn a_secret_kind_is_not_served_tonight() {
    let f = F::new().await;
    f.as_("adapter-slack");
    let e = f
        .get("slack-app-secret", "", "workforce")
        .await
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::Unimplemented);
    // The rule still comes first.
    f.as_("session");
    refused(
        f.get("slack-app-secret", "", "workforce").await,
        ErrorCode::PermissionDenied,
        "rule",
    );
}

// ---- the secret kind UpstreamSecret (REQ-ISO-106) ----

/// verifies: REQ-ISO-106
/// adapter-upstream-oidc holds no credential of its own: store@ serves the client secret of an Upstream from the
/// secret source, to that adapter alone, under the credential name the Upstream declares.
#[tokio::test]
async fn the_upstream_secret_is_served_to_its_one_reader_from_the_secret_source() {
    use buffa::Message as _;
    let f = F::new().await;
    f.docs.versions.lock().unwrap().insert("upstream".into(), 2);
    for (name, secret) in [("workforce", "upstream-workforce"), ("bare", "")] {
        let u = sluis_proto::sluis::config::v2alpha1::Upstream {
            name: name.into(),
            kind: "oidc".into(),
            secret: secret.into(),
            ..Default::default()
        };
        f.docs
            .items
            .lock()
            .unwrap()
            .insert(("upstream".into(), name.into()), u.encode_to_vec());
    }
    f.secrets
        .items
        .lock()
        .unwrap()
        .insert("upstream-workforce".into(), CLIENT_SECRET.to_vec());

    f.as_("adapter-upstream-oidc");
    let r = f.get("upstream-secret", "", "workforce").await.unwrap();
    let item = r.item.as_option().expect("an item");
    let s = sluis_proto::sluis::config::v2alpha1::UpstreamSecret::decode_from_slice(&item.value)
        .unwrap();
    assert_eq!(
        (s.upstream.as_str(), s.secret.as_slice()),
        ("workforce", CLIENT_SECRET)
    );
    // No such upstream, and an upstream that names no secret: one answer.
    for name in ["nobody", "bare"] {
        refused(
            f.get("upstream-secret", "", name).await,
            ErrorCode::NotFound,
            "absent",
        );
    }
    // Nobody else reads it, session included (ADR 0025: the client credential never leaves the adapter).
    let reads = f.secrets.reads.load(Ordering::SeqCst);
    for caller in ["session", "exchange", "policy", "signer"] {
        f.as_(caller);
        refused(
            f.get("upstream-secret", "", "workforce").await,
            ErrorCode::PermissionDenied,
            "rule",
        );
    }
    assert_eq!(f.secrets.reads.load(Ordering::SeqCst), reads);
}

// ---- the secret kind InstallationClientSecret (REQ-DATA-016, REQ-DATA-017) ----

/// A secret that no audit fact, log line or refusal may repeat.
const CLIENT_SECRET: &[u8] = b"s3cret-with-%20-and-+-and-spaces ok";

/// A fixture with the client `app` declared (secret credential `client-app`), `plain` declared without a secret.
fn with_clients(f: &F) {
    use buffa::Message as _;
    f.docs
        .versions
        .lock()
        .unwrap()
        .insert("installation-client".into(), 3);
    for (id, secret, kind) in [
        ("app", "client-app", "confidential"),
        ("plain", "", "confidential"),
        ("ghost", "client-ghost", "confidential"),
    ] {
        let c = sluis_proto::sluis::config::v2alpha1::InstallationClient {
            id: id.into(),
            kind: kind.into(),
            secret: secret.into(),
            ..Default::default()
        };
        f.docs
            .items
            .lock()
            .unwrap()
            .insert(("installation-client".into(), id.into()), c.encode_to_vec());
    }
    f.secrets
        .items
        .lock()
        .unwrap()
        .insert("client-app".into(), CLIENT_SECRET.to_vec());
}

fn decode_secret(
    r: &GetResponse,
) -> sluis_proto::sluis::config::v2alpha1::InstallationClientSecret {
    use buffa::Message as _;
    let item = r.item.as_option().expect("an item");
    sluis_proto::sluis::config::v2alpha1::InstallationClientSecret::decode_from_slice(&item.value)
        .unwrap()
}

#[tokio::test]
async fn a_listed_reader_gets_the_secret_of_the_client_the_config_names() {
    let f = F::new().await;
    with_clients(&f);
    for reader in ["session", "exchange"] {
        f.as_(reader);
        let r = f
            .get("installation-client-secret", "", "app")
            .await
            .unwrap();
        let s = decode_secret(&r);
        assert_eq!(
            (s.client.as_str(), s.secret.as_slice()),
            ("app", CLIENT_SECRET),
            "{reader}"
        );
        assert!(r.item.as_option().unwrap().version > 0);
    }
}

/// verifies: REQ-DATA-016
/// store@ serves a secret kind only to the readers that the kind lists.
#[tokio::test]
async fn a_caller_that_is_not_a_listed_reader_gets_no_secret_and_the_source_is_not_asked() {
    let f = F::new().await;
    with_clients(&f);
    for caller in ["quota", "policy", "signer", "adapter-upstream-oidc"] {
        f.as_(caller);
        refused(
            f.get("installation-client-secret", "", "app").await,
            ErrorCode::PermissionDenied,
            "rule",
        );
    }
    assert_eq!(f.secrets.reads.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn the_secret_is_fetched_on_first_use_and_an_unchanged_get_carries_no_value() {
    let f = F::new().await;
    with_clients(&f);
    f.as_("session");
    assert_eq!(
        f.secrets.reads.load(Ordering::SeqCst),
        0,
        "nothing is fetched before the first use"
    );
    f.get("installation-client-secret", "", "app")
        .await
        .unwrap();
    assert_eq!(f.secrets.reads.load(Ordering::SeqCst), 1);
    // The version label is the source's, so an unchanged get answers unchanged and carries no value.
    let v = f
        .get("installation-client-secret", "", "app")
        .await
        .unwrap()
        .item
        .as_option()
        .unwrap()
        .version;
    let r = f
        .get_req(GetRequest {
            address: addr("installation-client-secret", "", "app").into(),
            if_none_match: v,
            ..GetRequest::default()
        })
        .await
        .unwrap();
    assert!(r.unchanged && r.item.as_option().is_none());
}

/// verifies: REQ-DATA-018
#[tokio::test]
async fn a_client_the_config_does_not_declare_or_declares_without_a_secret_has_none() {
    let f = F::new().await;
    with_clients(&f);
    f.as_("session");
    // No such client, a client with no secret named, and a named secret the source does not hold: one answer.
    for id in ["nobody", "plain", "ghost"] {
        refused(
            f.get("installation-client-secret", "", id).await,
            ErrorCode::NotFound,
            "absent",
        );
    }
}

#[tokio::test]
async fn a_secret_source_that_does_not_answer_fails_closed() {
    let f = F::new().await;
    with_clients(&f);
    f.secrets.down.store(true, Ordering::SeqCst);
    f.as_("exchange");
    refused(
        f.get("installation-client-secret", "", "app").await,
        ErrorCode::Unavailable,
        "engine",
    );
}

#[tokio::test]
async fn a_config_outage_is_unavailable_and_not_an_unknown_client() {
    // The snapshot has no InstallationClient document: the secret cannot be located, which is not "no such client".
    let f = F::new().await;
    f.as_("session");
    refused(
        f.get("installation-client-secret", "", "app").await,
        ErrorCode::Unavailable,
        "engine",
    );
    assert_eq!(f.secrets.reads.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn no_audit_fact_and_no_refusal_carries_the_secret() {
    let f = F::new().await;
    with_clients(&f);
    // A listed reader whose read reaches the source, and succeeds.
    f.as_("session");
    f.get("installation-client-secret", "", "app")
        .await
        .unwrap();
    // Listed readers whose reads reach the source and fail after it was touched: the source is down, and the named
    // credential is missing. The secret of another client is in the source all the time.
    let touched = f.secrets.reads.load(Ordering::SeqCst);
    let mut errors = Vec::new();
    f.secrets.down.store(true, Ordering::SeqCst);
    errors.push(
        f.get("installation-client-secret", "", "app")
            .await
            .unwrap_err(),
    );
    f.secrets.down.store(false, Ordering::SeqCst);
    errors.push(
        f.get("installation-client-secret", "", "ghost")
            .await
            .unwrap_err(),
    );
    assert_eq!(f.secrets.reads.load(Ordering::SeqCst), touched + 2);
    assert_eq!(
        errors.iter().map(|e| e.code).collect::<Vec<_>>(),
        [ErrorCode::Unavailable, ErrorCode::NotFound]
    );
    for e in &errors {
        assert!(!format!("{e:?}").contains("s3cret"), "{e:?}");
    }
    // The facts of the refusals name the kind, the verb, the caller and the client id, and no value.
    let facts = f.audit();
    assert_eq!(facts.len(), 2);
    for ev in &facts {
        let text = format!("{ev:?}");
        assert!(!text.contains("s3cret"), "{text}");
        assert!(
            ev.fields.iter().any(|(k, _)| *k == "id")
                && ev
                    .fields
                    .iter()
                    .any(|(k, v)| *k == "caller" && v == "session"),
            "{text}"
        );
    }
    // A caller that is refused before any read leaves a fact with no id of a secret it never asked for.
    f.as_("quota");
    let _ = f.get("installation-client-secret", "", "app").await;
    // A list of a secret kind is not served: there is no consumer.
    f.as_("session");
    refused(
        f.list(ListRequest {
            kind: "installation-client-secret".into(),
            ..ListRequest::default()
        })
        .await,
        ErrorCode::Unimplemented,
        "-",
    );
}

// ---- audit ----

#[tokio::test]
async fn an_audit_emit_that_fails_never_fails_the_call() {
    let f = F::new().await;
    f.as_("quota");
    f.sink.fail.store(true, Ordering::SeqCst);
    // The refusal still reaches the caller, with its reason.
    refused(
        f.get("person", "acme", "x").await,
        ErrorCode::PermissionDenied,
        "rule",
    );
    f.sink.fail.store(false, Ordering::SeqCst);
    assert!(f.audit().is_empty());
    refused(
        f.get("person", "acme", "x").await,
        ErrorCode::PermissionDenied,
        "rule",
    );
    assert_eq!(f.audit().len(), 1);
}

/// verifies: REQ-DATA-052
#[tokio::test]
async fn every_refusal_is_an_audit_fact_whatever_its_code() {
    let f = F::new().await;
    f.as_("session");
    let grant = g(&f);
    let create = |id: &str| vec![op(Verb::CREATE, "person", "acme", id, &sealed())];
    let update = vec![op(Verb::UPDATE, "person", "acme", "p1", &sealed())];

    refused(
        f.get("person", "acme", "none").await,
        ErrorCode::NotFound,
        "absent",
    );
    f.write(create("p1"), &grant).await.unwrap();
    refused(
        f.write(create("p1"), &grant).await,
        ErrorCode::AlreadyExists,
        "taken",
    );
    refused(f.write(update, &grant).await, ErrorCode::Aborted, "version");
    refused(
        f.write(create("p2"), &[]).await,
        ErrorCode::PermissionDenied,
        "grant",
    );
    refused(
        f.get("Person", "acme", "x").await,
        ErrorCode::InvalidArgument,
        "address",
    );
    f.durable.set_down(true);
    refused(
        f.get("person", "acme", "p1").await,
        ErrorCode::Unavailable,
        "engine",
    );
    f.durable.set_down(false);
    // Not served yet is a refusal too.
    f.as_("adapter-slack");
    assert_eq!(
        f.get("slack-app-secret", "", "w").await.unwrap_err().code,
        ErrorCode::Unimplemented
    );

    let seen: Vec<(String, String)> = f
        .audit()
        .iter()
        .map(|e| {
            assert_eq!((e.action, e.failure), ("store.refused", true));
            let code = e
                .fields
                .iter()
                .find(|(k, _)| *k == "code")
                .unwrap()
                .1
                .clone();
            (code, e.reason.clone())
        })
        .collect();
    let want = [
        ("not_found", "absent"),
        ("already_exists", "taken"),
        ("aborted", "version"),
        ("permission_denied", "grant"),
        ("invalid_argument", "address"),
        ("unavailable", "engine"),
        ("unimplemented", "unimplemented"),
    ];
    assert_eq!(seen, want.map(|(c, r)| (c.to_owned(), r.to_owned())));
    // A call that is answered produces none.
    let before = f.audit().len();
    f.as_("session");
    f.get("person", "acme", "p1").await.unwrap();
    assert_eq!(f.audit().len(), before);
}

// ---- the shared vectors ----

fn vectors() -> serde_json::Value {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../kits/conformance/kit/store-address-vectors.json");
    serde_json::from_slice(&std::fs::read(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display())))
        .unwrap()
}

/// `<boundary>/<tenant | ->/<kind>/<id>` as the wire fields: the boundary is the connection's, and
/// a tenant of `-` is the empty tenant.
fn wire(address: &str) -> Option<(String, String, String)> {
    let mut it = address.splitn(4, '/');
    let (boundary, tenant, kind, id) = (it.next()?, it.next()?, it.next()?, it.next()?);
    if boundary.is_empty() {
        return None; // the boundary is not a field of the request
    }
    Some((
        kind.to_owned(),
        if tenant == "-" {
            String::new()
        } else {
            tenant.to_owned()
        },
        id.to_owned(),
    ))
}

/// verifies: REQ-DATA-011
#[tokio::test]
async fn the_shared_address_vectors_hold_on_the_wire() {
    let v = vectors();
    let (valid, invalid, segments) = (
        v["valid"].as_array().unwrap(),
        v["invalid"].as_array().unwrap(),
        v["segments"].as_array().unwrap(),
    );
    assert!(
        !valid.is_empty() && !invalid.is_empty() && !segments.is_empty(),
        "an empty sweep proves nothing"
    );

    // The segments are the registry's.
    for s in segments {
        let kind = sluis_registry::kind_by_name(s["kind"].as_str().unwrap()).unwrap();
        assert_eq!(kind.segment, s["segment"].as_str().unwrap());
    }

    let f = F::new().await;
    f.as_("session");
    let mut ran = 0;
    for c in invalid {
        let text = c["address"].as_str().unwrap();
        // The text form of the part the connection supplies (the boundary) is not a request field.
        let Some((kind, tenant, id)) = wire(text) else {
            continue;
        };
        let e = f.get(&kind, &tenant, &id).await.unwrap_err();
        assert_eq!(
            (e.code, reason(&e)),
            (ErrorCode::InvalidArgument, "address".into()),
            "{text}: {}",
            c["why"]
        );
        ran += 1;
    }
    assert!(
        ran >= invalid.len() - 1,
        "only the empty boundary is outside the request ({ran} of {})",
        invalid.len()
    );
    for a in valid {
        let text = a.as_str().unwrap();
        let (kind, tenant, id) = wire(text).unwrap();
        // Whatever the rules say next, it is not a refusal of the address.
        match f.get(&kind, &tenant, &id).await {
            Ok(_) => {}
            Err(e) => assert!(
                !(e.code == ErrorCode::InvalidArgument && reason(&e) == "address"),
                "{text} is a valid address"
            ),
        }
    }
}

#[tokio::test]
async fn a_refusal_carries_the_correlation_id_of_the_call() {
    let f = F::new().await;
    f.as_("quota");
    let call = f.get("person", "acme", "x");
    let r = sluis_kit::correlation::scope(Some("req-42".into()), call).await;
    refused(r, ErrorCode::PermissionDenied, "rule");
    refused(
        f.get("person", "acme", "x").await,
        ErrorCode::PermissionDenied,
        "rule",
    );
    let ev = f.audit();
    assert_eq!(ev[0].correlation_id.as_deref(), Some("req-42"));
    assert_eq!(ev[1].correlation_id, None, "a call without an id has none");
}

// ---- KeyRevocation: create only (ADR 0041) ----

/// verifies: REQ-KEYS-091
/// A revocation only grows. For every actor of the registry, key@ included, an update, a delete and an apply on an
/// existing KeyRevocation item are refused and the item is as it was; key@ creates one, at no tenant and at a tenant,
/// with no grant, and a second create of a target is `taken`. An item that is not a valid revocation, or that sits under
/// an id that does not name its target, is refused at the write, because the kind could not correct it later. Nobody
/// else can write the kind at all.
#[tokio::test]
async fn req_keys_091_a_key_revocation_only_grows_for_every_actor() {
    let f = F::new().await;
    f.as_("key");
    let create =
        |tenant: &str, id: &str, v: &[u8]| op(Verb::CREATE, "key-revocation", tenant, id, v);
    let mac = revocation("purpose", "mac", "compromise");
    let tok = revocation("purpose", "token-signing", "suspicion");
    f.write(vec![create("", "purpose/mac", &mac)], &[])
        .await
        .unwrap();
    f.write(vec![create("", "purpose/token-signing", &tok)], &[])
        .await
        .unwrap();
    // A tenant's data key generation: a tenant in the address, and still no grant for key@, its one writer.
    f.write(
        vec![create(
            "acme",
            "generation/data/3",
            &revocation("generation", "data/3", "drill"),
        )],
        &[],
    )
    .await
    .unwrap();
    // A second create of the same target is taken, not a replacement.
    refused(
        f.write(
            vec![create(
                "",
                "purpose/mac",
                &revocation("purpose", "mac", "drill"),
            )],
            &[],
        )
        .await,
        ErrorCode::AlreadyExists,
        "taken",
    );
    // An item that is wrong cannot be corrected, so it is refused: not a message, an id that does not name the target,
    // a reason outside the list.
    for (id, v) in [
        ("purpose/other", b"not a message".to_vec()),
        ("purpose/other", mac.clone()),
        ("purpose/other", revocation("purpose", "other", "because")),
    ] {
        refused(
            f.write(vec![create("", id, &v)], &[]).await,
            ErrorCode::InvalidArgument,
            "schema",
        );
    }
    // The tenant is part of the id: a revocation of a purpose has none and a data key generation has one, so a reader
    // that looks in the other place would never find it.
    for (tenant, id, v) in [
        (
            "acme",
            "purpose/other",
            revocation("purpose", "other", "drill"),
        ),
        (
            "",
            "generation/data/4",
            revocation("generation", "data/4", "drill"),
        ),
    ] {
        refused(
            f.write(vec![create(tenant, id, &v)], &[]).await,
            ErrorCode::InvalidArgument,
            "schema",
        );
    }
    // An apply is refused on a free address as well: the kind has no apply (the rule table gives key@ create, get and list).
    refused(
        f.write(
            vec![op(
                Verb::APPLY,
                "key-revocation",
                "",
                "purpose/other",
                &revocation("purpose", "other", "drill"),
            )],
            &[],
        )
        .await,
        ErrorCode::PermissionDenied,
        "rule",
    );

    let actors: Vec<&'static str> = sluis_registry::actors().iter().map(|a| a.name).collect();
    assert!(
        actors.contains(&"key") && actors.len() > 10,
        "the sweep must cover the registry"
    );
    for actor in actors {
        f.as_(actor);
        for (verb, name) in [
            (Verb::UPDATE, "update"),
            (Verb::DELETE, "delete"),
            (Verb::APPLY, "apply"),
        ] {
            for id in ["purpose/mac", "purpose/token-signing"] {
                let v = revocation("purpose", id.split_once('/').unwrap().1, "drill");
                let o = if verb == Verb::UPDATE {
                    with_version(op(verb, "key-revocation", "", id, &v), 1)
                } else {
                    op(verb, "key-revocation", "", id, &v)
                };
                let e = f
                    .write(vec![o], &[])
                    .await
                    .expect_err(&format!("{actor} {name} {id} must be refused"));
                assert_eq!(
                    e.code,
                    ErrorCode::PermissionDenied,
                    "{actor} {name} {id}: {e:?}"
                );
            }
        }
    }
    // The items are as key@ made them.
    f.as_("key");
    assert_eq!(
        f.get("key-revocation", "", "purpose/mac")
            .await
            .unwrap()
            .item
            .value,
        mac
    );
    assert_eq!(
        f.get("key-revocation", "", "purpose/token-signing")
            .await
            .unwrap()
            .item
            .value,
        tok
    );
    // The refusals were audited.
    assert!(
        f.audit()
            .iter()
            .filter(|e| e.action == "store.refused")
            .count()
            > 100
    );
}

/// verifies: REQ-KEYS-091
/// Only key@ writes the kind: a create by an actor that reads it, or by any other, has no rule.
#[tokio::test]
async fn req_keys_091_only_key_creates_a_key_revocation() {
    let f = F::new().await;
    for actor in ["signer", "entry", "exporter", "ca", "session", "policy"] {
        f.as_(actor);
        refused(
            f.write(
                vec![op(
                    Verb::CREATE,
                    "key-revocation",
                    "",
                    "purpose/mac",
                    &revocation("purpose", "mac", "drill"),
                )],
                &[],
            )
            .await,
            ErrorCode::PermissionDenied,
            "rule",
        );
    }
}

// ---- one writer per kind, the boundary, read-only kinds, the change log ----

/// The tenant and the id that make a valid address for `kind` as `caller` (the refusal under test is the rule, so the
/// address must be good).
fn address_for(kind: &sluis_registry::Kind, caller: &str) -> (&'static str, String) {
    let tenant = if kind.scope == sluis_registry::Scope::BoundaryTenant {
        "acme"
    } else {
        ""
    };
    let id = match kind.name {
        "DataKeyWrap" => "data/1/n-1".to_owned(),
        "KeyRevocation" => "purpose/p1".to_owned(),
        // An adapter writes a kind of its vendor under its own name.
        _ if kind.self_scoped
            || sluis_registry::store_self_scoped_for(caller, kind.segment, "create") =>
        {
            format!("{caller}/x")
        }
        _ => "x".to_owned(),
    };
    (tenant, id)
}

/// The actors the registry names as the one writer of the kind, among the callers of store@.
fn writers_of(kind: &sluis_registry::Kind) -> Vec<&'static str> {
    let callers = sluis_registry::callers_of("store");
    if kind.writer == "adapter-<vendor>" {
        return callers
            .iter()
            .copied()
            .filter(|c| c.starts_with("adapter-"))
            .collect();
    }
    callers
        .iter()
        .copied()
        .filter(|c| *c == kind.writer)
        .collect()
}

/// verifies: REQ-DATA-004
/// Every caller of store@ that is not the one writer of a kind, and holds a read rule on it or none, creates, updates and
/// deletes an item of the kind (and applies to it) and is refused with the rule's code, whatever the grant would say; the
/// engines are never reached. The writer is not refused by the rule. The restore command of store@ that the row names as
/// the one exception does not exist yet; the other exception, the actor named in the id of a self-scoped kind, is the
/// last part.
#[tokio::test]
async fn an_actor_that_is_not_the_writer_of_a_kind_is_refused_every_write() {
    use sluis_registry::Class;
    let f = F::new().await;
    let callers = sluis_registry::callers_of("store");
    assert!(callers.len() > 8, "the callers of store@: {callers:?}");

    let (mut refused_writes, mut readers_refused, mut kinds_swept) = (0usize, 0usize, 0usize);
    for kind in sluis_registry::kinds()
        .iter()
        .filter(|k| matches!(k.class, Class::Durable | Class::Temp) && !k.self_scoped)
    {
        kinds_swept += 1;
        let writers = writers_of(kind);
        for &caller in callers.iter().filter(|c| !writers.contains(c)) {
            f.as_(caller);
            let (tenant, id) = address_for(kind, caller);
            let reads = ["get", "list", "watch"]
                .iter()
                .any(|v| sluis_registry::store_allows(caller, kind.segment, v));
            for verb in [Verb::CREATE, Verb::UPDATE, Verb::DELETE, Verb::APPLY] {
                let o = with_version(op(verb, kind.segment, tenant, &id, &sealed()), 1);
                // A good grant of this very caller: the refusal must come from the writer rule, not from a missing grant.
                let grant = f.grant(caller, &["acme"], &WRITES, 60);
                let e = f
                    .write(vec![o], &grant)
                    .await
                    .expect_err(&format!("{caller} wrote {} ({verb:?})", kind.name));
                assert_eq!(
                    e.code,
                    ErrorCode::PermissionDenied,
                    "{caller} {}",
                    kind.name
                );
                assert!(
                    matches!(reason(&e).as_str(), "rule" | "writer"),
                    "{caller} {} {verb:?}: reason {}",
                    kind.name,
                    reason(&e)
                );
                refused_writes += 1;
                readers_refused += usize::from(reads);
            }
        }
    }
    assert!(kinds_swept > 40, "the sweep saw {kinds_swept} kinds");
    assert!(refused_writes > 1_000, "{refused_writes} refusals");
    assert!(
        readers_refused > 50,
        "callers with a read rule were refused {readers_refused} times"
    );
    assert!(
        f.durable.transactions().is_empty() && f.temp.transactions().is_empty(),
        "a refused write reached an engine"
    );

    // The writer of a kind is not refused by the rule or the writer check.
    let mut writers_passed = 0usize;
    for kind in sluis_registry::kinds()
        .iter()
        .filter(|k| matches!(k.class, Class::Durable | Class::Temp) && !k.self_scoped)
    {
        for caller in writers_of(kind) {
            f.as_(caller);
            let (tenant, id) = address_for(kind, caller);
            let mut o = op(Verb::CREATE, kind.segment, tenant, &id, &sealed());
            if !kind.ttl_max.is_zero() {
                o = with_ttl(o, 60);
            }
            let grant = f.grant(caller, &["acme"], &WRITES, 60);
            if let Err(e) = f.write(vec![o], &grant).await {
                assert!(
                    !matches!(reason(&e).as_str(), "rule" | "writer"),
                    "the writer {caller} of {} was refused by the rule: {}",
                    kind.name,
                    reason(&e)
                );
            }
            writers_passed += 1;
        }
    }
    assert!(writers_passed > 30, "{writers_passed} writers tried");

    // A self-scoped kind has every actor as a writer, each under its own id and no other: the actor named in the id.
    // Every write verb the caller holds a rule for is refused with `writer` on another actor's id, and on an id that
    // names no actor; a lease's delete and apply are refused by the rule for everyone.
    let (mut self_scoped_kinds, mut by_writer) = (0, 0);
    for kind in sluis_registry::kinds()
        .iter()
        .filter(|k| matches!(k.class, Class::Durable | Class::Temp) && k.self_scoped)
    {
        self_scoped_kinds += 1;
        let mut tried = 0;
        for &caller in callers
            .iter()
            .filter(|c| sluis_registry::store_allows(c, kind.segment, "create"))
        {
            f.as_(caller);
            let other = callers.iter().find(|c| **c != caller).unwrap();
            let (tenant, _) = address_for(kind, caller);
            let grant = f.grant(caller, &["acme"], &WRITES, 60);
            for id in [format!("{other}/x"), "x".to_owned()] {
                for (verb, name) in [
                    (Verb::CREATE, "create"),
                    (Verb::UPDATE, "update"),
                    (Verb::DELETE, "delete"),
                    (Verb::APPLY, "apply"),
                ] {
                    if !sluis_registry::store_allows(caller, kind.segment, name) {
                        continue;
                    }
                    let mut o = with_version(op(verb, kind.segment, tenant, &id, b"h"), 1);
                    if verb != Verb::DELETE {
                        o = with_ttl(o, 30);
                    }
                    let why = if kind.name == "Lease" && matches!(name, "delete" | "apply") {
                        "rule"
                    } else {
                        by_writer += 1;
                        "writer"
                    };
                    refused(
                        f.write(vec![o], &grant).await,
                        ErrorCode::PermissionDenied,
                        why,
                    );
                }
            }
            tried += 1;
        }
        assert!(tried > 0, "no caller creates {}", kind.name);
    }
    assert!(self_scoped_kinds > 0, "no self-scoped kind was swept");
    assert!(by_writer > 20, "{by_writer} refusals by the writer check");
}

/// The names of the kinds that kinds.yaml gives the profile `Fixed` (the generated registry carries no profile).
fn fixed_kinds() -> Vec<&'static str> {
    const KINDS: &str = include_str!("../../../docs/architecture/kinds.yaml");
    let (mut out, mut name, mut in_kinds) = (Vec::new(), "", false);
    for line in KINDS.lines() {
        if line == "kinds:" {
            in_kinds = true;
        } else if !in_kinds {
            continue;
        } else if let Some(n) = line.strip_prefix("  - name: ") {
            name = n.trim();
        } else if line.trim_end() == "    profile: Fixed" {
            out.push(name);
        }
    }
    out
}

/// Every caller, every write verb, each of the given kinds: refused with the rule, and the engines never reached.
async fn every_caller_is_refused_every_write(
    f: &F,
    kinds: &[&'static sluis_registry::Kind],
) -> usize {
    let mut n = 0;
    for kind in kinds {
        for &caller in sluis_registry::callers_of("store") {
            f.as_(caller);
            let (tenant, id) = address_for(kind, caller);
            let grant = f.grant(caller, &["acme"], &WRITES, 60);
            for verb in [Verb::CREATE, Verb::UPDATE, Verb::DELETE, Verb::APPLY] {
                let o = with_version(op(verb, kind.segment, tenant, &id, b"x"), 1);
                refused(
                    f.write(vec![o], &grant).await,
                    ErrorCode::PermissionDenied,
                    "rule",
                );
                n += 1;
            }
        }
    }
    assert!(
        f.durable.transactions().is_empty() && f.temp.transactions().is_empty(),
        "a write to a read-only kind reached an engine"
    );
    n
}

/// verifies: REQ-DATA-015
/// No actor creates, updates, deletes or applies any config kind or any secret kind: all of them, all callers of store@,
/// all four write verbs. A batch that mixes one such write with a good write is refused whole. The permission of the
/// store@ unit on its sources (the second line of the row) needs the serverless installation and is not proved here.
#[tokio::test]
async fn no_actor_writes_a_config_kind_or_a_secret_kind() {
    use sluis_registry::Class;
    let f = F::new().await;
    let read_only: Vec<_> = sluis_registry::kinds()
        .iter()
        .filter(|k| matches!(k.class, Class::Config | Class::Secret))
        .collect();
    assert!(
        read_only.iter().any(|k| k.class == Class::Config)
            && read_only.iter().any(|k| k.class == Class::Secret)
            && read_only.len() > 30,
        "{} read-only kinds",
        read_only.len()
    );
    let n = every_caller_is_refused_every_write(&f, &read_only).await;
    assert!(n > read_only.len() * 8, "{n} refusals");

    // The good write of the same batch is not written either.
    f.as_("session");
    let grant = g(&f);
    refused(
        f.write(
            vec![
                op(Verb::CREATE, "person", "acme", "p1", &sealed()),
                op(Verb::CREATE, "tunables", "", "default", b"x"),
            ],
            &grant,
        )
        .await,
        ErrorCode::PermissionDenied,
        "rule",
    );
    assert!(f.durable.keys().is_empty());
}

/// verifies: REQ-DATA-024
/// Every kind whose profile in kinds.yaml is Fixed refuses a write at run time: all callers of store@ (the console, which
/// carries what an operator or a tenant admin asks for, included), all four write verbs. An operator and a tenant admin
/// are not callers of store@; they reach it only through the console.
#[tokio::test]
async fn a_write_to_a_fixed_kind_is_refused_for_every_caller() {
    let f = F::new().await;
    let names = fixed_kinds();
    assert!(names.len() > 20, "{} Fixed kinds", names.len());
    let kinds: Vec<_> = names
        .iter()
        .map(|n| {
            sluis_registry::kind_by_name(n).unwrap_or_else(|| panic!("{n} is not in the registry"))
        })
        .collect();
    assert!(
        sluis_registry::callers_of("store").contains(&"console"),
        "the console calls store@"
    );
    let n = every_caller_is_refused_every_write(&f, &kinds).await;
    assert!(n > kinds.len() * 8, "{n} refusals");
}

/// verifies: REQ-DATA-013
/// The boundary of a call is the one store@ was started with, and the caller is the peer of the transport: no request
/// message has a field for either, a tenant, a grant or an id that names another boundary or another actor reaches
/// nothing of it, and every key lands under the boundary of the service.
///
/// Not proved here: that `store serve` builds the service with the boundary of its bootstrap file (`run.rs`, one field
/// copied into `Deps`). Under a test `serve` stops at the kit's own start, before any call can be made (see
/// `serve_config.rs`), so no key can be written through it; the row stays partial for that copy.
#[tokio::test]
async fn the_boundary_and_the_caller_never_come_from_a_field_of_the_request() {
    // No field of any request message of the store service, nor of the address it carries, could name a boundary or a
    // caller.
    const STORE: &str = include_str!("../../../proto/sluis/store/v2alpha1/store.proto");
    const TYPES: &str = include_str!("../../../proto/sluis/type/v2alpha1/type.proto");
    let (mut messages, mut fields) = (0, 0);
    for (proto, wanted) in [
        (
            STORE,
            (|m: &str| m.ends_with("Request") || m == "Operation") as fn(&str) -> bool,
        ),
        (TYPES, |m: &str| m == "Address"),
    ] {
        let mut inside = false;
        for line in proto.lines().map(str::trim) {
            if let Some(rest) = line.strip_prefix("message ") {
                let name = rest.split([' ', '{']).next().unwrap();
                inside = wanted(name);
                messages += usize::from(inside);
            } else if line.starts_with("enum ") || line.starts_with("service ") {
                inside = false;
            } else if inside && line.contains(" = ") && line.contains(';') {
                let field = line
                    .split(" = ")
                    .next()
                    .unwrap()
                    .split_whitespace()
                    .last()
                    .unwrap()
                    .to_ascii_lowercase();
                fields += 1;
                for word in ["boundary", "caller", "actor", "holder", "peer"] {
                    assert!(
                        !field.contains(word),
                        "a request field could name the boundary or the caller: {line}"
                    );
                }
            }
        }
    }
    assert!(messages >= 7, "the scan saw {messages} messages");
    assert!(fields > 10, "the scan saw {fields} fields");

    let f = F::new().await;
    f.as_("session");
    // A grant that says another boundary does not open a door to it.
    let other = f.grant_with(|g| g.boundary = "prod-b".into());
    refused(
        f.write(
            vec![op(Verb::CREATE, "person", "acme", "p1", &sealed())],
            &other,
        )
        .await,
        ErrorCode::PermissionDenied,
        "grant",
    );
    // A tenant that is spelled like a path into another boundary is no tenant.
    for tenant in ["prod-b/acme", "../prod-b", "prod-b/dev/acme"] {
        let e = f
            .write(
                vec![op(Verb::CREATE, "person", tenant, "p1", &sealed())],
                &f.grant("session", &[tenant], &WRITES, 60),
            )
            .await;
        refused(e, ErrorCode::InvalidArgument, "address");
        refused(
            f.get("person", tenant, "p1").await,
            ErrorCode::InvalidArgument,
            "address",
        );
    }
    // A tenant named "prod-b" is a tenant of this boundary: the key says so, and the service never holds any other prefix.
    f.write(
        vec![op(Verb::CREATE, "person", "prod-b", "p1", &sealed())],
        &f.grant("session", &["prod-b"], &WRITES, 60),
    )
    .await
    .unwrap();
    assert_eq!(f.durable.keys(), vec!["dev/prod-b/person/p1".to_owned()]);

    // An item that sits in the engine under another boundary is not reached by any address.
    f.durable.0.items.lock().unwrap().insert(
        b"prod-b/acme/person/p9".to_vec(),
        sluis_proto::sluis::port::item::v2alpha1::DriverItem {
            key: b"prod-b/acme/person/p9".to_vec(),
            version: 1,
            value: sealed(),
            ..Default::default()
        },
    );
    refused(
        f.get("person", "acme", "p9").await,
        ErrorCode::NotFound,
        "absent",
    );
    refused(
        f.get("person", "prod-b", "acme/person/p9").await,
        ErrorCode::NotFound,
        "absent",
    );

    // The rule applied is the caller's own, whichever actor an id names: session is refused the id of exchange and the
    // refusal is session's in the audit, while exchange writes it.
    f.as_("session");
    let guard = |id: &str| with_ttl(op(Verb::CREATE, "replay-guard", "", id, b"h"), 60);
    refused(
        f.write(vec![guard("exchange/jti-1")], &[]).await,
        ErrorCode::PermissionDenied,
        "writer",
    );
    let facts = f.audit();
    let last = facts.last().unwrap();
    assert_eq!(
        last.fields.first(),
        Some(&("caller", "session".to_owned())),
        "{last:?}"
    );
    f.as_("exchange");
    f.write(vec![guard("exchange/jti-1")], &[]).await.unwrap();
    assert_eq!(
        f.get("replay-guard", "", "exchange/jti-1")
            .await
            .unwrap()
            .item
            .version,
        1
    );
}

/// verifies: REQ-DATA-055
/// Each change of a kind that some actor may watch (or exporter@ exports) goes to the engine as one transaction that asks
/// for the change-log row of that very change, a put and a delete alike, and the engine's log grows by that row; a kind
/// that nobody watches asks for none. The engines' side (a transaction that fails leaves no row, one that succeeds leaves
/// its row) is the conformance suite's case `transact_writes_its_log_rows_atomically`.
#[tokio::test]
async fn a_change_of_a_watched_kind_asks_for_its_log_row_in_the_same_transaction() {
    use sluis_registry::Class;
    let f = F::new().await;
    let (mut watched, mut unwatched, mut deleted) = (0, 0, 0);
    for kind in sluis_registry::kinds()
        .iter()
        .filter(|k| matches!(k.class, Class::Durable | Class::Temp))
    {
        // The oracle is the rule table, not the service's own expression: a kind is watched when some caller of store@ may
        // watch it. (The service asks for the row when `watched || exportable`; the two must agree.)
        let want = sluis_registry::callers_of("store")
            .iter()
            .any(|c| sluis_registry::store_allows(c, kind.segment, "watch"));
        assert_eq!(
            want,
            kind.watched || kind.exportable,
            "{}: the registry flag against the watch rules",
            kind.name
        );
        let Some(caller) = sluis_registry::callers_of("store")
            .iter()
            .copied()
            .find(|c| {
                sluis_registry::store_allows(c, kind.segment, "create")
                    && (writers_of(kind).contains(c) || kind.self_scoped)
            })
        else {
            continue;
        };
        f.as_(caller);
        let (mut tenant, id) = address_for(kind, caller);
        let value = if kind.name == "KeyRevocation" {
            tenant = "";
            revocation("purpose", "p1", "drill")
        } else {
            sealed()
        };
        let engine = if kind.class == Class::Temp {
            &f.temp
        } else {
            &f.durable
        };
        let (txs, head) = (engine.transactions().len(), engine.head());
        let mut create = op(Verb::CREATE, kind.segment, tenant, &id, &value);
        if !kind.ttl_max.is_zero() {
            create = with_ttl(create, 20);
        }
        let grant = f.grant(caller, &["acme"], &WRITES, 60);
        f.write(vec![create], &grant)
            .await
            .unwrap_or_else(|e| panic!("{caller} creates {}: {e:?}", kind.name));
        let sent = engine.transactions();
        assert_eq!(sent.len(), txs + 1, "{}: one transaction", kind.name);
        let tx = &sent[txs];
        assert_eq!(tx.puts.len(), 1, "{}", kind.name);
        assert_eq!(
            tx.puts[0].log, want,
            "{}: the log row of the put",
            kind.name
        );
        assert_eq!(
            engine.head(),
            head + u64::from(want),
            "{}: the log grew by the row of the change",
            kind.name
        );
        if want {
            watched += 1;
        } else {
            unwatched += 1;
        }

        // A delete asks the same, where the kind allows one (a lease and a revocation are never deleted).
        if sluis_registry::store_allows(caller, kind.segment, "delete")
            && !matches!(kind.name, "Lease" | "KeyRevocation")
        {
            let head = engine.head();
            f.write(
                vec![op(Verb::DELETE, kind.segment, tenant, &id, b"")],
                &grant,
            )
            .await
            .unwrap_or_else(|e| panic!("{caller} deletes {}: {e:?}", kind.name));
            let sent = engine.transactions();
            let tx = sent.last().unwrap();
            assert_eq!(tx.deletes.len(), 1, "{}", kind.name);
            assert_eq!(
                tx.deletes[0].log, want,
                "{}: the log row of the delete",
                kind.name
            );
            assert_eq!(engine.head(), head + u64::from(want), "{}", kind.name);
            deleted += usize::from(want);
        }
    }
    assert!(watched >= 8, "{watched} watched kinds written");
    assert!(unwatched >= 8, "{unwatched} unwatched kinds written");
    assert!(deleted >= 3, "{deleted} watched deletes");
}

// ---- the consistency of a listing ----

/// verifies: REQ-DATA-113
/// A List that leaves the consistency unset, or asks for FOLLOWER, reaches the driver as the read it always was (not
/// linearizable), so that nothing else changes in cost; only LINEARIZABLE reaches it as a linearizable query. A value
/// this build does not know is refused and never read as the weak one. An engine that cannot answer is `unavailable`:
/// store@ does not retry a linearizable listing at a weaker level.
#[tokio::test]
async fn a_listing_passes_the_consistency_it_was_asked_for_to_the_driver() {
    let f = F::new().await;
    f.as_("key");
    let ask = |c: Option<Consistency>| ListRequest {
        kind: "key-revocation".into(),
        consistency: c.map(Into::into).unwrap_or_default(),
        ..ListRequest::default()
    };
    for (c, want) in [
        (None, false),
        (Some(Consistency::FOLLOWER), false),
        (Some(Consistency::LINEARIZABLE), true),
    ] {
        let before = f.durable.queries().len();
        f.list(ask(c)).await.unwrap();
        let qs = f.durable.queries();
        assert_eq!(qs.len(), before + 1, "{c:?}: one query reaches the driver");
        assert_eq!(qs[before].linearizable, want, "{c:?}");
    }
    let before = f.durable.queries().len();
    refused(
        f.list(ListRequest {
            kind: "key-revocation".into(),
            consistency: 99.into(),
            ..ListRequest::default()
        })
        .await,
        ErrorCode::InvalidArgument,
        "schema",
    );
    assert_eq!(
        f.durable.queries().len(),
        before,
        "a refused value reaches no driver"
    );

    f.durable.set_down(true);
    refused(
        f.list(ask(Some(Consistency::LINEARIZABLE))).await,
        ErrorCode::Unavailable,
        "engine",
    );
    assert_eq!(
        f.durable.queries().last().map(|q| q.linearizable),
        Some(true),
        "the one query that failed was the linearizable one"
    );
}
