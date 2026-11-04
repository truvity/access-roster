#![allow(clippy::unwrap_used, clippy::expect_used)] // a failed unwrap in a test is the failure
//! The rules of store@ on every call, over the kit's transport: the address vectors of
//! store-api.md, the scope refusals, each refusal reason, the grant check, TTL, batches, versions,
//! expiry and the config class.

mod common;

use std::sync::atomic::Ordering;

use common::*;
use connectrpc::error::ErrorCode;
use sluis_proto::sluis::store::v2alpha1::{Consistency, GetRequest, ListRequest, Verb};

const WRITES: [&str; 4] = ["create", "update", "delete", "apply"];

fn g(f: &F) -> Vec<u8> {
    f.grant("session", &["acme"], &WRITES, 60)
}

// ---- address and scope ----

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

#[tokio::test]
async fn watch_is_unimplemented() {
    let f = F::new().await;
    f.as_("key");
    assert_eq!(f.watch().await.code, ErrorCode::Unimplemented);
}

// ---- the grant ----

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
    ];
    let done = f.write(ops, &[]).await.unwrap();
    assert_eq!(done.items.len(), 4);
    assert_eq!(done.items[2].address.tenant, "");
    assert_eq!(
        f.durable.keys(),
        [
            "dev/-/data-key-wrap/cookie/1/node-1-aaaa",
            "dev/-/data-key-wrap/grant/1/node-1-aaaa",
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
    assert_eq!(f.durable.keys().len(), 4);

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
    assert_eq!(l.items.len(), 2);
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
    f.as_("adapter-upstream-oidc");
    let e = f.get("upstream-secret", "", "workforce").await.unwrap_err();
    assert_eq!(e.code, ErrorCode::Unimplemented);
    // The rule still comes first.
    f.as_("session");
    refused(
        f.get("upstream-secret", "", "workforce").await,
        ErrorCode::PermissionDenied,
        "rule",
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
    f.as_("adapter-upstream-oidc");
    assert_eq!(
        f.get("upstream-secret", "", "w").await.unwrap_err().code,
        ErrorCode::Unimplemented
    );
    f.as_("key");
    assert_eq!(f.watch().await.code, ErrorCode::Unimplemented);

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
