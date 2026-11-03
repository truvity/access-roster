//! The golden cases of the brief of the registry codegen; the Go package has the same cases in
//! `kits/go/registry/registry_test.go`.

use core::time::Duration;
use sluis_registry::{
    Class, actor_by_name, actors, callers_of, driver_owner, is_writer, key_allows, kind_by_name,
    kind_by_segment, kinds, may_call, name_for_uid, store_allows, store_self_scoped,
    store_self_scoped_for, uid,
};

#[test]
fn store_rules() {
    let cases = [
        ("session", "session-chain", "create", true),
        ("exchange", "session-chain", "get", true),
        ("exchange", "session-chain", "create", false),
        ("entry", "person", "get", false),
        ("key", "data-key-wrap", "create", true),
        ("signer", "signing-ring", "apply", true),
        ("entry", "signing-ring", "get", true),
        ("entry", "signing-ring", "create", false),
        ("nobody", "signing-ring", "get", false),
        ("entry", "no-such-kind", "get", false),
        ("entry", "signing-ring", "no-such-verb", false),
    ];
    for (actor, segment, verb, want) in cases {
        assert_eq!(
            store_allows(actor, segment, verb),
            want,
            "{actor} {segment} {verb}"
        );
    }
    assert!(store_self_scoped("exchange", "replay-guard"));
    assert!(!store_self_scoped("exchange", "session-chain"));
    assert!(is_writer("session", "session-chain"));
    assert!(!is_writer("exchange", "session-chain"));
    // The backup job reads every backed-up kind in full. Switch is backed up and its readers are
    // "the actor named in the id", which binds every other actor to its own ids; exporter must not
    // be bound.
    for verb in ["get", "list"] {
        assert!(
            store_allows("exporter", "switch", verb),
            "exporter {verb} switch"
        );
        assert!(!store_self_scoped_for("exporter", "switch", verb));
        assert!(store_self_scoped_for("session", "switch", verb));
    }
    assert!(!store_allows("exporter", "switch", "create"));
    // An adapter writes the directory facts under its own ids and reads them all: the verb decides.
    assert!(store_self_scoped_for(
        "adapter-github",
        "directory-user",
        "create"
    ));
    assert!(!store_self_scoped_for(
        "adapter-github",
        "directory-user",
        "get"
    ));
    assert!(!store_self_scoped_for(
        "session",
        "directory-user",
        "create"
    ));
}

#[test]
fn key_rules() {
    let cases = [
        ("policy", "grant", "seal", true),
        ("session", "grant", "seal", false),
        ("store", "grant", "open", true),
        ("writer", "audit-log", "sign", true),
        ("writer", "evidence", "seal", true),
        ("writer", "evidence", "open", false),
        ("sluis-node", "workload-issuer", "sign", true),
        ("product-emitter", "pseudonym", "mac", true),
        ("policy", "grant", "no-such-op", false),
        ("policy", "no-such-purpose", "seal", false),
    ];
    for (actor, purpose, op, want) in cases {
        assert_eq!(
            key_allows(actor, purpose, op),
            want,
            "{actor} {purpose} {op}"
        );
    }
}

#[test]
fn call_graph() {
    let cases = [
        ("entry", "session", true),
        ("session", "entry", false),
        ("entry", "signer", false),
        ("session", "store", true),
        ("session", "key", true),
        ("store", "transport", true),
        ("writer", "transport", true),
        ("entry", "adapter-github", true),
        ("signer", "adapter-github", false),
        ("key", "key", false),
        ("sluis-node", "key", true),
        ("sluis-node", "store", false),
    ];
    for (caller, callee, want) in cases {
        assert_eq!(may_call(caller, callee), want, "{caller} -> {callee}");
    }
    let callers = callers_of("session");
    assert!(callers.is_sorted());
    assert!(callers.contains(&"entry"));
    assert!(!callers.contains(&"signer"));
    assert!(callers_of("nobody").is_empty());
}

#[test]
fn uids() {
    assert_eq!(uid("store", 0), Some(61012));
    assert_eq!(uid("store", 3), Some(61012 + 3000));
    assert_eq!(uid("nobody", 0), None);
    assert_eq!(uid("store", 1 << 31), None);
    for a in actors() {
        for block in [0, 1, 2, 40] {
            let u = uid(a.name, block);
            assert!(u.is_some(), "{} has no uid", a.name);
            assert_eq!(name_for_uid(u.unwrap_or_default()), Some((a.name, block)));
        }
    }
    assert_eq!(name_for_uid(1000), None);
    assert_eq!(name_for_uid(61127), None);
}

#[test]
fn drivers() {
    assert_eq!(driver_owner("driver-store-rqlite"), Some("store"));
    assert_eq!(driver_owner("driver-key-software"), Some("key"));
    assert_eq!(driver_owner("driver-writer-spool"), Some("writer"));
    assert_eq!(driver_owner("driver-indexer-sqlite"), Some("indexer"));
    assert_eq!(driver_owner("store"), None);
}

#[test]
fn kinds_and_actors() {
    // The segment table of docs/reference/store-api.md, "Address encoding".
    for (name, segment) in [
        ("DataKeyWrap", "data-key-wrap"),
        ("SessionChain", "session-chain"),
        ("Lease", "lease"),
        (
            "PredefinedPolicyLinkTemporary",
            "predefined-policy-link-temporary",
        ),
    ] {
        assert_eq!(kind_by_name(name).map(|k| k.segment), Some(segment));
        assert_eq!(kind_by_segment(segment).map(|k| k.name), Some(name));
    }
    assert!(kind_by_name("NoSuchKind").is_none());
    let wrap = kind_by_name("DataKeyWrap");
    assert_eq!(wrap.map(|k| k.class), Some(Class::Durable));
    assert!(wrap.is_some_and(|k| k.indexes.contains(&"by_recipient")));
    let lease = kind_by_name("Lease");
    assert!(lease.is_some_and(|k| k.self_scoped && k.class == Class::Temp));
    assert_eq!(lease.map(|k| k.ttl_default), Some(Duration::from_secs(30)));
    assert_eq!(lease.map(|k| k.ttl_max), Some(Duration::from_secs(600)));
    let chain = kind_by_name("SessionChain");
    assert_eq!(
        chain.map(|k| k.ttl_max),
        Some(Duration::from_secs(90 * 86_400))
    );
    for k in kinds() {
        if k.class == Class::Temp {
            assert!(
                k.ttl_max > Duration::ZERO,
                "{} has no maximum lifetime",
                k.name
            );
        }
        assert!(
            k.ttl_max == Duration::ZERO || k.ttl_default <= k.ttl_max,
            "{}",
            k.name
        );
    }
    assert_eq!(kinds().len(), 112);
    assert_eq!(actors().len(), 20);
    let adapter = actor_by_name("adapter-github");
    assert!(adapter.is_some_and(|a| a.family == "work" && a.language == "Go" && !a.holder));
    assert!(actor_by_name("sluis-node").is_some_and(|a| a.family == "platform"));
    assert!(actor_by_name("product-emitter").is_none());
}
