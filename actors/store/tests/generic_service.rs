#![allow(clippy::unwrap_used, clippy::expect_used)] // a failed unwrap in a test is the failure
//! One generic store service (ADR 0005, "The generic service"): the same Write, Get and List serve every durable and
//! temp kind of the registry with a kind name and bytes, and no call is named after a kind.

mod common;

use common::*;
use sluis_proto::sluis::store::v2alpha1::{ListRequest, Verb};
use sluis_registry::{Class, Scope};

const WRITES: [&str; 4] = ["create", "update", "delete", "apply"];

/// The tenant and the id of a good address for `kind` written by `caller`.
fn address_for(kind: &sluis_registry::Kind, caller: &str) -> (&'static str, String) {
    let tenant = if kind.scope == Scope::BoundaryTenant {
        "acme"
    } else {
        ""
    };
    let id = match kind.name {
        "DataKeyWrap" => "data/1/n-1".to_owned(),
        _ if kind.self_scoped
            || sluis_registry::store_self_scoped_for(caller, kind.segment, "create") =>
        {
            format!("{caller}/x")
        }
        _ => "x".to_owned(),
    };
    (tenant, id)
}

/// The callers of store@ that the registry names as the writer of the kind.
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

/// verifies: REQ-DATA-045
/// Every durable and temp kind that has a writer and no message of its own is created, read and listed by its writer
/// through the same three calls. The registry is the only thing that names a kind: the sweep is over the registry, so a
/// kind added to it is in the next run with no new method.
#[tokio::test]
async fn every_kind_of_the_registry_is_served_by_the_same_calls() {
    let f = F::new().await;
    let (mut served, mut skipped) = (0usize, Vec::new());
    for kind in sluis_registry::kinds()
        .iter()
        .filter(|k| matches!(k.class, Class::Durable | Class::Temp))
    {
        let writers = writers_of(kind);
        let Some(&caller) = writers.first() else {
            skipped.push(format!("{}: no writer", kind.name));
            continue;
        };
        let (tenant, id) = address_for(kind, caller);
        let value: Vec<u8> = if kind.treatment == "sealed" {
            sealed()
        } else {
            b"value".to_vec()
        };
        // A kind with a message of its own is checked against it: the bytes of the sweep are not that message.
        if store::messages::decodes(kind.segment, tenant, &id, &value).is_some() {
            skipped.push(format!("{}: has a message", kind.name));
            continue;
        }
        f.as_(caller);
        let grant = f.grant(caller, &["acme"], &WRITES, 60);
        let mut o = op(Verb::CREATE, kind.segment, tenant, &id, &value);
        if kind.class == Class::Temp {
            o = with_ttl(o, 5);
        }
        f.write(vec![o], &grant)
            .await
            .unwrap_or_else(|e| panic!("{caller} creates {}: {e:?}", kind.name));
        let got = f
            .get(kind.segment, tenant, &id)
            .await
            .unwrap_or_else(|e| panic!("{caller} reads {}: {e:?}", kind.name));
        assert_eq!(got.item.value, value, "{}", kind.name);
        let listed = f
            .list(ListRequest {
                kind: kind.segment.into(),
                tenant: tenant.into(),
                ..ListRequest::default()
            })
            .await
            .unwrap_or_else(|e| panic!("{caller} lists {}: {e:?}", kind.name));
        assert!(
            listed.items.iter().any(|i| i.address.id == id),
            "{}: the item is not listed",
            kind.name
        );
        served += 1;
    }
    assert!(
        served > 60,
        "the sweep served {served} kinds, skipped {skipped:?}"
    );
}

/// verifies: REQ-DATA-019
/// store@ holds the ciphertext and the hash the writing actor produced, byte for byte, and no key that opens one: every
/// data key purpose of both scopes and every op is refused to store@ in the key rules, but the boundary `grant` key that
/// opens a grant, and the archive key that a restore unwraps. What the engines hold after the sweep of all kinds is
/// exactly the values the writers gave, as a dump of both engines shows.
#[tokio::test]
async fn store_holds_what_the_writer_produced_and_no_key_that_opens_it() {
    use sluis_registry::{KeyScope, key_allows};
    let ops = [
        "seal",
        "open",
        "sign",
        "mac",
        "public-key",
        "wrap",
        "unwrap",
    ];
    for scope in [KeyScope::Tenant, KeyScope::Boundary] {
        for purpose in [
            "data",
            "pseudonym",
            "pairwise",
            "evidence",
            "chain",
            "cookie",
            "mac",
            "grant",
        ] {
            for op in ops {
                let allowed = key_allows("store", scope, purpose, op);
                let may = scope == KeyScope::Boundary && purpose == "grant" && op == "open";
                assert_eq!(allowed, may, "store {scope:?} {purpose} {op}");
            }
        }
    }
    assert!(key_allows(
        "store",
        KeyScope::Boundary,
        "backup-archive",
        "unwrap"
    ));

    let f = F::new().await;
    let (mut ciphertext, mut hashed) = (0usize, 0usize);
    let mut given: Vec<Vec<u8>> = Vec::new();
    for kind in sluis_registry::kinds()
        .iter()
        .filter(|k| matches!(k.class, Class::Durable | Class::Temp))
        .filter(|k| matches!(k.treatment, "sealed" | "hashed"))
    {
        let Some(&caller) = writers_of(kind).first() else {
            continue;
        };
        let (tenant, id) = address_for(kind, caller);
        // The ciphertext of the writer (a sealed value) or the hash it computed (32 bytes that are no text).
        let value: Vec<u8> = if kind.treatment == "sealed" {
            let mut v = sealed();
            v.extend_from_slice(kind.name.as_bytes());
            v
        } else {
            (0u8..32)
                .map(|b| b.wrapping_mul(7).wrapping_add(0x80))
                .collect()
        };
        if store::messages::decodes(kind.segment, tenant, &id, &value).is_some() {
            continue;
        }
        f.as_(caller);
        let grant = f.grant(caller, &["acme"], &WRITES, 60);
        let mut o = op(Verb::CREATE, kind.segment, tenant, &id, &value);
        if kind.class == Class::Temp {
            o = with_ttl(o, 5);
        }
        f.write(vec![o], &grant).await.unwrap_or_else(|e| {
            panic!("{caller} creates {}: {e:?}", kind.name);
        });
        given.push(value);
        if kind.treatment == "sealed" {
            ciphertext += 1;
        } else {
            hashed += 1;
        }
    }
    assert!(
        ciphertext > 10 && hashed > 0,
        "{ciphertext} sealed, {hashed} hashed"
    );
    let mut held: Vec<Vec<u8>> = Vec::new();
    for engine in [&f.durable, &f.temp] {
        for key in engine.keys() {
            held.push(engine.item(&key).unwrap().value);
        }
    }
    given.sort();
    held.sort();
    assert_eq!(
        held, given,
        "the engines hold the writers' values unchanged"
    );
}
