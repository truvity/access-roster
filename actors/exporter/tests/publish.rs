#![allow(refining_impl_trait)] // the generated trait returns `impl Encodable`; a concrete type is fine
#![allow(clippy::unwrap_used, clippy::expect_used)] // a failed unwrap in a test is the failure
//! `exporter` against an in-process `store@` (a change log and a watch), the real directory driver and the in-memory
//! driver of the destination port. Each test says which row of REQ-EXPORT it proves.

mod common;

use std::sync::atomic::Ordering;
use std::time::Duration;

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P384_SHA384_FIXED, UnparsedPublicKey};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use common::{World, doc, kids, public_doc, spawn, test_key, until};
use exporter::config::Refused;
use exporter::run::Target;
use serde_json::Value;
use sluis_destination::memory::{Call, Memory, Op};
use sluis_destination::{Destination, Error, sha256_hex};
use sluis_driver_exporter_dir::{Directory, suite};
use sluis_proto::sluis::store::v2alpha1::Consistency;

struct Dir {
    root: tempfile::TempDir,
    _state: tempfile::TempDir,
    driver: Directory,
}

fn dir() -> Dir {
    let (root, state) = suite::temp().unwrap();
    let driver = Directory::open(root.path(), state.path()).unwrap();
    Dir {
        root,
        _state: state,
        driver,
    }
}

impl Dir {
    fn read(&self) -> Option<Vec<u8>> {
        std::fs::read(self.root.path().join("jwks")).ok()
    }
    fn target(&self) -> Vec<Target<Directory>> {
        vec![Target {
            name: "local".into(),
            driver: self.driver.clone(),
            documents: vec![doc()],
        }]
    }
}

/// Sign `msg` with the key and check it against the published document by `kid`, as a relying party does: the key is
/// found by its `kid`, its point is rebuilt from the published `x` and `y` (RFC 7518 section 6.2.1).
fn verifies_against(set: &[u8], kid: &str, k: &common::TestKey, msg: &[u8]) -> bool {
    let sig = k.pair.sign(&SystemRandom::new(), msg).unwrap();
    let v: Value = serde_json::from_slice(set).unwrap();
    let Some(jwk) = v["keys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|j| j["kid"] == kid)
    else {
        return false;
    };
    let part = |n: &str| URL_SAFE_NO_PAD.decode(jwk[n].as_str().unwrap()).unwrap();
    let mut point = vec![0x04];
    point.extend(part("x"));
    point.extend(part("y"));
    UnparsedPublicKey::new(&ECDSA_P384_SHA384_FIXED, &point)
        .verify(msg, sig.as_ref())
        .is_ok()
}

/// A revoked key leaves the key set at once, from the next write, and a token it signed fails against the document
/// while a token of the key that stays still verifies. The document is written with its content type and
/// `Cache-Control: public, max-age=300`, whole, to a directory.
///
/// verifies: REQ-EXPORT-020
#[tokio::test]
async fn a_revoked_key_leaves_the_set_and_its_tokens_fail_against_the_document() {
    let w = World::new().await;
    let d = dir();
    let (a, b) = (test_key("kid-a", "active"), test_key("kid-b", "active"));
    w.store.set_ring(vec![a.key.clone(), b.key.clone()]);
    let run = spawn(w.engine(d.target(), |_| {}));
    until(10, "the first document", || d.read().is_some()).await;
    let first = d.read().unwrap();
    assert_eq!(kids(&first), ["kid-a", "kid-b"]);
    assert!(verifies_against(&first, "kid-a", &a, b"token"));
    // The driver records the headers right after the document.
    until(10, "the record of the driver", || {
        let l = futures::executor::block_on(d.driver.list("jwks", None, 0)).unwrap();
        !l.documents.is_empty()
    })
    .await;
    let listed = d.driver.list("jwks", None, 0).await.unwrap().documents;
    assert_eq!(
        (
            listed[0].content_type.as_str(),
            listed[0].cache_control.as_str()
        ),
        ("application/json", "public, max-age=300")
    );

    w.store.revoke("kid-a");
    until(10, "the document without the revoked key", || {
        d.read().is_some_and(|b| kids(&b) == ["kid-b"])
    })
    .await;
    let after = d.read().unwrap();
    assert!(
        !verifies_against(&after, "kid-a", &a, b"token"),
        "a token of the revoked key verifies"
    );
    assert!(verifies_against(&after, "kid-b", &b, b"token"));

    // A key that joins the ring later is published too, and the revoked one stays out of every later document.
    let c = test_key("kid-c", "pre-published");
    w.store
        .set_ring(vec![a.key.clone(), b.key.clone(), c.key.clone()]);
    until(10, "the new key", || {
        d.read().is_some_and(|b| kids(&b) == ["kid-b", "kid-c"])
    })
    .await;
    run.stop().await;
}

/// Reads are linearizable on both kinds a revocation decides, and a listing that is not asked for that is never used
/// to build the document.
#[tokio::test]
async fn the_document_is_built_from_linearizable_listings() {
    let w = World::new().await;
    let d = dir();
    w.store.set_ring(vec![test_key("kid-a", "active").key]);
    let run = spawn(w.engine(d.target(), |_| {}));
    until(10, "the first document", || d.read().is_some()).await;
    run.stop().await;
    // The watches list their kinds as the helper does (not linearizable, they only start a follow); the reads the
    // document is built from ask for a linearizable one, for both kinds.
    let lists = w.store.lists();
    for kind in ["signing-ring", "key-revocation"] {
        assert!(
            lists
                .iter()
                .any(|(k, c)| k == kind && *c == Consistency::LINEARIZABLE),
            "{kind} was never read linearizably: {lists:?}"
        );
    }
}

/// A reader of the file while the key set is rebuilt many times sees a whole JSON document each time, never half of one
/// (ADR 0009: written whole and atomically, a rename in a directory).
///
/// verifies: REQ-EXPORT-020
#[tokio::test]
async fn a_reader_never_sees_half_a_document_while_it_is_rebuilt() {
    let w = World::new().await;
    let d = dir();
    let keys: Vec<_> = (0..12)
        .map(|i| test_key(&format!("kid-{i}"), "active").key)
        .collect();
    w.store.set_ring(keys[..1].to_vec());
    let run = spawn(w.engine(d.target(), |_| {}));
    until(10, "the first document", || d.read().is_some()).await;
    let path = d.root.path().join("jwks");
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let reader = {
        let (stop, path) = (stop.clone(), path.clone());
        std::thread::spawn(move || {
            let mut reads = 0u32;
            while !stop.load(Ordering::SeqCst) {
                let b = std::fs::read(&path).expect("the document is always there");
                let v: Value = serde_json::from_slice(&b).expect("the document is whole");
                assert!(v["keys"].is_array());
                reads += 1;
            }
            reads
        })
    };
    for n in 2..=keys.len() {
        w.store.set_ring(keys[..n].to_vec());
        let want = n;
        until(10, "a rebuilt document", || {
            d.read().is_some_and(|b| kids(&b).len() == want)
        })
        .await;
    }
    stop.store(true, Ordering::SeqCst);
    assert!(
        reader.join().unwrap() > 100,
        "the reader read too little to prove anything"
    );
    run.stop().await;
}

/// After a revocation the destination is called in the order write, purge, read back, and the report is written after
/// the read back and not before (the number of calls the destination had taken is in the log of the report).
///
/// verifies: REQ-EXPORT-021
#[tokio::test]
async fn write_purge_read_back_then_report_in_that_order() {
    let w = World::new().await;
    let m = Memory::with_public("https://sluis.example.com", true);
    *w.store.memory.lock().unwrap() = Some(m.clone());
    let (a, b) = (test_key("kid-a", "active"), test_key("kid-b", "active"));
    w.store.set_ring(vec![a.key.clone(), b.key.clone()]);
    let targets = vec![Target {
        name: "edge".into(),
        driver: m.clone(),
        documents: vec![public_doc("https://sluis.example.com")],
    }];
    let run = spawn(w.engine(targets, |_| {}));
    until(10, "the first publication", || {
        w.store
            .report("edge/jwks")
            .is_some_and(|r| r.state == "published")
    })
    .await;
    m.clear_calls();
    let before = w.store.report_log().len();

    w.store.revoke("kid-a");
    until(10, "the report after the revocation", || {
        w.store.report_log().len() > before
    })
    .await;
    let calls: Vec<_> = m
        .calls()
        .into_iter()
        .filter(|c| !matches!(c, Call::List(_)))
        .collect();
    let url = "https://sluis.example.com/jwks".to_owned();
    assert_eq!(
        calls,
        [
            Call::Put("jwks".into()),
            Call::Purge(vec![url.clone()]),
            Call::ReadBack(url)
        ],
        "write, purge, read back"
    );
    let (id, report, calls_at_report) = w.store.report_log().pop().unwrap();
    assert_eq!(id, "edge/jwks");
    assert_eq!(report.state, "published");
    assert!(
        calls_at_report >= 4,
        "the report was written before the read back ({calls_at_report} calls)"
    );
    assert_eq!(kids(&m.body("jwks").unwrap()), ["kid-b"]);
    run.stop().await;
}

/// The state is `published` only when the read back returned the written digest; an edge that serves the old document
/// after a purge keeps it `purge-pending` (and the publication is tried again), and `written` where the destination has
/// no public address to read back from.
///
/// verifies: REQ-EXPORT-022
#[tokio::test]
async fn the_report_says_published_only_for_the_written_digest() {
    let w = World::new().await;
    let m = Memory::with_public("https://sluis.example.com", true);
    let (a, b) = (test_key("kid-a", "active"), test_key("kid-b", "active"));
    w.store.set_ring(vec![a.key.clone(), b.key.clone()]);
    let targets = vec![Target {
        name: "edge".into(),
        driver: m.clone(),
        documents: vec![public_doc("https://sluis.example.com")],
    }];
    let run = spawn(w.engine(targets, |c| c.timing.budget = Duration::from_millis(400)));
    until(10, "published", || {
        w.store
            .report("edge/jwks")
            .is_some_and(|r| r.state == "published")
    })
    .await;
    let r = w.store.report("edge/jwks").unwrap();
    let first = sha256_hex(&m.body("jwks").unwrap());
    assert_eq!(r.sha256, first);
    assert_eq!(r.kids, ["kid-a", "kid-b"]);
    assert!(r.public && r.read_back_at.is_set() && r.written_at.is_set() && r.purged_at.is_set());
    assert_eq!(r.public_address, "https://sluis.example.com/jwks");

    // The edge keeps the old copy and ignores the purge: the read back returns another digest.
    m.purge_does_nothing(true);
    w.store.revoke("kid-a");
    until(10, "purge-pending", || {
        w.store
            .report("edge/jwks")
            .is_some_and(|r| r.state == "purge-pending")
    })
    .await;
    let r = w.store.report("edge/jwks").unwrap();
    assert_eq!(r.sha256, sha256_hex(&m.body("jwks").unwrap()));
    assert_ne!(r.sha256, first, "the report names the digest written");
    assert!(
        !r.read_back_at.is_set(),
        "a read back that did not match has no time"
    );
    // The edge recovers: the retry finds the written digest and reports it published.
    m.purge_does_nothing(false);
    until(10, "published again", || {
        w.store
            .report("edge/jwks")
            .is_some_and(|r| r.state == "published")
    })
    .await;
    assert_eq!(w.store.report("edge/jwks").unwrap().kids, ["kid-b"]);
    run.stop().await;

    // A destination with no public address cannot read back: written, no purge or read back time, not counted.
    let w = World::new().await;
    let d = dir();
    w.store.set_ring(vec![test_key("kid-a", "active").key]);
    let run = spawn(w.engine(d.target(), |_| {}));
    until(10, "written", || w.store.report("local/jwks").is_some()).await;
    let r = w.store.report("local/jwks").unwrap();
    assert_eq!(r.state, "written");
    assert!(
        !r.public && !r.read_back_at.is_set() && !r.purged_at.is_set() && r.written_at.is_set()
    );
    run.stop().await;
}

/// When `KeyRevocation` cannot be read, the published object is byte for byte what it was, even when the ring changed
/// (a new key is not published without knowing what is revoked), and the report says `unverified`. When it can be read
/// again the document is published.
///
/// verifies: REQ-EXPORT-024
#[tokio::test]
async fn an_unreadable_revocation_list_leaves_the_object_as_it_is_and_reports_unverified() {
    let w = World::new().await;
    let d = dir();
    let (a, b) = (
        test_key("kid-a", "active"),
        test_key("kid-b", "pre-published"),
    );
    w.store.set_ring(vec![a.key.clone()]);
    let run = spawn(w.engine(d.target(), |_| {}));
    until(10, "the first document", || d.read().is_some()).await;
    let before = d.read().unwrap();

    w.store.revocations_down.store(true, Ordering::SeqCst);
    w.store.set_ring(vec![a.key.clone(), b.key.clone()]);
    w.store.revoke("kid-a");
    until(10, "unverified", || {
        w.store
            .report("local/jwks")
            .is_some_and(|r| r.state == "unverified")
    })
    .await;
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(
        d.read().unwrap(),
        before,
        "the object changed while a revocation could not be read"
    );
    assert!(d.read().unwrap().len() > 2, "the object was emptied");

    w.store.revocations_down.store(false, Ordering::SeqCst);
    until(10, "the document after the read is back", || {
        d.read().is_some_and(|x| kids(&x) == ["kid-b"])
    })
    .await;
    until(10, "no longer unverified", || {
        w.store
            .report("local/jwks")
            .is_some_and(|r| r.state != "unverified")
    })
    .await;
    run.stop().await;
}

/// The same when the whole store goes away: the watch breaks, the document stays, the report says `unverified` once, and
/// the revocation made meanwhile is published when the store is back.
///
/// verifies: REQ-EXPORT-024
#[tokio::test]
async fn a_store_that_goes_away_leaves_the_object_and_a_revocation_made_meanwhile_is_published_after()
 {
    let w = World::new().await;
    let d = dir();
    let (a, b) = (test_key("kid-a", "active"), test_key("kid-b", "active"));
    w.store.set_ring(vec![a.key.clone(), b.key.clone()]);
    let run = spawn(w.engine(d.target(), |_| {}));
    until(10, "the first document", || d.read().is_some()).await;
    let before = d.read().unwrap();

    w.store.down.store(true, Ordering::SeqCst);
    // The report cannot be set while the store is down, so the proof is the object.
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(d.read().unwrap(), before);
    w.store.revoke("kid-a");
    w.store.down.store(false, Ordering::SeqCst);
    until(10, "the revoked key leaves", || {
        d.read().is_some_and(|x| kids(&x) == ["kid-b"])
    })
    .await;
    run.stop().await;
}

/// A restart watches from the saved cursor, and a revocation made while it was down is published; the cursor holds the
/// points of both kinds.
///
/// verifies: REQ-EXPORT-015
#[tokio::test]
async fn a_restart_resumes_from_the_cursor() {
    let w = World::new().await;
    let d = dir();
    let (a, b) = (test_key("kid-a", "active"), test_key("kid-b", "active"));
    w.store.set_ring(vec![a.key.clone(), b.key.clone()]);
    w.store.revoke("kid-zzz");
    let head = w.store.head();
    let (ring_point, revoke_point) = (head, head);
    let run = spawn(w.engine(d.target(), |_| {}));
    until(10, "the first document and a cursor at the head", || {
        d.read().is_some()
            && w.store
                .cursor("local")
                .is_some_and(|c| c.signing_ring == ring_point && c.key_revocation == revoke_point)
    })
    .await;
    run.stop().await;

    let down_point = w.store.revoke("kid-a");
    w.store.clear_requests();
    let run = spawn(w.engine(d.target(), |_| {}));
    until(10, "the revoked key leaves", || {
        d.read().is_some_and(|x| kids(&x) == ["kid-b"])
    })
    .await;
    let opens = w.store.opens();
    assert!(
        opens.contains(&("signing-ring".into(), ring_point)),
        "{opens:?}"
    );
    assert!(
        opens.contains(&("key-revocation".into(), revoke_point)),
        "{opens:?}"
    );
    until(10, "the cursor moves", || {
        w.store
            .cursor("local")
            .is_some_and(|c| c.key_revocation == down_point)
    })
    .await;
    run.stop().await;
}

/// A cursor that is gone costs a full reconcile and loses no document: the watch lists first and the document is
/// written again as it should be.
///
/// verifies: REQ-EXPORT-015
#[tokio::test]
async fn a_lost_cursor_costs_a_full_reconcile_and_loses_no_document() {
    let w = World::new().await;
    let d = dir();
    let (a, b) = (test_key("kid-a", "active"), test_key("kid-b", "active"));
    w.store.set_ring(vec![a.key.clone(), b.key.clone()]);
    let run = spawn(w.engine(d.target(), |_| {}));
    until(10, "a cursor", || w.store.cursor("local").is_some()).await;
    run.stop().await;
    w.store.delete_cursors();
    w.store.revoke("kid-a");
    w.store.clear_requests();
    let run = spawn(w.engine(d.target(), |_| {}));
    until(10, "the revoked key leaves", || {
        d.read().is_some_and(|x| kids(&x) == ["kid-b"])
    })
    .await;
    // No cursor: both watches were opened from the listing, never from a point of the engine's own making.
    let opens = w.store.opens();
    assert!(
        opens.iter().all(|(_, p)| *p == w.store.head() || *p > 0),
        "{opens:?}"
    );
    assert!(
        w.store
            .lists()
            .iter()
            .filter(|(k, _)| k == "signing-ring")
            .count()
            >= 2,
        "the ring was listed by the watch and by the reconcile"
    );
    run.stop().await;
}

/// A saved point the log no longer holds is not trusted: the watch lists again, nothing is skipped, and the revocation
/// made while the exporter was down is published.
///
/// verifies: REQ-EXPORT-015
#[tokio::test]
async fn a_stale_resume_point_is_resynced_and_nothing_is_skipped() {
    let w = World::new().await;
    let d = dir();
    let (a, b) = (test_key("kid-a", "active"), test_key("kid-b", "active"));
    w.store.set_ring(vec![a.key.clone(), b.key.clone()]);
    let run = spawn(w.engine(d.target(), |_| {}));
    until(10, "a cursor", || {
        w.store.cursor("local").is_some_and(|c| c.signing_ring > 0)
    })
    .await;
    run.stop().await;
    let saved = w.store.cursor("local").unwrap();

    // While it is down: a revocation, and the log forgets the point the cursor holds.
    w.store.revoke("kid-a");
    w.store.forget_before(w.store.head());
    assert!(saved.signing_ring < w.store.head());
    w.store.clear_requests();
    let run = spawn(w.engine(d.target(), |_| {}));
    until(10, "the revoked key leaves", || {
        d.read().is_some_and(|x| kids(&x) == ["kid-b"])
    })
    .await;
    let opens = w.store.opens();
    assert!(
        opens.contains(&("signing-ring".into(), saved.signing_ring)),
        "it tried the saved point first: {opens:?}"
    );
    assert!(
        w.store
            .lists()
            .iter()
            .filter(|(k, _)| k == "signing-ring")
            .count()
            >= 2
    );
    run.stop().await;
}

/// Every write is an audit fact, once; a document the check refused is one fact at the start and no more, however many
/// times the reconcile runs.
///
/// verifies: REQ-EXPORT-017
#[tokio::test]
async fn each_write_and_each_refusal_is_one_fact_and_no_fact_carries_a_list() {
    let w = World::new().await;
    let d = dir();
    w.store.set_ring(vec![
        test_key("kid-a", "active").key,
        test_key("kid-b", "active").key,
    ]);
    let refused = vec![Refused {
        destination: "local".into(),
        document: "bad".into(),
        reason: "not_exportable",
    }];
    let run = spawn(w.engine(d.target(), |c| {
        c.refused = refused;
        c.reconcile = Duration::from_millis(150);
    }));
    until(10, "the first write", || {
        !w.spool.of("exporter.write").is_empty()
    })
    .await;
    tokio::time::sleep(Duration::from_millis(800)).await; // several reconciles
    w.store.revoke("kid-a");
    until(10, "the second write", || {
        w.spool.of("exporter.write").len() == 2
    })
    .await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    run.stop().await;

    let writes = w.spool.of("exporter.write");
    assert_eq!(
        writes.len(),
        2,
        "one fact for each write, none for a reconcile that wrote nothing"
    );
    assert_eq!(writes[0]["activity_id"], 1);
    assert_eq!(writes[1]["activity_id"], 3);
    for r in &writes {
        let s = &r["unmapped"]["sluis"];
        assert_eq!(
            (
                s["destination"].as_str(),
                s["document"].as_str(),
                s["address"].as_str()
            ),
            (Some("local"), Some("jwks"), Some("jwks"))
        );
        assert_eq!(s["sha256"].as_str().map(str::len), Some(64));
        assert!(s["kids"].is_u64(), "a count and not a joined list");
    }
    assert_eq!(writes[0]["unmapped"]["sluis"]["kids"], 2);
    assert_eq!(writes[1]["unmapped"]["sluis"]["kids"], 1);
    assert_eq!(
        writes[1]["unmapped"]["sluis"]["sha256"].as_str().unwrap(),
        sha256_hex(&d.read().unwrap())
    );
    let refusals = w.spool.of("exporter.refused");
    assert_eq!(
        refusals.len(),
        1,
        "a refusal is a fact once, not a retry loop"
    );
    assert_eq!(refusals[0]["status_code"], "not_exportable");
    // No string of any record is near the limit of a record string.
    for r in w.spool.records() {
        assert!(
            r["unmapped"]["sluis"]
                .as_object()
                .unwrap()
                .values()
                .all(|v| v.as_str().is_none_or(|s| s.len() < 200))
        );
    }
}

/// An idle exporter writes no stream of audit records or refusals: over several reconciles and no change, the audit log
/// holds the one fact of the start and one for the first write, and store@ has seen no `Get` of an item that is absent.
///
/// verifies: REQ-AUDIT-180
#[tokio::test]
async fn an_idle_exporter_writes_no_stream_of_facts_and_asks_for_nothing_that_is_absent() {
    let w = World::new().await;
    let d = dir();
    // The ring does not exist yet: the normal state before signer has written it.
    let run = spawn(w.engine(d.target(), |c| c.reconcile = Duration::from_millis(100)));
    tokio::time::sleep(Duration::from_millis(900)).await;
    assert!(
        d.read().is_none(),
        "nothing is published before there is a ring"
    );
    w.store.set_ring(vec![test_key("kid-a", "active").key]);
    until(10, "the first document and its fact", || {
        d.read().is_some() && !w.spool.of("exporter.write").is_empty()
    })
    .await;
    let before = w.spool.records().len();
    tokio::time::sleep(Duration::from_millis(1500)).await; // at least ten reconciles
    run.stop().await;
    assert_eq!(
        w.spool.records().len(),
        before,
        "an idle exporter wrote facts: {:?}",
        w.spool
            .records()
            .iter()
            .map(|r| r["metadata"]["event_code"].clone())
            .collect::<Vec<_>>()
    );
    assert_eq!(w.spool.of("exporter.start").len(), 1);
    assert_eq!(w.spool.of("exporter.write").len(), 1);
    assert!(
        w.store.gets().is_empty(),
        "a Get of something expected to be absent: {:?}",
        w.store.gets()
    );
}

/// A reconcile corrects an edit made at the destination and a document deleted there, at the start and on its schedule.
///
/// verifies: REQ-EXPORT-014
#[tokio::test]
async fn the_reconcile_restores_an_edited_and_a_deleted_document() {
    let w = World::new().await;
    let d = dir();
    w.store.set_ring(vec![test_key("kid-a", "active").key]);
    let run = spawn(w.engine(d.target(), |c| c.reconcile = Duration::from_millis(200)));
    until(10, "the first document", || d.read().is_some()).await;
    let good = d.read().unwrap();

    std::fs::write(
        d.root.path().join("jwks"),
        b"{\"keys\":[\"edited by hand\"]}",
    )
    .unwrap();
    until(10, "the edit is undone", || {
        d.read().as_deref() == Some(&good[..])
    })
    .await;
    std::fs::remove_file(d.root.path().join("jwks")).unwrap();
    until(10, "the deletion is undone", || {
        d.read().as_deref() == Some(&good[..])
    })
    .await;
    run.stop().await;

    // And at the start: an edit made while it was down.
    std::fs::write(d.root.path().join("jwks"), b"{}").unwrap();
    let run = spawn(w.engine(d.target(), |_| {}));
    until(10, "the start corrects it", || {
        d.read().as_deref() == Some(&good[..])
    })
    .await;
    run.stop().await;
}

/// A destination that refuses a write is tried again within the budget; one that keeps refusing past it is reported
/// `unverified` (the object is not known to be the new one) and tried again until it takes it.
#[tokio::test]
async fn a_failing_destination_is_retried_and_reported_unverified_past_the_budget() {
    let w = World::new().await;
    let m = Memory::new();
    w.store.set_ring(vec![test_key("kid-a", "active").key]);
    m.fail(Op::Put, 2, Error::Unavailable("down".into()));
    let targets = vec![Target {
        name: "mem".into(),
        driver: m.clone(),
        documents: vec![doc()],
    }];
    let run = spawn(w.engine(targets, |c| c.timing.budget = Duration::from_secs(5)));
    until(10, "the document after two failures", || {
        m.body("jwks").is_some()
    })
    .await;
    until(10, "written", || {
        w.store
            .report("mem/jwks")
            .is_some_and(|r| r.state == "written")
    })
    .await;
    run.stop().await;

    let w = World::new().await;
    let m = Memory::new();
    w.store.set_ring(vec![test_key("kid-a", "active").key]);
    m.fail_for_good(Op::Put, Error::Unavailable("down".into()));
    let targets = vec![Target {
        name: "mem".into(),
        driver: m.clone(),
        documents: vec![doc()],
    }];
    let run = spawn(w.engine(targets, |c| c.timing.budget = Duration::from_millis(300)));
    until(10, "unverified", || {
        w.store
            .report("mem/jwks")
            .is_some_and(|r| r.state == "unverified")
    })
    .await;
    assert!(m.body("jwks").is_none());
    m.heal();
    until(10, "the document once the destination is back", || {
        m.body("jwks").is_some()
    })
    .await;
    until(10, "no longer unverified", || {
        w.store
            .report("mem/jwks")
            .is_some_and(|r| r.state == "written")
    })
    .await;
    run.stop().await;
}
