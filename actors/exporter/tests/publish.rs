#![allow(refining_impl_trait)] // the generated trait returns `impl Encodable`; a concrete type is fine
#![allow(clippy::unwrap_used, clippy::expect_used)] // a failed unwrap in a test is the failure
//! `exporter` against an in-process `store@` (a change log and a watch), the real directory driver and the in-memory
//! driver of the destination port. Each test says which row of REQ-EXPORT it proves.

mod common;

/// Everything the engines of this file log, for a test that reads it. A global subscriber, set once: a subscriber set
/// for one thread only would miss the interest the other tests' threads cached while there was none.
fn log_sink() -> LogSink {
    static SINK: std::sync::OnceLock<LogSink> = std::sync::OnceLock::new();
    SINK.get_or_init(|| {
        let sink = LogSink::default();
        tracing::subscriber::set_global_default(
            tracing_subscriber::fmt()
                .with_writer(sink.clone())
                .with_ansi(false)
                .finish(),
        )
        .expect("no other global subscriber");
        sink
    })
    .clone()
}

#[derive(Clone, Default)]
struct LogSink(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for LogSink {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogSink {
    type Writer = LogSink;
    fn make_writer(&'a self) -> LogSink {
        self.clone()
    }
}

use std::sync::atomic::Ordering;
use std::time::Duration;

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P384_SHA384_FIXED, UnparsedPublicKey};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use common::{World, doc, kids, public_doc, spawn, test_key, until, until_saying};
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
/// (a new key is not published without knowing what is revoked), and the report says `unverified`. The one change
/// is a removal: a kid that a revocation event names leaves the last good document, and nothing else is added or
/// changed, because removal is monotone. When the list can be read again the document is built whole. Each way into and
/// out of `unverified` is one audit fact.
///
/// verifies: REQ-EXPORT-024
#[tokio::test]
async fn an_unreadable_revocation_list_leaves_the_object_as_it_is_and_reports_unverified() {
    let w = World::new().await;
    let d = dir();
    let (a, b, c) = (
        test_key("kid-a", "active"),
        test_key("kid-b", "active"),
        test_key("kid-c", "pre-published"),
    );
    w.store.set_ring(vec![a.key.clone(), b.key.clone()]);
    let run = spawn(w.engine(d.target(), |_| {}));
    until(10, "the first document", || d.read().is_some()).await;
    let before = d.read().unwrap();

    w.store.revocations_down.store(true, Ordering::SeqCst);
    w.store
        .set_ring(vec![a.key.clone(), b.key.clone(), c.key.clone()]);
    until_saying(
        10,
        "unverified",
        || {
            w.store
                .report("local/jwks")
                .is_some_and(|r| r.state == "unverified")
        },
        || {
            format!(
                "the report is {:?}; reports written: {:?}; document {:?}",
                w.store.report("local/jwks").map(|r| r.state),
                w.store
                    .report_log()
                    .iter()
                    .map(|(_, r, _)| r.state.clone())
                    .collect::<Vec<_>>(),
                d.read().map(|b| kids(&b))
            )
        },
    )
    .await;
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(
        d.read().unwrap(),
        before,
        "the object changed while a revocation could not be read"
    );

    // A revocation event arrives: its kid, and only its kid, leaves. The new key `kid-c` is not added.
    w.store.revoke("kid-a");
    until(10, "the revoked kid leaves", || {
        d.read().is_some_and(|x| kids(&x) == ["kid-b"])
    })
    .await;
    // The report follows the document by a moment (it is stored after the write): wait for it, then for a quiet period in
    // which nothing else may be added.
    until(10, "the report of the trimmed document", || {
        w.store
            .report("local/jwks")
            .is_some_and(|r| r.kids == ["kid-b"])
    })
    .await;
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(
        kids(&d.read().unwrap()),
        ["kid-b"],
        "only the named kid left"
    );
    let r = w.store.report("local/jwks").unwrap();
    assert_eq!(r.state, "unverified", "the rest is still unknown");
    assert_eq!(r.kids, ["kid-b"]);

    // It can be read again: the document is built whole, with the new key, and the report is no longer unverified.
    w.store.revocations_down.store(false, Ordering::SeqCst);
    until(10, "the document after the read is back", || {
        d.read().is_some_and(|x| kids(&x) == ["kid-b", "kid-c"])
    })
    .await;
    until(10, "no longer unverified", || {
        w.store
            .report("local/jwks")
            .is_some_and(|r| r.state != "unverified")
    })
    .await;
    until(10, "the fact out of the state", || {
        w.spool.of("exporter.unverified").len() == 2
    })
    .await;
    let facts = w.spool.of("exporter.unverified");
    assert_eq!(
        facts.len(),
        2,
        "one fact into the state and one out: {facts:?}"
    );
    assert_eq!(facts[0]["status_id"], 2, "failure");
    assert_eq!(facts[1]["status_id"], 1, "success");
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
    assert_eq!(
        (
            writes[0]["activity_id"].clone(),
            writes[1]["activity_id"].clone()
        ),
        (3.into(), 3.into())
    );
    assert_eq!(writes[0]["unmapped"]["sluis"]["replaced"], false);
    assert_eq!(writes[1]["unmapped"]["sluis"]["replaced"], true);
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
    // Something has been written before, as in any installation: a store with an empty change log names no point to watch
    // from (the helper refuses it), which is not what this test is about.
    w.store.revoke("kid-unrelated");
    let targets = vec![Target {
        name: "idler".into(),
        driver: d.driver.clone(),
        documents: vec![doc()],
    }];
    let run = spawn(w.engine(targets, |c| c.reconcile = Duration::from_millis(100)));
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

/// With no destination exporter holds no watch open and reads neither kind: a board that has no destination file costs
/// the store one write, the empty manifest, which is what releases a destination that was removed.
#[tokio::test]
async fn with_no_destination_it_watches_and_reads_nothing() {
    let w = World::new().await;
    w.store.set_ring(vec![test_key("kid-a", "active").key]);
    let run = spawn(w.engine(Vec::<Target<Directory>>::new(), |_| {}));
    // The manifest is the one thing the start writes with no destination: it is written in a task of its own, so wait for it
    // (a fixed sleep missed it once on a loaded machine), then leave the exporter a moment in which a watch or a read it
    // should not make would show.
    until(10, "the empty manifest", || w.store.manifest().is_some()).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    run.stop().await;
    assert!(
        w.store.opens().is_empty() && w.store.gets().is_empty(),
        "no watch, and nothing asked for that is absent"
    );
    assert!(
        w.store.lists().iter().all(|(k, _)| k == "export-report"),
        "neither kind was read: {:?}",
        w.store.lists()
    );
    assert_eq!(w.store.manifest().unwrap().entries.len(), 0);
    assert_eq!(
        w.spool.of("exporter.start").len(),
        1,
        "it still says it started"
    );
}

/// The manifest says what is configured, for `signer`: an entry for each document with whether it has a public address.
/// The reports of what is not configured any more (a destination that was removed) are removed at the start, and the
/// reports of what is are kept.
///
/// verifies: REQ-KEYS-116
#[tokio::test]
async fn the_manifest_names_what_is_configured_and_the_reports_of_the_rest_are_removed() {
    let w = World::new().await;
    let m = Memory::with_public("https://sluis.example.com", true);
    let d = dir();
    w.store.set_ring(vec![test_key("kid-a", "active").key]);
    // A destination that was removed left its report behind, and an older run left one for a document since removed.
    let stale = sluis_proto::sluis::exporter::v2alpha1::ExportReport {
        state: "unverified".into(),
        kind: "SigningRing".into(),
        public: true,
        ..Default::default()
    };
    w.store.put_report("old/jwks", &stale);
    w.store.put_report("edge/other", &stale);
    let targets = vec![Target {
        name: "edge".into(),
        driver: m.clone(),
        documents: vec![public_doc("https://sluis.example.com")],
    }];
    let run = spawn(w.engine(targets, |_| {}));
    until(10, "published", || {
        w.store
            .report("edge/jwks")
            .is_some_and(|r| r.state == "published")
    })
    .await;
    let manifest = w.store.manifest().expect("the manifest is written");
    assert_eq!(manifest.entries.len(), 1);
    let e = &manifest.entries[0];
    assert_eq!(
        (
            e.destination.as_str(),
            e.document.as_str(),
            e.kind.as_str(),
            e.public
        ),
        ("edge", "jwks", "SigningRing", true)
    );
    until(10, "the stale reports are gone", || {
        w.store.report("old/jwks").is_none() && w.store.report("edge/other").is_none()
    })
    .await;
    assert!(
        w.store.report("edge/jwks").is_some(),
        "the report of what is configured stays"
    );
    run.stop().await;

    // A directory has no public address: its entry says so, and signer does not count it.
    let w = World::new().await;
    w.store.set_ring(vec![test_key("kid-a", "active").key]);
    let run = spawn(w.engine(d.target(), |_| {}));
    until(10, "written", || w.store.report("local/jwks").is_some()).await;
    assert!(!w.store.manifest().unwrap().entries[0].public);
    run.stop().await;
}

/// A destination that hangs delays nothing for the others: a revocation reaches the healthy one at once, a stop is not
/// held up by the call in flight, and the hung one is reported `unverified` once its budget is spent.
///
/// verifies: REQ-EXPORT-028
#[tokio::test]
async fn a_hung_destination_delays_neither_the_others_nor_a_stop() {
    let w = World::new().await;
    let slow = common::Hang::new(Memory::new());
    let fast = common::Hang::new(Memory::new());
    let (a, b) = (test_key("kid-a", "active"), test_key("kid-b", "active"));
    w.store.set_ring(vec![a.key.clone(), b.key.clone()]);
    let targets = vec![
        Target {
            name: "slow".into(),
            driver: slow.clone(),
            documents: vec![doc()],
        },
        Target {
            name: "fast".into(),
            driver: fast.clone(),
            documents: vec![doc()],
        },
    ];
    let run = spawn(w.engine(targets, |_| {}));
    until(10, "both documents", || {
        slow.inner.body("jwks").is_some() && fast.inner.body("jwks").is_some()
    })
    .await;

    slow.hang.store(true, Ordering::SeqCst);
    let revoked_at = std::time::Instant::now();
    w.store.revoke("kid-a");
    until(10, "the healthy destination drops the key", || {
        fast.inner
            .body("jwks")
            .is_some_and(|b| kids(&b) == ["kid-b"])
    })
    .await;
    assert!(
        revoked_at.elapsed() < Duration::from_millis(1500),
        "the healthy destination waited for the hung one ({:?})",
        revoked_at.elapsed()
    );
    assert_eq!(
        kids(&slow.inner.body("jwks").unwrap()),
        ["kid-a", "kid-b"],
        "the hung destination could not take it"
    );
    until(10, "the hung destination is unverified", || {
        w.store
            .report("slow/jwks")
            .is_some_and(|r| r.state == "unverified")
    })
    .await;
    assert_eq!(w.store.report("fast/jwks").unwrap().state, "written");

    // A stop is prompt even with a call stuck in flight.
    let stopped_at = std::time::Instant::now();
    run.stop().await;
    assert!(
        stopped_at.elapsed() < Duration::from_secs(2),
        "the stop waited for the hung call ({:?})",
        stopped_at.elapsed()
    );
}

/// A read back after a purge that failed proves nothing about the other copies of the edge: the state is not `published`
/// until a purge was accepted and the read back then showed the digest.
///
/// verifies: REQ-EXPORT-022, REQ-KEYS-116
#[tokio::test]
async fn a_failed_purge_is_never_published() {
    let w = World::new().await;
    let m = Memory::with_public("https://sluis.example.com", true);
    w.store.set_ring(vec![test_key("kid-a", "active").key]);
    m.fail_for_good(Op::Purge, Error::Unavailable("the edge API is down".into()));
    let targets = vec![Target {
        name: "edge".into(),
        driver: m.clone(),
        documents: vec![public_doc("https://sluis.example.com")],
    }];
    let run = spawn(w.engine(targets, |c| c.timing.budget = Duration::from_millis(300)));
    until(10, "purge-pending", || {
        w.store
            .report("edge/jwks")
            .is_some_and(|r| r.state == "purge-pending")
    })
    .await;
    tokio::time::sleep(Duration::from_millis(600)).await;
    let r = w.store.report("edge/jwks").unwrap();
    assert_eq!(
        r.state, "purge-pending",
        "the read back alone must not publish"
    );
    assert!(!r.read_back_at.is_set() && !r.purged_at.is_set());
    assert!(
        m.calls().iter().all(|c| !matches!(c, Call::ReadBack(_))),
        "a read back was made after a purge that failed: {:?}",
        m.calls()
    );
    m.heal();
    until(10, "published", || {
        w.store
            .report("edge/jwks")
            .is_some_and(|r| r.state == "published")
    })
    .await;
    assert!(w.store.report("edge/jwks").unwrap().purged_at.is_set());
    run.stop().await;
}

/// A report that could not be stored is not taken as stored: the `unverified` of a watch that broke is tried again until
/// it is, so a `published` report does not stay for the whole outage.
///
/// verifies: REQ-EXPORT-024
#[tokio::test]
async fn an_unverified_report_that_could_not_be_stored_is_tried_again() {
    let w = World::new().await;
    let m = Memory::new();
    w.store.set_ring(vec![test_key("kid-a", "active").key]);
    let targets = vec![Target {
        name: "mem".into(),
        driver: m.clone(),
        documents: vec![doc()],
    }];
    let run = spawn(w.engine(targets, |_| {}));
    until(10, "written", || {
        w.store
            .report("mem/jwks")
            .is_some_and(|r| r.state == "written")
    })
    .await;

    // Reports cannot be stored, and the ring's watch breaks: the first attempt to say `unverified` fails.
    w.store.reports_down.store(true, Ordering::SeqCst);
    w.store.watch_down("signing-ring");
    tokio::time::sleep(Duration::from_millis(700)).await;
    assert_eq!(
        w.store.report("mem/jwks").unwrap().state,
        "written",
        "nothing could be stored yet"
    );
    assert!(
        w.spool.of("exporter.unverified").is_empty(),
        "a state that was not stored is not a transition"
    );
    // Reports can be stored again, the watch is still broken: the report says so, without any other event.
    w.store.reports_down.store(false, Ordering::SeqCst);
    until(10, "unverified", || {
        w.store
            .report("mem/jwks")
            .is_some_and(|r| r.state == "unverified")
    })
    .await;
    // And when the watch is back the document is confirmed again.
    w.store.watch_up();
    until(10, "written again", || {
        w.store
            .report("mem/jwks")
            .is_some_and(|r| r.state == "written")
    })
    .await;
    until(10, "the fact out of the state", || {
        w.spool.of("exporter.unverified").len() == 2
    })
    .await;
    assert_eq!(w.spool.of("exporter.unverified").len(), 2);
    run.stop().await;
}

/// A `Resync` replaces the point that was held: after a restore the log is behind what the cursor saved, in an epoch of
/// its own, and the cursor follows the log, not the old point.
///
/// verifies: REQ-EXPORT-015
#[tokio::test]
async fn a_resync_below_the_saved_cursor_replaces_it() {
    let w = World::new().await;
    let d = dir();
    let (a, b) = (test_key("kid-a", "active"), test_key("kid-b", "active"));
    w.store.set_ring(vec![a.key.clone(), b.key.clone()]);
    w.store.revoke("kid-zzz");
    w.store.revoke("kid-yyy");
    let head = w.store.head();
    assert_eq!(head, 3);
    let run = spawn(w.engine(d.target(), |_| {}));
    until(10, "a cursor at the head", || {
        w.store.cursor("local").is_some_and(|c| {
            c.signing_ring == head && c.key_revocation == head && c.signing_ring_epoch == 1
        })
    })
    .await;
    run.stop().await;

    // A restore: the log is at 1 now, behind the cursor, and is a new epoch.
    w.store.restore_to(1);
    w.store.clear_requests();
    let run = spawn(w.engine(d.target(), |_| {}));
    until(10, "the cursor follows the log", || {
        w.store.cursor("local").is_some_and(|c| {
            (c.signing_ring, c.signing_ring_epoch) == (1, 2)
                && (c.key_revocation, c.key_revocation_epoch) == (1, 2)
        })
    })
    .await;
    let opens = w.store.opens();
    assert!(
        opens.contains(&("signing-ring".into(), head)),
        "it tried the saved point first: {opens:?}"
    );
    run.stop().await;
}

/// The same sequence in another epoch is another position: after a restore that reaches the same number the cursor is
/// saved under the new epoch, and a cursor that has no epoch (saved before epochs) is no point at all, so both kinds
/// are listed and nothing is trusted that the store cannot place.
///
/// verifies: REQ-EXPORT-015
#[tokio::test]
async fn a_sequence_means_something_only_inside_its_epoch() {
    let w = World::new().await;
    let d = dir();
    w.store.set_ring(vec![test_key("kid-a", "active").key]);
    let head = w.store.head();
    // A cursor from before epochs, at the head: it is not used.
    w.store.put_cursor(
        "local",
        &sluis_proto::sluis::exporter::v2alpha1::ExportCursor {
            signing_ring: head,
            key_revocation: head,
            ..Default::default()
        },
    );
    // (Writing the cursor is a change of the log too.)
    let head = w.store.head();
    let run = spawn(w.engine(d.target(), |_| {}));
    until(10, "a cursor with epochs", || {
        w.store
            .cursor("local")
            .is_some_and(|c| c.signing_ring_epoch == 1 && c.key_revocation_epoch == 1)
    })
    .await;
    assert!(
        w.store.opens().iter().all(|(_, from)| *from == head),
        "it watched from the listing, never from the point without an epoch: {:?}",
        w.store.opens()
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

    // A restore that reaches the same number again: another log.
    w.store.restore_to(head);
    let run = spawn(w.engine(d.target(), |_| {}));
    until(10, "the cursor is under the new epoch", || {
        w.store.cursor("local").is_some_and(|c| {
            c.signing_ring_epoch == 2 && c.key_revocation_epoch == 2 && c.signing_ring == head
        })
    })
    .await;
    run.stop().await;
}

/// The two follows are confirmed one by one: while the ring's watch is broken, the events of the revocations do not
/// confirm it, and the cursor does not move; it moves when the ring's own watch is back.
///
/// verifies: REQ-EXPORT-015
#[tokio::test]
async fn each_follow_is_confirmed_by_its_own_events() {
    let w = World::new().await;
    let d = dir();
    w.store.set_ring(vec![test_key("kid-a", "active").key]);
    let run = spawn(w.engine(d.target(), |_| {}));
    until(10, "a cursor at the head", || {
        w.store
            .cursor("local")
            .is_some_and(|c| c.signing_ring == w.store.head())
    })
    .await;
    let before = w.store.cursor("local").unwrap();

    w.store.watch_down("signing-ring");
    until(10, "the ring's watch is seen to be broken", || {
        !w.spool.of("exporter.unverified").is_empty()
    })
    .await;
    // A revocation event arrives on the other follow, and is published...
    w.store.revoke("kid-zzz");
    let after_revoke = w.store.head();
    tokio::time::sleep(Duration::from_millis(900)).await;
    // ...but it does not confirm the ring's follow: the cursor stays where it was.
    let cur = w.store.cursor("local").unwrap();
    assert_eq!(
        (cur.signing_ring, cur.key_revocation),
        (before.signing_ring, before.key_revocation),
        "the cursor moved while the ring's follow was not confirmed"
    );
    w.store.watch_up();
    until(
        10,
        "the cursor moves once the ring's follow is back",
        || {
            w.store
                .cursor("local")
                .is_some_and(|c| c.key_revocation == after_revoke)
        },
    )
    .await;
    run.stop().await;
}

/// A follow is confirmed only by the stream's own claim that it is caught up (or by a listing). The first change of a
/// reconnect, and a bookmark, may come before the rows still to be delivered, so they do not confirm it: the documents stay
/// `unverified` and the cursor stays where it was until the claim.
///
/// verifies: REQ-EXPORT-015, REQ-EXPORT-024
#[tokio::test]
async fn a_change_and_a_bookmark_do_not_confirm_a_follow_only_the_claim_does() {
    let w = World::new().await;
    let m = Memory::new();
    w.store.set_ring(vec![test_key("kid-a", "active").key]);
    let targets = vec![Target {
        name: "mem".into(),
        driver: m.clone(),
        documents: vec![doc()],
    }];
    let run = spawn(w.engine(targets, |_| {}));
    until(10, "a cursor at the head", || {
        w.store
            .cursor("mem")
            .is_some_and(|c| c.signing_ring == w.store.head())
    })
    .await;
    let before = w.store.cursor("mem").unwrap();
    // The ring's watch breaks, and it comes back with rows to deliver and its claim held back.
    w.store.claims_held.store(true, Ordering::SeqCst);
    w.store.watch_down("signing-ring");
    until(10, "unverified", || {
        w.store
            .report("mem/jwks")
            .is_some_and(|r| r.state == "unverified")
    })
    .await;
    w.store.watch_up();
    w.store.set_ring(vec![
        test_key("kid-a", "active").key,
        test_key("kid-b", "active").key,
    ]);
    let head = w.store.head();
    assert!(head > before.signing_ring);
    // Changes and bookmarks of the stream arrive (the fake says a bookmark every 300 ms) and the document is published from
    // the listings, but the follow is not confirmed: the cursor stays where it was.
    tokio::time::sleep(Duration::from_millis(1500)).await;
    until(10, "the new document", || {
        m.body("jwks").is_some_and(|b| kids(&b).len() == 2)
    })
    .await;
    assert_eq!(
        w.store.cursor("mem").unwrap().signing_ring,
        before.signing_ring,
        "the cursor moved while the follow was not confirmed: a change or a bookmark confirmed it"
    );
    // The claim comes: the follow is confirmed, and the cursor moves to the head.
    w.store.claims_held.store(false, Ordering::SeqCst);
    until(10, "the cursor at the new head", || {
        w.store
            .cursor("mem")
            .is_some_and(|c| c.signing_ring == head)
    })
    .await;
    run.stop().await;
}

/// `unverified` is an alarm that does not stop at one line: it is raised again every `alert_every` while it lasts, with
/// the number of documents in that state, and the audit log has one fact into the state and one out of it, not one for
/// each repeat.
///
/// verifies: REQ-EXPORT-024
#[tokio::test]
async fn the_unverified_alarm_repeats_while_it_lasts() {
    let sink = log_sink();

    let w = World::new().await;
    let d = dir();
    w.store.set_ring(vec![test_key("kid-a", "active").key]);
    let targets = vec![Target {
        name: "alarmed".into(),
        driver: d.driver.clone(),
        documents: vec![doc()],
    }];
    let run = spawn(w.engine(targets, |c| {
        c.retry = Duration::from_millis(100);
        c.timing.alert_every = Duration::from_millis(400);
    }));
    until(10, "the first document", || d.read().is_some()).await;
    w.store.revocations_down.store(true, Ordering::SeqCst);
    w.store.set_ring(vec![test_key("kid-b", "active").key]);
    tokio::time::sleep(Duration::from_millis(1700)).await;
    w.store.revocations_down.store(false, Ordering::SeqCst);
    until(10, "no longer unverified", || {
        w.store
            .report("alarmed/jwks")
            .is_some_and(|r| r.state != "unverified")
    })
    .await;
    until(10, "the fact out of the state", || {
        w.spool.of("exporter.unverified").len() == 2
    })
    .await;
    run.stop().await;
    let log = String::from_utf8(sink.0.lock().unwrap().clone()).unwrap();
    // The sink is shared by every test of this file; the destination's name is this test's.
    let alarms = log
        .lines()
        .filter(|l| {
            l.contains("exporter.unverified") && l.contains("ERROR") && l.contains("alarmed")
        })
        .count();
    assert!(
        (3..=7).contains(&alarms),
        "the alarm should repeat about every 400 ms for 1.7 s, not once and not at each retry: {alarms}\n{log}"
    );
    assert!(
        log.contains("unverified_documents"),
        "the gauge is in the alarm"
    );
    assert_eq!(
        w.spool.of("exporter.unverified").len(),
        2,
        "one fact in, one out"
    );
}

/// The write facts so far, in order: the digest, the number of kids and whether the write replaced a document.
fn write_facts(w: &World) -> Vec<(String, u64, bool)> {
    w.spool
        .of("exporter.write")
        .iter()
        .map(|r| {
            let s = &r["unmapped"]["sluis"];
            (
                s["sha256"].as_str().unwrap_or("").to_owned(),
                s["kids"].as_u64().unwrap(),
                s["replaced"].as_bool().unwrap(),
            )
        })
        .collect()
}

/// A `put` that timed out but landed leaves the last good document older than the destination. A later trim, with the
/// listings unreadable, must not write that old body back: it subtracts every kid this process was ever told is revoked,
/// not only the one the latest event names.
///
/// The trim must run on the old body, so nothing may refresh it in between: the retry is a minute, and the only thing
/// that makes the exporter look again is the revocation of `kid-c`, whose listings are unreadable. (Were the timer short,
/// a pass that found the landed document would refresh the last good document, and the test would pass for the wrong
/// reason on a quick machine.)
///
/// verifies: REQ-EXPORT-020, REQ-EXPORT-024
#[tokio::test]
async fn a_put_that_landed_but_timed_out_cannot_bring_a_revoked_key_back() {
    let w = World::new().await;
    let m = common::Lossy::new(Memory::new());
    let keys: Vec<_> = ["kid-a", "kid-b", "kid-c"]
        .iter()
        .map(|k| test_key(k, "active"))
        .collect();
    w.store
        .set_ring(keys.iter().map(|k| k.key.clone()).collect());
    let targets = vec![Target {
        name: "mem".into(),
        driver: m.clone(),
        documents: vec![doc()],
    }];
    let run = spawn(w.engine(targets, |c| {
        c.timing.budget = Duration::from_millis(600);
        c.retry = Duration::from_secs(60);
    }));
    until(10, "the first document", || m.inner.body("jwks").is_some()).await;
    until(10, "the fact of the first write", || {
        write_facts(&w).len() == 1
    })
    .await;
    let first = m.inner.body("jwks").unwrap();

    // `kid-a` is revoked and the new document lands, but the answer is lost: the last good document still lists it.
    m.lose_answer.store(true, Ordering::SeqCst);
    w.store.revoke("kid-a");
    until(
        10,
        "the document without kid-a is at the destination",
        || {
            m.inner
                .body("jwks")
                .is_some_and(|b| kids(&b) == ["kid-b", "kid-c"])
        },
    )
    .await;
    let second = m.inner.body("jwks").unwrap();
    // The report says `unverified` until a pass looks again; the reports written are the record of it.
    until_saying(
        10,
        "a report that says unverified (the destination did not answer)",
        || {
            w.store
                .report_log()
                .iter()
                .any(|(id, r, _)| id == "mem/jwks" && r.state == "unverified")
        },
        || {
            format!(
                "the report is {:?}; reports written: {:?}",
                w.store.report("mem/jwks").map(|r| r.state),
                w.store
                    .report_log()
                    .iter()
                    .map(|(_, r, _)| r.state.clone())
                    .collect::<Vec<_>>()
            )
        },
    )
    .await;
    assert_eq!(
        write_facts(&w).len(),
        1,
        "the write that was not answered is not a fact until the destination shows it"
    );

    // Now the answers come back, the listings cannot be read, and `kid-c` is revoked.
    m.lose_answer.store(false, Ordering::SeqCst);
    w.store.revocations_down.store(true, Ordering::SeqCst);
    w.store.revoke("kid-c");
    until(10, "kid-c leaves", || {
        m.inner
            .body("jwks")
            .is_some_and(|b| !kids(&b).contains(&"kid-c".to_owned()))
    })
    .await;
    tokio::time::sleep(Duration::from_millis(400)).await;
    let third = m.inner.body("jwks").unwrap();
    assert_eq!(
        kids(&third),
        ["kid-b"],
        "an old body brought a revoked key back"
    );
    // Every write is a fact, also the one whose answer was lost, and each says what it wrote: the digest of the body, its
    // kids, and whether it replaced a document (the first did not).
    until_saying(
        10,
        "a fact for each of the three writes",
        || write_facts(&w).len() == 3,
        || format!("{:?}", write_facts(&w)),
    )
    .await;
    let digest = |b: &[u8]| sha256_hex(b);
    assert_eq!(
        write_facts(&w),
        [
            (digest(&first), 3, false),
            (digest(&second), 2, true),
            (digest(&third), 1, true)
        ]
    );
    run.stop().await;
}

/// A first write whose answer was lost, on an empty destination, is a creation: the fact says it replaced nothing.
///
/// verifies: REQ-EXPORT-017
#[tokio::test]
async fn a_first_write_whose_answer_was_lost_is_a_creation() {
    let w = World::new().await;
    let m = common::Lossy::new(Memory::new());
    m.lose_answer.store(true, Ordering::SeqCst);
    w.store.set_ring(vec![test_key("kid-a", "active").key]);
    let targets = vec![Target {
        name: "mem".into(),
        driver: m.clone(),
        documents: vec![doc()],
    }];
    let run = spawn(w.engine(targets, |c| c.timing.budget = Duration::from_millis(600)));
    until(10, "the document", || m.inner.body("jwks").is_some()).await;
    until(10, "its fact", || !write_facts(&w).is_empty()).await;
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(
        write_facts(&w),
        [(sha256_hex(&m.inner.body("jwks").unwrap()), 1, false)]
    );
    run.stop().await;
}

/// A write that changes only a header leaves the digest as it was. A `put` of it that lands without an answer is one
/// fact, and one that does not land is none until the write that does: never a fact for a document that was already
/// there, and never two for one write. A `put` that did not land, with another document there by then, makes no fact for
/// the digest it was to write.
///
/// verifies: REQ-EXPORT-017
#[tokio::test]
async fn a_header_only_write_and_a_digest_that_does_not_match_make_exactly_the_facts_of_the_writes()
{
    for lands in [true, false] {
        let w = World::new().await;
        let m = common::Lossy::new(Memory::new());
        w.store.set_ring(vec![test_key("kid-a", "active").key]);
        let first = vec![Target {
            name: "mem".into(),
            driver: m.clone(),
            documents: vec![doc()],
        }];
        let run = spawn(w.engine(first, |_| {}));
        until(10, "the document and its fact", || {
            m.inner.body("jwks").is_some() && write_facts(&w).len() == 1
        })
        .await;
        run.stop().await;
        let body = m.inner.body("jwks").unwrap();

        // The cache time changes: the digest is the same, the put is to change a header.
        let changed = exporter::config::Doc {
            cache_control: "public, max-age=60".into(),
            ..doc()
        };
        let second = vec![Target {
            name: "mem".into(),
            driver: m.clone(),
            documents: vec![changed],
        }];
        if lands {
            m.lose_answer.store(true, Ordering::SeqCst);
        } else {
            m.inner
                .fail(Op::Put, usize::MAX, Error::Unavailable("down".into()));
        }
        let run = spawn(w.engine(second, |c| {
            c.timing.budget = Duration::from_millis(500);
            c.retry = Duration::from_millis(100);
        }));
        if lands {
            // The header is at the destination by now, and the next pass shows it: one fact.
            until(10, "the fact of the header write", || {
                write_facts(&w).len() == 2
            })
            .await;
        } else {
            // It did not land: nothing was written, nothing is a fact.
            tokio::time::sleep(Duration::from_millis(800)).await;
            assert_eq!(write_facts(&w).len(), 1, "a write that did not happen");
            m.inner.heal();
            until(10, "the write that lands", || write_facts(&w).len() == 2).await;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(
            write_facts(&w),
            [(sha256_hex(&body), 1, false), (sha256_hex(&body), 1, true)],
            "lands={lands}"
        );
        run.stop().await;
    }

    // A put that did not land, and another document there by the next pass: the digest it was to write is not there, so
    // there is no fact for it; the pass that writes the right one makes its own.
    let w = World::new().await;
    let m = common::Lossy::new(Memory::new());
    w.store.set_ring(vec![test_key("kid-a", "active").key]);
    let targets = vec![Target {
        name: "mem".into(),
        driver: m.clone(),
        documents: vec![doc()],
    }];
    m.inner
        .fail(Op::Put, usize::MAX, Error::Unavailable("down".into()));
    // Another document is there already, so every write replaces something.
    m.inner.tamper("jwks", b"{\"keys\":[{\"kid\":\"older\"}]}");
    let run = spawn(w.engine(targets, |c| {
        c.timing.budget = Duration::from_millis(400);
        c.retry = Duration::from_millis(100);
    }));
    until(10, "unverified", || {
        w.store
            .report_log()
            .iter()
            .any(|(_, r, _)| r.state == "unverified")
    })
    .await;
    // Someone else writes yet another document, and the destination takes writes again. (A pass may be in flight, with
    // what it listed before: it writes the right document over one or the other, and the facts are the same.)
    m.inner.heal();
    // (With the headers of the document, so that only its digest tells it from the one that was to be written.)
    m.inner
        .put(sluis_destination::Document {
            address: "jwks".into(),
            content_type: "application/json".into(),
            cache_control: "public, max-age=300".into(),
            body: b"{\"keys\":[{\"kid\":\"other\"}]}".to_vec(),
        })
        .await
        .unwrap();
    until(10, "the right document", || {
        m.inner.body("jwks").is_some_and(|b| kids(&b) == ["kid-a"])
    })
    .await;
    until(10, "its fact", || !write_facts(&w).is_empty()).await;
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(
        write_facts(&w),
        [(sha256_hex(&m.inner.body("jwks").unwrap()), 1, true)],
        "exactly the one write that happened, and it replaced the other document"
    );
    run.stop().await;
}

/// The revocations are read even when the ring cannot be, and what they list is taken out of the last good document: a
/// revocation is a fact whatever else is unknown. No event names the kid here (the watch of the revocations is down).
///
/// verifies: REQ-EXPORT-024
#[tokio::test]
async fn the_revoked_kids_are_used_when_only_the_ring_cannot_be_read() {
    let w = World::new().await;
    let d = dir();
    let (a, b) = (test_key("kid-a", "active"), test_key("kid-b", "active"));
    w.store.set_ring(vec![a.key.clone(), b.key.clone()]);
    let run = spawn(w.engine(d.target(), |_| {}));
    until(10, "the first document", || d.read().is_some()).await;

    w.store.watch_down("key-revocation");
    until(10, "the revocations' watch is seen to be broken", || {
        !w.spool.of("exporter.unverified").is_empty()
    })
    .await;
    w.store.ring_down.store(true, Ordering::SeqCst);
    w.store.revoke("kid-a");
    // The ring's watch is up: a change of the ring wakes the exporter, whose read of the ring is refused.
    w.store.set_ring(vec![a.key.clone(), b.key.clone()]);
    until(10, "kid-a leaves although the ring cannot be read", || {
        d.read().is_some_and(|x| kids(&x) == ["kid-b"])
    })
    .await;
    run.stop().await;
}

/// Every name of an audit fact is a name the table accepts, whatever the operator's file holds: the refusal of a
/// document is the very case in which its name is empty, has a space or starts with `-`. A name that does not fit is its
/// digest, and no fact is lost to the schema.
///
/// verifies: REQ-EXPORT-017
#[tokio::test]
async fn a_name_the_table_would_refuse_is_written_as_its_digest() {
    let w = World::new().await;
    let d = dir();
    w.store.set_ring(vec![test_key("kid-a", "active").key]);
    let odd = exporter::config::Doc {
        name: "-jwks".into(),
        ..doc()
    };
    let targets = vec![Target {
        name: "_edge".into(),
        driver: d.driver.clone(),
        documents: vec![odd],
    }];
    let refused = vec![
        Refused {
            destination: "_edge".into(),
            document: String::new(),
            reason: "name",
        },
        Refused {
            destination: "_edge".into(),
            document: "has a space".into(),
            reason: "name",
        },
        Refused {
            destination: "plain".into(),
            document: "plain".into(),
            reason: "not_exportable",
        },
    ];
    let run = spawn(w.engine(targets, |c| c.refused = refused));
    until(10, "the write and the three refusals", || {
        !w.spool.of("exporter.write").is_empty() && w.spool.of("exporter.refused").len() == 3
    })
    .await;
    // And a fact into and out of unverified.
    w.store.revocations_down.store(true, Ordering::SeqCst);
    w.store.set_ring(vec![test_key("kid-b", "active").key]);
    until(10, "unverified", || {
        !w.spool.of("exporter.unverified").is_empty()
    })
    .await;
    w.store.revocations_down.store(false, Ordering::SeqCst);
    until(10, "no longer unverified", || {
        w.spool.of("exporter.unverified").len() == 2
    })
    .await;
    run.stop().await;

    let fits = |v: &str| {
        !v.is_empty()
            && v.len() <= 256
            && v.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._:/+=@~*-".contains(&b))
    };
    let facts: Vec<_> = ["exporter.write", "exporter.unverified", "exporter.refused"]
        .iter()
        .flat_map(|a| w.spool.of(a))
        .collect();
    assert!(facts.len() >= 6, "{facts:?}");
    for f in &facts {
        for field in ["destination", "document", "address"] {
            if let Some(v) = f["unmapped"]["sluis"][field].as_str() {
                assert!(fits(v), "{field} {v:?} of {f}");
            }
        }
    }
    let refusals = w.spool.of("exporter.refused");
    assert!(
        refusals.iter().any(|r| r["unmapped"]["sluis"]["document"]
            .as_str()
            .is_some_and(|v| v.starts_with("h-"))),
        "an odd name is its digest: {refusals:?}"
    );
    assert!(
        refusals
            .iter()
            .any(|r| r["unmapped"]["sluis"]["document"] == "plain"),
        "a name that fits is written as it is"
    );
    // A leading `-` or `_` is a name like any other, and is written as it is.
    assert!(
        w.spool
            .of("exporter.write")
            .iter()
            .all(|r| r["unmapped"]["sluis"]["destination"] == "_edge"
                && r["unmapped"]["sluis"]["document"] == "-jwks"),
        "{:?}",
        w.spool.of("exporter.write")
    );
}
