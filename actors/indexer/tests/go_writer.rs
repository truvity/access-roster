//! The indexer over a log the merged Go writer made (`actors/writer`), not one made by this crate's test
//! support: the writer's real bundles, tiles, signed notes (P-256, SHA-256 over the note text, D-25), sealed
//! entries and seal entries. The fixture is in `testdata/go-writer/`; how it was made is in
//! `export_fixture_test.go.txt` beside it. The stand-in for key@ answers from what the writer's own stand-in
//! opened each entry to, at the address the entry was sealed at, so a wrong address is a refusal.

#![allow(clippy::unwrap_used, clippy::expect_used)] // a failed unwrap in a test is the failure

mod common;

use common::{Env, by_tenant, value};
use indexer::note::{Error, LogKey};
use indexer::run::Runner;

/// The fixture of the Go writer, in the source tree.
fn fixture(path: &str) -> Vec<u8> {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/testdata/go-writer");
    std::fs::read(p.join(path)).unwrap_or_else(|e| panic!("{path}: {e}"))
}

/// The origin of the fixture's log, and the checkpoint sizes the writer kept under `checkpoints/`.
const FIXTURE_ORIGIN: &str = "sluis.local.test/dev/sluis/audit/main";
const FIXTURE_SIZES: [u64; 4] = [11, 22, 33, 44];

/// verifies: REQ-SEC-018, REQ-AUDIT-050
#[test]
fn every_checkpoint_the_go_writer_signed_verifies_in_the_rust_indexer() {
    // The verifier key and the signed notes come from the Go writer (`actors/writer`, P-256, SHA-256 over
    // the note text, D-25); the library reads them with the verifier of `indexer::note`.
    let key = LogKey::parse(std::str::from_utf8(&fixture("vkey")).unwrap()).unwrap();
    assert_eq!(key.name(), FIXTURE_ORIGIN);
    let head = key.open(&fixture("audit/main/checkpoint")).unwrap();
    assert_eq!((head.origin.as_str(), head.size), (FIXTURE_ORIGIN, 44));
    // Each checkpoint of the history is under its own tree size, and no two roots are alike.
    let mut roots = vec![head.root];
    for size in FIXTURE_SIZES {
        let cp = key
            .open(&fixture(&format!("audit/main/checkpoints/{size}")))
            .unwrap();
        assert_eq!((cp.origin.as_str(), cp.size), (FIXTURE_ORIGIN, size));
        roots.push(cp.root);
    }
    assert_eq!(roots[0], roots[4], "the head is the checkpoint of size 44");
    roots.sort_unstable();
    roots.dedup();
    assert_eq!(roots.len(), 4);
}

/// verifies: REQ-SEC-018
#[test]
fn a_go_writer_checkpoint_that_is_changed_cut_or_under_another_key_is_refused() {
    let key = LogKey::parse(std::str::from_utf8(&fixture("vkey")).unwrap()).unwrap();
    let note = fixture("audit/main/checkpoint");
    // Every octet of the note, changed: refused, or the same checkpoint (a change in the base64 of the
    // signature cannot land on another valid signature; the text is signed).
    let want = key.open(&note).unwrap();
    for at in 0..note.len() {
        let mut m = note.clone();
        m[at] ^= 1;
        match key.open(&m) {
            Ok(cp) => assert_eq!(cp, want, "change at {at}"),
            Err(e) => assert_ne!(e, Error::Key, "change at {at}"),
        }
    }
    // The size of one checkpoint over the signature of another: the signature does not fit the text.
    let (a, b) = (
        String::from_utf8(fixture("audit/main/checkpoints/11")).unwrap(),
        String::from_utf8(fixture("audit/main/checkpoints/22")).unwrap(),
    );
    let (text_a, sigs_b) = (
        a.split_once("\n\n").unwrap().0,
        b.split_once("\n\n").unwrap().1,
    );
    let mixed = format!("{text_a}\n\n{sigs_b}");
    assert_eq!(key.open(mixed.as_bytes()), Err(Error::Signature));
    // A cut note is not a signed note, or its signature does not fit.
    for n in [0, 10, note.len() / 2, note.len() - 1] {
        assert!(key.open(&note[..n]).is_err(), "cut at {n}");
    }
    // Another key: the Go writer's signature is not its signature.
    let other = common::TestLog::new(std::path::Path::new("/nonexistent"));
    let other = LogKey::parse(&other.vkey()).unwrap();
    assert_eq!(other.open(&note), Err(Error::Signature));
}

/// verifies: REQ-AUDIT-005
#[tokio::test]
async fn the_log_of_the_go_writer_is_indexed_and_every_record_is_found() {
    let env = Env::go_writer().await;
    let mut runner = Runner::new(&env.settings).unwrap();
    let r = runner.round().await;
    assert_eq!((r.halted, r.transient, r.steps), (0, 0, 1), "{r:?}");
    // 40 messages, four batches of ten and a seal entry each: 44 entries, 40 of them records.
    assert_eq!(env.cursor_size(), 44);
    let rows = env.search(&["*"], "").await;
    assert_eq!(rows.len(), 40);
    // Tenants rotate acme, globex and none; a record of no tenant is the operator's own.
    let per = by_tenant(&rows);
    assert_eq!((per["acme"], per["globex"], per["operator"]), (14, 13, 13));
    // The actions alternate, and a word search finds them.
    assert_eq!(env.search(&["*"], "store").await.len(), 20);
    assert_eq!(env.search(&["*"], "key").await.len(), 20);
    assert_eq!(env.search(&["acme"], "store").await.len(), 7);
    for r in &rows {
        let v = value(r);
        assert_eq!(v["metadata"]["uid"], r.record_id.as_str());
        assert_eq!(v["metadata"]["log_name"], "dev");
        assert_eq!(
            (
                r.boundary.as_str(),
                r.product.as_str(),
                r.actor_uid.as_str()
            ),
            ("dev", "sluis", "key@dev")
        );
        assert_eq!(
            (r.class_uid, r.activity_id, r.status_id, r.actor_type_id),
            (6003, 99, 1, 3)
        );
        assert!(r.recorded_ms >= r.time_ms);
    }
    // Indexed again, nothing changes.
    let again = runner.round().await;
    assert_eq!((again.steps, again.halted, again.transient), (0, 0, 0));
    assert_eq!(env.search(&["*"], "").await.len(), 40);
}

#[tokio::test]
async fn a_changed_byte_in_the_go_writers_log_halts_it() {
    let env = Env::go_writer().await;
    let path = "tile/entries/000.p/44";
    let mut b = env.log.read(path);
    let i = b.len() / 2;
    b[i] ^= 1;
    env.log.write(path, &b);
    let mut runner = Runner::new(&env.settings).unwrap();
    let r = runner.round().await;
    assert_eq!((r.halted, r.steps), (1, 0), "{r:?}");
    assert_eq!(env.cursor_size(), 0);
    assert!(env.search(&["*"], "").await.is_empty());
}

#[tokio::test]
async fn a_verifier_key_that_is_not_the_go_writers_halts_the_log() {
    let env = Env::go_writer().await;
    // The same name and another key: no signature of the log is its.
    let fresh = common::TestLog::new(std::path::Path::new("/nonexistent"));
    std::fs::write(env.settings.key_dir.join("main.vkey"), fresh.vkey()).unwrap();
    let mut runner = Runner::new(&env.settings).unwrap();
    let r = runner.round().await;
    assert_eq!((r.halted, r.steps), (1, 0), "{r:?}");
    assert_eq!(env.cursor_size(), 0);
}

/// A tree of the leaf hashes of the entry bundle, every node hash stored, to make proofs from.
struct Tree(Vec<tlog_core::Hash>);

impl tlog_core::HashReader for Tree {
    fn read_hashes(&self, indexes: &[u64]) -> Result<Vec<tlog_core::Hash>, tlog_core::TlogError> {
        indexes
            .iter()
            .map(|i| {
                usize::try_from(*i)
                    .ok()
                    .and_then(|i| self.0.get(i).copied())
                    .ok_or(tlog_core::TlogError::BadMath)
            })
            .collect()
    }
}

/// The inclusion proof of every entry of the Go writer's log, and the consistency proof between every two of its signed
/// checkpoints, verify offline: from the files of the log (the entry bundle, the signed notes) and the verifier key,
/// with no writer, no store and no index. The leaves are the hashes of the entries in the bundle, the roots are those
/// of the checkpoints whose signatures verified, and the proofs are made from the bundle and checked against the signed
/// roots. A proof for another entry, and a proof of a root the writer never signed, are refused.
///
/// verifies: REQ-AUDIT-024, REQ-AUDIT-005
#[test]
fn the_proofs_of_the_go_writers_log_verify_offline_against_its_signed_checkpoints() {
    let key = LogKey::parse(std::str::from_utf8(&fixture("vkey")).unwrap()).unwrap();
    // The entries of the bundle of the head: a two-octet length and the entry (C2SP tlog-tiles).
    let bundle = fixture("audit/main/tile/entries/000.p/44");
    let (mut rest, mut leaves) = (bundle.as_slice(), Vec::new());
    while !rest.is_empty() {
        let n = usize::from(u16::from_be_bytes([rest[0], rest[1]]));
        leaves.push(tlog_core::record_hash(&rest[2..2 + n]));
        rest = &rest[2 + n..];
    }
    assert_eq!(leaves.len(), 44);
    let mut tree = Tree(Vec::new());
    for (n, l) in leaves.iter().enumerate() {
        let more = tlog_core::stored_hashes_for_record_hash(n as u64, *l, &tree).unwrap();
        tree.0.extend(more);
    }

    // The signed roots: the head and the checkpoints of the history.
    let head = key.open(&fixture("audit/main/checkpoint")).unwrap();
    let head_root = tlog_core::Hash(head.root);
    assert_eq!(tlog_core::tree_hash(44, &tree).unwrap(), head_root);
    for (i, leaf) in leaves.iter().enumerate() {
        let proof = tlog_core::inclusion_proof(44, i as u64, &tree).unwrap();
        tlog_core::verify_inclusion_proof(&proof, 44, head_root, i as u64, *leaf)
            .unwrap_or_else(|e| panic!("entry {i}: {e:?}"));
        let other = leaves[(i + 1) % 44];
        assert!(
            tlog_core::verify_inclusion_proof(&proof, 44, head_root, i as u64, other).is_err(),
            "the proof of entry {i} holds for another entry"
        );
    }
    let mut checked = 0;
    for old in FIXTURE_SIZES {
        let cp = key
            .open(&fixture(&format!("audit/main/checkpoints/{old}")))
            .unwrap();
        let old_root = tlog_core::Hash(cp.root);
        let proof = tlog_core::consistency_proof(44, old, &tree).unwrap();
        tlog_core::verify_consistency_proof(&proof, 44, head_root, old, old_root)
            .unwrap_or_else(|e| panic!("{old} to 44: {e:?}"));
        // Between every two signed checkpoints, not only to the head.
        for newer in FIXTURE_SIZES.into_iter().filter(|n| *n > old) {
            let cp2 = key
                .open(&fixture(&format!("audit/main/checkpoints/{newer}")))
                .unwrap();
            let p = tlog_core::consistency_proof(newer, old, &tree).unwrap();
            tlog_core::verify_consistency_proof(
                &p,
                newer,
                tlog_core::Hash(cp2.root),
                old,
                old_root,
            )
            .unwrap_or_else(|e| panic!("{old} to {newer}: {e:?}"));
            checked += 1;
        }
        // A root the writer never signed is not shown consistent.
        let mut forged = old_root;
        forged.0[0] ^= 1;
        assert!(tlog_core::verify_consistency_proof(&proof, 44, head_root, old, forged).is_err());
    }
    assert_eq!(checked, 6);
}
