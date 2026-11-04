//! The indexer over real Unix sockets: a log made as the writer makes it, the real `sqlite` index driver
//! on its two sockets, and stand-ins for the blob driver, key@, policy and store@. The indexer reaches
//! all of them with the kit's clients, and the test reads the index only through the reader's socket.

#![allow(clippy::unwrap_used, clippy::expect_used)] // a failed unwrap in a test is the failure

mod common;

use std::sync::atomic::Ordering;

use common::{Env, LOG, PROJECT, Rec, TestLog, by_tenant, new_key, value};
use indexer::follow::CHUNK;
use indexer::run::{Round, Runner};

fn recs(range: std::ops::Range<u32>) -> Vec<Rec> {
    range
        .map(|n| {
            let tenant = if n % 3 == 0 { "globex" } else { "acme" };
            let action = if n % 2 == 0 {
                "token.exchange"
            } else {
                "key.sign"
            };
            Rec::new(n, tenant, action)
        })
        .collect()
}

async fn round(env: &Env) -> Round {
    Runner::new(&env.settings).unwrap().round().await
}

#[tokio::test]
async fn it_indexes_the_log_the_writer_made_and_a_reader_finds_the_records() {
    let mut env = Env::new().await;
    // 600 records in three batches, so the log has full bundles, a partial one and seal entries.
    for batch in [recs(0..250), recs(250..420), recs(420..600)] {
        env.log.append_records(&batch);
    }
    let size = env.log.entries.len() as i64;
    assert_eq!(size, 600 + 3);

    let r = round(&env).await;
    assert_eq!((r.transient, r.halted), (0, 0), "{r:?}");
    assert_eq!(env.cursor_size(), size);

    // Every record is there, once, per tenant; the seal entries are not records.
    let rows = env.search(&["*"], "").await;
    assert_eq!(rows.len(), 600);
    let per = by_tenant(&rows);
    assert_eq!(per["globex"], 200);
    assert_eq!(per["acme"], 400);
    // A tenant sees its own rows only.
    let acme = env.search(&["acme"], "").await;
    assert_eq!(acme.len(), 400);
    assert!(acme.iter().all(|r| r.tenant == "acme"));

    // The row is the record: the columns come from it, and the record is kept as the bytes the writer sealed.
    let one = rows
        .iter()
        .find(|r| r.record_id == Rec::new(7, "acme", "key.sign").uid)
        .unwrap();
    let want = Rec::new(7, "acme", "key.sign");
    assert_eq!(one.record, want.bytes());
    assert_eq!(
        (
            one.tenant.as_str(),
            one.action.as_str(),
            one.status_code.as_str(),
            one.trace_id.as_str()
        ),
        ("acme", "key.sign", "ok", "trace-7")
    );
    assert_eq!(
        (
            one.boundary.as_str(),
            one.product.as_str(),
            one.actor_uid.as_str()
        ),
        ("dev", PROJECT, "signer@dev")
    );
    assert_eq!(
        (
            one.class_uid,
            one.activity_id,
            one.status_id,
            one.actor_type_id
        ),
        (6003, 99, 1, 3)
    );
    assert_eq!((one.time_ms, one.recorded_ms), (want.time, want.time + 5));
    assert_eq!(one.hash.len(), 48);
    assert_eq!(
        (one.project.as_str(), one.kind.as_str(), one.log.as_str()),
        (PROJECT, "audit", LOG)
    );
    assert_eq!(value(one)["metadata"]["uid"], want.uid);

    // Word search over the action reaches the right rows.
    let ex = env.search(&["*"], "exchange").await;
    assert_eq!(ex.len(), 300);
    assert!(ex.iter().all(|r| r.action == "token.exchange"));
    assert_eq!(env.search(&["*"], "token").await.len(), 300);
    assert_eq!(env.search(&["*"], "sign").await.len(), 300);
    assert_eq!(
        env.search(&["*"], "xchange").await.len(),
        0,
        "a substring is not a word"
    );
    // A trace id is a filter, not a full-text word.
    assert!(env.search(&["*"], "trace").await.is_empty());

    // key@ was asked to open under the address the writer sealed at, and policy for a grant of the indexer.
    let addrs = env.control.addresses.lock().unwrap().clone();
    assert_eq!(addrs.len(), 600);
    assert!(
        addrs
            .iter()
            .all(|a| a.kind == "audit-entry" && a.id.starts_with("sluis/audit/main/0194d000"))
    );
    let ds = env.control.decides.lock().unwrap().clone();
    assert!(!ds.is_empty());
    for d in &ds {
        assert_eq!(d.action, "audit.index");
        assert_eq!(d.tenant, "*");
        assert_eq!(d.grant_key_ops, ["open"]);
        assert_eq!(
            d.principal
                .as_option()
                .map(|p| (p.r#type.as_str(), p.id.as_str())),
            Some(("Actor", "indexer"))
        );
        assert_eq!(
            d.resource
                .as_option()
                .map(|p| (p.r#type.as_str(), p.id.as_str())),
            Some(("Boundary", "dev"))
        );
    }
}

#[tokio::test]
async fn indexing_again_changes_nothing_and_a_new_index_is_rebuilt_from_the_log_alone() {
    let mut env = Env::new().await;
    env.log.append_records(&recs(0..40));
    round(&env).await;
    let before = env.search(&["*"], "").await;
    let opens = env.control.opened.load(Ordering::SeqCst);
    assert_eq!(before.len(), 40);

    // A second round with nothing new opens nothing.
    let r = round(&env).await;
    assert_eq!((r.steps, r.transient, r.halted), (0, 0, 0));
    assert_eq!(env.control.opened.load(Ordering::SeqCst), opens);

    // A new records batch is added once.
    env.log.append_records(&recs(40..50));
    assert_eq!(round(&env).await.steps, 1);
    assert_eq!(env.search(&["*"], "").await.len(), 50);

    // The index is lost: a new index file and the same log, indexed from nothing, gives the same rows.
    let dir = tempfile::tempdir().unwrap();
    let mut again = TestLog::with_key(dir.path(), clone_key(&env.log));
    again.seal = env.log.seal.clone();
    again.entries = env.log.entries.clone();
    common::copy_dir(&env.log.root.join("audit"), &dir.path().join("audit"));
    let fresh = Env::with_log(again, dir).await;
    assert_eq!(round(&fresh).await.halted, 0);
    let mut a: Vec<_> = env
        .search(&["*"], "")
        .await
        .into_iter()
        .map(|r| (r.hash, r.record))
        .collect();
    let mut b: Vec<_> = fresh
        .search(&["*"], "")
        .await
        .into_iter()
        .map(|r| (r.hash, r.record))
        .collect();
    a.sort();
    b.sort();
    assert_eq!(a.len(), 50);
    assert_eq!(a, b);
}

#[tokio::test]
async fn a_long_backlog_is_taken_in_steps_to_signed_checkpoints_of_the_history() {
    let mut env = Env::new().await;
    // 20 batches of 255 records and a seal each: 5120 entries, past one chunk.
    for b in 0..20u32 {
        env.log.append_records(&recs(b * 255..(b + 1) * 255));
    }
    assert_eq!(env.log.entries.len(), 5120);
    let mut runner = Runner::new(&env.settings).unwrap();
    let r = runner.round().await;
    assert_eq!((r.transient, r.halted), (0, 0));
    assert!(
        r.steps >= 2,
        "{} steps for {} entries",
        r.steps,
        env.log.entries.len()
    );
    assert_eq!(env.cursor_size(), 5120);
    assert_eq!(env.search(&["*"], "").await.len(), 20 * 255);
    const { assert!(CHUNK < 5120) };
}

/// What a halted log leaves: the alert, no row past the cursor, and no change on a later round.
async fn assert_halted(env: &Env, runner: &mut Runner, cursor: i64, rows: usize) {
    let r = runner.round().await;
    assert_eq!((r.halted, r.steps), (1, 0), "{r:?}");
    assert_eq!(env.cursor_size(), cursor, "the cursor moved");
    assert_eq!(
        env.search(&["*"], "").await.len(),
        rows,
        "rows past the cursor were written"
    );
    // It stays halted for the life of the process, whatever the log now says.
    let again = runner.round().await;
    assert_eq!((again.halted, again.steps), (1, 0));
}

#[tokio::test]
async fn a_checkpoint_signed_by_another_key_halts_the_log() {
    let mut env = Env::new().await;
    env.log.append_records(&recs(0..10));
    let mut runner = Runner::new(&env.settings).unwrap();
    assert_eq!(runner.round().await.steps, 1);
    let good = env.log.entries.len() as i64;

    // The next batch is signed by a key the verifier key does not name.
    let mut forged = TestLog::with_key(env.log.root.as_path(), new_key());
    forged.seal = env.log.seal.clone();
    forged.entries = env.log.entries.clone();
    forged.append_records(&recs(10..20));
    assert_halted(&env, &mut runner, good, 10).await;
}

#[tokio::test]
async fn an_entry_that_is_not_in_the_signed_tree_halts_the_log() {
    let mut env = Env::new().await;
    env.log.append_records(&recs(0..10));
    let mut runner = Runner::new(&env.settings).unwrap();
    runner.round().await;
    let good = env.log.entries.len() as i64;

    env.log.append_records(&recs(10..20));
    // One byte of one entry of the new batch is changed after the checkpoint was signed.
    let path = format!("tile/entries/000.p/{}", env.log.entries.len());
    let mut b = env.log.read(&path);
    let i = b.len() - 3;
    b[i] ^= 1;
    env.log.write(&path, &b);
    assert_halted(&env, &mut runner, good, 10).await;
}

#[tokio::test]
async fn a_log_that_does_not_extend_the_last_checkpoint_halts_it() {
    let mut env = Env::new().await;
    env.log.append_records(&recs(0..10));
    let mut runner = Runner::new(&env.settings).unwrap();
    runner.round().await;
    let good = env.log.entries.len() as i64;

    // The writer's history is rewritten: an earlier entry is replaced and a new, correctly signed checkpoint
    // covers more entries. Its tree is not the old tree plus new entries.
    let mut forked = TestLog::with_key(env.log.root.as_path(), clone_key(&env.log));
    forked.seal = env.log.seal.clone();
    forked.entries = env.log.entries.clone();
    forked.entries[0] = forked.record_entry(&Rec::new(999, "acme", "key.sign"));
    forked.append_records(&recs(10..20));
    assert_halted(&env, &mut runner, good, 10).await;
}

fn clone_key(l: &TestLog) -> aws_lc_rs::signature::EcdsaKeyPair {
    aws_lc_rs::signature::EcdsaKeyPair::from_pkcs8(
        &aws_lc_rs::signature::ECDSA_P384_SHA384_ASN1_SIGNING,
        l.key.to_pkcs8v1().unwrap().as_ref(),
    )
    .unwrap()
}

#[tokio::test]
async fn a_checkpoint_smaller_than_the_cursor_is_a_rollback_and_halts_the_log() {
    let mut env = Env::new().await;
    env.log.append_records(&recs(0..10));
    env.log.append_records(&recs(10..20));
    let mut runner = Runner::new(&env.settings).unwrap();
    runner.round().await;
    let good = env.log.entries.len() as i64;
    // The pointer is put back to the first checkpoint, which is validly signed.
    env.log.set_pointer(&env.log.checkpoint_note(11));
    assert_halted(&env, &mut runner, good, 20).await;
}

#[tokio::test]
async fn a_second_checkpoint_of_the_same_size_with_another_root_is_a_fork_and_halts_the_log() {
    let mut env = Env::new().await;
    env.log.append_records(&recs(0..10));
    let mut runner = Runner::new(&env.settings).unwrap();
    runner.round().await;
    let good = env.log.entries.len() as i64;
    // Same size, a root the entries do not make, signed by the log key.
    let note = env.log.note(&env.log.origin, good as u64, &[7; 32]);
    env.log.set_pointer(&note);
    assert_halted(&env, &mut runner, good, 10).await;
}

#[tokio::test]
async fn a_checkpoint_of_another_log_origin_halts_the_log() {
    let mut env = Env::new().await;
    env.log.append_records(&recs(0..10));
    // Signed by the right key, for another log.
    let root = TestLog::root_of(&env.log.entries);
    let note = env
        .log
        .note("sluis.local.test/dev/sluis/audit/other", 11, &root);
    env.log.set_pointer(&note);
    let mut runner = Runner::new(&env.settings).unwrap();
    assert_halted(&env, &mut runner, 0, 0).await;
}

#[tokio::test]
async fn a_missing_bundle_under_a_signed_checkpoint_halts_the_log() {
    let mut env = Env::new().await;
    env.log.append_records(&recs(0..10));
    env.log
        .remove(&format!("tile/entries/000.p/{}", env.log.entries.len()));
    let mut runner = Runner::new(&env.settings).unwrap();
    assert_halted(&env, &mut runner, 0, 0).await;
}

#[tokio::test]
async fn entries_beyond_the_signed_checkpoint_are_never_indexed() {
    let mut env = Env::new().await;
    env.log.append_records(&recs(0..10));
    // A crash left a longer bundle that no checkpoint covers: three records past the size.
    let extra: Vec<Vec<u8>> = recs(10..13)
        .iter()
        .map(|r| env.log.record_entry(r))
        .collect();
    let mut all = env.log.entries.clone();
    all.extend(extra);
    let mut b = Vec::new();
    for e in &all {
        b.extend_from_slice(&u16::try_from(e.len()).unwrap().to_be_bytes());
        b.extend_from_slice(e);
    }
    env.log
        .write(&format!("tile/entries/000.p/{}", all.len()), &b);
    let r = round(&env).await;
    assert_eq!((r.steps, r.halted, r.transient), (1, 0, 0));
    assert_eq!(env.search(&["*"], "").await.len(), 10);
    assert_eq!(env.cursor_size(), 11);
}

#[tokio::test]
async fn a_partial_bundle_that_is_gone_is_read_from_the_full_one() {
    let mut env = Env::new().await;
    // Three batches of 99 records and a seal: checkpoints at 100, 200 and 300, and a full bundle 0 of 256.
    for b in 0..3u32 {
        env.log.append_records(&recs(b * 99..(b + 1) * 99));
    }
    // The pointer is the checkpoint at 100, and its partial bundle is gone (C2SP tlog-tiles: a client falls
    // back to the full bundle, whose first 100 entries are the same bytes).
    env.log.set_pointer(&env.log.checkpoint_note(100));
    env.log.remove("tile/entries/000.p/100");
    let r = round(&env).await;
    assert_eq!((r.steps, r.halted, r.transient), (1, 0, 0));
    assert_eq!(env.cursor_size(), 100);
    assert_eq!(env.search(&["*"], "").await.len(), 99);
}

#[tokio::test]
async fn nothing_is_indexed_when_key_at_cannot_open_and_it_goes_on_when_it_can_again() {
    let mut env = Env::new().await;
    env.log.append_records(&recs(0..10));
    env.control.key_down.store(true, Ordering::SeqCst);
    let mut runner = Runner::new(&env.settings).unwrap();
    let r = runner.round().await;
    assert_eq!((r.transient, r.halted, r.steps), (1, 0, 0));
    assert_eq!(env.cursor_size(), 0);
    assert!(env.search(&["*"], "").await.is_empty());
    env.control.key_down.store(false, Ordering::SeqCst);
    let r = runner.round().await;
    assert_eq!((r.transient, r.halted, r.steps), (0, 0, 1));
    assert_eq!(env.search(&["*"], "").await.len(), 10);
}

#[tokio::test]
async fn a_record_that_does_not_open_halts_the_log_and_nothing_of_its_batch_is_written() {
    let mut env = Env::new().await;
    env.log.append_records(&recs(0..5));
    let mut runner = Runner::new(&env.settings).unwrap();
    runner.round().await;
    let good = env.log.entries.len() as i64;
    // A record sealed for one tenant is put in the log for another (a record copied to another tenant).
    let mut moved = Rec::new(50, "acme", "key.sign");
    moved.routed = Some("globex".into());
    // The record names acme; the entry says globex; the seal binds the address of globex, so it opens, but the
    // clear envelope and the record disagree about the tenant.
    env.log
        .append_records(&[Rec::new(49, "acme", "key.sign"), moved]);
    assert_halted(&env, &mut runner, good, 5).await;
}

#[tokio::test]
async fn an_envelope_that_lies_about_the_record_halts_the_log() {
    let mut env = Env::new().await;
    let mut lie = Rec::new(1, "acme", "key.sign");
    lie.envelope_time = Some(lie.time + 1);
    env.log
        .append_records(&[Rec::new(0, "acme", "key.sign"), lie]);
    let mut runner = Runner::new(&env.settings).unwrap();
    assert_halted(&env, &mut runner, 0, 0).await;
}

#[tokio::test]
async fn a_record_of_another_boundary_halts_the_log() {
    let mut env = Env::new().await;
    let mut other = Rec::new(1, "acme", "key.sign");
    other.boundary = "stage".into();
    env.log.append_records(&[other]);
    let mut runner = Runner::new(&env.settings).unwrap();
    assert_halted(&env, &mut runner, 0, 0).await;
}

#[tokio::test]
async fn a_record_of_no_tenant_is_indexed_under_the_tenant_the_writer_routed_it_to() {
    let mut env = Env::new().await;
    let mut r = Rec::new(1, "acme", "key.sign");
    r.tenant = None;
    r.routed = Some("operator".into());
    env.log.append_records(&[r]);
    assert_eq!(round(&env).await.halted, 0);
    let rows = env.search(&["operator"], "").await;
    assert_eq!(rows.len(), 1);
    assert!(env.search(&["acme"], "").await.is_empty());
}

#[tokio::test]
async fn policy_that_denies_the_grant_halts_the_log_and_one_that_is_down_does_not() {
    let mut env = Env::new().await;
    env.log.append_records(&recs(0..5));
    let mut runner = Runner::new(&env.settings).unwrap();
    env.control.policy_down.store(true, Ordering::SeqCst);
    let r = runner.round().await;
    assert_eq!((r.transient, r.halted), (1, 0));
    env.control.policy_down.store(false, Ordering::SeqCst);
    env.control.deny.store(true, Ordering::SeqCst);
    assert_halted(&env, &mut runner, 0, 0).await;
    assert_eq!(
        env.control.opens.load(Ordering::SeqCst),
        0,
        "key@ was asked without a grant"
    );
}

#[tokio::test]
async fn a_grant_that_key_at_finds_expired_is_asked_for_again_once() {
    let mut env = Env::new().await;
    env.log.append_records(&recs(0..5));
    env.control.expire_first_grant.store(true, Ordering::SeqCst);
    let r = round(&env).await;
    assert_eq!((r.steps, r.halted, r.transient), (1, 0, 0));
    assert_eq!(env.control.made.load(Ordering::SeqCst), 2);
    let g = env.control.grants.lock().unwrap().clone();
    assert_eq!(g.len(), 2);
    assert_ne!(g[0], g[1]);
    assert_eq!(env.search(&["*"], "").await.len(), 5);
}

#[tokio::test]
async fn two_indexers_on_one_index_do_no_harm() {
    let mut env = Env::new().await;
    for b in 0..4u32 {
        env.log.append_records(&recs(b * 50..(b + 1) * 50));
    }
    let (mut a, mut b) = (
        Runner::new(&env.settings).unwrap(),
        Runner::new(&env.settings).unwrap(),
    );
    let (ra, rb) = tokio::join!(a.round(), b.round());
    assert_eq!((ra.halted, rb.halted), (0, 0));
    // One may have lost the conditional write and tried again later.
    for _ in 0..3 {
        a.round().await;
        b.round().await;
    }
    assert_eq!(env.cursor_size(), 204);
    assert_eq!(env.search(&["*"], "").await.len(), 200);
}

#[tokio::test]
async fn the_usage_log_and_the_logs_of_other_kinds_are_not_followed() {
    // The AuditLog of the environment declares a usage log with an origin and no key file: a follower that
    // took it would halt on the missing verifier key.
    let mut env = Env::new().await;
    env.log.append_records(&recs(0..3));
    let r = round(&env).await;
    assert_eq!((r.steps, r.halted), (1, 0));
    assert_eq!(LOG, "main");
}

#[tokio::test]
async fn a_missing_verifier_key_halts_everything_with_an_alert() {
    let env = Env::new().await;
    std::fs::remove_file(env.settings.key_dir.join(format!("{LOG}.vkey"))).unwrap();
    let r = round(&env).await;
    assert_eq!((r.halted, r.steps), (1, 0));
}
