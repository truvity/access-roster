//! The indexer over a log the merged Go writer made (`actors/writer`), not one made by this crate's test
//! support: the writer's real bundles, tiles, signed notes (SHA-384 over the note text, D-25), sealed
//! entries and seal entries. The fixture is in `testdata/go-writer/`; how it was made is in
//! `export_fixture_test.go.txt` beside it. The stand-in for key@ answers from what the writer's own stand-in
//! opened each entry to, at the address the entry was sealed at, so a wrong address is a refusal.

#![allow(clippy::unwrap_used, clippy::expect_used)] // a failed unwrap in a test is the failure

mod common;

use common::{Env, by_tenant, value};
use indexer::run::Runner;

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
