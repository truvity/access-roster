#![allow(clippy::unwrap_used, clippy::expect_used)] // a failed unwrap in a test is the failure
//! The watch helper of the typed Rust client (`sluis_store::Store::watch`) against the real store@ service: the
//! listing and the follow, a delete and an expiry, and a resume point the change log no longer holds. The scripted
//! cases (reconnects, backoff, malformed changes) are in `kits/rust/sluis-store/tests/watch.rs`.

mod common;

use std::time::Duration;

use common::*;
use sluis_proto::sluis::store::v2alpha1::Provenance;
use sluis_store::revocation::KeyRevocations;
use sluis_store::{
    Backoff, Event, Kind, ResumePoint, ResyncCause, Store, Watch, WatchOpts, WriteOpts,
};

/// `PinReleaseRequest`: a temp kind that key@ alone writes and watches, with a time to live.
struct Pin;
impl Kind for Pin {
    type Id = String;
    type Value = Provenance;
    const NAME: &'static str = "PinReleaseRequest";
}

const FAST: Backoff = Backoff {
    initial: Duration::from_millis(20),
    max: Duration::from_millis(100),
};

async fn ev<K: Kind>(w: &mut Watch<K>) -> Event<K> {
    tokio::time::timeout(Duration::from_secs(5), w.next())
        .await
        .expect("the watch said nothing in five seconds")
        .expect("the watch ended in an error")
}

fn create_revocation(target: &str) -> sluis_proto::sluis::store::v2alpha1::Operation {
    op(
        sluis_proto::sluis::store::v2alpha1::Verb::CREATE,
        "key-revocation",
        "",
        &format!("purpose/{target}"),
        &revocation("purpose", target, "drill"),
    )
}

/// verifies: REQ-DATA-108
/// The reader of `KeyRevocation` is told the revocations that exist (one resync), then each new one as a put, with
/// store@'s own log sequence; a restart from the last sequence gets the one made in between and nothing before.
#[tokio::test]
async fn the_revocation_watch_lists_then_follows_and_a_restart_resumes() {
    let f = F::new().await;
    f.as_("key");
    f.write(vec![create_revocation("session")], &[])
        .await
        .unwrap();
    let revocations = KeyRevocations::new(&f.kit).unwrap();
    let opts = WatchOpts {
        from: None,
        backoff: FAST,
        ..WatchOpts::default()
    };
    let mut w = revocations.watch_with(opts).unwrap();
    let start = match ev(&mut w).await {
        Event::Resync {
            cause,
            items,
            resume_point,
        } => {
            assert_eq!(cause, ResyncCause::Start);
            assert_eq!(items.len(), 1);
            assert_eq!(items[0].id, "purpose/session");
            assert_eq!(items[0].value.target, "session");
            assert!(resume_point.sequence >= 1 && resume_point.epoch != 0);
            resume_point
        }
        e => panic!("not a resync: {e:?}"),
    };
    f.write(vec![create_revocation("cookie")], &[])
        .await
        .unwrap();
    let seq = match ev(&mut w).await {
        Event::Put { item, resume_point } => {
            assert_eq!(item.id, "purpose/cookie");
            assert_eq!(item.version, 1);
            assert!(resume_point.sequence > start.sequence && resume_point.epoch == start.epoch);
            resume_point
        }
        e => panic!("not a put: {e:?}"),
    };
    assert_eq!(w.resume_point(), seq);
    drop(w);

    // The watcher was away while a third was made; it comes back with the point it kept.
    f.write(vec![create_revocation("mac")], &[]).await.unwrap();
    let mut w = revocations
        .watch_with(WatchOpts {
            from: Some(seq),
            backoff: FAST,
            ..WatchOpts::default()
        })
        .unwrap();
    match ev(&mut w).await {
        Event::Put { item, .. } => assert_eq!(item.id, "purpose/mac"),
        e => panic!("not the revocation made while away: {e:?}"),
    }
}

/// verifies: REQ-DATA-109
/// A saved resume point below the floor of the change log is refused by store@ and becomes a resync with the whole
/// state of the kind, never a silent jump; the watch then follows from the new position.
#[tokio::test]
async fn a_point_the_log_no_longer_holds_is_a_resync_with_the_whole_kind() {
    let f = F::new().await;
    f.as_("key");
    for t in ["session", "cookie", "mac"] {
        f.write(vec![create_revocation(t)], &[]).await.unwrap();
    }
    let head = f.durable.head();
    f.durable.trim(head - 1);
    let mut w = KeyRevocations::new(&f.kit)
        .unwrap()
        .watch_with(WatchOpts {
            from: Some(ResumePoint {
                epoch: f.durable.epoch(),
                sequence: 1,
            }),
            backoff: FAST,
            ..WatchOpts::default()
        })
        .unwrap();
    match ev(&mut w).await {
        Event::Resync {
            cause,
            items,
            resume_point,
        } => {
            assert_eq!(cause, ResyncCause::Expired);
            let mut ids: Vec<_> = items.iter().map(|i| i.id.clone()).collect();
            ids.sort();
            assert_eq!(ids, ["purpose/cookie", "purpose/mac", "purpose/session"]);
            assert!(resume_point.sequence >= head - 1);
        }
        e => panic!("not a resync: {e:?}"),
    }
    f.write(vec![create_revocation("data")], &[]).await.unwrap();
    match ev(&mut w).await {
        Event::Put { item, .. } => assert_eq!(item.id, "purpose/data"),
        e => panic!("not a put: {e:?}"),
    }
}

/// verifies: REQ-DATA-108
/// A removal and an expiry are deletes with no value, in the order of the log, and an idle stream's bookmark
/// carries the latest point.
#[tokio::test]
async fn a_delete_and_an_expiry_reach_the_watcher_and_an_idle_stream_says_its_point() {
    let f = F::new_with(Duration::from_millis(200)).await;
    f.as_("key");
    let pins = Store::<Pin>::new(f.kit.clone()).unwrap();
    let mut w = pins
        .watch_with(
            "",
            WatchOpts {
                from: None,
                backoff: FAST,
                ..WatchOpts::default()
            },
        )
        .unwrap();
    assert!(matches!(ev(&mut w).await, Event::Resync { items, .. } if items.is_empty()));
    let ttl = |secs| WriteOpts {
        ttl: Some(Duration::from_secs(secs)),
        ..WriteOpts::default()
    };
    let v = Provenance {
        field_path: "x".into(),
        ..Provenance::default()
    };
    pins.create("", "node-a/r1", &v, ttl(600)).await.unwrap();
    pins.create("", "node-a/r2", &v, ttl(30)).await.unwrap();
    match ev(&mut w).await {
        Event::Put { item, .. } => {
            assert_eq!((item.id.as_str(), item.version), ("node-a/r1", 1));
            assert_eq!(item.value.field_path, "x");
        }
        e => panic!("{e:?}"),
    }
    assert!(matches!(ev(&mut w).await, Event::Put { item, .. } if item.id == "node-a/r2"));
    pins.delete("", "node-a/r1", None, WriteOpts::default())
        .await
        .unwrap();
    match ev(&mut w).await {
        Event::Delete { id, tenant, .. } => {
            assert_eq!((id.as_str(), tenant.as_str()), ("node-a/r1", ""))
        }
        e => panic!("not a delete: {e:?}"),
    }
    f.advance(31);
    f.temp.sweep();
    let mut seen = None;
    loop {
        match ev(&mut w).await {
            Event::Delete {
                id, resume_point, ..
            } => {
                assert_eq!(id, "node-a/r2", "the expiry is a delete");
                seen = Some(resume_point);
            }
            Event::Bookmark { resume_point } => {
                assert_eq!(
                    Some(resume_point),
                    seen,
                    "the bookmark names the last point"
                );
                break;
            }
            e => panic!("{e:?}"),
        }
    }
}

/// verifies: REQ-DATA-108
/// A kind of more than one page (store@'s default is 100 items) is listed over all its pages through the client:
/// one resync with every item, at one position, and the watch follows from it.
#[tokio::test]
async fn a_listing_of_several_pages_is_one_resync() {
    let f = F::new().await;
    f.as_("key");
    let pins = Store::<Pin>::new(f.kit.clone()).unwrap();
    let v = Provenance {
        field_path: "x".into(),
        ..Provenance::default()
    };
    for i in 0..150 {
        pins.create(
            "",
            &format!("node-a/r{i:03}"),
            &v,
            WriteOpts {
                ttl: Some(Duration::from_secs(600)),
                ..WriteOpts::default()
            },
        )
        .await
        .unwrap();
    }
    let mut w = pins
        .watch_with(
            "",
            WatchOpts {
                backoff: FAST,
                ..WatchOpts::default()
            },
        )
        .unwrap();
    match ev(&mut w).await {
        Event::Resync {
            cause,
            items,
            resume_point,
        } => {
            assert_eq!(cause, ResyncCause::Start);
            assert_eq!(items.len(), 150, "two pages");
            assert!(resume_point.sequence >= 150);
        }
        e => panic!("not a resync: {e:?}"),
    }
    pins.create(
        "",
        "node-a/r150",
        &v,
        WriteOpts {
            ttl: Some(Duration::from_secs(600)),
            ..WriteOpts::default()
        },
    )
    .await
    .unwrap();
    assert!(matches!(ev(&mut w).await, Event::Put { item, .. } if item.id == "node-a/r150"));
}

/// A watcher keeps a point in the log of a kind, the log is made again (a restore into a new database, or a reset) and
/// `restored` revocations are written back into the new log; then a watcher starts from the point it kept.
async fn restore_scenario(restored: &[&str]) {
    let f = F::new().await;
    f.as_("key");
    for t in ["a", "b", "c", "d"] {
        f.write(vec![create_revocation(t)], &[]).await.unwrap();
    }
    let revocations = KeyRevocations::new(&f.kit).unwrap();
    let mut w = revocations
        .watch_with(WatchOpts {
            backoff: FAST,
            ..WatchOpts::default()
        })
        .unwrap();
    assert!(matches!(ev(&mut w).await, Event::Resync { .. }));
    f.write(vec![create_revocation("e")], &[]).await.unwrap();
    let saved = match ev(&mut w).await {
        Event::Put { resume_point, .. } => resume_point,
        e => panic!("not a put: {e:?}"),
    };
    assert!(
        saved.sequence >= 6,
        "the saved point is well into the log: {saved:?}"
    );
    drop(w);

    f.durable.remake_log();
    for t in restored {
        // The restore writes the revocations back, through the store, into the new database.
        f.write(vec![create_revocation(t)], &[]).await.unwrap();
    }
    let grown = f.durable.head() >= saved.sequence;
    let mut w = revocations
        .watch_with(WatchOpts {
            from: Some(saved),
            backoff: FAST,
            ..WatchOpts::default()
        })
        .unwrap();
    let relisted = match ev(&mut w).await {
        Event::Resync {
            cause,
            items,
            resume_point,
        } => {
            assert_eq!(
                cause,
                ResyncCause::Expired,
                "refused, not resumed from a number of another log"
            );
            assert_eq!(
                items.len(),
                restored.len(),
                "the whole state of the new log"
            );
            assert_eq!(resume_point.epoch, f.durable.epoch());
            assert_ne!(resume_point.epoch, saved.epoch);
            resume_point
        }
        e => panic!("not a resync: {e:?}"),
    };
    // A change of the new log is applied, whatever its number is next to the point applied before the restore.
    f.write(vec![create_revocation("g")], &[]).await.unwrap();
    match ev(&mut w).await {
        Event::Put { item, resume_point } => {
            assert_eq!(item.id, "purpose/g");
            assert_eq!(resume_point.epoch, f.durable.epoch());
            assert!(resume_point.sequence > relisted.sequence);
            assert_eq!(
                resume_point.sequence <= saved.sequence,
                !grown,
                "the scenario puts the new change {} the old point",
                if grown { "above" } else { "at or below" }
            );
        }
        e => panic!("not the change of the new log: {e:?}"),
    }
}

/// verifies: REQ-DATA-117, REQ-DATA-118
/// A restore or a reset makes the change log again: its sequence begins at the start and the epoch is new. A watcher that
/// kept a point from before is refused by store@ and lists again, with the whole state of the new log, even when the new
/// log has already grown past the saved sequence. Without the epoch the number in the new log would be a position in
/// it, the watch would resume there, and the revocations between the start of the new log and the saved sequence would be
/// skipped without a word.
#[tokio::test]
async fn a_point_saved_before_a_restore_is_refused_when_the_new_log_has_grown_past_it() {
    restore_scenario(&["a", "b", "c", "d", "e", "f"]).await;
}

/// verifies: REQ-DATA-118
/// The dedupe of applied points: the helper drops a change at or below the sequence it has applied, but only in one
/// epoch. After a restore the new log is shorter than the point the watcher had applied; the watch lists the new log, and
/// its next change, which has a lower number than the old applied point, is applied and not taken for a repeat.
#[tokio::test]
async fn a_change_of_a_restored_log_below_the_old_point_is_applied_and_not_dropped_as_a_repeat() {
    restore_scenario(&["a", "b"]).await;
}
