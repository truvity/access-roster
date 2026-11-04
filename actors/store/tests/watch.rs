#![allow(clippy::unwrap_used, clippy::expect_used)] // a failed unwrap in a test is the failure
//! `Watch` (ADR 0005 "Watch and the resume point"; store-api.md "Watch"), over the kit's transport: the changes of a
//! kind from a resume point, the state read at delivery, expiry as a delete, the position a listing names, the
//! bookmark of an idle stream, the limit per caller, the refusal of a point the log no longer holds, and the
//! change of a config kind at a swap of the snapshot.

mod common;

use std::time::Duration;

use common::*;
use connectrpc::error::ErrorCode;
use sluis_proto::sluis::store::v2alpha1::{ChangeType, ListRequest, Verb, WatchResponse};

const SHORT: Duration = Duration::from_millis(400);

/// `PinReleaseRequest`: a temp kind that key@ alone writes and watches, with a time to live.
const TEMP: &str = "pin-release-request";

fn write_temp(
    verb: Verb,
    id: &str,
    value: &[u8],
) -> sluis_proto::sluis::store::v2alpha1::Operation {
    let o = op(verb, TEMP, "", id, value);
    if verb == Verb::CREATE {
        with_ttl(o, 600)
    } else {
        o
    }
}

fn kind_of(m: &WatchResponse) -> ChangeType {
    m.r#type.as_known().expect("a known change type")
}

/// The id of the item a change is about.
fn id_of(m: &WatchResponse) -> String {
    m.item
        .as_option()
        .expect("an item")
        .address
        .as_option()
        .expect("an address")
        .id
        .clone()
}

/// The position that a listing of a kind names.
async fn position(f: &F, kind: &str) -> u64 {
    f.list(ListRequest {
        kind: kind.into(),
        ..ListRequest::default()
    })
    .await
    .unwrap()
    .resume_point
}

// ---- the state at delivery ----

/// verifies: REQ-DATA-100
/// A change carries the address, the type, the version and the log sequence, and the value as read when it is
/// delivered: an item that changed three times since the point is delivered once, at the version it has, because
/// the later rows of its address supersede the earlier ones. An item that is gone is a delete with no value.
#[tokio::test]
async fn a_watch_delivers_the_state_at_delivery_and_a_gone_item_as_one_delete() {
    let f = F::new().await;
    f.as_("key");
    let from = position(&f, TEMP).await;
    assert!(
        from >= 1,
        "a listing of a watched kind names a position, never 0"
    );
    // r1 is written three times, r2 is made and removed: five rows after the point, two items.
    f.write(vec![write_temp(Verb::CREATE, "node-a/r1", b"one")], &[])
        .await
        .unwrap();
    f.write(
        vec![with_version(
            write_temp(Verb::UPDATE, "node-a/r1", b"two"),
            1,
        )],
        &[],
    )
    .await
    .unwrap();
    f.write(
        vec![with_version(
            write_temp(Verb::UPDATE, "node-a/r1", b"three"),
            2,
        )],
        &[],
    )
    .await
    .unwrap();
    f.write(vec![write_temp(Verb::CREATE, "node-a/r2", b"x")], &[])
        .await
        .unwrap();
    f.write(vec![write_temp(Verb::DELETE, "node-a/r2", b"")], &[])
        .await
        .unwrap();

    let mut w = f.watch(TEMP, "", from).await.unwrap();
    let m = w.msg().await;
    assert_eq!(kind_of(&m), ChangeType::CHANGE_TYPE_PUT);
    assert_eq!(id_of(&m), "node-a/r1");
    let item = m.item.as_option().unwrap();
    assert_eq!(
        (item.version, item.value.as_slice()),
        (3, b"three".as_slice()),
        "the state as read now"
    );
    assert!(m.resume_point > from);
    let m = w.msg().await;
    assert_eq!(
        (kind_of(&m), id_of(&m).as_str()),
        (ChangeType::CHANGE_TYPE_DELETE, "node-a/r2")
    );
    assert!(
        m.item.as_option().unwrap().value.is_empty(),
        "a delete has no value"
    );
    assert!(
        w.quiet(SHORT).await,
        "the rows below the delivered version, and the second row of r2, are skipped"
    );

    // A live change after that: the stream goes on, in order.
    f.write(vec![write_temp(Verb::CREATE, "node-a/r3", b"y")], &[])
        .await
        .unwrap();
    f.write(vec![write_temp(Verb::DELETE, "node-a/r3", b"")], &[])
        .await
        .unwrap();
    let m = w.msg().await;
    assert_eq!(id_of(&m), "node-a/r3");
    // Whatever the timing, r3 ends as a delete, and a repeat of the same state is the consumer's to skip.
    let mut last = kind_of(&m);
    while let Some(Ok(m)) = w.next(SHORT).await {
        assert_eq!(id_of(&m), "node-a/r3");
        last = kind_of(&m);
    }
    assert_eq!(last, ChangeType::CHANGE_TYPE_DELETE);
}

/// verifies: REQ-DATA-101
/// Expiry is a delete: the sweeper that frees an item written with a log row writes the delete row, and a watcher
/// that is told after the expiry gets the delete even before the sweep, because an expired item is gone.
#[tokio::test]
async fn expiry_is_delivered_as_a_delete() {
    let f = F::new().await;
    f.as_("key");
    let mut w = f.watch(TEMP, "", 0).await.unwrap();
    f.write(
        vec![with_ttl(op(Verb::CREATE, TEMP, "", "node-a/e1", b"v"), 30)],
        &[],
    )
    .await
    .unwrap();
    let m = w.msg().await;
    assert_eq!(
        (kind_of(&m), id_of(&m).as_str()),
        (ChangeType::CHANGE_TYPE_PUT, "node-a/e1")
    );
    f.advance(31);
    f.temp.sweep();
    let m = w.msg().await;
    assert_eq!(
        (kind_of(&m), id_of(&m).as_str()),
        (ChangeType::CHANGE_TYPE_DELETE, "node-a/e1")
    );
    assert!(m.item.as_option().unwrap().value.is_empty());

    // Not yet swept: a watcher from before the write is told the item is gone, not its stale value.
    let from = f.temp.head();
    f.write(
        vec![with_ttl(op(Verb::CREATE, TEMP, "", "node-a/e2", b"v"), 30)],
        &[],
    )
    .await
    .unwrap();
    f.advance(31);
    let mut late = f.watch(TEMP, "", from).await.unwrap();
    let m = late.msg().await;
    assert_eq!(
        (kind_of(&m), id_of(&m).as_str()),
        (ChangeType::CHANGE_TYPE_DELETE, "node-a/e2")
    );
}

// ---- list, then watch ----

/// verifies: REQ-DATA-102
/// `List` names the log position of its snapshot, the same on every page, and a watch from it gives every change
/// after the listing (and may repeat one the listing shows: the consumer dedupes by address and version). A kind that
/// nobody watches names none.
#[tokio::test]
async fn a_listing_names_the_position_to_watch_from() {
    let f = F::new().await;
    f.as_("key");
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
    .await
    .unwrap();
    f.write(
        vec![op(
            Verb::CREATE,
            "key-revocation",
            "",
            "purpose/token-signing",
            &revocation("purpose", "token-signing", "drill"),
        )],
        &[],
    )
    .await
    .unwrap();
    let first = f
        .list(ListRequest {
            kind: "key-revocation".into(),
            page_size: 1,
            ..ListRequest::default()
        })
        .await
        .unwrap();
    assert_eq!(first.items.len(), 1);
    assert!(
        first.resume_point >= 3,
        "two logged writes after the marker row"
    );
    assert!(!first.next_page_token.is_empty());
    // A write between the pages does not move the position of the listing.
    f.write(
        vec![op(
            Verb::CREATE,
            "key-revocation",
            "",
            "purpose/session",
            &revocation("purpose", "session", "drill"),
        )],
        &[],
    )
    .await
    .unwrap();
    let second = f
        .list(ListRequest {
            kind: "key-revocation".into(),
            page_size: 1,
            page_token: first.next_page_token.clone(),
            ..ListRequest::default()
        })
        .await
        .unwrap();
    assert_eq!(
        second.resume_point, first.resume_point,
        "every page of one listing names the same position"
    );
    // The watch from it gives the write made after the first page, and nothing is lost.
    let mut w = f
        .watch("key-revocation", "", first.resume_point)
        .await
        .unwrap();
    let m = w.msg().await;
    assert_eq!(id_of(&m), "purpose/session");
    assert!(w.quiet(SHORT).await);

    // A kind nobody watches writes no log and names no position.
    f.as_("session");
    let none = f
        .list(ListRequest {
            kind: "person".into(),
            tenant: "acme".into(),
            ..ListRequest::default()
        })
        .await
        .unwrap();
    assert_eq!(none.resume_point, 0);
}

// ---- the bookmark ----

/// verifies: REQ-DATA-103
/// An idle stream says the latest resume point, so that a watcher that restarts does not fall behind the retention of
/// the log: first the point it started from, then the point of the last change it was told.
#[tokio::test]
async fn an_idle_watch_says_its_resume_point() {
    let f = F::new_with(Duration::from_millis(250)).await;
    f.as_("key");
    let head = position(&f, TEMP).await;
    let mut w = f.watch(TEMP, "", 0).await.unwrap();
    let m = w.msg().await;
    assert_eq!(kind_of(&m), ChangeType::CHANGE_TYPE_BOOKMARK);
    assert_eq!(
        m.resume_point, head,
        "a watch from now names the point it started from"
    );
    assert!(m.item.as_option().is_none(), "a bookmark has no item");
    f.write(vec![write_temp(Verb::CREATE, "node-a/b1", b"v")], &[])
        .await
        .unwrap();
    let mut told = 0;
    for _ in 0..40 {
        let m = w.msg().await;
        if kind_of(&m) == ChangeType::CHANGE_TYPE_PUT {
            told = m.resume_point;
        } else if told != 0 {
            assert_eq!(
                m.resume_point, told,
                "the bookmark names the point of the last change"
            );
            return;
        }
    }
    panic!("no bookmark followed the change");
}

// ---- the limit ----

/// verifies: REQ-DATA-104
/// A caller has at most 16 watches; the 17th is refused with `resource_exhausted`, audited, and one is free again
/// when a watch ends.
#[tokio::test]
async fn a_caller_has_at_most_sixteen_watches() {
    let f = F::new().await;
    f.as_("key");
    let mut open = Vec::new();
    for _ in 0..16 {
        open.push(f.watch(TEMP, "", 0).await.unwrap());
    }
    let e = f
        .watch(TEMP, "", 0)
        .await
        .err()
        .expect("the 17th watch is refused");
    assert_eq!(
        (e.code, reason(&e)),
        (ErrorCode::ResourceExhausted, "watch_limit".into())
    );
    assert!(
        f.audit()
            .iter()
            .any(|a| a.action == "store.refused" && a.reason == "watch_limit")
    );
    // Another caller has its own sixteen.
    f.as_("signer");
    let other = f.watch("key-revocation", "", 0).await;
    assert!(other.is_ok(), "the limit is per caller");
    // One ends, and the slot is given back.
    f.as_("key");
    drop(open.pop());
    let mut again = None;
    for _ in 0..100 {
        match f.watch(TEMP, "", 0).await {
            Ok(w) => {
                again = Some(w);
                break;
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
        }
    }
    assert!(
        again.is_some(),
        "a watch that ended did not give its slot back"
    );
}

// ---- the retention of the log ----

/// verifies: REQ-DATA-057
/// A resume point that the change log no longer holds is `failed_precondition` with the reason
/// `resume_point_expired`, an audit fact, and a listing then catches up; one the log has not reached is the same
/// refusal. A point at the floor itself is held.
#[tokio::test]
async fn a_resume_point_the_log_no_longer_holds_is_refused_and_a_listing_catches_up() {
    let f = F::new().await;
    f.as_("key");
    for i in 1..=3 {
        f.write(
            vec![write_temp(Verb::CREATE, &format!("node-a/p{i}"), b"v")],
            &[],
        )
        .await
        .unwrap();
    }
    let head = f.temp.head();
    f.temp.trim(head - 1); // the driver kept its window: the oldest rows are gone
    let e = f
        .watch(TEMP, "", 1)
        .await
        .err()
        .expect("a point below the floor");
    assert_eq!(
        (e.code, reason(&e)),
        (ErrorCode::FailedPrecondition, "resume_point_expired".into())
    );
    assert_eq!(refusal_path(&e), "resume_point");
    let e = f
        .watch(TEMP, "", head + 10)
        .await
        .err()
        .expect("a point the log has not reached");
    assert_eq!(
        (e.code, reason(&e)),
        (ErrorCode::FailedPrecondition, "resume_point_expired".into())
    );
    assert!(f.audit().iter().any(|a| a.action == "store.refused"
        && a.reason == "resume_point_expired"
        && a.fields.contains(&("verb", "watch".to_owned()))));
    // The listing shows every item and names a point that the log holds.
    let listed = f
        .list(ListRequest {
            kind: TEMP.into(),
            ..ListRequest::default()
        })
        .await
        .unwrap();
    assert_eq!(listed.items.len(), 3);
    let mut w = f.watch(TEMP, "", listed.resume_point).await.unwrap();
    f.write(vec![write_temp(Verb::CREATE, "node-a/p4", b"v")], &[])
        .await
        .unwrap();
    assert_eq!(id_of(&w.msg().await), "node-a/p4");
}

// ---- who may watch ----

/// verifies: REQ-DATA-106
/// A watch is judged as a read is: a kind that the registry does not declare, an actor with no watch rule on the
/// kind, a tenant that does not fit the kind's scope and an engine that is down each get their refusal, audited.
#[tokio::test]
async fn a_watch_is_refused_like_a_read() {
    let f = F::new().await;
    f.as_("key");
    let e = f.watch("no-such-kind", "", 0).await.err().unwrap();
    assert_eq!(
        (e.code, reason(&e)),
        (ErrorCode::InvalidArgument, "address".into())
    );
    assert_eq!(refusal_path(&e), "kind.kind");
    // `session` may not watch a kind that only key@ and a few readers watch.
    f.as_("session");
    let e = f.watch(TEMP, "", 0).await.err().unwrap();
    assert_eq!(
        (e.code, reason(&e)),
        (ErrorCode::PermissionDenied, "rule".into())
    );
    // A kind with a tenant is watched under a tenant, as it is listed; a kind without one under none.
    f.as_("policy");
    let e = f.watch("policy-link", "", 0).await.err().unwrap();
    assert_eq!(
        (e.code, reason(&e)),
        (ErrorCode::InvalidArgument, "address".into())
    );
    assert!(f.watch("policy-link", "acme", 0).await.is_ok());
    f.as_("key");
    let e = f.watch(TEMP, "acme", 0).await.err().unwrap();
    assert_eq!(
        (e.code, reason(&e)),
        (ErrorCode::InvalidArgument, "address".into())
    );
    // key@'s revocation at no tenant is the boundary's own, so an empty tenant is allowed there.
    assert!(f.watch("key-revocation", "", 0).await.is_ok());
    // An engine that is down fails closed.
    f.temp.set_down(true);
    let e = f.watch(TEMP, "", 0).await.err().unwrap();
    assert_eq!(
        (e.code, reason(&e)),
        (ErrorCode::Unavailable, "engine".into())
    );
    f.temp.set_down(false);
    let refused = f
        .audit()
        .iter()
        .filter(|a| a.action == "store.refused")
        .count();
    assert!(refused >= 5, "every refusal is an audit fact ({refused})");
}

// ---- a config kind ----

/// verifies: REQ-DATA-058
/// A config kind has no change log: a watcher is sent the snapshot in force as puts and a bookmark, then each item
/// that a swap of the snapshot added, changed or removed, with resume point 0, and a swap of another kind tells it nothing. A
/// resume point is refused, so that the watcher reads the kind again.
#[tokio::test]
async fn a_swap_of_the_snapshot_is_delivered_to_the_watchers_of_that_kind() {
    let f = F::new().await;
    f.as_("key");
    let set = |kind: &str, id: &str, bytes: &[u8], seq: u64| {
        f.docs
            .items
            .lock()
            .unwrap()
            .insert((kind.into(), id.into()), bytes.to_vec());
        f.docs.versions.lock().unwrap().insert(kind.into(), seq);
    };
    set("key-plan", "default", b"plan-1", 1);
    set("front-host", "a", b"host-1", 1);
    let mut w = f.watch("key-plan", "", 0).await.unwrap();
    // The snapshot in force comes first, as puts: a swap between a listing and the watch is not lost.
    let m = w.msg().await;
    assert_eq!(
        (kind_of(&m), id_of(&m).as_str(), m.resume_point),
        (ChangeType::CHANGE_TYPE_PUT, "default", 0)
    );
    assert_eq!(m.item.as_option().unwrap().value, b"plan-1".to_vec());
    // A bookmark closes the snapshot: the items before it are the whole kind.
    let m = w.msg().await;
    assert_eq!(
        (kind_of(&m), m.resume_point),
        (ChangeType::CHANGE_TYPE_BOOKMARK, 0)
    );
    assert!(
        w.quiet(SHORT).await,
        "nothing changed since the snapshot was sent"
    );
    // A swap of another kind tells this watcher nothing.
    set("front-host", "a", b"host-2", 2);
    assert!(
        w.quiet(SHORT).await,
        "a swap of front-host is not for a watcher of key-plan"
    );
    // A swap of this kind: the changed item.
    set("key-plan", "default", b"plan-2", 2);
    let m = w.msg().await;
    assert_eq!(
        (kind_of(&m), id_of(&m).as_str(), m.resume_point),
        (ChangeType::CHANGE_TYPE_PUT, "default", 0)
    );
    let item = m.item.as_option().unwrap();
    assert_eq!(
        (item.version, item.value.as_slice()),
        (2, b"plan-2".as_slice())
    );
    // A swap that adds an item and removes the first.
    f.docs
        .items
        .lock()
        .unwrap()
        .remove(&("key-plan".to_owned(), "default".to_owned()));
    set("key-plan", "second", b"plan-3", 3);
    let a = w.msg().await;
    let b = w.msg().await;
    let mut got = [(kind_of(&a), id_of(&a)), (kind_of(&b), id_of(&b))];
    got.sort_by_key(|(_, id)| id.clone());
    assert_eq!(
        got,
        [
            (ChangeType::CHANGE_TYPE_DELETE, "default".to_owned()),
            (ChangeType::CHANGE_TYPE_PUT, "second".to_owned())
        ]
    );
    // There is no point to resume from.
    let e = f.watch("key-plan", "", 5).await.err().unwrap();
    assert_eq!(
        (e.code, reason(&e)),
        (ErrorCode::FailedPrecondition, "resume_point_expired".into())
    );
}

/// verifies: REQ-DATA-103
/// A config watch says a bookmark, with resume point 0, after a silence, as a watch of the log does.
#[tokio::test]
async fn an_idle_config_watch_sends_a_bookmark() {
    let f = F::new_with(Duration::from_millis(250)).await;
    f.as_("key");
    f.docs
        .items
        .lock()
        .unwrap()
        .insert(("key-plan".into(), "default".into()), b"p".to_vec());
    f.docs.versions.lock().unwrap().insert("key-plan".into(), 1);
    let mut w = f.watch("key-plan", "", 0).await.unwrap();
    assert_eq!(kind_of(&w.msg().await), ChangeType::CHANGE_TYPE_PUT);
    // The bookmark that closes the snapshot, then the one of the silence.
    for _ in 0..2 {
        let m = w.msg().await;
        assert_eq!(
            (kind_of(&m), m.resume_point),
            (ChangeType::CHANGE_TYPE_BOOKMARK, 0)
        );
        assert!(m.item.as_option().is_none());
    }
}

/// verifies: REQ-DATA-058
/// An item that a swap removes between a listing and the watch: the watch begins with the full snapshot and a
/// bookmark, and a consumer that replaces its state with the items before that bookmark drops the item. The
/// changes after it carry no sequence, and the consumer applies every one.
#[tokio::test]
async fn a_removal_between_the_listing_and_the_watch_is_not_lost() {
    let f = F::new().await;
    f.as_("key");
    let set = |id: &str, bytes: &[u8], seq: u64| {
        f.docs
            .items
            .lock()
            .unwrap()
            .insert(("key-plan".into(), id.into()), bytes.to_vec());
        f.docs
            .versions
            .lock()
            .unwrap()
            .insert("key-plan".into(), seq);
    };
    set("x", b"plan-x", 1);
    set("y", b"plan-y", 1);
    let listed = f
        .list(ListRequest {
            kind: "key-plan".into(),
            ..ListRequest::default()
        })
        .await
        .unwrap();
    let mut c = Consumer::listed(
        listed
            .items
            .iter()
            .map(|i| (i.address.as_option().unwrap().id.clone(), i.value.clone()))
            .collect(),
    );
    assert_eq!(c.state.len(), 2, "the listing has both items");
    // A swap removes x before the watch opens.
    f.docs
        .items
        .lock()
        .unwrap()
        .remove(&("key-plan".to_owned(), "x".to_owned()));
    f.docs.versions.lock().unwrap().insert("key-plan".into(), 2);
    let mut w = f.watch("key-plan", "", 0).await.unwrap();
    c.drain(&mut w).await;
    assert!(c.synced, "the snapshot was closed by a bookmark");
    assert_eq!(
        c.state.keys().cloned().collect::<Vec<_>>(),
        vec!["y".to_owned()],
        "the consumer dropped x"
    );
    // Later changes are applied, every one, though they all say resume point 0.
    {
        let mut items = f.docs.items.lock().unwrap();
        items.insert(("key-plan".into(), "y".into()), b"plan-y2".to_vec());
        items.insert(("key-plan".into(), "z".into()), b"plan-z".to_vec());
    }
    f.docs.versions.lock().unwrap().insert("key-plan".into(), 3);
    c.drain(&mut w).await;
    assert_eq!(
        c.state.get("y").map(Vec::as_slice),
        Some(b"plan-y2".as_slice())
    );
    assert_eq!(
        c.state.get("z").map(Vec::as_slice),
        Some(b"plan-z".as_slice())
    );
}

// ---- a consumer that dedupes by the sequence ----

/// What a consumer of a watch holds, as the store API tells it to behave:
/// - a change of the log carries its sequence, and one at or below the sequence applied is a repeat (at-least-once);
///   a version is not an identity, because a re-created item starts again at 1;
/// - a config change has no sequence (resume point 0) and is applied, every one; a config watch begins with the full
///   snapshot, and the items before the first bookmark replace the state of the kind.
#[derive(Default)]
struct Consumer {
    state: std::collections::BTreeMap<String, Vec<u8>>,
    applied: u64,
    deletes: Vec<String>,
    /// The items of a config watch's opening snapshot, until its first bookmark.
    opening: std::collections::BTreeMap<String, Vec<u8>>,
    synced: bool,
}

impl Consumer {
    /// A consumer of a config kind, which begins with what a listing gave it.
    #[allow(dead_code)] // one of the two test files watches a config kind
    fn listed(state: std::collections::BTreeMap<String, Vec<u8>>) -> Self {
        Self {
            state,
            ..Self::default()
        }
    }

    fn apply(&mut self, m: &WatchResponse) {
        let config = m.resume_point == 0;
        if kind_of(m) == ChangeType::CHANGE_TYPE_BOOKMARK {
            // The first bookmark of a config watch closes its snapshot: it replaces the state of the kind.
            if config && !self.synced {
                self.state = std::mem::take(&mut self.opening);
                self.synced = true;
            }
            return;
        }
        if config {
            if !self.synced {
                if kind_of(m) == ChangeType::CHANGE_TYPE_PUT {
                    self.opening
                        .insert(id_of(m), m.item.as_option().unwrap().value.clone());
                }
                return;
            }
        } else {
            if m.resume_point <= self.applied {
                return;
            }
            self.applied = m.resume_point;
        }
        let id = id_of(m);
        if kind_of(m) == ChangeType::CHANGE_TYPE_DELETE {
            self.state.remove(&id);
            self.deletes.push(id);
        } else {
            self.state
                .insert(id, m.item.as_option().unwrap().value.clone());
        }
    }

    async fn drain(&mut self, w: &mut Watcher) {
        while let Some(Ok(m)) = w.next(Duration::from_millis(600)).await {
            self.apply(&m);
        }
    }
}

/// verifies: REQ-DATA-100
/// An item removed and made again starts at version 1 again, so a version is not an identity: the delete is delivered
/// and then the new put, whatever the batching, and a consumer that dedupes by the sequence ends with the new value.
#[tokio::test]
async fn a_delete_and_the_re_creation_that_follows_it_are_both_delivered() {
    let f = F::new().await;
    f.as_("key");
    let from = position(&f, TEMP).await;
    f.write(vec![write_temp(Verb::CREATE, "node-a/n1", b"old")], &[])
        .await
        .unwrap();
    f.write(vec![write_temp(Verb::DELETE, "node-a/n1", b"")], &[])
        .await
        .unwrap();
    f.write(vec![write_temp(Verb::CREATE, "node-a/n1", b"new")], &[])
        .await
        .unwrap();
    // The re-created item is at version 1, as the first was.
    assert_eq!(
        f.get(TEMP, "", "node-a/n1")
            .await
            .unwrap()
            .item
            .as_option()
            .unwrap()
            .version,
        1
    );
    let mut w = f.watch(TEMP, "", from).await.unwrap();
    let mut seen = Vec::new();
    while let Some(Ok(m)) = w.next(Duration::from_millis(600)).await {
        seen.push(m);
    }
    let types: Vec<_> = seen.iter().map(kind_of).collect();
    let delete = types
        .iter()
        .position(|t| *t == ChangeType::CHANGE_TYPE_DELETE);
    let last_put = types
        .iter()
        .rposition(|t| *t == ChangeType::CHANGE_TYPE_PUT);
    assert!(
        delete.is_some() && last_put > delete,
        "the delete, then the new put: {types:?}"
    );
    let mut c = Consumer::default();
    for m in &seen {
        c.apply(m);
    }
    assert_eq!(
        c.state.get("node-a/n1").map(Vec::as_slice),
        Some(b"new".as_slice())
    );
    // Each change carries the sequence of its row, and they only grow.
    assert!(
        seen.windows(2)
            .all(|p| p[0].resume_point < p[1].resume_point)
    );
}

/// verifies: REQ-DATA-100, REQ-DATA-101
/// An item that expired, was swept and was made again: the consumer sees the delete of the expiry and then the new
/// put, and ends with the new value.
#[tokio::test]
async fn expiry_then_re_creation_ends_with_the_new_value() {
    let f = F::new().await;
    f.as_("key");
    let from = position(&f, TEMP).await;
    f.write(
        vec![with_ttl(
            op(Verb::CREATE, TEMP, "", "node-a/x1", b"first"),
            30,
        )],
        &[],
    )
    .await
    .unwrap();
    f.advance(31);
    f.temp.sweep();
    f.write(
        vec![with_ttl(
            op(Verb::CREATE, TEMP, "", "node-a/x1", b"second"),
            600,
        )],
        &[],
    )
    .await
    .unwrap();
    let mut w = f.watch(TEMP, "", from).await.unwrap();
    let mut c = Consumer::default();
    c.drain(&mut w).await;
    assert_eq!(
        c.deletes,
        vec!["node-a/x1".to_owned()],
        "the expiry was delivered"
    );
    assert_eq!(
        c.state.get("node-a/x1").map(Vec::as_slice),
        Some(b"second".as_slice())
    );
}
