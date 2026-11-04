//! The key set: the kind `SigningRing`, one item `default` per boundary (PLAN.md D-17), that
//! `signer` writes and `entry` and exporter@ read (kinds.yaml).
//!
//! # Nodes and keys
//!
//! Every board has a token-signing key of its own in its card, and the boards share one ring, so the
//! ring holds one `active` key per node (ADR 0006 "The token-signing key": the key set carries every
//! active token key). Each key names its node, and a `signer` changes the keys of its own node
//! only: it never promotes, retires or reactivates another node's key. A node that rotates its key
//! therefore cannot make the other boards' keys stop, and two boards never undo each other.
//!
//! # The states of a key
//!
//! A key moves one way, `pre-published`, then `active`, then `retiring`, then it is dropped
//! (ADR 0006 "Rotation": the new key first, the old one after; ADR 0017 "Issuers"). A retiring
//! key never signs again:
//!
//! - **`pre-published`**: in the key set, not signing. A verifier that caches the key set learns the
//!   key before the first token is signed with it, which is the lesson of v1 (SLU-290: a verifier
//!   may hold a key set for a long time and does not refetch on an unknown `kid`; v1.80.2 publishes a
//!   key for 12 hours before it signs). A key becomes `active` after [`Timing::prepublish`].
//! - **`active`**: the key that signs. `signer` signs only when the key key@ signs with is `active`.
//! - **`retiring`**: stopped signing, still in the key set until every token it signed has expired:
//!   the longest token lifetime plus the clock skew (REQ-KEYS-007). Any instance then drops it.
//!
//! A node's first key is `active` at once while the ring is young: when no key of the ring is older
//! than [`Timing::bootstrap`]. The boards of a first deploy start within minutes of each other, no
//! verifier has seen a token yet, and holding every board's first token back for the window would
//! stop the installation from starting. A node that joins later, or a key that replaces another,
//! is published for the full window first.
//!
//! # How it is written
//!
//! The ring is created once (`create`: it fails if another instance did it first) and every later
//! change is an `update` at the version that was read, so two instances of `signer` never overwrite
//! each other: the one that loses re-reads and plans again. Each change is an audit fact.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use buffa_types::google::protobuf::Timestamp;
use sluis_kit::Client;
use sluis_proto::sluis::signer::v2alpha1::{SigningKey, SigningRing};
use sluis_store::{Error as StoreError, Kind, Store, WriteOpts};
use tokio::sync::Mutex;

use crate::audit::Auditor;
use crate::claims::HARD_CAP_SECS;
use crate::keys::{ALGORITHM, Current, KeyAt, KeyError};
use crate::service::Clock;

/// The state of a key that is in the key set and does not sign yet.
pub const PRE_PUBLISHED: &str = "pre-published";
/// The state of the key that signs.
pub const ACTIVE: &str = "active";
/// The state of a key that stopped signing and stays in the key set.
pub const RETIRING: &str = "retiring";

/// The singleton id of the ring (PLAN.md D-17).
const ID: &str = "default";
/// How long a snapshot of the ring is used before `signer` looks again.
const REFRESH: Duration = Duration::from_secs(10);
/// How long one call to store@ may take.
const CALL: Duration = Duration::from_secs(5);
/// How many times a lost race is retried before the attempt is given up.
const ATTEMPTS: usize = 3;

struct RingKind;
impl Kind for RingKind {
    type Id = &'static str;
    type Value = SigningRing;
    const NAME: &'static str = "SigningRing";
}

/// How long a key is published before it signs, and after it stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Timing {
    /// A new key is published this long before it signs. v1.80.2 uses 12 hours (SLU-290).
    pub prepublish: Duration,
    /// A key that stopped signing stays published this long: the longest token lifetime of one hour
    /// (ADR 0020 "Lifetimes") plus five minutes of clock skew (REQ-KEYS-007).
    pub retain: Duration,
    /// A node's first key signs at once while no key of the ring is older than this: the boards of
    /// a first deploy.
    pub bootstrap: Duration,
}

impl Timing {
    /// The values of v1, kept so that a relying party tuned to them keeps working.
    pub const DEFAULT: Self = Self {
        prepublish: Duration::from_secs(12 * 3600),
        retain: Duration::from_secs(HARD_CAP_SECS.unsigned_abs() + 5 * 60),
        bootstrap: Duration::from_secs(15 * 60),
    };
}

/// One change to the ring, for the audit log and for the tests.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Change {
    /// The key.
    pub key_id: String,
    /// What happened.
    pub kind: ChangeKind,
}

/// What happened to a key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChangeKind {
    /// The key joined the ring in the given state.
    Added(&'static str),
    /// The key became `active`.
    Activated,
    /// The key stopped signing.
    Retired,
    /// The key left the ring.
    Dropped,
}

fn stamp(t: SystemTime) -> Timestamp {
    let d = t.duration_since(UNIX_EPOCH).unwrap_or_default();
    Timestamp {
        seconds: i64::try_from(d.as_secs()).unwrap_or(i64::MAX),
        nanos: i32::try_from(d.subsec_nanos()).unwrap_or(0),
        ..Timestamp::default()
    }
}

fn instant(t: Option<&Timestamp>) -> Option<SystemTime> {
    let t = t?;
    let secs = u64::try_from(t.seconds).ok()?;
    Some(UNIX_EPOCH + Duration::new(secs, u32::try_from(t.nanos).unwrap_or(0)))
}

/// When the key entered its state. A key without the stamp counts from when it joined, and one with
/// neither counts from now, so that a missing stamp never drops a key early.
fn since(k: &SigningKey, now: SystemTime) -> SystemTime {
    instant(k.state_since.as_option())
        .or_else(|| instant(k.added_at.as_option()))
        .unwrap_or(now)
}

fn enter(k: &mut SigningKey, state: &str, now: SystemTime) {
    k.state = state.to_owned();
    k.state_since = stamp(now).into();
}

/// Plans the next ring from the ring as it is, the key key@ signs with, the node it belongs to, and
/// the clock. Nothing is written here. The ring is unchanged when the list of changes is empty.
///
/// Only the keys of `node` are changed, apart from the drop of any key that has been retiring for
/// the retention.
#[must_use]
pub fn plan(
    ring: &SigningRing,
    cur: &Current,
    node: &str,
    now: SystemTime,
    t: &Timing,
) -> (SigningRing, Vec<Change>) {
    let mut keys = ring.keys.clone();
    let mut changes = Vec::new();
    let change = |k: &str, kind| Change {
        key_id: k.to_owned(),
        kind,
    };

    match keys.iter().position(|k| k.key_id == cur.key_id) {
        None => {
            // A node's first key signs at once while the ring is young (the first deploy); every other
            // key is published for the full window first.
            let first_of_node = !keys.iter().any(|k| k.node == node);
            // A key of unknown age counts as old: it never makes the ring young.
            let young = keys
                .iter()
                .all(|k| instant(k.added_at.as_option()).is_some_and(|at| now < at + t.bootstrap));
            let state = if first_of_node && young {
                ACTIVE
            } else {
                PRE_PUBLISHED
            };
            keys.push(SigningKey {
                key_id: cur.key_id.clone(),
                algorithm: ALGORITHM.to_owned(),
                spki_der: cur.spki_der.clone(),
                x5c: cur.x5c.clone(),
                added_at: stamp(now).into(),
                state: state.to_owned(),
                state_since: stamp(now).into(),
                node: node.to_owned(),
                ..SigningKey::default()
            });
            changes.push(change(&cur.key_id, ChangeKind::Added(state)));
        }
        Some(i) => {
            let k = &mut keys[i];
            // Only the node's own key, and only a key that was published for the whole window. A
            // retiring key does not come back, and another node's key is not ours to promote.
            if k.node == node && k.state == PRE_PUBLISHED && now >= since(k, now) + t.prepublish {
                enter(k, ACTIVE, now);
                changes.push(change(&cur.key_id, ChangeKind::Activated));
            }
        }
    }

    // Once the key key@ signs with is active, the node's earlier keys stop. The keys of other nodes
    // are theirs: their signers retire them.
    if keys
        .iter()
        .any(|k| k.key_id == cur.key_id && k.node == node && k.state == ACTIVE)
    {
        for k in keys.iter_mut().filter(|k| {
            k.node == node
                && k.key_id != cur.key_id
                && (k.state == ACTIVE || k.state == PRE_PUBLISHED)
        }) {
            enter(k, RETIRING, now);
            changes.push(change(&k.key_id.clone(), ChangeKind::Retired));
        }
    }

    keys.retain(|k| {
        let gone = k.state == RETIRING && now >= since(k, now) + t.retain;
        if gone {
            changes.push(change(&k.key_id, ChangeKind::Dropped));
        }
        !gone
    });

    (
        SigningRing {
            keys,
            ..ring.clone()
        },
        changes,
    )
}

/// Why `signer` has no key to sign with.
#[derive(Debug)]
pub enum RingError {
    /// store@ cannot be reached, or the ring could not be written after the attempts.
    Store,
    /// key@ gave no usable key.
    Key(KeyError),
    /// The key that key@ signs with is not an active key of the ring: it is still being published
    /// (or it is not one of the states that sign).
    NotActive,
}

/// What `signer` knows of the ring a moment ago.
#[derive(Clone)]
struct Snapshot {
    at: SystemTime,
    current: Current,
    active: bool,
}

/// The manager of the ring: reads it, plans, writes with the version guard, and says which key may
/// sign.
pub struct RingKeeper {
    store: Store<RingKind>,
    key: Arc<KeyAt>,
    audit: Arc<Auditor>,
    clock: Clock,
    timing: Timing,
    node: String,
    snapshot: Mutex<Option<Snapshot>>,
}

impl RingKeeper {
    /// A keeper over store@'s socket.
    ///
    /// # Errors
    ///
    /// When the kind is not in the registry.
    pub fn new(
        store: &Client,
        key: Arc<KeyAt>,
        audit: Arc<Auditor>,
        clock: Clock,
        timing: Timing,
        node: String,
    ) -> Result<Self, StoreError> {
        Ok(Self {
            store: Store::new(store.clone())?,
            key,
            audit,
            clock,
            timing,
            node,
            snapshot: Mutex::new(None),
        })
    }

    /// The key key@ signs with, once it is an active key of the ring. The ring is looked at again
    /// when the last look is older than ten seconds, so a key that was retired or promoted is
    /// noticed within that time.
    ///
    /// # Errors
    ///
    /// [`RingError`]; `signer` signs nothing then.
    pub async fn signing_key(&self) -> Result<Current, RingError> {
        let mut guard = self.snapshot.lock().await;
        let now = (self.clock)();
        let fresh = guard
            .as_ref()
            .filter(|s| now.duration_since(s.at).is_ok_and(|age| age < REFRESH));
        let snap = match fresh {
            Some(s) => s.clone(),
            None => {
                let s = self.reconcile_locked().await?;
                *guard = Some(s.clone());
                s
            }
        };
        if snap.active {
            Ok(snap.current)
        } else {
            Err(RingError::NotActive)
        }
    }

    /// Brings the ring in line with key@'s key and the clock, now. The loop of the service calls it,
    /// so a boundary with no traffic still promotes and drops keys on time.
    ///
    /// # Errors
    ///
    /// [`RingError`].
    pub async fn reconcile(&self) -> Result<(), RingError> {
        let mut guard = self.snapshot.lock().await;
        *guard = Some(self.reconcile_locked().await?);
        Ok(())
    }

    /// The ring as store@ holds it (empty when none was written).
    ///
    /// # Errors
    ///
    /// [`RingError::Store`].
    pub async fn read(&self) -> Result<SigningRing, RingError> {
        match tokio::time::timeout(CALL, self.store.get("", ID)).await {
            Ok(Ok(item)) => Ok(item.value),
            Ok(Err(StoreError::NotFound)) => Ok(SigningRing::default()),
            _ => Err(RingError::Store),
        }
    }

    async fn reconcile_locked(&self) -> Result<Snapshot, RingError> {
        for _ in 0..ATTEMPTS {
            let cur = self.key.current().await.map_err(RingError::Key)?;
            let (ring, version) = match tokio::time::timeout(CALL, self.store.get("", ID)).await {
                Ok(Ok(item)) => (item.value, item.version),
                Ok(Err(StoreError::NotFound)) => (SigningRing::default(), 0),
                _ => return Err(RingError::Store),
            };
            let now = (self.clock)();
            let (next, changes) = plan(&ring, &cur, &self.node, now, &self.timing);
            if changes.is_empty() {
                return Ok(snapshot(&ring, cur, now));
            }
            let written = if version == 0 {
                self.store.create("", ID, &next, WriteOpts::default()).await
            } else {
                self.store
                    .update("", ID, &next, version, WriteOpts::default())
                    .await
            };
            match written {
                Ok(_) => {
                    for c in &changes {
                        // The ring is public material and key@ audits every signature, so a fact
                        // the log could not take is logged and counted, and the change stays.
                        if self.audit.ring(c).await.is_err() {
                            tracing::error!(key_id = %c.key_id, "the audit of a change of the ring failed");
                        }
                    }
                    return Ok(snapshot(&next, cur, now));
                }
                // Another instance wrote first: read again and plan again.
                Err(StoreError::Exists | StoreError::Version) => {}
                Err(_) => return Err(RingError::Store),
            }
        }
        Err(RingError::Store)
    }
}

fn snapshot(ring: &SigningRing, current: Current, at: SystemTime) -> Snapshot {
    let active = ring
        .keys
        .iter()
        .any(|k| k.key_id == current.key_id && k.state == ACTIVE);
    Snapshot {
        at,
        current,
        active,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIN: u64 = 60;
    const HOUR: u64 = 3600;
    const WINDOW: u64 = 12 * HOUR;
    const A: &str = "node-a";
    const B: &str = "node-b";

    fn at(secs: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(secs)
    }
    fn cur(id: &str) -> Current {
        Current {
            key_id: id.into(),
            spki_der: vec![1, 2, 3],
            x5c: vec![],
        }
    }
    fn states(r: &SigningRing) -> Vec<(&str, &str)> {
        r.keys
            .iter()
            .map(|k| (k.key_id.as_str(), k.state.as_str()))
            .collect()
    }
    fn added(id: &str, kind: ChangeKind) -> Change {
        Change {
            key_id: id.into(),
            kind,
        }
    }
    const T: Timing = Timing::DEFAULT;

    /// Runs `signer` of `node`, whose key@ signs with `id`, at `secs`, and returns the ring.
    fn step(ring: &SigningRing, node: &str, id: &str, secs: u64) -> (SigningRing, Vec<Change>) {
        plan(ring, &cur(id), node, at(secs), &T)
    }

    #[test]
    fn the_window_is_the_twelve_hours_of_v1() {
        assert_eq!(T.prepublish, Duration::from_secs(12 * HOUR));
        assert_eq!(T.retain, Duration::from_secs(65 * MIN));
    }

    #[test]
    fn the_first_key_of_a_boundary_is_active_at_once_and_names_its_node() {
        let (r, ch) = step(&SigningRing::default(), A, "a", 1000);
        assert_eq!(states(&r), [("a", ACTIVE)]);
        assert_eq!(ch, [added("a", ChangeKind::Added(ACTIVE))]);
        assert_eq!(r.keys[0].algorithm, "ES384");
        assert_eq!(r.keys[0].spki_der, [1, 2, 3]);
        assert_eq!(r.keys[0].node, A);
    }

    #[test]
    fn the_boards_of_a_first_deploy_each_activate_their_first_key_at_once() {
        let (r, _) = step(&SigningRing::default(), A, "a", 1000);
        let (r, _) = step(&r, B, "b", 1000 + 5 * MIN);
        let (r, _) = step(&r, "node-c", "c", 1000 + 14 * MIN);
        assert_eq!(states(&r), [("a", ACTIVE), ("b", ACTIVE), ("c", ACTIVE)]);
    }

    #[test]
    fn a_board_that_joins_after_the_first_deploy_is_published_for_the_full_window() {
        let (r, _) = step(&SigningRing::default(), A, "a", 1000);
        let (r, ch) = step(&r, B, "b", 1000 + 15 * MIN);
        assert_eq!(states(&r), [("a", ACTIVE), ("b", PRE_PUBLISHED)]);
        assert_eq!(ch, [added("b", ChangeKind::Added(PRE_PUBLISHED))]);
        let joined = 1000 + 15 * MIN;
        let (r2, ch) = step(&r, B, "b", joined + WINDOW - 1);
        assert!(ch.is_empty());
        assert_eq!(r2, r);
        let (r3, ch) = step(&r, B, "b", joined + WINDOW);
        assert_eq!(states(&r3), [("a", ACTIVE), ("b", ACTIVE)]);
        assert_eq!(ch, [added("b", ChangeKind::Activated)]);
    }

    #[test]
    fn nothing_changes_when_nothing_is_due() {
        let (r, _) = step(&SigningRing::default(), A, "a", 1000);
        let (r2, ch) = step(&r, A, "a", 1000 + 30 * HOUR);
        assert!(ch.is_empty());
        assert_eq!(r2, r);
    }

    #[test]
    fn a_new_key_of_a_node_is_published_for_the_window_before_it_signs() {
        let (r, _) = step(&SigningRing::default(), A, "a", 1000);
        // Even in the first minutes: a replacement key is never a first key.
        let (r, ch) = step(&r, A, "a2", 2000);
        assert_eq!(states(&r), [("a", ACTIVE), ("a2", PRE_PUBLISHED)]);
        assert_eq!(ch.len(), 1);
        let (r2, ch) = step(&r, A, "a2", 2000 + WINDOW - 1);
        assert!(ch.is_empty());
        assert_eq!(r2, r);
        // At the window: it signs, and the node's old key stops.
        let (r3, ch) = step(&r, A, "a2", 2000 + WINDOW);
        assert_eq!(states(&r3), [("a", RETIRING), ("a2", ACTIVE)]);
        assert_eq!(
            ch,
            [
                added("a2", ChangeKind::Activated),
                added("a", ChangeKind::Retired)
            ]
        );
    }

    #[test]
    fn a_retired_key_stays_for_a_token_lifetime_plus_the_skew_and_then_leaves() {
        let (r, _) = step(&SigningRing::default(), A, "a", 1000);
        let (r, _) = step(&r, A, "a2", 2000);
        let retired_at = 2000 + WINDOW;
        let (r, _) = step(&r, A, "a2", retired_at);
        let keep = 65 * MIN;
        let (r2, ch) = step(&r, A, "a2", retired_at + keep - 1);
        assert!(ch.is_empty(), "a token it signed may still be valid");
        assert_eq!(states(&r2), [("a", RETIRING), ("a2", ACTIVE)]);
        let (r3, ch) = step(&r, A, "a2", retired_at + keep);
        assert_eq!(states(&r3), [("a2", ACTIVE)]);
        assert_eq!(ch, [added("a", ChangeKind::Dropped)]);
    }

    #[test]
    fn a_retiring_key_never_signs_again() {
        let (r, _) = step(&SigningRing::default(), A, "a", 1000);
        let (r, _) = step(&r, A, "a2", 2000);
        let (r, _) = step(&r, A, "a2", 2000 + WINDOW);
        // key@ goes back to a, which is retiring: it stays retiring, and nothing else changes.
        let (r2, ch) = step(&r, A, "a", 2000 + WINDOW + MIN);
        assert!(ch.is_empty());
        assert_eq!(states(&r2), [("a", RETIRING), ("a2", ACTIVE)]);
    }

    #[test]
    fn a_node_never_changes_the_key_of_another_node() {
        // Both boards have a key; B rotates. A's signer, running at every moment, changes nothing.
        let (r, _) = step(&SigningRing::default(), A, "a", 1000);
        let (r, _) = step(&r, B, "b", 1000);
        let (r, _) = step(&r, B, "b2", 2 * HOUR);
        assert_eq!(
            states(&r),
            [("a", ACTIVE), ("b", ACTIVE), ("b2", PRE_PUBLISHED)]
        );
        for t in [2 * HOUR + 1, 2 * HOUR + WINDOW / 2, 2 * HOUR + WINDOW - 1] {
            let (r2, ch) = step(&r, A, "a", t);
            assert!(ch.is_empty(), "A changed something at {t}: {ch:?}");
            assert_eq!(r2, r);
        }
        // A's signer does not promote B's key even when it is due, and B's does not retire A's.
        let due = 2 * HOUR + WINDOW;
        let (r2, ch) = step(&r, A, "a", due);
        assert!(ch.is_empty());
        assert_eq!(r2, r);
        let (r3, _) = step(&r, B, "b2", due);
        assert_eq!(
            states(&r3),
            [("a", ACTIVE), ("b", RETIRING), ("b2", ACTIVE)]
        );
    }

    #[test]
    fn two_boards_with_one_ring_do_not_flap() {
        // 90 hours of both signers looking every 30 seconds, as the loop does, with B rotating once
        // in the middle: every change is one that its own node makes, and no key goes back.
        let (mut r, _) = step(&SigningRing::default(), A, "a", 0);
        (r, _) = step(&r, B, "b", 0);
        let mut b_key = "b";
        let mut seen: Vec<(String, String)> = Vec::new();
        let mut t = 0;
        while t < 90 * HOUR {
            if t == 30 * HOUR {
                b_key = "b2";
            }
            for (node, key) in [(A, "a"), (B, b_key)] {
                let (next, ch) = step(&r, node, key, t);
                for c in &ch {
                    seen.push((c.key_id.clone(), format!("{:?}", c.kind)));
                    let owner = next
                        .keys
                        .iter()
                        .find(|k| k.key_id == c.key_id)
                        .map(|k| k.node.clone());
                    // A change is made by the node that owns the key, except the drop of a retiring key.
                    if c.kind != ChangeKind::Dropped {
                        assert_eq!(owner.as_deref(), Some(node), "{node} changed {}", c.key_id);
                    }
                }
                r = next;
            }
            t += 30 * 60; // a coarser step than the loop's 30 seconds; the plan has no state of its own
        }
        let log: Vec<_> = seen.iter().map(|(k, c)| format!("{k}:{c}")).collect();
        assert_eq!(
            log,
            [
                "b2:Added(\"pre-published\")",
                "b2:Activated",
                "b:Retired",
                "b:Dropped"
            ]
        );
        assert_eq!(states(&r), [("a", ACTIVE), ("b2", ACTIVE)]);
    }

    #[test]
    fn a_pre_published_key_that_key_never_signs_with_retires_and_leaves() {
        let (r, _) = step(&SigningRing::default(), A, "a", 1000);
        let (r, _) = step(&r, A, "a2", 2000);
        // a2 was replaced by a3 before its window: a3 is published, a2 never signs.
        let (r, _) = step(&r, A, "a3", 3000);
        assert_eq!(
            states(&r),
            [("a", ACTIVE), ("a2", PRE_PUBLISHED), ("a3", PRE_PUBLISHED)]
        );
        let (r, ch) = step(&r, A, "a3", 3000 + WINDOW);
        assert_eq!(
            states(&r),
            [("a", RETIRING), ("a2", RETIRING), ("a3", ACTIVE)]
        );
        assert_eq!(ch.len(), 3);
        let (r, ch) = step(&r, A, "a3", 3000 + WINDOW + 65 * MIN);
        assert_eq!(states(&r), [("a3", ACTIVE)]);
        assert_eq!(ch.len(), 2);
    }

    #[test]
    fn a_key_with_no_stamp_is_never_dropped_early_and_a_foreign_state_is_left_alone() {
        let ring = SigningRing {
            keys: vec![
                SigningKey {
                    key_id: "old".into(),
                    state: RETIRING.into(),
                    ..SigningKey::default()
                },
                SigningKey {
                    key_id: "odd".into(),
                    state: "revoked".into(),
                    ..SigningKey::default()
                },
            ],
            ..SigningRing::default()
        };
        let (r, ch) = step(&ring, A, "a", 10_000_000);
        // a joins pre-published (the ring was not young: no key has a stamp, so none counts as old,
        // and the node has no key yet); "old" counts from now and stays; "odd" is untouched.
        assert_eq!(r.keys.len(), 3);
        assert_eq!(r.keys[2].state, PRE_PUBLISHED);
        assert_eq!(r.keys[0].state, RETIRING);
        assert_eq!(r.keys[1].state, "revoked");
        assert_eq!(ch.len(), 1);
    }
}
