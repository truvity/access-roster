//! The key set: the kind `SigningRing`, one item `default` per boundary (PLAN.md D-17), that
//! `signer` writes and `entry` and exporter@ read (kinds.yaml).
//!
//! # The states of a key
//!
//! A key moves one way, `pre-published`, then `active`, then `retiring`, then it is dropped
//! (ADR 0006 "Rotation": the new key first, the old one after; ADR 0017 "Issuers"):
//!
//! - **`pre-published`**: in the key set, not signing. A verifier that caches the key set learns the
//!   key before the first token is signed with it, which is the lesson of v1 (SLU-290: Envoy's
//!   `jwt_authn` caches a key set for 10 minutes and does not refetch on an unknown `kid`). A key
//!   becomes `active` after [`Timing::prepublish`].
//! - **`active`**: the key that signs. `signer` signs only when the key key@ signs with is `active`.
//! - **`retiring`**: stopped signing, still in the key set until every token it signed has expired:
//!   the longest token lifetime plus the clock skew (REQ-KEYS-007). Then it is dropped.
//!
//! The first key of a boundary is `active` at once: there is no earlier key set for a verifier to
//! have cached, and nothing else could sign.
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
    /// A new key is published this long before it signs. v1 used 15 minutes, more than the 10 minutes
    /// a verifier may cache a key set for.
    pub prepublish: Duration,
    /// A key that stopped signing stays published this long: the longest token lifetime of one hour
    /// (ADR 0020 "Lifetimes") plus five minutes of clock skew (REQ-KEYS-007).
    pub retain: Duration,
}

impl Timing {
    /// The values of v1, kept so that a relying party tuned to them keeps working.
    pub const DEFAULT: Self = Self {
        prepublish: Duration::from_secs(15 * 60),
        retain: Duration::from_secs(HARD_CAP_SECS.unsigned_abs() + 5 * 60),
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

/// Plans the next ring from the ring as it is, the key key@ signs with, and the clock. Nothing
/// is written here. The ring is unchanged when the list of changes is empty.
#[must_use]
pub fn plan(
    ring: &SigningRing,
    cur: &Current,
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
            let state = if keys.is_empty() {
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
                ..SigningKey::default()
            });
            changes.push(change(&cur.key_id, ChangeKind::Added(state)));
        }
        Some(i) => {
            let k = &mut keys[i];
            // Published long enough, or published all along and called back (a key that was
            // retiring has been in the key set for longer than the window).
            let due = k.state == PRE_PUBLISHED && now >= since(k, now) + t.prepublish;
            if due || k.state == RETIRING {
                enter(k, ACTIVE, now);
                changes.push(change(&cur.key_id, ChangeKind::Activated));
            }
        }
    }

    // The key key@ signs with is the only one that signs: once it is active the others stop.
    if keys
        .iter()
        .any(|k| k.key_id == cur.key_id && k.state == ACTIVE)
    {
        for k in keys
            .iter_mut()
            .filter(|k| k.key_id != cur.key_id && (k.state == ACTIVE || k.state == PRE_PUBLISHED))
        {
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
    ) -> Result<Self, StoreError> {
        Ok(Self {
            store: Store::new(store.clone())?,
            key,
            audit,
            clock,
            timing,
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
            let (next, changes) = plan(&ring, &cur, now, &self.timing);
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
    const T: Timing = Timing::DEFAULT;

    #[test]
    fn the_first_key_of_a_boundary_is_active_at_once() {
        let (r, ch) = plan(&SigningRing::default(), &cur("a"), at(1000), &T);
        assert_eq!(states(&r), [("a", ACTIVE)]);
        assert_eq!(
            ch,
            [Change {
                key_id: "a".into(),
                kind: ChangeKind::Added(ACTIVE)
            }]
        );
        assert_eq!(r.keys[0].algorithm, "ES384");
        assert_eq!(r.keys[0].spki_der, [1, 2, 3]);
    }

    #[test]
    fn nothing_changes_when_nothing_is_due() {
        let (r, _) = plan(&SigningRing::default(), &cur("a"), at(1000), &T);
        let (r2, ch) = plan(&r, &cur("a"), at(1000 + 3 * 3600), &T);
        assert!(ch.is_empty());
        assert_eq!(r2, r);
    }

    #[test]
    fn a_new_key_is_published_for_the_window_before_it_signs() {
        let (r, _) = plan(&SigningRing::default(), &cur("a"), at(1000), &T);
        let (r, ch) = plan(&r, &cur("b"), at(2000), &T);
        assert_eq!(states(&r), [("a", ACTIVE), ("b", PRE_PUBLISHED)]);
        assert_eq!(ch.len(), 1);
        // One second short of the window: still not signing.
        let almost = 2000 + 15 * MIN - 1;
        let (r2, ch) = plan(&r, &cur("b"), at(almost), &T);
        assert!(ch.is_empty());
        assert_eq!(r2, r);
        // At the window: it signs, and the old key stops.
        let (r3, ch) = plan(&r, &cur("b"), at(2000 + 15 * MIN), &T);
        assert_eq!(states(&r3), [("a", RETIRING), ("b", ACTIVE)]);
        assert_eq!(
            ch,
            [
                Change {
                    key_id: "b".into(),
                    kind: ChangeKind::Activated
                },
                Change {
                    key_id: "a".into(),
                    kind: ChangeKind::Retired
                },
            ]
        );
    }

    #[test]
    fn a_retired_key_stays_for_a_token_lifetime_plus_the_skew_and_then_leaves() {
        let (r, _) = plan(&SigningRing::default(), &cur("a"), at(1000), &T);
        let (r, _) = plan(&r, &cur("b"), at(2000), &T);
        let retired_at = 2000 + 15 * MIN;
        let (r, _) = plan(&r, &cur("b"), at(retired_at), &T);
        let keep = 65 * MIN;
        let (r2, ch) = plan(&r, &cur("b"), at(retired_at + keep - 1), &T);
        assert!(ch.is_empty(), "a token it signed may still be valid");
        assert_eq!(states(&r2), [("a", RETIRING), ("b", ACTIVE)]);
        let (r3, ch) = plan(&r, &cur("b"), at(retired_at + keep), &T);
        assert_eq!(states(&r3), [("b", ACTIVE)]);
        assert_eq!(
            ch,
            [Change {
                key_id: "a".into(),
                kind: ChangeKind::Dropped
            }]
        );
    }

    #[test]
    fn a_key_called_back_is_active_again_and_the_other_stops() {
        let (r, _) = plan(&SigningRing::default(), &cur("a"), at(1000), &T);
        let (r, _) = plan(&r, &cur("b"), at(2000), &T);
        let (r, _) = plan(&r, &cur("b"), at(2000 + 15 * MIN), &T);
        // key@ goes back to a, which is retiring: it has been published all along.
        let (r, ch) = plan(&r, &cur("a"), at(2000 + 16 * MIN), &T);
        assert_eq!(states(&r), [("a", ACTIVE), ("b", RETIRING)]);
        assert_eq!(ch.len(), 2);
    }

    #[test]
    fn a_pre_published_key_that_key_never_signs_with_retires_and_leaves() {
        let (r, _) = plan(&SigningRing::default(), &cur("a"), at(1000), &T);
        let (r, _) = plan(&r, &cur("b"), at(2000), &T);
        // key@ went back to a before b was due: b never signed, and a is still active.
        let (r, ch) = plan(&r, &cur("a"), at(2000 + 5 * MIN), &T);
        assert_eq!(states(&r), [("a", ACTIVE), ("b", RETIRING)]);
        assert_eq!(
            ch,
            [Change {
                key_id: "b".into(),
                kind: ChangeKind::Retired
            }]
        );
        let (r, ch) = plan(&r, &cur("a"), at(2000 + 5 * MIN + 65 * MIN), &T);
        assert_eq!(states(&r), [("a", ACTIVE)]);
        assert_eq!(ch.len(), 1);
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
        let (r, ch) = plan(&ring, &cur("a"), at(10_000_000), &T);
        // a joins pre-published (the ring was not empty); "old" counts from now and stays; "odd" is untouched.
        assert_eq!(
            states(&r),
            [("old", RETIRING), ("odd", "revoked"), ("a", PRE_PUBLISHED)]
        );
        assert_eq!(ch.len(), 1);
    }
}
