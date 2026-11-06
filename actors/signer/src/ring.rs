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
//! - **`pre-published`**: in the key set, not signing. Every cache between sluis and a verifier learns
//!   the key before the first token is signed with it. The lead time, [`Timing::prepublish`], is
//!   derived from the cache budget that sluis publishes (ADR 0006 "Rotation"): the key set's
//!   `max-age` of 300 s, the edge cache's time to live of at most as much, 10 minutes for a
//!   verifier's throttled refetch on an unknown `kid` (OpenID Connect Core section 10.1.1) and
//!   5 minutes of clock skew, 25 minutes, rounded up to 30. A verifier that keeps the set longer than
//!   `max-age` and does not refetch on an unknown `kid` is broken; v1 published a key for 12 hours
//!   because of one, and v2 detects such a verifier instead. A key becomes `active` after the lead time.
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
//! A key also signs at once when the issuer has no other key that signs: no `active` key of the ring
//! that `KeyRevocation` does not list (see "A replacement for a revoked key"). Waiting would stop
//! every sign-in for the whole lead time, and there is no cached key for a verifier to rely on.
//!
//! # A revoked key
//!
//! `revoked` is a fourth state, and a key is in it when `KeyRevocation` lists its kid (ADR 0041, "The
//! tighten-only record"): the item is the state, so `signer` writes nothing for it. A revoked key is never
//! added, promoted or signed with here (REQ-KEYS-106), and it is not in the key set that `signer`
//! answers with (REQ-KEYS-107). `signer` reads `KeyRevocation` at every call that needs it, and a
//! `KeyRevocation` that cannot be read refuses the call.
//!
//! # A replacement for a revoked key
//!
//! A replacement signs soon, not after the lead time, when the issuer has no live key that signs (ADR
//! 0041, "The replacement", REQ-KEYS-089). The issuer is the boundary, so the keys of every node
//! count: while any node still has a key that signs and that `KeyRevocation` does not list, verifiers
//! know it and see no unfamiliar `kid`, and a replacement is published for the full window like any
//! other new key. A key signs when it is `active`; one in a state this code does not know counts as
//! possibly signing (a rolling upgrade or downgrade must not skip the window), and only `retiring`
//! and `pre-published` keys, and revoked ones, count as not signing. So a normal rotation (the old key
//! is `active`) and a revoked spare never skip the window; in practice the shortcut is the case where
//! every `active` key is revoked. A revoked key itself never gets the shortcut (REQ-KEYS-106). The
//! change is an audit fact with the reason [`NO_ACTIVE_KEY`].
//!
//! What holds when the shortcut is taken: the new key is written to the ring, which `signer` and
//! `entry` build `/jwks` from, before `signer` answers for it, but `entry` keeps its built key set for
//! [`KEY_SET_CACHE`] (`entry` is separate and cannot be told to rebuild). So when the ring holds a
//! revoked entry, `signer` signs with an `active` key only from [`KEY_SET_HOLD`] (that time and a
//! second of margin) after the key joined the ring, and refuses the call as "not yet" until then. The
//! hold is read from the ring (`added_at`), so a restart does not lose it. After the hold, a key set
//! that `entry` serves lists the new key. A relying party may still hold a copy of `/jwks` from before
//! for the key set's `max-age` (300 s) plus the edge copy, which `exporter@` is to purge (REQ-KEYS-088;
//! not built): it must fetch the key set again on an unfamiliar `kid` (OpenID Connect Core 1.0,
//! section 10.1.1), and one that does not is broken, not accommodated (ADR 0041).
//!
//! A revoked key stays in the ring in the state it had, and every reader filters it by
//! `KeyRevocation` (`without_revoked`); nothing removes it yet (a garbage-collection follow-up).
//!
//! # How it is written
//!
//! The ring is created once (`create`: it fails if another instance did it first) and every later
//! change is an `update` at the version that was read, so two instances of `signer` never overwrite
//! each other: the one that loses re-reads and plans again. Each change is an audit fact.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use buffa_types::google::protobuf::Timestamp;
use sluis_kit::Client;
use sluis_proto::sluis::signer::v2alpha1::{SigningKey, SigningRing};
use sluis_store::KEY_SET_CACHE;
use sluis_store::revocation::{KeyRevocations, without_revoked};
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

/// The reason of a change that skips the lead time because no key of the issuer signs (REQ-KEYS-089),
/// in the audit fact.
pub const NO_ACTIVE_KEY: &str = "no_active_key";
/// How long after a key joined the ring `signer` waits to sign with it when the ring holds a revoked
/// key: `entry` keeps its built key set for [`KEY_SET_CACHE`], and a second more for the clocks of
/// two hosts and a read in flight.
pub const KEY_SET_HOLD: Duration = KEY_SET_CACHE.saturating_add(Duration::from_secs(1));

/// The singleton id of the ring (PLAN.md D-17).
const ID: &str = "default";
/// How long a snapshot of the ring is used before `signer` looks again.
const REFRESH: Duration = Duration::from_secs(10);
/// How long one call to store@ may take.
const CALL: Duration = Duration::from_secs(5);
/// How many times a lost race is retried before the attempt is given up.
const ATTEMPTS: usize = 3;

/// The ring keeps a revoked key in the state it had: `signer` writes nothing for a revoked key (the item
/// of `KeyRevocation` is its state), so every reader of the kind filters by `KeyRevocation`
/// (`without_revoked`). Nothing removes a revoked entry yet (a garbage-collection follow-up).
struct RingKind;
impl Kind for RingKind {
    type Id = &'static str;
    type Value = SigningRing;
    const NAME: &'static str = "SigningRing";
}

/// How long a key is published before it signs, and after it stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Timing {
    /// A new key is published this long before it signs: the key set's `max-age` (300 s), the edge
    /// time to live (at most 300 s), a verifier's throttled refetch (10 minutes) and clock skew
    /// (5 minutes), rounded up to 30 minutes (ADR 0006 "Rotation", REQ-KEYS-076).
    pub prepublish: Duration,
    /// A key that stopped signing stays published this long: the longest token lifetime of one hour
    /// (ADR 0020 "Lifetimes") plus five minutes of clock skew (REQ-KEYS-007).
    pub retain: Duration,
    /// A node's first key signs at once while no key of the ring is older than this: the boards of
    /// a first deploy.
    pub bootstrap: Duration,
}

impl Timing {
    /// The values of ADR 0006 "Rotation": 30 minutes before a key signs, 65 minutes after.
    pub const DEFAULT: Self = Self {
        prepublish: Duration::from_secs(30 * 60),
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
    /// Why the lead time was skipped ([`NO_ACTIVE_KEY`]); `None` for every other change.
    pub reason: Option<&'static str>,
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

/// Plans the next ring from the ring as it is, the key key@ signs with, the node it belongs to, the
/// kids that `KeyRevocation` lists, and the clock. Nothing is written here. The ring is unchanged when
/// the list of changes is empty.
///
/// Only the keys of `node` are changed, apart from the drop of any key that has been retiring for
/// the retention. A revoked key is not added to the ring and is not promoted or made to retire others
/// (REQ-KEYS-106): the item of `KeyRevocation` is its state, and the ring does not write it. A key
/// that replaces a revoked one is `active` at once when no non-revoked key of the ring is `active`
/// (REQ-KEYS-089), and published for the lead time otherwise.
#[must_use]
pub fn plan(
    ring: &SigningRing,
    cur: &Current,
    node: &str,
    now: SystemTime,
    t: &Timing,
    revoked: &HashSet<String>,
) -> (SigningRing, Vec<Change>) {
    let cur_revoked = revoked.contains(&cur.key_id);
    let mut keys = ring.keys.clone();
    // Whether the issuer signs now: a key of any node that `KeyRevocation` does not list and that is not
    // known not to sign.
    // When nothing signs, a key waits for the lead time for nobody (REQ-KEYS-089).
    // A state this code does not know counts as signing: only the known states that do not sign, and
    // revoked keys, are left out, so another version's state never skips the lead time.
    let issuer_signs = keys
        .iter()
        .any(|k| !revoked.contains(&k.key_id) && k.state != RETIRING && k.state != PRE_PUBLISHED);
    let mut changes = Vec::new();
    let change = |k: &str, kind| Change {
        key_id: k.to_owned(),
        kind,
        reason: None,
    };

    match keys.iter().position(|k| k.key_id == cur.key_id) {
        // A revoked key does not join the ring, in any state.
        None if cur_revoked => {}
        None => {
            // A node's first key signs at once while the ring is young (the first deploy); every other
            // key is published for the full window first.
            let first_of_node = !keys.iter().any(|k| k.node == node);
            // A key of unknown age counts as old: it never makes the ring young.
            let young = keys
                .iter()
                .all(|k| instant(k.added_at.as_option()).is_some_and(|at| now < at + t.bootstrap));
            let first_deploy = first_of_node && young;
            let state = if first_deploy || !issuer_signs {
                ACTIVE
            } else {
                PRE_PUBLISHED
            };
            let skipped = (state == ACTIVE && !first_deploy).then_some(NO_ACTIVE_KEY);
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
            changes.push(Change {
                reason: skipped,
                ..change(&cur.key_id, ChangeKind::Added(state))
            });
        }
        Some(i) => {
            let k = &mut keys[i];
            // Only the node's own key, and only a key that was published for the whole window, or any
            // time once the issuer has no key that signs. A retiring key does not come back, and
            // another node's key is not ours to promote.
            if !cur_revoked
                && k.node == node
                && k.state == PRE_PUBLISHED
                && (!issuer_signs || now >= since(k, now) + t.prepublish)
            {
                let skipped = now < since(k, now) + t.prepublish;
                enter(k, ACTIVE, now);
                changes.push(Change {
                    reason: skipped.then_some(NO_ACTIVE_KEY),
                    ..change(&cur.key_id, ChangeKind::Activated)
                });
            }
        }
    }

    // Once the key key@ signs with is active, the node's earlier keys stop. The keys of other nodes
    // are theirs: their signers retire them. A revoked key is left as it is: the item of
    // `KeyRevocation` is its state, and it is not in the key set.
    if !cur_revoked
        && keys
            .iter()
            .any(|k| k.key_id == cur.key_id && k.node == node && k.state == ACTIVE)
    {
        for k in keys.iter_mut().filter(|k| {
            k.node == node
                && k.key_id != cur.key_id
                && !revoked.contains(&k.key_id)
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
    /// `KeyRevocation` lists the key that key@ signs with: it signs nothing more (REQ-KEYS-106).
    Revoked,
}

/// What `signer` knows of the ring a moment ago.
#[derive(Clone)]
struct Snapshot {
    at: SystemTime,
    current: Current,
    /// The key is an active key of the ring.
    active: bool,
    /// `KeyRevocation` listed the key when the snapshot was made.
    revoked: bool,
    /// Until when `entry`'s key set may lack the key, when the ring holds a revoked key and this one is
    /// new: the key does not sign before then. `None` when it is not held, or the time has passed.
    hold_until: Option<SystemTime>,
}

/// The manager of the ring: reads it, plans, writes with the version guard, and says which key may
/// sign.
pub struct RingKeeper {
    store: Store<RingKind>,
    revocations: KeyRevocations,
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
            revocations: KeyRevocations::new(store)?,
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
        // The guard is held only to read or to refresh the snapshot, never across the store call below: a slow
        // `KeyRevocation` must not queue every other caller behind it.
        let snap = {
            let mut guard = self.snapshot.lock().await;
            let now = (self.clock)();
            let fresh = guard
                .as_ref()
                .filter(|s| now.duration_since(s.at).is_ok_and(|age| age < REFRESH))
                // A held snapshot is looked at again once the hold is over.
                .filter(|s| s.hold_until.is_none_or(|h| now < h));
            match fresh {
                Some(s) => s.clone(),
                None => {
                    let s = self.reconcile_locked().await?;
                    *guard = Some(s.clone());
                    s
                }
            }
        };
        // A key that `KeyRevocation` lists is revoked, whatever else is true of it.
        if snap.revoked {
            return Err(RingError::Revoked);
        }
        if !snap.active {
            return Err(RingError::NotActive);
        }
        // The key joined the ring a moment ago, after a revocation: the key set that `entry` serves may
        // not list it yet, and no token is signed before it does.
        if snap.hold_until.is_some_and(|h| (self.clock)() < h) {
            return Err(RingError::NotActive);
        }
        // The snapshot is up to ten seconds old, and a revocation must stop a signature at once: look at the key's
        // own item at every call, and refuse when it cannot be read in time (fail closed).
        match tokio::time::timeout(CALL, self.revocations.is_revoked(&snap.current.key_id)).await {
            Ok(Ok(false)) => Ok(snap.current),
            Ok(Ok(true)) => Err(RingError::Revoked),
            _ => Err(RingError::Store),
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

    /// The ring as store@ holds it (empty when none was written), without the keys that
    /// `KeyRevocation` lists: the ring that the key set is built from (REQ-KEYS-107).
    ///
    /// # Errors
    ///
    /// [`RingError::Store`], also when `KeyRevocation` cannot be read: a key set that might list a
    /// revoked key is not served.
    pub async fn read(&self) -> Result<SigningRing, RingError> {
        let ring = match tokio::time::timeout(CALL, self.store.get("", ID)).await {
            Ok(Ok(item)) => item.value,
            Ok(Err(StoreError::NotFound)) => SigningRing::default(),
            _ => return Err(RingError::Store),
        };
        let revoked = self.revoked().await?;
        Ok(without_revoked(ring, &revoked))
    }

    /// The kids that `KeyRevocation` lists.
    async fn revoked(&self) -> Result<HashSet<String>, RingError> {
        match tokio::time::timeout(CALL, self.revocations.revoked_kids()).await {
            Ok(Ok(kids)) => Ok(kids),
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
            let revoked = self.revoked().await?;
            let now = (self.clock)();
            let (next, changes) = plan(&ring, &cur, &self.node, now, &self.timing, &revoked);
            if changes.is_empty() {
                return Ok(snapshot(&ring, cur, now, &revoked));
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
                    return Ok(snapshot(&next, cur, now, &revoked));
                }
                // Another instance wrote first: read again and plan again.
                Err(StoreError::Exists | StoreError::Version) => {}
                Err(_) => return Err(RingError::Store),
            }
        }
        Err(RingError::Store)
    }
}

fn snapshot(
    ring: &SigningRing,
    current: Current,
    at: SystemTime,
    revoked: &HashSet<String>,
) -> Snapshot {
    let active = ring
        .keys
        .iter()
        .any(|k| k.key_id == current.key_id && k.state == ACTIVE);
    // The hold is only for a ring that holds a revoked key: the first keys of a first deploy sign at
    // once, as nothing has seen a token yet. A key that waited for the lead time is long past it.
    let hold_until = ring
        .keys
        .iter()
        .any(|k| revoked.contains(&k.key_id))
        .then(|| {
            ring.keys
                .iter()
                .find(|k| k.key_id == current.key_id && k.state == ACTIVE)
                .and_then(|k| instant(k.added_at.as_option()))
                .map(|added| added + KEY_SET_HOLD)
        })
        .flatten()
        .filter(|h| *h > at);
    let revoked = revoked.contains(&current.key_id);
    Snapshot {
        at,
        current,
        active,
        revoked,
        hold_until,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIN: u64 = 60;
    const HOUR: u64 = 3600;
    const WINDOW: u64 = 30 * MIN;
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
            reason: None,
        }
    }
    /// A change that skipped the lead time because no key of the issuer signed.
    fn skipped(id: &str, kind: ChangeKind) -> Change {
        Change {
            reason: Some(NO_ACTIVE_KEY),
            ..added(id, kind)
        }
    }
    const T: Timing = Timing::DEFAULT;

    /// Runs `signer` of `node`, whose key@ signs with `id`, at `secs`, and returns the ring.
    fn step(ring: &SigningRing, node: &str, id: &str, secs: u64) -> (SigningRing, Vec<Change>) {
        plan(ring, &cur(id), node, at(secs), &T, &HashSet::new())
    }

    fn revoked(ids: &[&str]) -> HashSet<String> {
        ids.iter().map(|i| (*i).to_owned()).collect()
    }

    /// verifies: REQ-KEYS-106
    #[test]
    fn a_revoked_key_is_never_added_to_the_ring() {
        let (r, ch) = plan(
            &SigningRing::default(),
            &cur("a"),
            A,
            at(1000),
            &T,
            &revoked(&["a"]),
        );
        assert!(r.keys.is_empty());
        assert!(ch.is_empty());
    }

    /// verifies: REQ-KEYS-106
    #[test]
    fn a_revoked_key_is_never_promoted_even_when_its_window_is_over() {
        let (r, _) = step(&SigningRing::default(), A, "a", 1000);
        let (r, _) = step(&r, A, "a2", 2000);
        let due = 2000 + WINDOW;
        let (r2, ch) = plan(&r, &cur("a2"), A, at(due), &T, &revoked(&["a2"]));
        assert!(
            ch.is_empty(),
            "the owner node promoted a revoked key: {ch:?}"
        );
        assert_eq!(states(&r2), [("a", ACTIVE), ("a2", PRE_PUBLISHED)]);
        // Nor does the revoked key stop the key that is signing.
        let (r3, ch) = plan(&r, &cur("a2"), A, at(due), &T, &revoked(&[]));
        assert_eq!(states(&r3), [("a", RETIRING), ("a2", ACTIVE)]);
        assert_eq!(ch.len(), 2);
    }

    /// verifies: REQ-KEYS-106
    #[test]
    fn a_revoked_active_key_does_not_retire_the_nodes_other_keys() {
        let (r, _) = step(&SigningRing::default(), A, "a", 1000);
        let (r, _) = step(&r, A, "a2", 2000);
        // key@ is back on `a`, which is active and revoked: the plan leaves the ring alone.
        let (r2, ch) = plan(&r, &cur("a"), A, at(2000 + WINDOW), &T, &revoked(&["a"]));
        assert!(ch.is_empty());
        assert_eq!(r2, r);
    }

    /// A ring that is long past its first deploy, with `a` the only key of A, active.
    fn old_ring_of_one() -> SigningRing {
        step(&SigningRing::default(), A, "a", 1000).0
    }

    /// verifies: REQ-KEYS-089
    #[test]
    fn the_replacement_of_the_only_key_signs_at_once_when_that_key_is_revoked() {
        let r = old_ring_of_one();
        let now = 1000 + 30 * HOUR;
        let (r2, ch) = plan(&r, &cur("a2"), A, at(now), &T, &revoked(&["a"]));
        assert_eq!(states(&r2), [("a", ACTIVE), ("a2", ACTIVE)]);
        assert_eq!(ch, [skipped("a2", ChangeKind::Added(ACTIVE))]);
        // The revoked entry is left as it is: its state is the item of `KeyRevocation`.
        assert_eq!(r2.keys[0], r.keys[0]);
    }

    /// verifies: REQ-KEYS-089
    #[test]
    fn the_replacement_signs_at_once_even_in_the_first_minutes_of_the_ring() {
        // The ring is a minute old, so it is young, but the node already has a key, the revoked one:
        // `first_of_node` is false for a2, so the first-deploy rule does not apply. The rule that
        // holds here is that no live key signs.
        let r = old_ring_of_one();
        let (r2, _) = plan(&r, &cur("a2"), A, at(1000 + MIN), &T, &revoked(&["a"]));
        assert_eq!(states(&r2), [("a", ACTIVE), ("a2", ACTIVE)]);
    }

    /// verifies: REQ-KEYS-089
    #[test]
    fn a_pre_published_key_activates_at_once_when_the_active_key_is_revoked() {
        // a2 was published a minute ago for a rotation, then a was revoked: a2 signs now.
        let (r, _) = step(&old_ring_of_one(), A, "a2", 5000);
        assert_eq!(states(&r), [("a", ACTIVE), ("a2", PRE_PUBLISHED)]);
        let (r2, ch) = plan(&r, &cur("a2"), A, at(5000 + MIN), &T, &revoked(&["a"]));
        assert_eq!(states(&r2), [("a", ACTIVE), ("a2", ACTIVE)]);
        assert_eq!(ch, [skipped("a2", ChangeKind::Activated)]);
        // Without the revocation it waits for the window.
        let (r3, ch) = step(&r, A, "a2", 5000 + MIN);
        assert!(ch.is_empty());
        assert_eq!(r3, r);
    }

    /// verifies: REQ-KEYS-089
    #[test]
    fn the_replacement_retires_the_nodes_other_live_keys_but_leaves_the_revoked_one() {
        let (r, _) = step(&old_ring_of_one(), A, "a2", 5000);
        let (r, _) = step(&r, A, "a3", 5001);
        // a is revoked and a2 is a live spare; a3 signs at once and a2 stops, a stays as it is.
        let (r2, ch) = plan(&r, &cur("a3"), A, at(6000), &T, &revoked(&["a"]));
        assert_eq!(
            states(&r2),
            [("a", ACTIVE), ("a2", RETIRING), ("a3", ACTIVE)]
        );
        assert_eq!(
            ch,
            [
                skipped("a3", ChangeKind::Activated),
                added("a2", ChangeKind::Retired)
            ]
        );
    }

    /// verifies: REQ-KEYS-089, REQ-KEYS-106
    #[test]
    fn a_revoked_replacement_never_signs_at_once() {
        let r = old_ring_of_one();
        let (r2, ch) = plan(
            &r,
            &cur("a2"),
            A,
            at(1000 + 30 * HOUR),
            &T,
            &revoked(&["a", "a2"]),
        );
        assert!(ch.is_empty());
        assert_eq!(r2, r);
    }

    /// verifies: REQ-KEYS-089, REQ-KEYS-076
    #[test]
    fn a_node_with_a_revoked_key_waits_for_the_window_while_another_node_signs() {
        // Both boards have a key, long after the first deploy. A's key is revoked: the issuer still
        // signs with B's key, which every verifier has, so A's replacement is published first.
        let (r, _) = step(&SigningRing::default(), A, "a", 1000);
        let (r, _) = step(&r, B, "b", 1000);
        let now = 2 * HOUR;
        let (r2, ch) = plan(&r, &cur("a2"), A, at(now), &T, &revoked(&["a"]));
        assert_eq!(
            states(&r2),
            [("a", ACTIVE), ("b", ACTIVE), ("a2", PRE_PUBLISHED)]
        );
        assert_eq!(ch, [added("a2", ChangeKind::Added(PRE_PUBLISHED))]);
        let (r3, ch) = plan(
            &r2,
            &cur("a2"),
            A,
            at(now + WINDOW - 1),
            &T,
            &revoked(&["a"]),
        );
        assert!(ch.is_empty());
        assert_eq!(r3, r2);
        let (r4, _) = plan(&r2, &cur("a2"), A, at(now + WINDOW), &T, &revoked(&["a"]));
        assert_eq!(states(&r4), [("a", ACTIVE), ("b", ACTIVE), ("a2", ACTIVE)]);
        // When B's key is revoked too, nothing signs, and A's replacement signs at once.
        let (r5, _) = plan(&r, &cur("a2"), A, at(now), &T, &revoked(&["a", "b"]));
        assert_eq!(r5.keys[2].state, ACTIVE);
    }

    /// verifies: REQ-KEYS-089, REQ-KEYS-076
    #[test]
    fn a_normal_rotation_and_a_revoked_spare_still_wait_for_the_window() {
        let r = old_ring_of_one();
        let now = 1000 + 30 * HOUR;
        // No revocation at all.
        let (r2, _) = step(&r, A, "a2", now);
        assert_eq!(states(&r2), [("a", ACTIVE), ("a2", PRE_PUBLISHED)]);
        // A revoked entry of another state, or of another node, that is not the live active key.
        let mut ring = r.clone();
        ring.keys.push(SigningKey {
            key_id: "old".into(),
            state: RETIRING.into(),
            node: A.into(),
            ..SigningKey::default()
        });
        ring.keys.push(SigningKey {
            key_id: "spare".into(),
            state: PRE_PUBLISHED.into(),
            node: B.into(),
            ..SigningKey::default()
        });
        let (r3, ch) = plan(
            &ring,
            &cur("a2"),
            A,
            at(now),
            &T,
            &revoked(&["old", "spare"]),
        );
        assert_eq!(r3.keys[3].state, PRE_PUBLISHED);
        assert_eq!(ch, [added("a2", ChangeKind::Added(PRE_PUBLISHED))]);
        // The live active key is revoked for an unrelated kid only: the window stands.
        let (r4, _) = plan(&r, &cur("a2"), A, at(now), &T, &revoked(&["unrelated"]));
        assert_eq!(states(&r4), [("a", ACTIVE), ("a2", PRE_PUBLISHED)]);
        let (r5, ch) = plan(
            &r4,
            &cur("a2"),
            A,
            at(now + WINDOW - 1),
            &T,
            &revoked(&["unrelated"]),
        );
        assert!(ch.is_empty());
        assert_eq!(r5, r4);
    }

    /// verifies: REQ-KEYS-089
    #[test]
    fn a_key_in_a_state_this_code_does_not_know_counts_as_signing() {
        // A rolling upgrade or downgrade: a state of another version must not skip the lead time.
        let mut r = old_ring_of_one();
        r.keys[0].state = "signing-v2".into();
        let (r2, ch) = step(&r, A, "a2", 1000 + 30 * HOUR);
        assert_eq!(r2.keys[1].state, PRE_PUBLISHED);
        assert_eq!(ch, [added("a2", ChangeKind::Added(PRE_PUBLISHED))]);
        // Revoked, it counts for nothing, as an active key would.
        let (r3, _) = plan(
            &r,
            &cur("a2"),
            A,
            at(1000 + 30 * HOUR),
            &T,
            &revoked(&["a"]),
        );
        assert_eq!(r3.keys[1].state, ACTIVE);
        // Known non-signing states alone leave nothing that signs.
        r.keys[0].state = RETIRING.into();
        let (r4, ch) = step(&r, A, "a2", 1000 + 10 * MIN);
        assert_eq!(states(&r4), [("a", RETIRING), ("a2", ACTIVE)]);
        assert_eq!(ch, [skipped("a2", ChangeKind::Added(ACTIVE))]);
    }

    /// verifies: REQ-KEYS-089, REQ-KEYS-080
    #[test]
    fn only_a_change_that_skips_the_lead_time_names_the_reason() {
        // The first keys of a first deploy are not a skipped lead time.
        let (r, ch) = step(&SigningRing::default(), A, "a", 1000);
        assert_eq!(ch, [added("a", ChangeKind::Added(ACTIVE))]);
        // A normal rotation neither.
        let (r, ch) = step(&r, A, "a2", 1000 + 30 * HOUR);
        assert_eq!(ch, [added("a2", ChangeKind::Added(PRE_PUBLISHED))]);
        let (_, ch) = step(&r, A, "a2", 1000 + 31 * HOUR);
        assert_eq!(
            ch,
            [
                added("a2", ChangeKind::Activated),
                added("a", ChangeKind::Retired)
            ]
        );
    }

    /// verifies: REQ-KEYS-089
    #[test]
    fn two_nodes_with_every_key_revoked_converge_on_one_active_replacement() {
        // The signers look one after the other, each with the ring the other wrote. A's replacement
        // is active, so B's sees a key that signs and waits for the window: a ring with two nodes,
        // each of which would go on alone, does not end with both skipping it.
        let (r, _) = step(&SigningRing::default(), A, "a", 1000);
        let (r, _) = step(&r, B, "b", 1000);
        let all = revoked(&["a", "b"]);
        let now = 2 * HOUR;
        let (r, ch) = plan(&r, &cur("a2"), A, at(now), &T, &all);
        assert_eq!(ch, [skipped("a2", ChangeKind::Added(ACTIVE))]);
        let (r, ch) = plan(&r, &cur("b2"), B, at(now), &T, &all);
        assert_eq!(
            states(&r),
            [
                ("a", ACTIVE),
                ("b", ACTIVE),
                ("a2", ACTIVE),
                ("b2", PRE_PUBLISHED)
            ]
        );
        assert_eq!(ch, [added("b2", ChangeKind::Added(PRE_PUBLISHED))]);
        // B's replacement is promoted after its window, like any other.
        let (r, _) = plan(&r, &cur("b2"), B, at(now + WINDOW), &T, &all);
        assert_eq!(r.keys[3].state, ACTIVE);
    }

    #[test]
    fn the_window_is_the_cache_budget_of_the_key_set() {
        // 300 s of max-age + 300 s of edge time to live + 10 minutes of refetch + 5 minutes of
        // skew is 25 minutes, rounded up to 30 (ADR 0006 "Rotation").
        let derived = Duration::from_secs(300 + 300 + 10 * 60 + 5 * 60);
        assert!(T.prepublish >= derived);
        assert_eq!(T.prepublish, Duration::from_secs(30 * MIN));
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

    /// verifies: REQ-KEYS-080
    #[test]
    fn the_boards_of_a_first_deploy_each_activate_their_first_key_at_once() {
        let (r, _) = step(&SigningRing::default(), A, "a", 1000);
        let (r, _) = step(&r, B, "b", 1000 + 5 * MIN);
        let (r, _) = step(&r, "node-c", "c", 1000 + 14 * MIN);
        assert_eq!(states(&r), [("a", ACTIVE), ("b", ACTIVE), ("c", ACTIVE)]);
    }

    /// verifies: REQ-KEYS-080
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

    /// verifies: REQ-KEYS-076, REQ-KEYS-085
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

    /// verifies: REQ-KEYS-007, REQ-KEYS-078
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

    /// verifies: REQ-KEYS-077
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
        // and the node has no key yet), because "odd" is in a state this code does not know and counts
        // as possibly signing; "old" counts from now and stays; "odd" is untouched.
        assert_eq!(r.keys.len(), 3);
        assert_eq!(r.keys[2].state, PRE_PUBLISHED);
        assert_eq!(r.keys[0].state, RETIRING);
        assert_eq!(r.keys[1].state, "revoked");
        assert_eq!(ch.len(), 1);
    }
}
