//! `Watch`: the list-watch loop of [0005 Watch and the resume point](https://sluis.id/decisions/0005-the-store/#watch-and-the-resume-point)
//! for one kind, typed like [`Store`], for the actors that follow a kind instead of reading it again
//! (`exporter@` first; `entry` and `signer` for `KeyRevocation` and `SigningRing`).
//!
//! The contract is the Kubernetes one, which store-api.md "Watch" documents, and the loop is the one every
//! consumer would otherwise write by hand:
//!
//! - **List, then watch.** A new watch lists the kind and watches from the `resume_point` of the listing, so
//!   nothing between the two is lost. The listing is the first event, [`Event::Resync`]. A caller that kept its
//!   own state and a resume point (an `ExportCursor`) starts from the point with [`WatchOpts::from`] and gets no
//!   listing.
//! - **A resume point is a pair.** [`ResumePoint`] is the epoch of the change log and the sequence in it. A restore or
//!   a reset makes the log again and its sequence begins again, so a bare number could name another position; the epoch
//!   is what tells the two logs apart. A consumer that saves a point saves both, and hands both back.
//! - **Events.** A [`Event::Put`] is the item as store@ read it at delivery, an [`Event::Delete`] is its address
//!   and the version of the row (an expiry is a delete), and an [`Event::Bookmark`] is the latest resume point of
//!   an idle stream (every 30 seconds): a sign of life, and a point a restart can use. An [`Event::CaughtUp`] is the one
//!   bookmark that says more ("Caught up", below).
//! - **Once, in the order of the log, for each address.** A change at or below the sequence already applied, in the same
//!   epoch, is a repeat and is dropped here, so a consumer sees each sequence once and in increasing order. store@ coalesces
//!   rows: a put is skipped when a later row of the same address is in the run, so the order is guaranteed *for one
//!   address* and the state a put carries is the state at delivery, not at the sequence; do not infer an order
//!   across addresses from the sequence numbers. Right after a [`Event::Resync`] a change the listing already shows
//!   may come again (store-api.md "Watch"), and a delete of an item that expired may repeat or arrive for an item
//!   the consumer never held: apply a delete by removing the address if present, and treat a put as the full state.
//! - **A sequence is compared only inside its epoch.** A restore or a reset of the change log makes a new log whose
//!   sequence begins again, under a new epoch. store@ refuses a watch from a point whose epoch is not the log's, and
//!   the loop never drops a change as a repeat because its sequence is at or below the applied one unless the epoch
//!   is the same: a message that names another epoch than the stream was opened under ends the stream and lists the
//!   kind again. A saved point with no epoch (`epoch` 0), which store@ did not give, is refused the same way.
//! - **A resync is an event.** When store@ no longer holds the resume point (the change log is kept for a bounded
//!   window, or was made again, so the epoch differs), or has not reached it, the loop lists the kind again and says
//!   [`Event::Resync`] with the whole state, `cause` [`ResyncCause::Expired`]. A consumer *replaces* its state with the items; it never applies
//!   changes it did not see. The loop never skips from one point to a later one without saying so.
//! - **A broken stream is an event too.** A stream that ends or fails, and a store@ that is down, give
//!   [`Event::Interrupted`] and the loop reconnects from the last point with an exponential [`Backoff`]. A watch that
//!   is silent for [`WatchOpts::idle_timeout`] is interrupted too, so a store@ that is half open is noticed.
//! - **Caught up.** After a listing, a reconnect or a start from a saved point, the consumer's state is *unconfirmed*:
//!   the first change may be the first of many rows still to come. When a stream opens, store@ reads the head of the
//!   change log linearizably, and says [`Event::CaughtUp`] as soon as it has delivered every row up to that head: at
//!   once when there is nothing to deliver, and never before the rows. From then on the state holds every change that
//!   was committed before the stream opened, and [`Watch::caught_up`] is true. It is false again at the next
//!   [`Event::Resync`], [`Event::Interrupted`] or dropped call of [`Watch::next`] until the next [`Event::CaughtUp`].
//!   An idle [`Event::Bookmark`] is no such claim: it proves nothing about rows the stream may not have seen. The claim
//!   is one of rows delivered, so a store@ whose log lags delays it and cannot make it early.
//! - **A claim has an age, and a reader that fails closed bounds it.** The claim is about the moment store@ read the
//!   head. store@ renews it about every 30 seconds (every idle tick of a caught-up stream reads the head again,
//!   linearizably, and says [`Event::CaughtUp`] again if it is at the position the stream has delivered; a head that is
//!   ahead, or a read that fails, renews nothing), so a tail that reads from a deposed or isolated node stops being
//!   renewed. Only a claim moves [`Confirmation::last_claim`]: a bookmark or a change proves that store@ is talking,
//!   which is not the same as the log being fresh. A reader on another task takes [`Watch::confirmation`] and asks
//!   [`Confirmation::caught_up_within`] at the moment it answers, with a bound of 45 seconds (a renewal and a margin):
//!   it then trusts its state only while a claim younger than that stands. A claim that the consumer read after it
//!   had been slow with the event before (more than [`WatchOpts::slow_consumer`]) may have waited in a queue and does
//!   not count as new. The confirmation belongs to the stream that said it: a call of [`Watch::next`] that is dropped
//!   takes the stream, and with it the confirmation. A stream that makes no progress toward its first claim within
//!   [`WatchOpts::catch_up_timeout`] is interrupted (`catch-up stalled`) and reconnects with a growing backoff; a
//!   bookmark that moves the position is progress (a catch-up through the rows of other kinds is slow, not stalled).
//! - **It gives up only when asked.** The loop retries for ever by default and reports each failure as
//!   [`Event::Interrupted`] with its `attempt`: a consumer must escalate on it (raise an alarm, refuse to serve from
//!   its state). [`WatchOpts::give_up_after`] ends the watch with [`Error::GaveUp`] once the failures have gone on
//!   for that long.
//! - **It fails closed.** An item that does not decode, a change that is not well formed, a refusal that a retry
//!   cannot cure (`permission_denied`, `invalid_argument`, `failed_precondition` other than an expired point,
//!   `unimplemented`, ...) and a kind that has no change log end the watch with an [`Error`]; after it every call
//!   gives [`Error::Closed`]. The consumer starts a new watch (which lists again) or reports itself broken. A listing
//!   of more than 1000 pages is fatal too.
//! - **Values are the kind's, as store@ read them.** An item that has a time to live carries `expires_at`; the
//!   expiry reaches the watcher as a delete only when the sweeper runs, so a reader that must not use an expired item
//!   honours `expires_at` itself. [`KeyRevocations::watch`](crate::revocation::KeyRevocations::watch) covers the
//!   revocations at no tenant only (a boundary's keys), not the data key generations of a tenant. The events print
//!   their items with `Debug`: do not log them for a secret kind.
//!
//! The loop is pulled: nothing runs between calls of [`Watch::next`], and there is no buffer beyond the stream
//! (HTTP/2 flow control is the backpressure, as store-api.md says). Dropping the [`Watch`] ends the stream; dropping
//! the future of [`Watch::next`] (a `select!` that takes another branch) drops the stream too, and the next call
//! reconnects from the last point, so no event is lost either way. The time still to wait before a retry is kept as
//! a deadline, so a cancelled call does not shorten the backoff, and a cancelled listing is read again from its start. Run it in a task of its own, started outside a request handler: a call made from a handler
//! carries the handler's deadline (contracts.md "Every call"), which would cut the stream short.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::time::Instant;

use connectrpc::client::{ClientTransport, ServerStream};
use connectrpc::error::ErrorCode;
use sluis_kit::Transport;
use sluis_proto::sluis::store::v2alpha1::{
    ChangeType, Item as WireItem, WatchRequest, WatchResponse, WatchResponseView,
};
use sluis_registry::Class;

use crate::{Error, Item, Kind, Store};

/// More pages than this are not read: a list that does not end is a store that is not answering as it should.
const MAX_PAGES: usize = 1000;

/// The reason store@ gives for a resume point the change log does not hold (store-api.md "Refusals").
const EXPIRED: &str = "resume_point_expired";

type Stream =
    ServerStream<<Transport as ClientTransport>::ResponseBody, WatchResponseView<'static>>;

/// How long the loop waits before it tries again after a failure: `initial` (at least 1 ms) for the first retry,
/// doubled for each further one, never more than `max`. A message received resets it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Backoff {
    /// The wait before the first retry.
    pub initial: Duration,
    /// The longest wait.
    pub max: Duration,
}

impl Default for Backoff {
    fn default() -> Self {
        Self {
            initial: Duration::from_millis(250),
            max: Duration::from_secs(15),
        }
    }
}

impl Backoff {
    /// The wait before attempt number `attempt`: none for 0 (nothing has failed), then `initial`, `2 * initial`, ...
    /// up to `max`.
    #[must_use]
    pub fn delay(&self, attempt: u32) -> Duration {
        match attempt {
            0 => Duration::ZERO,
            n => {
                // Never a busy loop: at least a millisecond, and never less than the first wait.
                let initial = self.initial.max(Duration::from_millis(1));
                initial
                    .saturating_mul(1u32 << (n - 1).min(20))
                    .min(self.max.max(initial))
            }
        }
    }
}

/// Where a watcher is in the change log of a kind: the epoch of the log, and the sequence in it (store-api.md "Watch").
///
/// The sequence is an order only inside its epoch. Two points of different epochs are not ordered, so this type has no
/// `Ord`; compare the sequences only after the epochs are equal. A consumer that persists a point (an `ExportCursor`)
/// keeps both fields and hands both back in [`WatchOpts::from`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct ResumePoint {
    /// The epoch of the change log that `sequence` belongs to; never 0 in a point that store@ gave.
    pub epoch: u64,
    /// The log sequence.
    pub sequence: u64,
}

/// What a watch starts from, and how it retries.
#[derive(Clone, Copy, Debug)]
pub struct WatchOpts {
    /// The resume point the caller last applied (a persisted cursor, or the point of an event). `None` and a point with
    /// sequence 0 list the kind first: a watch from 0 starts "from now" in store@ and would lose what changed since, so
    /// it is not offered. A point of another epoch than the log's, or with none, is refused by store@, and the watch
    /// lists the kind again.
    pub from: Option<ResumePoint>,
    /// The wait between retries.
    pub backoff: Backoff,
    /// How long a stream may say nothing before it is taken for dead: store@ sends a bookmark when a stream has been
    /// idle for 30 seconds, so the default is three of those. On expiry the stream is dropped, the watch says
    /// [`Event::Interrupted`] (`no bookmark`) and reconnects. It also bounds the wait for the first message.
    pub idle_timeout: Duration,
    /// Ends the watch with [`Error::GaveUp`] once the failures have gone on for this long without a message or a
    /// listing getting through. `None` retries for ever; the consumer escalates on `attempt` of
    /// [`Event::Interrupted`].
    pub give_up_after: Option<Duration>,
    /// How long a stream may wait for store@ to say it is caught up without making progress (the time spent waiting for
    /// it, not the time the consumer spends on the events; a change or a bookmark that moves the position is progress and
    /// starts the count again). The default, 60 seconds, is two idle intervals: a catch-up through rows of other kinds
    /// shows its progress in the idle bookmark of each interval and is not taken for a stall, and a stream that is stuck
    /// behind the head shows the same position twice. On expiry the stream is dropped, the watch says
    /// [`Event::Interrupted`] (`catch-up stalled`) and reconnects after the backoff, which grows with each stall: a
    /// consumer that fails closed sees the state unconfirmed, and can alarm on `attempt`.
    pub catch_up_timeout: Duration,
    /// How long a stream must have been up, and caught up, before a message of it ends the count of failures. A stream
    /// that says it is caught up and then dies is a failure, and a loop of them must back off to the cap, not start again
    /// at the first wait. store@ says something at least every 30 seconds, so the default, 15 seconds, is reached by a
    /// stream that is healthy and idle, with half an interval of margin.
    pub stable_after: Duration,
    /// How long the consumer may take, after it is handed an event, to ask for the next one before the claims it reads
    /// next are not taken as new: a consumer that is slow reads what the stream queued meanwhile, and a claim in that
    /// queue may be old. A heuristic for the age of a claim, which the stream cannot date. The default is 5 seconds.
    pub slow_consumer: Duration,
}

impl Default for WatchOpts {
    fn default() -> Self {
        Self {
            from: None,
            backoff: Backoff::default(),
            idle_timeout: Duration::from_secs(90),
            give_up_after: None,
            catch_up_timeout: Duration::from_secs(60),
            stable_after: Duration::from_secs(15),
            slow_consumer: Duration::from_secs(5),
        }
    }
}

/// Why the loop listed the kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResyncCause {
    /// The first listing of a watch that was given no resume point.
    Start,
    /// store@ no longer holds the resume point, or has not reached it (`failed_precondition`,
    /// `resume_point_expired`): changes may have been missed, so the state is read again, whole.
    Expired,
}

/// One thing the loop tells its consumer. Apply them in order.
pub enum Event<K: Kind> {
    /// The whole state of the kind, at `resume_point`: replace everything held with these items. Nothing else
    /// holds for the items that are not in it.
    Resync {
        /// Why.
        cause: ResyncCause,
        /// Every item of the kind (of the tenant), decoded.
        items: Vec<Item<K>>,
        /// The change-log position the listing reflects; changes after it follow.
        resume_point: ResumePoint,
    },
    /// The item was written; this is its state at delivery.
    Put {
        /// The item.
        item: Item<K>,
        /// The point after the change: the epoch and the log sequence of the change.
        resume_point: ResumePoint,
    },
    /// The item was removed or expired.
    Delete {
        /// The tenant of the item; empty for a kind with none.
        tenant: String,
        /// The id of the item.
        id: String,
        /// The version of the row that was removed.
        version: u64,
        /// The point after the change.
        resume_point: ResumePoint,
    },
    /// No change: the latest resume point of a stream that has been idle. A sign of life, and no claim that the
    /// consumer has seen everything.
    Bookmark {
        /// The latest point.
        resume_point: ResumePoint,
    },
    /// The stream has delivered every change that was committed before it was opened: the consumer's state is
    /// confirmed (see "Caught up" in the module). Said when the stream is caught up (right after the listing or the
    /// reconnect when there was nothing to deliver) and again at every renewal, about every 30 seconds.
    CaughtUp {
        /// The point the claim is made at: the log head that store@ read when the stream opened, or the position at a
        /// renewal. The consumer is at it.
        resume_point: ResumePoint,
    },
    /// The stream broke or store@ could not be reached; the loop reconnects (from the last point) after the backoff.
    /// The consumer's state is unconfirmed until it has caught up: see the module on "caught up". The consumer
    /// escalates on `attempt` when it keeps growing.
    Interrupted {
        /// The code and reason of the failure, never a value.
        reason: String,
        /// Consecutive failures so far, from 1.
        attempt: u32,
    },
}

impl<K: Kind> Event<K> {
    /// The resume point the event leaves the consumer at, or `None` for [`Event::Interrupted`].
    #[must_use]
    pub fn resume_point(&self) -> Option<ResumePoint> {
        match self {
            Event::Resync { resume_point, .. }
            | Event::Put { resume_point, .. }
            | Event::Delete { resume_point, .. }
            | Event::Bookmark { resume_point }
            | Event::CaughtUp { resume_point } => Some(*resume_point),
            Event::Interrupted { .. } => None,
        }
    }
}

impl<K: Kind> std::fmt::Debug for Event<K>
where
    K::Value: std::fmt::Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Event::Resync {
                cause,
                items,
                resume_point,
            } => f
                .debug_struct("Resync")
                .field("cause", cause)
                .field("items", items)
                .field("resume_point", resume_point)
                .finish(),
            Event::Put { item, resume_point } => f
                .debug_struct("Put")
                .field("item", item)
                .field("resume_point", resume_point)
                .finish(),
            Event::Delete {
                tenant,
                id,
                version,
                resume_point,
            } => f
                .debug_struct("Delete")
                .field("tenant", tenant)
                .field("id", id)
                .field("version", version)
                .field("resume_point", resume_point)
                .finish(),
            Event::Bookmark { resume_point } => f
                .debug_struct("Bookmark")
                .field("resume_point", resume_point)
                .finish(),
            Event::CaughtUp { resume_point } => f
                .debug_struct("CaughtUp")
                .field("resume_point", resume_point)
                .finish(),
            Event::Interrupted { reason, attempt } => f
                .debug_struct("Interrupted")
                .field("reason", reason)
                .field("attempt", attempt)
                .finish(),
        }
    }
}

/// What a reader on another task may ask about the state of a watch: whether it is confirmed, and since when.
#[derive(Default)]
struct Claim {
    /// Whether the stream that is current has said it is caught up.
    confirmed: bool,
    /// A lower bound for the time of the newest claim of the current stream, from the loop's own clock (see
    /// [`Confirmation::last_claim`]).
    at: Option<Instant>,
}

/// A view of the confirmation of a [`Watch`] that can be held by a reader on another task: it is read at the moment the
/// reader answers, so the age of the claim is the age at use, not at the last event. Clone it freely. It is made by
/// [`Watch::confirmation`].
#[derive(Clone)]
pub struct Confirmation(Arc<Mutex<Claim>>);

impl Confirmation {
    fn lock(&self) -> std::sync::MutexGuard<'_, Claim> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Whether the state holds every change that was committed before the current stream's last claim: true from
    /// [`Event::CaughtUp`] until the next [`Event::Resync`], [`Event::Interrupted`] or dropped call of [`Watch::next`].
    /// It has no age: use [`Confirmation::caught_up_within`] to decide.
    #[must_use]
    pub fn caught_up(&self) -> bool {
        self.lock().confirmed
    }

    /// A lower bound for the time of the newest caught-up claim of the current stream: the moment the stream was opened,
    /// for the first one, and the moment a renewal was read by a consumer that was keeping up, for the next ones. `None`
    /// when the state is not confirmed. A bookmark or a change does not move it: they show that store@ is talking, not
    /// that its log is fresh.
    #[must_use]
    pub fn last_claim(&self) -> Option<std::time::Instant> {
        let c = self.lock();
        c.confirmed.then_some(c.at).flatten().map(Instant::into_std)
    }

    /// [`Confirmation::caught_up`], and the newest claim is not older than `max_age`. The test a reader that fails closed
    /// makes when it answers. store@ renews the claim about every 30 seconds, so `max_age` of 45 seconds passes a healthy
    /// stream and fails closed 45 seconds after the last renewal when the renewals stop: a tail that reads from a
    /// deposed or isolated node, a store@ that is down or half open. The worst case for an answer "not revoked" after a
    /// revocation is then the lag of the log while the claims go on (the tail polls every 200 ms in the rqlite driver,
    /// and the replica it reads may trail) and, once they stop, `max_age` after the last claim.
    #[must_use]
    pub fn caught_up_within(&self, max_age: Duration) -> bool {
        let c = self.lock();
        c.confirmed && c.at.is_some_and(|t| t.elapsed() <= max_age)
    }

    fn unconfirm(&self) {
        let mut c = self.lock();
        c.confirmed = false;
        c.at = None;
    }
}

/// Takes the confirmation away when the future it lives in is dropped before it is disarmed.
struct Unconfirm {
    claim: Confirmation,
    armed: bool,
}

impl Drop for Unconfirm {
    fn drop(&mut self) {
        if self.armed {
            self.claim.unconfirm();
        }
    }
}

/// The follower of one kind in one tenant. Build it with [`Store::watch`] or [`Store::watch_with`].
pub struct Watch<K: Kind> {
    store: Store<K>,
    /// The tenant as the caller gave it (checked at construction).
    tenant: String,
    /// The tenant on the wire.
    wire_tenant: String,
    backoff: Backoff,
    /// The point last applied: epoch and sequence. Zero until the first listing, unless the caller gave a point.
    point: ResumePoint,
    /// Whether the stream has said it is caught up. Every way to a new stream or a new listing ends the old stream by a
    /// break (`interrupted_by`) or an expiry (`expire`), and both take it away; a watch starts without it.
    claim: Confirmation,
    /// When the current stream was opened (before the call was made), and how long the loop has waited for progress since
    /// (a wait for a message, not the consumer's time): the clock of the stall deadline.
    opened: Option<Instant>,
    waited: Duration,
    /// When the last event was handed to the consumer: the time it takes to ask for the next shows whether it is slow.
    returned_at: Option<Instant>,
    catch_up_timeout: Duration,
    stable_after: Duration,
    slow_consumer: Duration,
    /// Whether `point` is a position to watch from (a listing was read, or the caller gave one).
    synced: bool,
    /// The cause of the next listing.
    cause: ResyncCause,
    stream: Option<Stream>,
    /// Consecutive failures since a listing or a message last arrived.
    attempt: u32,
    /// Consecutive listings forced by an expired point since a message last arrived: a store that keeps expiring
    /// the point is not listed in a tight loop.
    expiries: u32,
    /// When the next try may start, set when a failure is reported and cleared when the wait is over. A deadline and
    /// not a duration, so that a dropped `next` does not lose it.
    retry_at: Option<Instant>,
    idle_timeout: Duration,
    give_up_after: Option<Duration>,
    /// When the failures that go on began.
    failing_since: Option<Instant>,
    closed: bool,
}

impl<K: Kind> Store<K> {
    /// Lists the kind in the tenant, then follows it. See the module.
    ///
    /// # Errors
    ///
    /// [`Error::Address`] for a tenant that does not fit the kind; [`Error::NotWatchable`] for a config kind.
    pub fn watch(&self, tenant: &str) -> Result<Watch<K>, Error> {
        self.watch_with(tenant, WatchOpts::default())
    }

    /// As [`Store::watch`], from the resume point in `opts` when it has one, and with its backoff.
    ///
    /// # Errors
    ///
    /// As [`Store::watch`].
    pub fn watch_with(&self, tenant: &str, opts: WatchOpts) -> Result<Watch<K>, Error> {
        // A config kind has no change log: its watch begins with a snapshot and carries no sequence (store-api.md
        // "Watch"), which this loop does not model. Its reader lists, or reads the signed document.
        let kind = sluis_registry::kind_by_name(K::NAME).ok_or(Error::UnknownKind(K::NAME))?;
        if kind.class == Class::Config {
            return Err(Error::NotWatchable);
        }
        let wire_tenant = self.wire_tenant(tenant)?;
        let from = opts.from.filter(|p| p.sequence != 0);
        Ok(Watch {
            store: self.clone(),
            tenant: tenant.to_owned(),
            wire_tenant,
            backoff: opts.backoff,
            point: from.unwrap_or_default(),
            claim: Confirmation(Arc::default()),
            opened: None,
            waited: Duration::ZERO,
            returned_at: None,
            catch_up_timeout: opts.catch_up_timeout,
            stable_after: opts.stable_after,
            slow_consumer: opts.slow_consumer,
            synced: from.is_some(),
            cause: ResyncCause::Start,
            stream: None,
            attempt: 0,
            expiries: 0,
            retry_at: None,
            idle_timeout: opts.idle_timeout,
            give_up_after: opts.give_up_after,
            failing_since: None,
            closed: false,
        })
    }
}

/// Whether a retry can cure the error: the store was unreachable or busy, not a rule that refused the caller.
fn retryable(e: &Error) -> bool {
    match e {
        Error::Version => true,
        Error::Rpc(c, _) => !matches!(
            c.code,
            ErrorCode::PermissionDenied
                | ErrorCode::Unauthenticated
                | ErrorCode::InvalidArgument
                | ErrorCode::Unimplemented
                | ErrorCode::FailedPrecondition
                | ErrorCode::OutOfRange
                | ErrorCode::DataLoss
        ),
        _ => false,
    }
}

fn expired(e: &Error) -> bool {
    matches!(e, Error::Rpc(c, Some(r)) if c.code == ErrorCode::FailedPrecondition && r == EXPIRED)
}

impl<K: Kind> Watch<K> {
    /// The point the consumer has been told of: where a restart may resume. Zero before the first listing.
    #[must_use]
    pub fn resume_point(&self) -> ResumePoint {
        self.point
    }

    /// Whether the consumer's state holds every change that was committed before the current stream's last claim: true
    /// from [`Event::CaughtUp`] until the next [`Event::Resync`], [`Event::Interrupted`] or dropped call of
    /// [`Watch::next`], and false before the first. It has no age: a reader that fails closed uses
    /// [`Watch::caught_up_within`], or [`Watch::confirmation`] on another task.
    #[must_use]
    pub fn caught_up(&self) -> bool {
        self.claim.caught_up()
    }

    /// See [`Confirmation::last_claim`].
    #[must_use]
    pub fn last_claim(&self) -> Option<std::time::Instant> {
        self.claim.last_claim()
    }

    /// See [`Confirmation::caught_up_within`].
    #[must_use]
    pub fn caught_up_within(&self, max_age: Duration) -> bool {
        self.claim.caught_up_within(max_age)
    }

    /// A handle for a reader on another task: the confirmation and the age of the last claim, read at the moment the
    /// reader answers. The watch task keeps calling [`Watch::next`]; the reader holds this.
    #[must_use]
    pub fn confirmation(&self) -> Confirmation {
        self.claim.clone()
    }

    /// The next event. It waits for one: a change, a bookmark, or the report of a failure that it is recovering from.
    ///
    /// # Errors
    ///
    /// The error that ended the watch (see the module), then [`Error::Closed`] for every later call.
    pub async fn next(&mut self) -> Result<Event<K>, Error> {
        if self.closed {
            return Err(Error::Closed);
        }
        let called = Instant::now();
        let slow = self
            .returned_at
            .is_some_and(|t| called.saturating_duration_since(t) > self.slow_consumer);
        let r = self.step(slow).await;
        match &r {
            Ok(_) => self.returned_at = Some(Instant::now()),
            Err(_) => {
                self.closed = true;
                self.stream = None;
                self.claim.unconfirm();
            }
        }
        r
    }

    async fn step(&mut self, slow: bool) -> Result<Event<K>, Error> {
        loop {
            if let Some(at) = self.retry_at {
                tokio::time::sleep_until(at).await;
                self.retry_at = None;
            }
            if !self.synced {
                match self.list().await {
                    Ok(ev) => return Ok(ev),
                    Err(e) if retryable(&e) => return self.interrupted(&e),
                    Err(e) => return Err(e),
                }
            }
            let Some(mut stream) = self.stream.take() else {
                // Every message of the stream is made after this call starts: its time is the lower bound of the first claim.
                let before_open = Instant::now();
                match self.open().await {
                    Ok(s) => {
                        self.stream = Some(s);
                        self.opened = Some(before_open);
                        self.waited = Duration::ZERO;
                        continue;
                    }
                    Err(e) if expired(&e) => {
                        self.expire();
                        continue;
                    }
                    Err(e) if retryable(&e) => return self.interrupted(&e),
                    Err(e) => return Err(e),
                }
            };
            // The stream is out of `self` while it is read: a dropped future leaves none, and the next call
            // reconnects from `point`, which only moves in the same step that returns the event.
            // The confirmation goes with the stream: a future that is dropped while it waits for a message takes the stream
            // with it, and the guard takes the confirmation, so the stream that replaces it must say it itself. (The
            // reader on another task sees the confirmation while the call waits, which is the state of the stream.)
            let mut guard = Unconfirm {
                claim: self.claim.clone(),
                armed: true,
            };
            let confirmed = self.claim.caught_up();
            // A stream that is not caught up has a deadline for it, counted over the time spent waiting.
            let (limit, stall) = if confirmed {
                (self.idle_timeout, false)
            } else {
                let left = self.catch_up_timeout.saturating_sub(self.waited);
                (left.min(self.idle_timeout), left <= self.idle_timeout)
            };
            let started = Instant::now();
            let read = tokio::time::timeout(limit, stream.message::<WatchResponse>()).await;
            guard.armed = false;
            self.waited += started.elapsed();
            match read {
                Err(_) if stall => return self.interrupted_by("catch-up stalled"),
                Err(_) => return self.interrupted_by("no bookmark"),
                Ok(Ok(Some(m))) => {
                    self.stream = Some(stream);
                    let before = self.point.sequence;
                    if let Some(ev) = self.apply(&m.to_owned_message())? {
                        if self.point.sequence > before {
                            // Progress toward the claim, whatever the event.
                            self.waited = Duration::ZERO;
                        }
                        if matches!(ev, Event::CaughtUp { .. }) {
                            self.dated_claim(slow);
                        }
                        // The failures are over when a change shows the log is being read, or when a stream that said
                        // it was caught up has stayed up: a stream that says so and dies at once is a failure, and
                        // the loop of them backs off to the cap and reaches `give_up_after`.
                        let change = matches!(ev, Event::Put { .. } | Event::Delete { .. });
                        let stable = self.claim.caught_up()
                            && self
                                .opened
                                .is_some_and(|t| t.elapsed() >= self.stable_after);
                        if change || stable {
                            self.attempt = 0;
                            self.failing_since = None;
                        }
                        // A store that alternates a bookmark and an expired point is still backed off: only a
                        // change shows that the log is being read.
                        if !matches!(ev, Event::Bookmark { .. } | Event::CaughtUp { .. }) {
                            self.expiries = 0;
                        }
                        return Ok(ev);
                    }
                }
                Ok(Ok(None)) => return self.interrupted_by("stream ended"),
                Ok(Err(e)) => {
                    let e = Error::from(e);
                    if expired(&e) {
                        self.expire();
                    } else if retryable(&e) {
                        return self.interrupted(&e);
                    } else {
                        return Err(e);
                    }
                }
            }
        }
    }

    /// Dates the claim that was just read. The first of a stream is dated by the moment the stream was opened, which every
    /// message of it follows. A renewal is dated by now, unless the consumer was slow with the event before: what it reads
    /// then may have waited in the stream's queue, and the claim keeps the date of the one before.
    fn dated_claim(&self, slow: bool) {
        let mut c = self.claim.lock();
        match c.at {
            None => c.at = self.opened,
            Some(_) if !slow => c.at = Some(Instant::now()),
            Some(_) => {}
        }
    }

    /// The listing: every page, then the event. The position is the one the first page names.
    async fn list(&mut self) -> Result<Event<K>, Error> {
        let mut items = Vec::new();
        let mut point = None;
        let mut page = None;
        for _ in 0..MAX_PAGES {
            let p = self.store.list_page(&self.tenant, page).await?;
            point.get_or_insert(p.resume_point);
            items.extend(p.items);
            match p.next {
                Some(n) => page = Some(n),
                None => {
                    // A kind that nobody may watch has no log, and names no position and no epoch (0 and 0): it is
                    // refused. A log that names an epoch and position 0 breaks the contract of the engines (a log starts
                    // with a marker row, so its head is never 0, store-api.md): a watch from 0 would start "from now" and
                    // lose what changed since the listing, so the loop never builds on it, and says what is wrong.
                    let resume_point = point.unwrap_or_default();
                    if resume_point == ResumePoint::default() {
                        return Err(Error::NotWatchable);
                    }
                    if resume_point.sequence == 0 {
                        return Err(Error::Protocol(
                            "a listing names a log epoch and no position: the log has no marker row",
                        ));
                    }
                    // A position with no epoch could be the same number in another log after a restore: the loop
                    // never builds on one.
                    if resume_point.epoch == 0 {
                        return Err(Error::Protocol(
                            "a listing names a resume point with no log epoch",
                        ));
                    }
                    self.point = resume_point;
                    self.synced = true;
                    self.attempt = 0;
                    self.failing_since = None;
                    return Ok(Event::Resync {
                        cause: self.cause,
                        items,
                        resume_point,
                    });
                }
            }
        }
        Err(Error::Protocol("list: more pages than the limit"))
    }

    async fn open(&self) -> Result<Stream, Error> {
        let req = WatchRequest {
            kind: self.store.segment.to_owned(),
            tenant: self.wire_tenant.clone(),
            resume_point: self.point.sequence,
            log_epoch: self.point.epoch,
            ..WatchRequest::default()
        };
        Ok(self.store.client.watch(req).await?)
    }

    /// The point is gone: list again, after a wait when this keeps happening.
    fn expire(&mut self) {
        self.claim.unconfirm();
        self.synced = false;
        self.cause = ResyncCause::Expired;
        self.retry_after(self.backoff.delay(self.expiries));
        self.expiries = self.expiries.saturating_add(1);
    }

    fn retry_after(&mut self, wait: Duration) {
        self.retry_at = (!wait.is_zero()).then(|| Instant::now() + wait);
    }

    fn interrupted(&mut self, e: &Error) -> Result<Event<K>, Error> {
        self.interrupted_by(&e.to_string())
    }

    /// Reports a failure, or gives up when the failures have gone on for too long.
    fn interrupted_by(&mut self, reason: &str) -> Result<Event<K>, Error> {
        self.stream = None;
        self.claim.unconfirm();
        let since = *self.failing_since.get_or_insert_with(Instant::now);
        if self.give_up_after.is_some_and(|d| since.elapsed() >= d) {
            return Err(Error::GaveUp);
        }
        self.attempt = self.attempt.saturating_add(1);
        self.retry_after(self.backoff.delay(self.attempt));
        Ok(Event::Interrupted {
            reason: reason.to_owned(),
            attempt: self.attempt,
        })
    }

    /// One message of the stream: an event, `None` for a repeat or for a stream that is given up, or the error that ends
    /// the watch.
    fn apply(&mut self, m: &WatchResponse) -> Result<Option<Event<K>>, Error> {
        let seq = m.resume_point;
        // Every message names the epoch of the log the stream follows, and it is the one the stream was opened under.
        // Another one is a log made again under a stream that went on: its sequence is not comparable with the applied
        // one, so nothing of it is applied or dropped as a repeat; the stream ends and the kind is listed again.
        if m.log_epoch != self.point.epoch {
            self.stream = None;
            self.expire();
            return Ok(None);
        }
        match m.r#type.as_known() {
            Some(ChangeType::CHANGE_TYPE_BOOKMARK) if m.caught_up => {
                // The head read at the opening is never below the point the stream started from, and the stream
                // delivers nothing past it before this message: a head below the applied point is a claim made
                // about something else.
                if seq < self.point.sequence {
                    return Err(Error::Protocol("caught up below the applied point"));
                }
                self.point.sequence = seq;
                self.claim.lock().confirmed = true;
                Ok(Some(Event::CaughtUp {
                    resume_point: self.point,
                }))
            }
            Some(ChangeType::CHANGE_TYPE_BOOKMARK) => {
                // The point never goes back, and a bookmark is said even when it names the same point.
                self.point.sequence = self.point.sequence.max(seq);
                Ok(Some(Event::Bookmark {
                    resume_point: self.point,
                }))
            }
            Some(t @ (ChangeType::CHANGE_TYPE_PUT | ChangeType::CHANGE_TYPE_DELETE)) => {
                // Only a bookmark makes the claim.
                if m.caught_up {
                    return Err(Error::Protocol("a change that says caught up"));
                }
                // A kind with a log has a sequence for every change; without one there is nothing to dedupe by.
                if seq == 0 {
                    return Err(Error::Protocol("a change with no log sequence"));
                }
                // A repeat: the same epoch, checked above, and a sequence at or below the applied one.
                if seq <= self.point.sequence {
                    return Ok(None);
                }
                let wire = m
                    .item
                    .as_option()
                    .ok_or(Error::Protocol("a change with no item"))?;
                self.check_address(wire)?;
                let resume_point = ResumePoint {
                    epoch: m.log_epoch,
                    sequence: seq,
                };
                let ev = if t == ChangeType::CHANGE_TYPE_PUT {
                    Event::Put {
                        item: self.store.item(wire)?,
                        resume_point,
                    }
                } else {
                    Event::Delete {
                        tenant: wire.address.tenant.clone(),
                        id: wire.address.id.clone(),
                        version: wire.version,
                        resume_point,
                    }
                };
                self.point = resume_point;
                Ok(Some(ev))
            }
            _ => Err(Error::Protocol("an unknown type of change")),
        }
    }

    /// The change is about the kind and tenant that were asked for.
    fn check_address(&self, wire: &WireItem) -> Result<(), Error> {
        let a = wire
            .address
            .as_option()
            .ok_or(Error::Protocol("a change with no address"))?;
        if a.kind != self.store.segment || a.tenant != self.wire_tenant {
            return Err(Error::Protocol("a change of another kind or tenant"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_backoff_doubles_from_the_initial_wait_up_to_the_maximum() {
        let b = Backoff {
            initial: Duration::from_millis(100),
            max: Duration::from_millis(700),
        };
        let ms: Vec<u128> = (0..6).map(|n| b.delay(n).as_millis()).collect();
        assert_eq!(ms, [0, 100, 200, 400, 700, 700]);
        // A long outage cannot overflow the shift or the product.
        assert_eq!(b.delay(u32::MAX), Duration::from_millis(700));
    }

    #[test]
    fn the_backoff_is_never_a_busy_loop_and_never_shorter_than_its_first_wait() {
        let zero = Backoff {
            initial: Duration::ZERO,
            max: Duration::ZERO,
        };
        assert_eq!(zero.delay(0), Duration::ZERO);
        assert_eq!(zero.delay(1), Duration::from_millis(1));
        assert_eq!(zero.delay(5), Duration::from_millis(1));
        let inverted = Backoff {
            initial: Duration::from_secs(2),
            max: Duration::from_secs(1),
        };
        assert_eq!(inverted.delay(3), Duration::from_secs(2));
    }

    #[test]
    fn only_a_failure_of_the_store_is_retried() {
        use connectrpc::ConnectError;
        let e = |c| Error::from(ConnectError::new(c, "x"));
        for c in [
            ErrorCode::Unavailable,
            ErrorCode::Unknown,
            ErrorCode::Internal,
            ErrorCode::DeadlineExceeded,
            ErrorCode::ResourceExhausted,
        ] {
            assert!(retryable(&e(c)), "{c:?}");
        }
        for c in [
            ErrorCode::PermissionDenied,
            ErrorCode::Unauthenticated,
            ErrorCode::InvalidArgument,
            ErrorCode::Unimplemented,
            ErrorCode::FailedPrecondition,
        ] {
            assert!(!retryable(&e(c)), "{c:?}");
        }
        assert!(!retryable(&Error::Decode));
        assert!(!retryable(&Error::NotWatchable));
        assert!(!retryable(&Error::Protocol("x")));
    }
}
