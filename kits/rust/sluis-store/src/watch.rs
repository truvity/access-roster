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
//! - **Events.** A [`Event::Put`] is the item as store@ read it at delivery, an [`Event::Delete`] is its address
//!   and the version of the row (an expiry is a delete), and an [`Event::Bookmark`] is the latest resume point of
//!   an idle stream (every 30 seconds): a sign of life, and a point a restart can use.
//! - **At-least-once, in the order of the log.** A change at or below the point already applied is a repeat and is
//!   dropped here, so a consumer sees each sequence once and in order.
//! - **A resync is an event.** When store@ no longer holds the resume point (the change log is kept for a bounded
//!   window), or has not reached it, the loop lists the kind again and says [`Event::Resync`] with the whole
//!   state, `cause` [`ResyncCause::Expired`]. A consumer *replaces* its state with the items; it never applies
//!   changes it did not see. The loop never skips from one point to a later one without saying so.
//! - **A broken stream is an event too.** A stream that ends or fails, and a store@ that is down, give
//!   [`Event::Interrupted`] and the loop reconnects from the last point with an exponential [`Backoff`]. Until the
//!   next event of any kind arrives (a bookmark at the latest) the consumer's state is *unconfirmed*: a reader
//!   that fails closed (REQ-KEYS-107's "not revoked" is a claim to verify) stops answering from it, and carries on
//!   when events come again.
//! - **It fails closed.** An item that does not decode, a change that is not well formed, a refusal that a retry
//!   cannot cure (`permission_denied`, `invalid_argument`, `failed_precondition` other than an expired point,
//!   `unimplemented`, ...) and a kind that has no change log end the watch with an [`Error`]; after it every call
//!   gives [`Error::Closed`]. The consumer starts a new watch (which lists again) or reports itself broken.
//!
//! The loop is pulled: nothing runs between calls of [`Watch::next`], and there is no buffer beyond the stream
//! (HTTP/2 flow control is the backpressure, as store-api.md says). Dropping the [`Watch`] ends the stream; dropping
//! the future of [`Watch::next`] drops the stream too, and the next call reconnects from the last point, so no event
//! is lost either way. Run it in a task of its own, started outside a request handler: a call made from a handler
//! carries the handler's deadline (contracts.md "Every call"), which would cut the stream short.

use std::time::Duration;

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

/// How long the loop waits before it tries again after a failure: `initial` for the first retry, doubled for each
/// further one, never more than `max`. A message received resets it.
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
            n => self
                .initial
                .saturating_mul(1u32 << (n - 1).min(20))
                .min(self.max),
        }
    }
}

/// What a watch starts from, and how it retries.
#[derive(Clone, Copy, Debug, Default)]
pub struct WatchOpts {
    /// The resume point the caller last applied (a persisted cursor, or the point of an event). `None` and `Some(0)`
    /// list the kind first: a watch from 0 starts "from now" in store@ and would lose what changed since, so it is
    /// not offered.
    pub from: Option<u64>,
    /// The wait between retries.
    pub backoff: Backoff,
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
        resume_point: u64,
    },
    /// The item was written; this is its state at delivery.
    Put {
        /// The item.
        item: Item<K>,
        /// The log sequence of the change: the resume point after it.
        resume_point: u64,
    },
    /// The item was removed or expired.
    Delete {
        /// The tenant of the item; empty for a kind with none.
        tenant: String,
        /// The id of the item.
        id: String,
        /// The version of the row that was removed.
        version: u64,
        /// The log sequence of the change.
        resume_point: u64,
    },
    /// No change: the latest resume point of a stream that has been idle. A sign of life.
    Bookmark {
        /// The latest point.
        resume_point: u64,
    },
    /// The stream broke or store@ could not be reached; the loop reconnects (from the last point) after the backoff.
    /// The consumer's state is unconfirmed until the next event.
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
    pub fn resume_point(&self) -> Option<u64> {
        match self {
            Event::Resync { resume_point, .. }
            | Event::Put { resume_point, .. }
            | Event::Delete { resume_point, .. }
            | Event::Bookmark { resume_point } => Some(*resume_point),
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
            Event::Interrupted { reason, attempt } => f
                .debug_struct("Interrupted")
                .field("reason", reason)
                .field("attempt", attempt)
                .finish(),
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
    /// The log sequence last applied. 0 until the first listing, unless the caller gave a point.
    point: u64,
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
    /// The wait before the next try, set when a failure is reported.
    wait: Duration,
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
        let from = opts.from.filter(|p| *p != 0);
        Ok(Watch {
            store: self.clone(),
            tenant: tenant.to_owned(),
            wire_tenant,
            backoff: opts.backoff,
            point: from.unwrap_or(0),
            synced: from.is_some(),
            cause: ResyncCause::Start,
            stream: None,
            attempt: 0,
            expiries: 0,
            wait: Duration::ZERO,
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
    /// The log sequence the consumer has been told of: where a restart may resume. 0 before the first listing.
    #[must_use]
    pub fn resume_point(&self) -> u64 {
        self.point
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
        let r = self.step().await;
        if r.is_err() {
            self.closed = true;
            self.stream = None;
        }
        r
    }

    async fn step(&mut self) -> Result<Event<K>, Error> {
        loop {
            if !self.wait.is_zero() {
                tokio::time::sleep(std::mem::take(&mut self.wait)).await;
            }
            if !self.synced {
                match self.list().await {
                    Ok(ev) => return Ok(ev),
                    Err(e) if retryable(&e) => return Ok(self.interrupted(&e)),
                    Err(e) => return Err(e),
                }
            }
            let Some(mut stream) = self.stream.take() else {
                match self.open().await {
                    Ok(s) => {
                        self.stream = Some(s);
                        continue;
                    }
                    Err(e) if expired(&e) => {
                        self.expire();
                        continue;
                    }
                    Err(e) if retryable(&e) => return Ok(self.interrupted(&e)),
                    Err(e) => return Err(e),
                }
            };
            // The stream is out of `self` while it is read: a dropped future leaves none, and the next call
            // reconnects from `point`, which only moves in the same step that returns the event.
            match stream.message::<WatchResponse>().await {
                Ok(Some(m)) => {
                    self.stream = Some(stream);
                    self.attempt = 0;
                    self.expiries = 0;
                    if let Some(ev) = self.apply(&m.to_owned_message())? {
                        return Ok(ev);
                    }
                }
                Ok(None) => return Ok(self.interrupted_by("stream ended")),
                Err(e) => {
                    let e = Error::from(e);
                    if expired(&e) {
                        self.expire();
                    } else if retryable(&e) {
                        return Ok(self.interrupted(&e));
                    } else {
                        return Err(e);
                    }
                }
            }
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
                    // A kind that nobody may watch has no log, and names 0: a watch from it would start "from now"
                    // and lose what changed since the listing, so it is refused.
                    let resume_point = point.filter(|p| *p != 0).ok_or(Error::NotWatchable)?;
                    self.point = resume_point;
                    self.synced = true;
                    self.attempt = 0;
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
            resume_point: self.point,
            ..WatchRequest::default()
        };
        Ok(self.store.client.watch(req).await?)
    }

    /// The point is gone: list again, after a wait when this keeps happening.
    fn expire(&mut self) {
        self.synced = false;
        self.cause = ResyncCause::Expired;
        self.wait = self.backoff.delay(self.expiries);
        self.expiries = self.expiries.saturating_add(1);
    }

    fn interrupted(&mut self, e: &Error) -> Event<K> {
        self.interrupted_by(&e.to_string())
    }

    fn interrupted_by(&mut self, reason: &str) -> Event<K> {
        self.stream = None;
        self.attempt = self.attempt.saturating_add(1);
        self.wait = self.backoff.delay(self.attempt);
        Event::Interrupted {
            reason: reason.to_owned(),
            attempt: self.attempt,
        }
    }

    /// One message of the stream: an event, `None` for a repeat, or the error that ends the watch.
    fn apply(&mut self, m: &WatchResponse) -> Result<Option<Event<K>>, Error> {
        let seq = m.resume_point;
        match m.r#type.as_known() {
            Some(ChangeType::CHANGE_TYPE_BOOKMARK) => {
                // The point never goes back, and a bookmark is said even when it names the same point.
                self.point = self.point.max(seq);
                Ok(Some(Event::Bookmark {
                    resume_point: self.point,
                }))
            }
            Some(t @ (ChangeType::CHANGE_TYPE_PUT | ChangeType::CHANGE_TYPE_DELETE)) => {
                // A kind with a log has a sequence for every change; without one there is nothing to dedupe by.
                if seq == 0 {
                    return Err(Error::Protocol("a change with no log sequence"));
                }
                if seq <= self.point {
                    return Ok(None);
                }
                let wire = m
                    .item
                    .as_option()
                    .ok_or(Error::Protocol("a change with no item"))?;
                self.check_address(wire)?;
                let ev = if t == ChangeType::CHANGE_TYPE_PUT {
                    Event::Put {
                        item: self.store.item(wire)?,
                        resume_point: seq,
                    }
                } else {
                    Event::Delete {
                        tenant: wire.address.tenant.clone(),
                        id: wire.address.id.clone(),
                        version: wire.version,
                        resume_point: seq,
                    }
                };
                self.point = seq;
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
