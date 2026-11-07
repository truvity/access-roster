//! `Watch` (ADR 0005 "Watch and the resume point"; store-api.md "Watch"): the Kubernetes list-watch contract.
//!
//! - A watcher lists (`List` answers with a `resume_point`), then watches from that point. A watch from 0 starts
//!   from now.
//! - A change carries the address, the type, the version and its log sequence (the resume point after it). The
//!   value is read when the change is delivered (level-triggered): a watcher applies state, not edits. A version is
//!   not an identity, because a re-created item starts again at 1: consumers dedupe by the sequence.
//! - Rows are read in runs. Inside a run a put row is skipped only when a later row of the same address is in the
//!   run, because that row delivers the state. A delete row is never skipped, and an item that is gone is a delete
//!   with no value: a delete and the re-creation that follows it are delivered in that order.
//! - Delivery is at-least-once, in the order of the change log.
//! - store@ buffers nothing beyond the driver's log: the stream is read at the pace of its consumer, and HTTP/2 flow
//!   control is the backpressure. An idle stream says the latest resume point as a bookmark every 30 seconds.
//! - **Caught up.** When a stream opens, store@ reads the head of the change log linearizably. The stream says so with one
//!   bookmark, `caught_up`, as soon as it has delivered every row up to that head: at once when there was nothing to
//!   deliver, after the last row up to the head otherwise, and before any row past it. The claim is made from the rows the
//!   stream has delivered, never from the head alone, so a driver that lags (a deposed leader's weak read of the rows)
//!   delays the bookmark and cannot make it early. An idle bookmark carries no claim.
//! - **The claim is renewed, from the head, every bookmark interval.** A caught-up stream reads the head again,
//!   linearizably, when the interval since its last claim has passed: on a quiet stream at the idle tick, on a busy one
//!   between two runs of rows. If the head is at or below the last row it has dealt with, it sends the `caught_up` bookmark
//!   again, and a reader that gets it in the order of the stream knows that every row before it was consumed and that, at
//!   the read, none was missing. If the read fails or the head is ahead, it sends no claim (a quiet stream sends the plain
//!   idle bookmark); the stream then claims again once it has delivered through that head. So a reader that bounds the age
//!   of the last claim stops trusting a tail that reads from a deposed or isolated node: that tail shows the head ahead, or
//!   the read fails, and the claim is not renewed. The cost is one linearizable read per interval and per watch, and no
//!   audit record. A watch from 0 ("from now") never claims: it was given no point, so there is nothing it could say it
//!   had delivered up to.
//! - A resume point that the change log no longer holds is `failed_precondition` / `resume_point_expired`: the
//!   watcher lists again. A point is a pair, the log's epoch and the sequence: a restore or a reset makes a new log
//!   whose sequence begins again, so a point under another epoch (or under none) is refused the same way, and every
//!   message of a stream names the epoch of the log it follows.
//! - A caller has at most 16 watches at once.
//! - A config kind has no change log: a watch sends the snapshot in force as puts and then a bookmark, and the
//!   watcher replaces its state of the kind with the items before that bookmark; then each item that a swap added,
//!   changed or removed, with resume point 0. A config change has no sequence: the watcher applies every one.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use sluis_proto::sluis::port::item::v2alpha1::{DriverItem, QueryRequest, TailLogResponse};
use sluis_proto::sluis::store::v2alpha1::{ChangeType, Item, WatchResponse};
use sluis_proto::sluis::r#type::v2alpha1::Address;

use crate::config::ConfigSnapshot;
use crate::engine::{EngineError, ItemEngine, LogRows};
use crate::grant::to_system_time;

/// How long a stream may be silent before it says the latest resume point.
pub const BOOKMARK_EVERY: Duration = Duration::from_secs(30);
/// How often a watcher of a config kind looks at the snapshot.
pub const CONFIG_POLL: Duration = Duration::from_millis(250);
/// The most watches one caller holds at once.
pub const MAX_WATCHES_PER_CALLER: usize = 16;

/// The watches that are open, by caller.
#[derive(Clone, Default)]
pub struct Slots(Arc<Mutex<HashMap<String, usize>>>);

/// One open watch of a caller; it is given back when the stream is dropped.
pub struct Slot {
    map: Arc<Mutex<HashMap<String, usize>>>,
    caller: String,
}

impl Slots {
    /// A slot for the caller, or None when it holds [`MAX_WATCHES_PER_CALLER`].
    #[must_use]
    pub fn take(&self, caller: &str) -> Option<Slot> {
        let mut m = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let n = m.entry(caller.to_owned()).or_insert(0);
        if *n >= MAX_WATCHES_PER_CALLER {
            return None;
        }
        *n += 1;
        Some(Slot {
            map: Arc::clone(&self.0),
            caller: caller.to_owned(),
        })
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        let mut m = self
            .map
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(n) = m.get_mut(&self.caller) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                m.remove(&self.caller);
            }
        }
    }
}

/// What one call of a stream ends with.
#[derive(Debug, PartialEq, Eq)]
pub enum Ended {
    /// The change log no longer holds the resume point.
    Expired,
    /// The engine failed or ended its stream: store@ fails closed.
    Engine,
}

impl From<EngineError> for Ended {
    fn from(e: EngineError) -> Self {
        match e {
            EngineError::SequenceExpired => Ended::Expired,
            EngineError::Aborted(_) | EngineError::Unavailable => Ended::Engine,
        }
    }
}

fn bookmark(resume_point: u64, log_epoch: u64) -> WatchResponse {
    WatchResponse {
        resume_point,
        log_epoch,
        r#type: ChangeType::CHANGE_TYPE_BOOKMARK.into(),
        ..WatchResponse::default()
    }
}

/// The bookmark that says the stream has delivered every change up to the head read at its opening.
fn caught_up_bookmark(head: u64, log_epoch: u64) -> WatchResponse {
    WatchResponse {
        caught_up: true,
        ..bookmark(head, log_epoch)
    }
}

/// What a wait for rows came to.
enum Read {
    /// A run of rows of this watch to deliver.
    Rows,
    /// Rows were read, none of them for this watch: the position moved.
    Moved,
    /// Nothing came before the idle deadline.
    Idle,
    /// Nothing came before the time to renew the claim, which is before the idle deadline.
    Tick,
}

/// The address a key stands for: `<boundary>/<tenant|->/<kind>/<id>`. None when it is not this boundary's.
fn address_of(boundary: &str, key: &[u8]) -> Option<Address> {
    let text = std::str::from_utf8(key).ok()?;
    let mut it = text.splitn(4, '/');
    let (b, t, k, id) = (it.next()?, it.next()?, it.next()?, it.next()?);
    if b != boundary {
        return None;
    }
    Some(Address {
        kind: k.to_owned(),
        tenant: if t == "-" {
            String::new()
        } else {
            t.to_owned()
        },
        id: id.to_owned(),
        ..Address::default()
    })
}

/// The head of the log and its epoch, read linearizably, with the page of one item that the query gives (the prefix is
/// the watch's). A read that cannot be made at that level fails: it is never answered at a weaker one.
///
/// # Errors
///
/// [`EngineError`] when the engine fails.
pub async fn read_head<E: ItemEngine>(
    engine: &E,
    prefix: &[u8],
) -> Result<(u64, u64), EngineError> {
    let q = QueryRequest {
        prefix: prefix.to_vec(),
        page_size: 1,
        linearizable: true,
        ..QueryRequest::default()
    };
    let r = engine.query(q).await?;
    Ok((r.log_head, r.log_epoch))
}

/// The rows of a run: read together, so that a row a later one supersedes is not read twice.
const RUN_MAX: usize = 256;

/// The stream of the changes of an item kind.
pub struct LogWatch<E> {
    engine: E,
    boundary: String,
    /// The keys watched: the kind (and the tenant, and the caller's own ids) as a key prefix.
    prefix: Vec<u8>,
    now: Arc<dyn Fn() -> SystemTime + Send + Sync>,
    bookmark_every: Duration,
    rows: LogRows,
    /// The epoch of the log the stream follows: on every message, so that a consumer's applied point is a pair.
    epoch: u64,
    /// The head of the log that store@ read, linearizably, when the stream opened (or at a renewal that found the head
    /// ahead of the stream), until the stream has delivered through it and said so (the `caught_up` bookmark).
    catching_up: Option<u64>,
    /// Whether the stream makes the claim at all: not a watch from 0 ("from now"), which was given no point.
    claims: bool,
    /// The sequence of the last row dealt with (the start position before any): what a bookmark says.
    last: u64,
    /// The rows of the run being delivered: the row, its address, and whether a later row of the address follows
    /// in the run.
    run: VecDeque<(TailLogResponse, Address, bool)>,
    /// The sequence of the last row read into the run, a row of another kind included: where the run ends.
    run_end: u64,
    /// An error the driver said after the rows of a run: it ends the stream once those rows are delivered.
    pending: Option<EngineError>,
    deadline: tokio::time::Instant,
    /// When the claim is next renewed: the bookmark interval after the last claim or the last attempt to renew it. A stream
    /// that changes more often than the interval is renewed too, between its messages.
    renew_at: tokio::time::Instant,
    /// Held for the life of the stream.
    _slot: Slot,
}

impl<E: ItemEngine> LogWatch<E> {
    /// A stream that reads `rows` (opened at `start`, under `epoch`). `head` is the head of the log read when the stream
    /// opened, which the `caught_up` bookmark names once the stream has delivered through it; it is never below `start`.
    /// `claims` is false for a watch from 0 ("from now"): it says no `caught_up` at all.
    #[allow(clippy::too_many_arguments)] // the parts of one stream, named at the one call
    pub fn new(
        engine: E,
        boundary: String,
        prefix: Vec<u8>,
        now: Arc<dyn Fn() -> SystemTime + Send + Sync>,
        bookmark_every: Duration,
        rows: LogRows,
        start: u64,
        head: u64,
        epoch: u64,
        claims: bool,
        slot: Slot,
    ) -> Self {
        Self {
            engine,
            boundary,
            prefix,
            now,
            bookmark_every,
            rows,
            epoch,
            catching_up: claims.then_some(head),
            claims,
            last: start,
            run: VecDeque::new(),
            run_end: start,
            pending: None,
            deadline: tokio::time::Instant::now() + bookmark_every,
            renew_at: tokio::time::Instant::now() + bookmark_every,
            _slot: slot,
        }
    }

    fn expired(&self, item: &DriverItem) -> bool {
        item.expires_at
            .as_option()
            .and_then(to_system_time)
            .is_some_and(|e| e <= (self.now)())
    }

    fn wire(address: Address, item: &DriverItem) -> Item {
        Item {
            address: address.into(),
            version: item.version,
            value: item.value.clone(),
            expires_at: item.expires_at.as_option().cloned().into(),
            indexes: item.indexes.clone(),
            ..Item::default()
        }
    }

    /// Takes a row of the log into the run, or drops it when it is not about this watch. A row of another kind,
    /// another tenant, another boundary or the marker row is not an error: it only moves the position.
    ///
    /// The rows of a log come in increasing order, and the claim rests on it (a row delivered at or after the head is
    /// past it): a row at or below the one before ends the stream, as an engine that breaks its contract.
    fn take(
        &mut self,
        row: TailLogResponse,
        run: &mut Vec<(TailLogResponse, Address)>,
    ) -> Result<(), Ended> {
        if row.sequence <= self.run_end {
            return Err(Ended::Engine);
        }
        self.run_end = row.sequence;
        if row.key.starts_with(&self.prefix)
            && let Some(address) = address_of(&self.boundary, &row.key)
        {
            run.push((row, address));
        }
        Ok(())
    }

    /// Waits for the next row, then takes the rows that are there already, up to a run.
    async fn read_run(&mut self) -> Result<Read, Ended> {
        // The run before is delivered: the position is past every row it read, its last one included.
        self.last = self.last.max(self.run_end);
        if let Some(e) = self.pending.take() {
            return Err(e.into());
        }
        // A caught-up stream that claims also wakes for the renewal, which comes before the idle deadline.
        let until = if self.claims && self.catching_up.is_none() {
            self.deadline.min(self.renew_at)
        } else {
            self.deadline
        };
        let first = match tokio::time::timeout_at(until, self.rows.recv()).await {
            Err(_) if tokio::time::Instant::now() >= self.deadline => return Ok(Read::Idle),
            Err(_) => return Ok(Read::Tick),
            // The driver ended its stream: the watcher resumes from its point.
            Ok(None) => return Err(Ended::Engine),
            Ok(Some(Err(e))) => return Err(e.into()),
            Ok(Some(Ok(row))) => row,
        };
        let mut run = Vec::new();
        self.take(first, &mut run)?;
        while run.len() < RUN_MAX {
            match self.rows.try_recv() {
                Ok(Ok(row)) => self.take(row, &mut run)?,
                // An error after rows: the rows are delivered first, and the error ends the stream after them.
                Ok(Err(e)) => {
                    self.pending = Some(e);
                    break;
                }
                // Nothing more is there yet; a closed stream is seen by the next wait.
                Err(_) => break,
            }
        }
        if run.is_empty() {
            // Rows of other kinds only: the position moved, and the stream may have reached the head it was
            // opened at.
            return Ok(Read::Moved);
        }
        // A put row is superseded when a later row of the same address is in the run. While the stream is catching
        // up to the head it was opened at, a row up to the head is superseded only by a later row up to the head:
        // the state a skipped row stands for is delivered by the row that supersedes it, and that must come before
        // the caught-up bookmark, which claims every change up to the head. A later row past the head would
        // deliver it after the claim.
        let bound = self.catching_up.unwrap_or(u64::MAX);
        let mut last_any: HashMap<&[u8], usize> = HashMap::new();
        let mut last_to_bound: HashMap<&[u8], usize> = HashMap::new();
        for (i, (row, _)) in run.iter().enumerate() {
            last_any.insert(row.key.as_slice(), i);
            if row.sequence <= bound {
                last_to_bound.insert(row.key.as_slice(), i);
            }
        }
        let superseded: Vec<bool> = run
            .iter()
            .enumerate()
            .map(|(i, (row, _))| {
                let last = if row.sequence <= bound {
                    &last_to_bound
                } else {
                    &last_any
                };
                last.get(row.key.as_slice()).is_some_and(|l| *l > i)
            })
            .collect();
        self.run = run
            .into_iter()
            .zip(superseded)
            .map(|((row, address), later)| (row, address, later))
            .collect();
        Ok(Read::Rows)
    }

    /// The `caught_up` bookmark, once, when every row up to the head read at the opening has been dealt with: the next row
    /// to deliver is past the head (the rows are in the order of the log), or none is waiting and the position is. Never
    /// from the head alone: a log that lags has not yet shown the rows, and the stream waits for them.
    fn caught_up(&mut self) -> Option<WatchResponse> {
        let head = self.catching_up?;
        let reached = match self.run.front() {
            Some((row, _, _)) => row.sequence > head,
            None => self.last.max(self.run_end) >= head,
        };
        if !reached {
            return None;
        }
        self.catching_up = None;
        Some(caught_up_bookmark(head, self.epoch))
    }

    /// The position the stream has dealt with: the last row delivered, or the last row read when none is waiting.
    fn position(&self) -> u64 {
        if self.run.is_empty() {
            self.last.max(self.run_end)
        } else {
            self.last
        }
    }

    /// Whether the claim is due for renewal: the stream claims, has said it is caught up, and the interval since its last
    /// claim or attempt has passed.
    fn renewal_due(&self) -> bool {
        self.claims && self.catching_up.is_none() && tokio::time::Instant::now() >= self.renew_at
    }

    /// Renews the claim, if it is due, from a new linearizable read of the head. The head at or below the position the
    /// stream has dealt with: the claim again, in the order of the stream. A head that is ahead: the stream waits for the
    /// rows and the claim follows them, as at the opening. A read that fails: nothing, and the reader's bound on the age
    /// of the claim runs out. A log made again under the stream ends it. Done between runs, so the claim sits after every
    /// row delivered and before any row not yet.
    async fn renew(&mut self) -> Result<Option<WatchResponse>, Ended> {
        if !self.renewal_due() {
            return Ok(None);
        }
        self.renew_at = tokio::time::Instant::now() + self.bookmark_every;
        match read_head(&self.engine, &self.prefix).await {
            Ok((head, epoch)) if epoch == self.epoch => {
                let position = self.position();
                if head <= position {
                    return Ok(Some(caught_up_bookmark(position, self.epoch)));
                }
                self.catching_up = Some(head);
                Ok(None)
            }
            // The log was made again under the stream: its rows are not the ones this stream follows.
            Ok(_) => Err(Ended::Expired),
            Err(_) => Ok(None),
        }
    }

    /// The next message: a change, or a bookmark after a silence. `Err` ends the stream.
    ///
    /// # Errors
    ///
    /// [`Ended`] when the log no longer holds the point or the engine failed.
    pub async fn next(&mut self) -> Result<WatchResponse, Ended> {
        loop {
            if let Some(m) = self.caught_up() {
                let now = tokio::time::Instant::now();
                self.deadline = now + self.bookmark_every;
                self.renew_at = now + self.bookmark_every;
                return Ok(m);
            }
            // Between runs, when the interval has passed: a stream that changes more often than the interval is renewed too.
            if self.run.is_empty()
                && let Some(m) = self.renew().await?
            {
                self.deadline = tokio::time::Instant::now() + self.bookmark_every;
                return Ok(m);
            }
            let Some((row, address, later)) = self.run.pop_front() else {
                if let Read::Idle = self.read_run().await? {
                    self.deadline = tokio::time::Instant::now() + self.bookmark_every;
                    // A silence: the renewal if it is due (it is, unless the stream is waiting for rows), else the plain
                    // idle bookmark, a sign of life that proves nothing.
                    if let Some(m) = self.renew().await? {
                        return Ok(m);
                    }
                    return Ok(bookmark(self.last, self.epoch));
                }
                continue;
            };
            self.last = row.sequence;
            let message = if row.deleted {
                // A delete row is delivered whatever the item is now: if it was made again, its put row is later in
                // the log and follows.
                gone(row.sequence, self.epoch, row.version, address)
            } else if later {
                // The state comes with the later row of the address.
                continue;
            } else {
                let current = self
                    .engine
                    .get(row.key.clone(), true)
                    .await
                    .map_err(Ended::from)?
                    .filter(|i| !self.expired(i));
                match current {
                    // Gone since the row was written (removed or expired): a delete, with no value.
                    None => gone(row.sequence, self.epoch, row.version, address),
                    Some(item) => WatchResponse {
                        resume_point: row.sequence,
                        log_epoch: self.epoch,
                        r#type: ChangeType::CHANGE_TYPE_PUT.into(),
                        item: Self::wire(address, &item).into(),
                        ..WatchResponse::default()
                    },
                }
            };
            self.deadline = tokio::time::Instant::now() + self.bookmark_every;
            return Ok(message);
        }
    }
}

/// A delete: the address and the version of the row, no value.
fn gone(sequence: u64, log_epoch: u64, version: u64, address: Address) -> WatchResponse {
    WatchResponse {
        resume_point: sequence,
        log_epoch,
        r#type: ChangeType::CHANGE_TYPE_DELETE.into(),
        item: Item {
            address: address.into(),
            version,
            ..Item::default()
        }
        .into(),
        ..WatchResponse::default()
    }
}

/// The stream of a config kind: the snapshot in force as puts and a bookmark that closes it, then each item that a
/// swap of the snapshot added, changed or removed, with resume point 0 (a config kind has no change log; a watcher
/// that reconnects reads the kind again). A watcher replaces its state of the kind with the items before the first
/// bookmark, and applies every later change: a config change has no sequence to dedupe by.
pub struct ConfigWatch {
    config: Arc<dyn ConfigSnapshot>,
    segment: &'static str,
    id_prefix: String,
    poll: Duration,
    bookmark_every: Duration,
    /// The document's seq of the snapshot last looked at: a swap changes it, and nothing else is copied or compared.
    version: Option<u64>,
    started: bool,
    seen: BTreeMap<String, Vec<u8>>,
    queue: VecDeque<WatchResponse>,
    deadline: tokio::time::Instant,
    _slot: Slot,
}

impl ConfigWatch {
    /// A stream that starts with the snapshot in force.
    #[must_use]
    pub fn new(
        config: Arc<dyn ConfigSnapshot>,
        segment: &'static str,
        id_prefix: String,
        poll: Duration,
        bookmark_every: Duration,
        slot: Slot,
    ) -> Self {
        Self {
            config,
            segment,
            id_prefix,
            poll,
            bookmark_every,
            version: None,
            started: false,
            seen: BTreeMap::new(),
            queue: VecDeque::new(),
            deadline: tokio::time::Instant::now() + bookmark_every,
            _slot: slot,
        }
    }

    fn item(&self, id: &str, version: u64, value: Vec<u8>) -> Item {
        Item {
            address: Address {
                kind: self.segment.to_owned(),
                id: id.to_owned(),
                ..Address::default()
            }
            .into(),
            version,
            value,
            ..Item::default()
        }
    }

    /// Looks at the snapshot and queues what changed since the last look.
    fn look(&mut self) {
        if self.started && self.config.version(self.segment) == self.version {
            return;
        }
        let first = !self.started;
        self.started = true;
        // The seq and the items from one snapshot: a swap between two reads would stamp them with another seq.
        let (version, items) = self.config.listing(self.segment);
        self.version = version;
        let seq = version.unwrap_or(0);
        let now: BTreeMap<String, Vec<u8>> = items
            .into_iter()
            .filter(|(id, _)| id.starts_with(&self.id_prefix))
            .collect();
        let mut out = Vec::new();
        for (id, bytes) in &now {
            if self.seen.get(id) != Some(bytes) {
                out.push(WatchResponse {
                    r#type: ChangeType::CHANGE_TYPE_PUT.into(),
                    item: self.item(id, seq, bytes.clone()).into(),
                    ..WatchResponse::default()
                });
            }
        }
        for id in self.seen.keys() {
            if !now.contains_key(id) {
                out.push(WatchResponse {
                    r#type: ChangeType::CHANGE_TYPE_DELETE.into(),
                    item: self.item(id, seq, Vec::new()).into(),
                    ..WatchResponse::default()
                });
            }
        }
        self.seen = now;
        self.queue.extend(out);
        // The snapshot is whole: a watcher replaces its state of the kind with the items before this bookmark, so an
        // item removed between its listing and the watch is dropped too.
        if first {
            self.queue.push_back(bookmark(0, 0));
        }
    }

    /// The next message: the snapshot, then the changes of a swap, or a bookmark after a silence.
    pub async fn next(&mut self) -> WatchResponse {
        loop {
            if let Some(m) = self.queue.pop_front() {
                self.deadline = tokio::time::Instant::now() + self.bookmark_every;
                return m;
            }
            if !self.started {
                self.look();
                continue;
            }
            if tokio::time::Instant::now() >= self.deadline {
                self.deadline = tokio::time::Instant::now() + self.bookmark_every;
                return bookmark(0, 0);
            }
            tokio::time::sleep(self.poll).await;
            self.look();
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)] // a failed unwrap in a test is the failure

    use super::*;
    use sluis_proto::sluis::port::item::v2alpha1::{
        QueryRequest, QueryResponse, TransactRequest, TransactResponse,
    };
    use tokio::sync::mpsc;

    /// An engine that holds every key at version 1 with the value `v`: the stream reads an item at delivery. Its query
    /// answers the head and epoch it is set to (`None`: the engine is down), and records the levels it was asked at.
    #[derive(Clone, Default)]
    struct Stub {
        head: Arc<Mutex<Option<(u64, u64)>>>,
        asked: Arc<Mutex<Vec<bool>>>,
    }

    impl ItemEngine for Stub {
        async fn get(
            &self,
            key: Vec<u8>,
            _linearizable: bool,
        ) -> Result<Option<DriverItem>, EngineError> {
            Ok(Some(DriverItem {
                key,
                version: 1,
                value: b"v".to_vec(),
                ..DriverItem::default()
            }))
        }
        async fn query(&self, q: QueryRequest) -> Result<QueryResponse, EngineError> {
            self.asked.lock().unwrap().push(q.linearizable);
            let (log_head, log_epoch) =
                self.head.lock().unwrap().ok_or(EngineError::Unavailable)?;
            Ok(QueryResponse {
                log_head,
                log_epoch,
                ..QueryResponse::default()
            })
        }
        async fn transact(&self, _t: TransactRequest) -> Result<TransactResponse, EngineError> {
            Err(EngineError::Unavailable)
        }
        async fn tail_log(&self, _from: u64, _epoch: u64) -> Result<LogRows, EngineError> {
            Err(EngineError::Unavailable)
        }
    }

    /// The key of kind `kind` (`pin` is watched here, anything else is another kind) and id `id`.
    fn key(kind: &str, id: &str) -> Vec<u8> {
        format!("dev/-/{kind}/{id}").into_bytes()
    }

    fn row(sequence: u64, key: Vec<u8>, deleted: bool) -> TailLogResponse {
        TailLogResponse {
            sequence,
            key,
            version: 1,
            deleted,
            ..TailLogResponse::default()
        }
    }

    /// A stream over a log that the test feeds, opened at `start` with the head `head`, idle bookmark every 150 ms.
    fn stream(
        start: u64,
        head: u64,
    ) -> (
        LogWatch<Stub>,
        mpsc::Sender<Result<TailLogResponse, EngineError>>,
    ) {
        stream_of(Stub::default(), start, head, true)
    }

    fn stream_of(
        engine: Stub,
        start: u64,
        head: u64,
        claims: bool,
    ) -> (
        LogWatch<Stub>,
        mpsc::Sender<Result<TailLogResponse, EngineError>>,
    ) {
        let (tx, rx) = mpsc::channel(64);
        let w = LogWatch::new(
            engine,
            "dev".into(),
            b"dev/-/pin/".to_vec(),
            Arc::new(SystemTime::now),
            Duration::from_millis(150),
            rx,
            start,
            head,
            9,
            claims,
            Slots::default().take("t").unwrap(),
        );
        (w, tx)
    }

    /// What a message says: (type, sequence, caught up).
    async fn say(w: &mut LogWatch<Stub>) -> (ChangeType, u64, bool) {
        let m = tokio::time::timeout(Duration::from_secs(5), w.next())
            .await
            .expect("a message in five seconds")
            .expect("the stream goes on");
        assert_eq!(m.log_epoch, 9);
        (m.r#type.as_known().unwrap(), m.resume_point, m.caught_up)
    }

    const PUT: ChangeType = ChangeType::CHANGE_TYPE_PUT;
    const MARK: ChangeType = ChangeType::CHANGE_TYPE_BOOKMARK;

    /// verifies: REQ-DATA-120
    /// A stream opened at the head says it is caught up before it reads a row, and says it once.
    #[tokio::test]
    async fn a_stream_opened_at_the_head_is_caught_up_at_once() {
        let (mut w, tx) = stream(7, 7);
        assert_eq!(say(&mut w).await, (MARK, 7, true));
        // Then it is an ordinary stream: a row is a change, and silence is an idle bookmark that claims nothing.
        tx.send(Ok(row(8, key("pin", "a"), false))).await.unwrap();
        assert_eq!(say(&mut w).await, (PUT, 8, false));
        assert_eq!(say(&mut w).await, (MARK, 8, false));
    }

    /// verifies: REQ-DATA-120
    /// Rows of other kinds are not changes of the watch, but they are rows of the log: a catch-up whose rows up to the head
    /// are all of other kinds ends on the last of them, at once, without an idle wait.
    #[tokio::test]
    async fn rows_of_other_kinds_up_to_the_head_end_the_catch_up() {
        let (mut w, tx) = stream(2, 5);
        for seq in 3..=5 {
            tx.send(Ok(row(seq, key("other", "x"), false)))
                .await
                .unwrap();
        }
        assert_eq!(say(&mut w).await, (MARK, 5, true));
    }

    /// verifies: REQ-DATA-120
    /// The bookmark sits between the last row up to the head and the first row past it, whatever the runs: a row of the
    /// watch before the head, one of another kind, a row of the watch past the head, all read together.
    #[tokio::test]
    async fn the_bookmark_sits_between_the_head_and_the_first_row_past_it() {
        let (mut w, tx) = stream(2, 5);
        for (seq, kind) in [
            (3, "other"),
            (4, "pin"),
            (5, "other"),
            (6, "pin"),
            (7, "pin"),
        ] {
            tx.send(Ok(row(seq, key(kind, &format!("i{seq}")), false)))
                .await
                .unwrap();
        }
        assert_eq!(say(&mut w).await, (PUT, 4, false));
        assert_eq!(say(&mut w).await, (MARK, 5, true));
        assert_eq!(say(&mut w).await, (PUT, 6, false));
        assert_eq!(say(&mut w).await, (PUT, 7, false));
    }

    /// verifies: REQ-DATA-120
    /// A put that a later row of the same address supersedes is skipped, because the later row delivers the state. Not past
    /// the head: if the later row is past the head, the put is delivered, before the bookmark, so that the state the
    /// bookmark claims is in the consumer's hands. The later row then follows the bookmark.
    #[tokio::test]
    async fn a_put_is_not_skipped_for_a_row_past_the_head() {
        let (mut w, tx) = stream(2, 3);
        tx.send(Ok(row(3, key("pin", "a"), false))).await.unwrap();
        tx.send(Ok(row(4, key("pin", "a"), false))).await.unwrap();
        assert_eq!(say(&mut w).await, (PUT, 3, false), "delivered, not skipped");
        assert_eq!(say(&mut w).await, (MARK, 3, true));
        assert_eq!(say(&mut w).await, (PUT, 4, false));
        // Up to the head the skip is the same as ever.
        let (mut w, tx) = stream(2, 4);
        tx.send(Ok(row(3, key("pin", "a"), false))).await.unwrap();
        tx.send(Ok(row(4, key("pin", "a"), false))).await.unwrap();
        assert_eq!(
            say(&mut w).await,
            (PUT, 4, false),
            "3 is superseded by 4, both up to the head"
        );
        assert_eq!(say(&mut w).await, (MARK, 4, true));
    }

    /// verifies: REQ-DATA-120
    /// The claim is made from rows delivered. A log that shows only part of the rows up to the head (a replica that lags)
    /// gets idle bookmarks that name where the stream is and claim nothing, and the caught-up bookmark when the rest
    /// arrives, after them.
    #[tokio::test]
    async fn a_log_that_lags_gets_no_claim_until_the_rows_arrive() {
        let (mut w, tx) = stream(2, 6);
        tx.send(Ok(row(3, key("pin", "a"), false))).await.unwrap();
        tx.send(Ok(row(4, key("pin", "b"), false))).await.unwrap();
        assert_eq!(say(&mut w).await, (PUT, 3, false));
        assert_eq!(say(&mut w).await, (PUT, 4, false));
        for _ in 0..2 {
            assert_eq!(
                say(&mut w).await,
                (MARK, 4, false),
                "the position, and no claim"
            );
        }
        tx.send(Ok(row(5, key("pin", "c"), false))).await.unwrap();
        tx.send(Ok(row(6, key("other", "z"), false))).await.unwrap();
        assert_eq!(say(&mut w).await, (PUT, 5, false));
        assert_eq!(say(&mut w).await, (MARK, 6, true));
    }

    /// verifies: REQ-DATA-120
    /// A stream that ends before it has delivered through the head never says it is caught up: the error is the end of it.
    #[tokio::test]
    async fn a_stream_that_ends_before_the_head_never_claims_it() {
        let (mut w, tx) = stream(2, 6);
        tx.send(Ok(row(3, key("pin", "a"), false))).await.unwrap();
        tx.send(Err(EngineError::SequenceExpired)).await.unwrap();
        assert_eq!(say(&mut w).await, (PUT, 3, false));
        let end = tokio::time::timeout(Duration::from_secs(5), w.next())
            .await
            .unwrap();
        assert_eq!(end.unwrap_err(), Ended::Expired);
    }

    /// verifies: REQ-DATA-125
    /// A caught-up stream that has been silent for the interval reads the head again, linearizably, and says it is caught
    /// up again when the head is at or below the position it has dealt with. The claim is renewed on every tick.
    #[tokio::test]
    async fn an_idle_tick_that_finds_the_head_at_the_position_renews_the_claim() {
        let engine = Stub::default();
        *engine.head.lock().unwrap() = Some((8, 9));
        let (mut w, tx) = stream_of(engine.clone(), 7, 7, true);
        assert_eq!(say(&mut w).await, (MARK, 7, true));
        tx.send(Ok(row(8, key("pin", "a"), false))).await.unwrap();
        assert_eq!(say(&mut w).await, (PUT, 8, false));
        for _ in 0..3 {
            assert_eq!(
                say(&mut w).await,
                (MARK, 8, true),
                "the head is the position: the claim again"
            );
        }
        assert!(
            engine.asked.lock().unwrap().iter().all(|l| *l),
            "every read of the head is linearizable"
        );
        assert_eq!(engine.asked.lock().unwrap().len(), 3, "one read per tick");
    }

    /// verifies: REQ-DATA-125
    /// A tail that is behind the log (the head is ahead of what the stream has dealt with, or the read fails) renews
    /// nothing: the plain idle bookmark. When the rows then arrive the claim follows them, as at the opening.
    #[tokio::test]
    async fn an_idle_tick_that_finds_the_head_ahead_or_cannot_read_it_claims_nothing() {
        let engine = Stub::default();
        let (mut w, tx) = stream_of(engine.clone(), 7, 7, true);
        assert_eq!(say(&mut w).await, (MARK, 7, true));
        // The read fails: no claim.
        assert_eq!(say(&mut w).await, (MARK, 7, false));
        // The head is ahead of the tail, which has shown nothing yet: no claim, however many ticks.
        *engine.head.lock().unwrap() = Some((9, 9));
        for _ in 0..3 {
            assert_eq!(say(&mut w).await, (MARK, 7, false));
        }
        assert_eq!(
            engine.asked.lock().unwrap().len(),
            2,
            "the failed read and the one that found the head ahead; a stream that waits for its rows reads no more"
        );
        // The rows arrive: the claim follows the last of them, once.
        tx.send(Ok(row(8, key("pin", "a"), false))).await.unwrap();
        tx.send(Ok(row(9, key("other", "x"), false))).await.unwrap();
        assert_eq!(say(&mut w).await, (PUT, 8, false));
        assert_eq!(say(&mut w).await, (MARK, 9, true));
        // And it is renewed again when the head stays at the position.
        assert_eq!(say(&mut w).await, (MARK, 9, true));
    }

    /// verifies: REQ-DATA-125
    /// A log that was made again under an open stream ends it at the tick that finds the new epoch.
    #[tokio::test]
    async fn an_idle_tick_that_finds_another_epoch_ends_the_stream() {
        let engine = Stub::default();
        *engine.head.lock().unwrap() = Some((7, 10));
        let (mut w, _tx) = stream_of(engine, 7, 7, true);
        assert_eq!(say(&mut w).await, (MARK, 7, true));
        let end = tokio::time::timeout(Duration::from_secs(5), w.next())
            .await
            .unwrap();
        assert_eq!(end.unwrap_err(), Ended::Expired);
    }

    /// verifies: REQ-DATA-126
    /// A watch from 0 ("from now") was given no point and says no `caught_up`: not first, and not on a tick.
    #[tokio::test]
    async fn a_watch_from_now_never_claims() {
        let engine = Stub::default();
        *engine.head.lock().unwrap() = Some((7, 9));
        let (mut w, tx) = stream_of(engine.clone(), 7, 7, false);
        assert_eq!(
            say(&mut w).await,
            (MARK, 7, false),
            "an idle bookmark first"
        );
        tx.send(Ok(row(8, key("pin", "a"), false))).await.unwrap();
        assert_eq!(say(&mut w).await, (PUT, 8, false));
        assert_eq!(say(&mut w).await, (MARK, 8, false));
        assert!(
            engine.asked.lock().unwrap().is_empty(),
            "and it reads no head"
        );
    }

    /// verifies: REQ-DATA-127
    /// The rows of a log come in increasing order, and the claim rests on it: a row at or below the one before ends the
    /// stream with the engine's failure, whether it comes in the same run or in the next.
    #[tokio::test]
    async fn a_row_that_is_not_past_the_one_before_ends_the_stream() {
        for rows in [[4, 4], [5, 3]] {
            let (mut w, tx) = stream(2, 9);
            for seq in rows {
                tx.send(Ok(row(seq, key("pin", &format!("i{seq}")), false)))
                    .await
                    .unwrap();
            }
            // The stream ends within a few messages; an engine that is believed would go on with idle bookmarks for ever.
            let mut end = None;
            for _ in 0..8 {
                let m = tokio::time::timeout(Duration::from_secs(5), w.next())
                    .await
                    .unwrap();
                if let Err(e) = m {
                    end = Some(e);
                    break;
                }
            }
            assert_eq!(end, Some(Ended::Engine), "{rows:?}");
        }
    }

    /// verifies: REQ-DATA-125
    /// A stream that changes more often than the interval is renewed too: the head is read between the runs when the
    /// interval has passed, and the claim names the position of the rows delivered, in the order of the stream. Without
    /// that a busy kind would be unconfirmed for good.
    #[tokio::test]
    async fn a_stream_that_changes_more_often_than_the_interval_is_renewed_between_runs() {
        let engine = Stub::default();
        let (mut w, tx) = stream_of(engine.clone(), 7, 7, true);
        assert_eq!(say(&mut w).await, (MARK, 7, true));
        let mut claims = Vec::new();
        let mut seen = Vec::new();
        let started = tokio::time::Instant::now();
        let mut seq = 7;
        // A change every 40 ms for about 900 ms; the interval is 150 ms, and the stream is never silent for 150 ms.
        while started.elapsed() < Duration::from_millis(900) {
            seq += 1;
            *engine.head.lock().unwrap() = Some((seq, 9));
            tx.send(Ok(row(seq, key("pin", &format!("i{seq}")), false)))
                .await
                .unwrap();
            while let Ok(m) = tokio::time::timeout(Duration::from_millis(40), w.next()).await {
                let m = m.unwrap();
                seen.push((m.r#type.as_known().unwrap(), m.resume_point, m.caught_up));
                if m.caught_up {
                    claims.push(m.resume_point);
                }
            }
        }
        assert!(
            claims.len() >= 3,
            "renewed while busy: {} claims in {seen:?}",
            claims.len()
        );
        // A claim is never ahead of the rows delivered before it.
        let mut delivered = 7;
        for (t, point, claim) in seen {
            if claim {
                assert_eq!(
                    point, delivered,
                    "a claim names the position of the rows before it"
                );
            } else if t == PUT {
                delivered = point;
            }
        }
    }
}
