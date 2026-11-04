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
//! - A resume point that the change log no longer holds is `failed_precondition` / `resume_point_expired`: the
//!   watcher lists again.
//! - A caller has at most 16 watches at once.
//! - A config kind has no change log: a watch sends the snapshot in force as puts and then a bookmark, and the
//!   watcher replaces its state of the kind with the items before that bookmark; then each item that a swap added,
//!   changed or removed, with resume point 0. A config change has no sequence: the watcher applies every one.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use sluis_proto::sluis::port::item::v2alpha1::{DriverItem, TailLogResponse};
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

fn bookmark(resume_point: u64) -> WatchResponse {
    WatchResponse {
        resume_point,
        r#type: ChangeType::CHANGE_TYPE_BOOKMARK.into(),
        ..WatchResponse::default()
    }
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
    /// Held for the life of the stream.
    _slot: Slot,
}

impl<E: ItemEngine> LogWatch<E> {
    /// A stream that reads `rows` (opened at `start`).
    #[allow(clippy::too_many_arguments)] // the parts of one stream, named at the one call
    pub fn new(
        engine: E,
        boundary: String,
        prefix: Vec<u8>,
        now: Arc<dyn Fn() -> SystemTime + Send + Sync>,
        bookmark_every: Duration,
        rows: LogRows,
        start: u64,
        slot: Slot,
    ) -> Self {
        Self {
            engine,
            boundary,
            prefix,
            now,
            bookmark_every,
            rows,
            last: start,
            run: VecDeque::new(),
            run_end: start,
            pending: None,
            deadline: tokio::time::Instant::now() + bookmark_every,
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
    fn take(&mut self, row: TailLogResponse, run: &mut Vec<(TailLogResponse, Address)>) {
        self.run_end = self.run_end.max(row.sequence);
        if row.key.starts_with(&self.prefix)
            && let Some(address) = address_of(&self.boundary, &row.key)
        {
            run.push((row, address));
        }
    }

    /// Waits for the next row, then takes the rows that are there already, up to a run.
    async fn read_run(&mut self) -> Result<Option<()>, Ended> {
        loop {
            // The run before is delivered: the position is past every row it read, its last one included.
            self.last = self.last.max(self.run_end);
            if let Some(e) = self.pending.take() {
                return Err(e.into());
            }
            let first = match tokio::time::timeout_at(self.deadline, self.rows.recv()).await {
                Err(_) => return Ok(None),
                // The driver ended its stream: the watcher resumes from its point.
                Ok(None) => return Err(Ended::Engine),
                Ok(Some(Err(e))) => return Err(e.into()),
                Ok(Some(Ok(row))) => row,
            };
            let mut run = Vec::new();
            self.take(first, &mut run);
            while run.len() < RUN_MAX {
                match self.rows.try_recv() {
                    Ok(Ok(row)) => self.take(row, &mut run),
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
                continue;
            }
            // A put row is superseded when a later row of the same address is in the run.
            let mut lastof: HashMap<&[u8], usize> = HashMap::new();
            for (i, (row, _)) in run.iter().enumerate() {
                lastof.insert(row.key.as_slice(), i);
            }
            let superseded: Vec<bool> = run
                .iter()
                .enumerate()
                .map(|(i, (row, _))| lastof.get(row.key.as_slice()).is_some_and(|l| *l > i))
                .collect();
            self.run = run
                .into_iter()
                .zip(superseded)
                .map(|((row, address), later)| (row, address, later))
                .collect();
            return Ok(Some(()));
        }
    }

    /// The next message: a change, or a bookmark after a silence. `Err` ends the stream.
    ///
    /// # Errors
    ///
    /// [`Ended`] when the log no longer holds the point or the engine failed.
    pub async fn next(&mut self) -> Result<WatchResponse, Ended> {
        loop {
            let Some((row, address, later)) = self.run.pop_front() else {
                if self.read_run().await?.is_none() {
                    self.deadline = tokio::time::Instant::now() + self.bookmark_every;
                    return Ok(bookmark(self.last));
                }
                continue;
            };
            self.last = row.sequence;
            let message = if row.deleted {
                // A delete row is delivered whatever the item is now: if it was made again, its put row is later in
                // the log and follows.
                gone(row.sequence, row.version, address)
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
                    None => gone(row.sequence, row.version, address),
                    Some(item) => WatchResponse {
                        resume_point: row.sequence,
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
fn gone(sequence: u64, version: u64, address: Address) -> WatchResponse {
    WatchResponse {
        resume_point: sequence,
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
            self.queue.push_back(bookmark(0));
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
                return bookmark(0);
            }
            tokio::time::sleep(self.poll).await;
            self.look();
        }
    }
}
