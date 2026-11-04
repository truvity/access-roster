//! `Watch` (ADR 0005 "Watch and the resume point"; store-api.md "Watch"): the Kubernetes list-watch contract.
//!
//! - A watcher lists (`List` answers with a `resume_point`), then watches from that point. A watch from 0 starts
//!   from now.
//! - A change carries the address, the type and the version. The value is read when the change is delivered
//!   (level-triggered): a watcher applies state, not edits. If the item is above the version of the row it is
//!   delivered once and the rows at or below that version are skipped; an item that is gone, expired included,
//!   is a delete with no value.
//! - Delivery is at-least-once, in the order of the change log. A consumer dedupes by (address, version).
//! - store@ buffers nothing beyond the driver's log: the stream is read at the pace of its consumer, and HTTP/2 flow
//!   control is the backpressure. An idle stream says the latest resume point as a bookmark every 30 seconds.
//! - A resume point that the change log no longer holds is `failed_precondition` / `resume_point_expired`: the
//!   watcher lists again.
//! - A caller has at most 16 watches at once.
//! - A config kind has no change log: a watcher is told each item that a snapshot swap changed, with resume point 0.

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
/// Items remembered per stream to skip a row whose state was already delivered. A stream that forgets one
/// delivers the state again, which at-least-once allows.
const DELIVERED_MAX: usize = 1024;

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

/// The stream of the changes of an item kind.
pub struct LogWatch<E> {
    engine: E,
    boundary: String,
    /// The keys watched: the kind (and the tenant, and the caller's own ids) as a key prefix.
    prefix: Vec<u8>,
    now: Arc<dyn Fn() -> SystemTime + Send + Sync>,
    bookmark_every: Duration,
    rows: LogRows,
    /// A row read while the start was probed, delivered before the rest.
    first: Option<TailLogResponse>,
    /// The sequence of the last row read (the start position before any): what a bookmark says.
    last: u64,
    /// The version delivered for a key, to skip the rows below it.
    delivered: HashMap<Vec<u8>, u64>,
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
        first: Option<TailLogResponse>,
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
            first,
            last: start,
            delivered: HashMap::new(),
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

    /// The next message: a change, or a bookmark after a silence. `Err` ends the stream.
    ///
    /// # Errors
    ///
    /// [`Ended`] when the log no longer holds the point or the engine failed.
    pub async fn next(&mut self) -> Result<WatchResponse, Ended> {
        loop {
            let row = if let Some(row) = self.first.take() {
                row
            } else {
                match tokio::time::timeout_at(self.deadline, self.rows.recv()).await {
                    Err(_) => {
                        self.deadline = tokio::time::Instant::now() + self.bookmark_every;
                        return Ok(bookmark(self.last));
                    }
                    // The driver ended its stream: the watcher resumes from its point.
                    Ok(None) => return Err(Ended::Engine),
                    Ok(Some(Err(e))) => return Err(e.into()),
                    Ok(Some(Ok(row))) => row,
                }
            };
            self.last = row.sequence;
            if !row.key.starts_with(&self.prefix) {
                continue;
            }
            let Some(address) = address_of(&self.boundary, &row.key) else {
                // A key of another boundary or of no address (the marker row): not ours, and not an error.
                continue;
            };
            let current = self
                .engine
                .get(row.key.clone(), true)
                .await
                .map_err(Ended::from)?
                .filter(|i| !self.expired(i));
            let message = match (current, row.deleted) {
                // Gone: a delete, whatever the row said. The version is the one the row had.
                (None, _) => {
                    // Once: the other rows the item left (a put, an update, the delete itself) say the same.
                    if self.delivered.get(&row.key) == Some(&0) {
                        continue;
                    }
                    if self.delivered.len() >= DELIVERED_MAX {
                        self.delivered.clear();
                    }
                    self.delivered.insert(row.key.clone(), 0);
                    WatchResponse {
                        resume_point: row.sequence,
                        r#type: ChangeType::CHANGE_TYPE_DELETE.into(),
                        item: Item {
                            address: address.into(),
                            version: row.version,
                            ..Item::default()
                        }
                        .into(),
                        ..WatchResponse::default()
                    }
                }
                // A delete row, but the item is there again: its put row follows and carries it.
                (Some(_), true) => continue,
                (Some(item), false) => {
                    // The state at this version was delivered: skip the row (a later row of the same item).
                    if self.delivered.get(&row.key) == Some(&item.version)
                        && row.version <= item.version
                    {
                        continue;
                    }
                    if self.delivered.len() >= DELIVERED_MAX {
                        self.delivered.clear();
                    }
                    self.delivered.insert(row.key.clone(), item.version);
                    WatchResponse {
                        resume_point: row.sequence,
                        r#type: ChangeType::CHANGE_TYPE_PUT.into(),
                        item: Self::wire(address, &item).into(),
                        ..WatchResponse::default()
                    }
                }
            };
            self.deadline = tokio::time::Instant::now() + self.bookmark_every;
            return Ok(message);
        }
    }
}

/// The stream of the changes of a config kind: each item that a swap of the snapshot added, changed or removed,
/// with resume point 0 (a config kind has no change log; a watcher that reconnects reads the kind again).
pub struct ConfigWatch {
    config: Arc<dyn ConfigSnapshot>,
    segment: &'static str,
    id_prefix: String,
    poll: Duration,
    seen: BTreeMap<String, Vec<u8>>,
    queue: VecDeque<WatchResponse>,
    _slot: Slot,
}

impl ConfigWatch {
    /// A stream that starts from the snapshot in force.
    #[must_use]
    pub fn new(
        config: Arc<dyn ConfigSnapshot>,
        segment: &'static str,
        id_prefix: String,
        poll: Duration,
        slot: Slot,
    ) -> Self {
        let seen = Self::snapshot(&*config, segment, &id_prefix);
        Self {
            config,
            segment,
            id_prefix,
            poll,
            seen,
            queue: VecDeque::new(),
            _slot: slot,
        }
    }

    fn snapshot(
        config: &dyn ConfigSnapshot,
        segment: &str,
        id_prefix: &str,
    ) -> BTreeMap<String, Vec<u8>> {
        config
            .list(segment)
            .into_iter()
            .filter(|(id, _)| id.starts_with(id_prefix))
            .collect()
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

    /// The next change of the snapshot.
    pub async fn next(&mut self) -> WatchResponse {
        loop {
            if let Some(m) = self.queue.pop_front() {
                return m;
            }
            tokio::time::sleep(self.poll).await;
            let now = Self::snapshot(&*self.config, self.segment, &self.id_prefix);
            let version = self.config.version(self.segment).unwrap_or(0);
            let mut out = Vec::new();
            for (id, bytes) in &now {
                if self.seen.get(id) != Some(bytes) {
                    out.push(WatchResponse {
                        r#type: ChangeType::CHANGE_TYPE_PUT.into(),
                        item: self.item(id, version, bytes.clone()).into(),
                        ..WatchResponse::default()
                    });
                }
            }
            for id in self.seen.keys() {
                if !now.contains_key(id) {
                    out.push(WatchResponse {
                        r#type: ChangeType::CHANGE_TYPE_DELETE.into(),
                        item: self.item(id, version, Vec::new()).into(),
                        ..WatchResponse::default()
                    });
                }
            }
            self.seen = now;
            self.queue.extend(out);
        }
    }
}
