//! The pass: how the indexer follows one log (ADR 0028, "Search and the index"; ADR 0029, "Tiled log").
//!
//! One pass takes the log from the cursor to a signed checkpoint:
//!
//! 1. Read the cursor from the index: the size and root of the last checkpoint it verified, and the
//!    compact range of the tree at that size.
//! 2. Read the checkpoint pointer, and check its signature with the log key and its origin with the
//!    log's. A checkpoint that does not verify refuses the log (never a skip). One that is smaller than
//!    the cursor is a rollback, and one of the same size with another root is a fork: both refuse.
//! 3. Choose the checkpoint to index to. A long backlog is taken in steps of at most [`CHUNK`] entries,
//!    to a signed checkpoint of the history (`checkpoints/<size>`), so each step is a verified one and
//!    memory stays bounded. The pointer is the last step.
//! 4. Read the entry bundles from the cursor to that size, append each entry's leaf hash to the range,
//!    and compare the root with the checkpoint's. If they agree, the checkpoint extends the previous one
//!    and covers exactly these entries (RFC 6962): nothing is trusted that the signed root does not
//!    cover. If they differ, the log is refused.
//! 5. Only then open the records at key@ under the tenant's `evidence` key, with a grant that `policy`
//!    gave for this pass, check each against the clear envelope of its entry, and write the rows and the
//!    new cursor to the index.
//!
//! Indexing is idempotent by record hash (the index ignores a row it has), so a pass that stopped
//! half-way, or a second indexer during a deploy, does no harm: the cursor moves forward by a
//! conditional write and the rows are keyed by hash.

use std::time::{Duration, Instant};

use sluis_proto::sluis::key::v2alpha1::{OpenItem, OpenRequest};
use sluis_proto::sluis::policy::v2alpha1::{ActorFacts, DecideRequest, Decision, EntityRef};
use sluis_proto::sluis::port::index::v2alpha1::{
    ApplyRequest, Cursor, GetCursorRequest, LogRef, Row,
};
use sluis_proto::sluis::r#type::v2alpha1::Address;
use tokio::sync::Mutex;

use crate::entry::{self, Entry, Opened, RecordEntry, TILE};
use crate::merkle::{Range, leaf_hash};
use crate::note::{Checkpoint, LogKey};
use crate::ports::{CALL, Failure, Ports};

/// The most entries one step takes when the history lets it stop sooner (see the module comment).
pub const CHUNK: u64 = 4096;
/// The most envelopes key@ opens in one call.
const OPEN_BATCH: usize = 64;
/// A grant lives 60 seconds at most (0007); one older than this is asked for again.
const GRANT_REUSE: Duration = Duration::from_secs(30);
/// The most rows, and the most record bytes, one `Apply` call carries.
const APPLY_ROWS: usize = 256;
const APPLY_BYTES: usize = 1 << 20;
/// The name policy knows the indexer by (decision D-6: the audit pieces are principals).
const PRINCIPAL: &str = "indexer";
/// The purpose of the key the records are sealed under.
const EVIDENCE: &str = "evidence";

/// One log the indexer follows.
#[derive(Clone)]
pub struct Log {
    /// The audit project.
    pub project: String,
    /// The log kind (`audit`).
    pub kind: String,
    /// The log's id.
    pub id: String,
    /// The origin line its checkpoints name.
    pub origin: String,
    /// The log key's verifier.
    pub key: LogKey,
}

impl Log {
    /// `<kind>/<log>/`: the prefix of the log in the project's bucket.
    #[must_use]
    pub fn prefix(&self) -> String {
        format!("{}/{}/", self.kind, self.id)
    }

    /// `<kind>/<log>`, for logs.
    #[must_use]
    pub fn name(&self) -> String {
        format!("{}/{}/{}", self.project, self.kind, self.id)
    }

    fn log_ref(&self) -> LogRef {
        LogRef {
            project: self.project.clone(),
            kind: self.kind.clone(),
            log: self.id.clone(),
            ..LogRef::default()
        }
    }
}

/// What a pass did.
#[derive(Debug, PartialEq, Eq)]
pub enum Progress {
    /// The cursor is at the log's newest checkpoint.
    Idle,
    /// The cursor moved to a checkpoint of this size, with this many rows written.
    Advanced {
        /// The size the cursor is at.
        size: u64,
        /// The records the step wrote (new or repeated).
        rows: usize,
    },
}

/// The indexer's use of the ports, for the logs of one boundary.
pub struct Follower {
    boundary: String,
    ports: Ports,
    grant: Mutex<Option<(Instant, Vec<u8>)>>,
}

impl Follower {
    /// A follower for a boundary.
    #[must_use]
    pub fn new(boundary: &str, ports: Ports) -> Self {
        Self {
            boundary: boundary.to_owned(),
            ports,
            grant: Mutex::new(None),
        }
    }

    /// The grant for opening evidence (decision D-6): action `audit.index`, every tenant of the boundary,
    /// the key operation `open`. policy seals it for the indexer, and key@ checks it on every Open.
    async fn grant(&self, fresh: bool) -> Result<Vec<u8>, Failure> {
        let mut held = self.grant.lock().await;
        if !fresh
            && let Some((at, g)) = held.as_ref()
            && at.elapsed() < GRANT_REUSE
        {
            return Ok(g.clone());
        }
        let req = DecideRequest {
            action: "audit.index".into(),
            principal: ::buffa::MessageField::some(EntityRef {
                r#type: "Actor".into(),
                id: PRINCIPAL.into(),
                ..EntityRef::default()
            }),
            resource: ::buffa::MessageField::some(EntityRef {
                r#type: "Boundary".into(),
                id: self.boundary.clone(),
                ..EntityRef::default()
            }),
            tenant: "*".into(),
            actor: ::buffa::MessageField::some(ActorFacts {
                name: PRINCIPAL.into(),
                ..ActorFacts::default()
            }),
            grant_key_ops: vec!["open".into()],
            ..DecideRequest::default()
        };
        let res = match tokio::time::timeout(CALL, self.ports.policy.decide(req)).await {
            Err(_) => return Err(Failure::Transient("policy.decide: timed out".into())),
            Ok(Err(e)) => return Err(Failure::of("policy.decide", &e)),
            Ok(Ok(r)) => r.into_owned(),
        };
        if res.decision != Decision::ALLOW || res.sealed_grant.is_empty() {
            return Err(Failure::refused("policy.denied", "audit.index"));
        }
        *held = Some((Instant::now(), res.sealed_grant.clone()));
        Ok(res.sealed_grant)
    }

    async fn checkpoint(&self, log: &Log, path: &str) -> Result<Option<Checkpoint>, Failure> {
        let Some(note) = self.ports.get(&format!("{}{path}", log.prefix())).await? else {
            return Ok(None);
        };
        let cp = log
            .key
            .open(&note)
            .map_err(|e| Failure::refused(e.word(), path))?;
        if cp.origin != log.origin {
            return Err(Failure::refused("checkpoint.origin", path));
        }
        Ok(Some(cp))
    }

    /// The signed checkpoint to index to from a cursor at `from`, given the newest one.
    async fn target(&self, log: &Log, from: u64, head: Checkpoint) -> Result<Checkpoint, Failure> {
        if head.size - from <= CHUNK {
            return Ok(head);
        }
        let mut sizes: Vec<u64> = self
            .ports
            .list(&format!("{}checkpoints/", log.prefix()))
            .await?
            .iter()
            .filter_map(|p| p.rsplit('/').next()?.parse::<u64>().ok())
            .filter(|s| *s > from && *s < head.size)
            .collect();
        sizes.sort_unstable();
        // The largest checkpoint within a chunk, or the first one past it.
        let pick = sizes
            .iter()
            .rev()
            .find(|s| **s <= from + CHUNK)
            .or_else(|| sizes.first())
            .copied();
        let Some(size) = pick else {
            return Ok(head);
        };
        // A history object that is missing falls back to the newest checkpoint: it is signed too.
        match self.checkpoint(log, &format!("checkpoints/{size}")).await? {
            Some(cp) if cp.size == size => Ok(cp),
            Some(_) => Err(Failure::refused(
                "checkpoint.size",
                format!("checkpoints/{size}"),
            )),
            None => Ok(head),
        }
    }

    /// Reads the entries from `from` to `to`, and appends their leaf hashes to the range.
    async fn entries(
        &self,
        log: &Log,
        from: u64,
        to: u64,
        range: &mut Range,
    ) -> Result<Vec<(u64, Vec<u8>)>, Failure> {
        let mut out = Vec::new();
        for n in from / TILE..=(to - 1) / TILE {
            let width = TILE.min(to - n * TILE);
            let first = n * TILE;
            let exact = format!("{}{}", log.prefix(), entry::bundle_path(n, width));
            let (data, full) = match self.ports.get(&exact).await? {
                Some(d) => (d, false),
                // C2SP tlog-tiles: a client falls back to the full bundle when a partial one is gone.
                None => match self
                    .ports
                    .get(&format!("{}{}", log.prefix(), entry::bundle_path(n, TILE)))
                    .await?
                {
                    Some(d) => (d, true),
                    None => return Err(Failure::refused("bundle.missing", first)),
                },
            };
            let bundle = entry::parse_bundle(&data)
                .ok_or_else(|| Failure::refused("bundle.format", first))?;
            // A bundle read from its own path holds exactly its entries; a full one that stands in for a
            // partial one holds at least that many.
            let w = usize::try_from(width).unwrap_or(usize::MAX);
            if bundle.len() < w || (!full && bundle.len() != w) {
                return Err(Failure::refused("bundle.format", first));
            }
            for (i, e) in bundle.iter().take(w).enumerate() {
                let g = first + i as u64;
                if g >= from {
                    range.append(leaf_hash(e));
                    out.push((g, e.to_vec()));
                }
            }
        }
        Ok(out)
    }

    /// Runs one pass over a log. See the module comment.
    ///
    /// # Errors
    ///
    /// [`Failure::Transient`] to try again later; [`Failure::Refused`] to halt the log.
    pub async fn pass(&self, log: &Log) -> Result<Progress, Failure> {
        let cur = tokio::time::timeout(
            CALL,
            self.ports.index.get_cursor(GetCursorRequest {
                log: ::buffa::MessageField::some(log.log_ref()),
                ..GetCursorRequest::default()
            }),
        )
        .await
        .map_err(|_| Failure::Transient("index.get_cursor: timed out".into()))?
        .map_err(|e| Failure::of("index.get_cursor", &e))?
        .into_owned();
        let cur = cur.cursor.into_option().unwrap_or_default();
        let from =
            u64::try_from(cur.size).map_err(|_| Failure::refused("cursor.size", cur.size))?;
        let mut range = if from == 0 {
            Range::new()
        } else {
            let r =
                Range::decode(&cur.state).map_err(|_| Failure::refused("cursor.state", from))?;
            if r.size() != from || r.root().as_slice() != cur.root.as_slice() {
                return Err(Failure::refused("cursor.state", from));
            }
            r
        };

        let Some(head) = self.checkpoint(log, "checkpoint").await? else {
            return if from == 0 {
                Ok(Progress::Idle)
            } else {
                Err(Failure::refused("checkpoint.missing", from))
            };
        };
        if head.size < from {
            return Err(Failure::refused("checkpoint.rollback", head.size));
        }
        if head.size == from {
            return if from == 0 || head.root.as_slice() == cur.root.as_slice() {
                Ok(Progress::Idle)
            } else {
                Err(Failure::refused("checkpoint.fork", from))
            };
        }
        let cp = self.target(log, from, head).await?;

        let raw = self.entries(log, from, cp.size, &mut range).await?;
        if range.size() != cp.size || range.root() != cp.root {
            // The entries since the cursor do not make the tree the checkpoint signs, from the tree the
            // cursor holds: a changed entry, a log that does not extend the last checkpoint, or a fork.
            return Err(Failure::refused("tree.root", cp.size));
        }

        let mut records: Vec<(u64, RecordEntry)> = Vec::new();
        for (g, bytes) in &raw {
            match entry::parse_entry(bytes).map_err(|e| Failure::refused(e.word(), g))? {
                Entry::Seal => {}
                Entry::Record(r) => records.push((*g, r)),
            }
        }
        let rows = self.open(log, &records).await?;
        let n = rows.len();
        self.apply(log, from, &cp, &range, rows).await?;
        Ok(Progress::Advanced {
            size: cp.size,
            rows: n,
        })
    }

    /// Opens the records of a step at key@ and builds their rows.
    async fn open(&self, log: &Log, records: &[(u64, RecordEntry)]) -> Result<Vec<Row>, Failure> {
        let mut rows = Vec::with_capacity(records.len());
        for batch in records.chunks(OPEN_BATCH) {
            let plain = self.open_batch(log, batch).await?;
            for ((g, e), pt) in batch.iter().zip(plain) {
                let rec = Opened::parse(&pt).map_err(|er| Failure::refused(er.word(), g))?;
                rec.check(e, &self.boundary)
                    .map_err(|er| Failure::refused(er.word(), g))?;
                rows.push(
                    rec.row(e, *g, pt)
                        .map_err(|er| Failure::refused(er.word(), g))?,
                );
            }
        }
        Ok(rows)
    }

    async fn open_batch(
        &self,
        log: &Log,
        batch: &[(u64, RecordEntry)],
    ) -> Result<Vec<Vec<u8>>, Failure> {
        let items = |b: &[(u64, RecordEntry)]| -> Vec<OpenItem> {
            b.iter()
                .map(|(_, e)| OpenItem {
                    purpose: EVIDENCE.into(),
                    address: ::buffa::MessageField::some(Address {
                        kind: entry::SEAL_KIND.into(),
                        tenant: e.tenant.clone(),
                        id: entry::seal_id(&log.project, &log.kind, &log.id, &e.uid),
                        ..Address::default()
                    }),
                    envelope: e.sealed.clone(),
                    ..OpenItem::default()
                })
                .collect()
        };
        let mut fresh = false;
        loop {
            let grant = self.grant(fresh).await?;
            let res = tokio::time::timeout(
                CALL,
                self.ports.keys.open(OpenRequest {
                    items: items(batch),
                    grant,
                    ..OpenRequest::default()
                }),
            )
            .await
            .map_err(|_| Failure::Transient("key.open: timed out".into()))?;
            match res {
                Ok(r) => {
                    let plain = r.into_owned().plaintexts;
                    if plain.len() != batch.len() {
                        return Err(Failure::refused("key.open", "plaintexts"));
                    }
                    return Ok(plain);
                }
                // The grant may have run out while the pass worked: ask again once, then halt.
                Err(e) if !fresh && sluis_kit::refusal_reason(&e).as_deref() == Some("grant") => {
                    fresh = true;
                }
                Err(e) => {
                    let f = Failure::of("key.open", &e);
                    if matches!(f, Failure::Refused(..)) {
                        // key@ opens all or none. Find the first entry that does not open, so that the alert
                        // can name its position, without logging anything of it.
                        let g = self.first_unopenable(log, batch).await;
                        return Err(Failure::Refused(
                            "key.open",
                            format!("{} at {g}", f_detail(&f)),
                        ));
                    }
                    return Err(f);
                }
            }
        }
    }

    async fn first_unopenable(&self, log: &Log, batch: &[(u64, RecordEntry)]) -> String {
        for one in batch.chunks(1) {
            let Ok(grant) = self.grant(true).await else {
                return "?".into();
            };
            let req = OpenRequest {
                items: vec![OpenItem {
                    purpose: EVIDENCE.into(),
                    address: ::buffa::MessageField::some(Address {
                        kind: entry::SEAL_KIND.into(),
                        tenant: one[0].1.tenant.clone(),
                        id: entry::seal_id(&log.project, &log.kind, &log.id, &one[0].1.uid),
                        ..Address::default()
                    }),
                    envelope: one[0].1.sealed.clone(),
                    ..OpenItem::default()
                }],
                grant,
                ..OpenRequest::default()
            };
            if matches!(
                tokio::time::timeout(CALL, self.ports.keys.open(req)).await,
                Ok(Err(_))
            ) {
                return one[0].0.to_string();
            }
        }
        "?".into()
    }

    /// Writes the rows, in calls of a bounded size, and then the cursor with the last of them.
    async fn apply(
        &self,
        log: &Log,
        from: u64,
        cp: &Checkpoint,
        range: &Range,
        rows: Vec<Row>,
    ) -> Result<(), Failure> {
        let call = |rows: Vec<Row>, next: Option<Cursor>| {
            let req = ApplyRequest {
                log: ::buffa::MessageField::some(log.log_ref()),
                expect_size: i64::try_from(from).unwrap_or(i64::MAX),
                next: next.map_or_else(::buffa::MessageField::none, ::buffa::MessageField::some),
                rows,
                ..ApplyRequest::default()
            };
            async move {
                tokio::time::timeout(CALL, self.ports.index.apply(req))
                    .await
                    .map_err(|_| Failure::Transient("index.apply: timed out".into()))?
                    .map_err(|e| Failure::of("index.apply", &e))
                    .map(|_| ())
            }
        };
        let (mut batch, mut bytes) = (Vec::new(), 0usize);
        for r in rows {
            bytes += r.record.len();
            batch.push(r);
            if batch.len() >= APPLY_ROWS || bytes >= APPLY_BYTES {
                call(std::mem::take(&mut batch), None).await?;
                bytes = 0;
            }
        }
        let next = Cursor {
            size: i64::try_from(cp.size)
                .map_err(|_| Failure::refused("checkpoint.size", cp.size))?,
            root: cp.root.to_vec(),
            state: range.encode(),
            ..Cursor::default()
        };
        call(batch, Some(next)).await
    }
}

fn f_detail(f: &Failure) -> String {
    match f {
        Failure::Transient(s) | Failure::Refused(_, s) => s.clone(),
    }
}
