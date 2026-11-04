//! The in-memory engine of the item contract, for tests only (0005 "Engines"): it keeps items in
//! a map under a mutex and passes the same suite as the rqlite driver. It exists behind the
//! `memory` feature because it serves with a uid table of its own: every caller under this
//! process's uid is `store`, the one owner a driver socket admits.

#![allow(refining_impl_trait)] // the generated trait returns `impl Encodable`; a concrete type is fine

use std::collections::BTreeMap;
use std::future::Future;
use std::ops::Bound;
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use connectrpc::error::ErrorCode;
use connectrpc::{RequestContext, Response, Router, ServiceRequest, ServiceResult, ServiceStream};
use sluis_kit::{Allow, Identities, ServerConfig, refusal};
use sluis_proto::sluis::port::item::v2alpha1::{
    DriverItem, ItemGetRequest, ItemGetResponse, ItemService, ItemServiceExt, QueryRequest,
    QueryResponse, TailLogRequest, TailLogResponse, TransactRequest, TransactResponse,
};
use sluis_proto::sluis::r#type::v2alpha1::IndexEntry;

use crate::rules::{self, Expected, now_ms};

/// The rows one poll of a tail takes, and how often a tail looks for new ones.
const TAIL_BATCH: usize = 500;
const TAIL_POLL: Duration = Duration::from_millis(50);

struct Row {
    version: u64,
    value: Vec<u8>,
    expires_ms: Option<i64>,
    /// Written with a change-log row: its expiry is logged as a delete when it is swept.
    logged: bool,
    /// Sorted by name and value, without repeats.
    indexes: Vec<(String, Vec<u8>)>,
}

impl Row {
    fn live(&self, now: i64) -> bool {
        self.expires_ms.is_none_or(|e| e > now)
    }

    fn item(&self, key: &[u8]) -> DriverItem {
        DriverItem {
            key: key.to_vec(),
            version: self.version,
            value: self.value.clone(),
            expires_at: self.expires_ms.map(rules::ms_to_ts).into(),
            indexes: self
                .indexes
                .iter()
                .map(|(name, value)| IndexEntry {
                    name: name.clone(),
                    value: value.clone(),
                    ..IndexEntry::default()
                })
                .collect(),
            ..DriverItem::default()
        }
    }
}

struct LogRow {
    sequence: u64,
    key: Vec<u8>,
    version: u64,
    deleted: bool,
}

struct State {
    items: BTreeMap<Vec<u8>, Row>,
    log: Vec<LogRow>,
}

impl Default for State {
    /// The log starts with a marker row, sequence 1, so that its head is never 0 (0 means "from now").
    fn default() -> Self {
        Self {
            items: BTreeMap::new(),
            log: vec![LogRow {
                sequence: 1,
                key: Vec::new(),
                version: 0,
                deleted: false,
            }],
        }
    }
}

impl State {
    fn live(&self, key: &[u8], now: i64) -> Option<&Row> {
        self.items.get(key).filter(|r| r.live(now))
    }

    fn head(&self) -> u64 {
        self.log.last().map_or(0, |r| r.sequence)
    }

    /// Frees the expired items, as the sweeper of a real engine does, and logs the removal of each one that
    /// was written with a log row. Expiry is a delete to a watcher.
    fn sweep(&mut self, now: i64) {
        let gone: Vec<Vec<u8>> = self
            .items
            .iter()
            .filter(|(_, r)| !r.live(now))
            .map(|(k, _)| k.clone())
            .collect();
        for key in gone {
            if let Some(row) = self.items.remove(&key)
                && row.logged
            {
                self.append(&key, row.version, true);
            }
        }
    }

    fn append(&mut self, key: &[u8], version: u64, deleted: bool) {
        let sequence = self.head() + 1;
        self.log.push(LogRow {
            sequence,
            key: key.to_vec(),
            version,
            deleted,
        });
    }
}

/// An item engine that keeps everything in memory.
#[derive(Clone, Default)]
pub struct MemoryEngine {
    state: Arc<Mutex<State>>,
}

impl MemoryEngine {
    /// An empty engine.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Serves the item contract on `socket` until `shutdown`. Every caller under this process's
    /// uid is the actor `store`: a test runs both ends as one user.
    ///
    /// # Errors
    ///
    /// When the socket cannot be made, as `sluis_kit::serve`.
    pub async fn serve(
        self,
        socket: &Path,
        shutdown: impl Future<Output = ()> + Send,
    ) -> anyhow::Result<()> {
        let me = rustix::process::geteuid().as_raw();
        let identities = Identities::with(0, move |uid| (uid == me).then_some(("store", 0)));
        let cfg = ServerConfig {
            actor: "memory",
            boundary: "dev".into(),
            socket: socket.to_path_buf(),
            mode: 0o600,
            socket_gid: None,
            allow: Allow::OwnerOnly("store"),
            default_deadline: Duration::from_secs(30),
        };
        let router = Arc::new(self).register(Router::new());
        sluis_kit::serve_with(cfg, router, shutdown, identities).await
    }

    /// One tick of the sweeper: frees the expired items and logs the removal of those that were logged. A real
    /// engine runs it on a timer; here a tail runs it when it looks for rows, and a test may call it.
    pub fn sweep(&self) {
        self.lock().sweep(now_ms());
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        // A panic while the lock was held leaves a map that is still consistent for a test.
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl ItemService for MemoryEngine {
    async fn get(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, ItemGetRequest>,
    ) -> ServiceResult<ItemGetResponse> {
        let key = request.key.to_vec();
        rules::check_key(&key, "key")?;
        let st = self.lock();
        let Some(row) = st.live(&key, now_ms()) else {
            return Err(refusal(ErrorCode::NotFound, "absent", ""));
        };
        Response::ok(ItemGetResponse {
            item: Some(row.item(&key)).into(),
            ..ItemGetResponse::default()
        })
    }

    async fn query(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, QueryRequest>,
    ) -> ServiceResult<QueryResponse> {
        let req = request.to_owned_message();
        if !req.prefix.is_empty() {
            rules::check_key(&req.prefix, "prefix")?;
        }
        let size = rules::page_size(req.page_size)?;
        rules::check_token(&req.page_token, &req.prefix)?;
        if req.index.is_empty() && !req.index_value.is_empty() {
            return Err(refusal(ErrorCode::InvalidArgument, "index", "index"));
        }
        let now = now_ms();
        let st = self.lock();
        let log_head = st.head();
        let from = if req.page_token.is_empty() {
            Bound::Included(req.prefix.clone())
        } else {
            Bound::Excluded(req.page_token.clone())
        };
        let mut found: Vec<DriverItem> = st
            .items
            .range((from, Bound::Unbounded))
            .take_while(|(k, _)| k.starts_with(&req.prefix))
            .filter(|(_, r)| r.live(now))
            .filter(|(_, r)| {
                req.index.is_empty()
                    || r.indexes
                        .iter()
                        .any(|(n, v)| *n == req.index && *v == req.index_value)
            })
            .take(size + 1)
            .map(|(k, r)| r.item(k))
            .collect();
        let next_page_token = if found.len() > size {
            found.truncate(size);
            found.last().map(|i| i.key.clone()).unwrap_or_default()
        } else {
            Vec::new()
        };
        Response::ok(QueryResponse {
            items: found,
            next_page_token,
            log_head,
            ..QueryResponse::default()
        })
    }

    async fn transact(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, TransactRequest>,
    ) -> ServiceResult<TransactResponse> {
        let req = request.to_owned_message();
        let expected = rules::check_transact(&req)?;
        let now = now_ms();
        let mut st = self.lock();
        for (i, (c, want)) in req.conditions.iter().zip(&expected).enumerate() {
            let held = match (want, st.live(&c.key, now)) {
                (Expected::Absent, row) => row.is_none(),
                (Expected::Version(v), Some(row)) => row.version == *v,
                (Expected::Version(_), None) => false,
            };
            if !held {
                return Err(refusal(
                    ErrorCode::Aborted,
                    "version",
                    &format!("conditions[{i}]"),
                ));
            }
        }
        // Nothing below can fail: the transaction is all or none.
        for d in &req.deletes {
            // An item that was written with a log row is logged when it is removed, expired and not swept or not.
            if let Some(row) = st.items.remove(&d.key)
                && (d.log || row.logged)
            {
                st.append(&d.key, row.version, true);
            }
        }
        let mut written = Vec::with_capacity(req.puts.len());
        for p in &req.puts {
            // Over an item past its expiry the version continues: it never goes back (ABA).
            let version = st.items.get(&p.key).map_or(1, |r| r.version + 1);
            let mut indexes: Vec<(String, Vec<u8>)> = p
                .indexes
                .iter()
                .map(|e| (e.name.clone(), e.value.clone()))
                .collect();
            indexes.sort();
            indexes.dedup();
            let row = Row {
                version,
                value: p.value.clone(),
                expires_ms: p.expires_at.as_option().map(rules::ts_to_ms),
                logged: p.log,
                indexes,
            };
            written.push(row.item(&p.key));
            st.items.insert(p.key.clone(), row);
            if p.log {
                st.append(&p.key, version, false);
            }
        }
        Response::ok(TransactResponse {
            items: written,
            ..TransactResponse::default()
        })
    }

    async fn tail_log(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, TailLogRequest>,
    ) -> ServiceResult<ServiceStream<TailLogResponse>> {
        let from = {
            let st = self.lock();
            let head = st.head();
            match request.from_sequence {
                0 => head,
                // The log keeps every row, so a sequence it holds is one it has reached. One it
                // has not reached is refused like one it dropped: a change could be missed.
                n if n > head => {
                    return Err(refusal(
                        ErrorCode::FailedPrecondition,
                        "sequence_expired",
                        "from_sequence",
                    ));
                }
                n => n,
            }
        };
        let engine = self.clone();
        Response::stream_ok(futures::stream::unfold(from, move |last| {
            let engine = engine.clone();
            async move {
                loop {
                    let rows: Vec<TailLogResponse> = {
                        let mut st = engine.lock();
                        st.sweep(now_ms());
                        let start = st.log.partition_point(|r| r.sequence <= last);
                        st.log[start..]
                            .iter()
                            .take(TAIL_BATCH)
                            .map(|r| TailLogResponse {
                                sequence: r.sequence,
                                key: r.key.clone(),
                                version: r.version,
                                deleted: r.deleted,
                                ..TailLogResponse::default()
                            })
                            .collect()
                    };
                    if let Some(first) = rows.into_iter().next() {
                        let sequence = first.sequence;
                        return Some((Ok(first), sequence));
                    }
                    tokio::time::sleep(TAIL_POLL).await;
                }
            }
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{item_suite, report};

    /// verifies: REQ-DATA-101, REQ-DATA-102
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn the_memory_engine_passes_the_item_suite() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("durable.sock");
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let engine = MemoryEngine::new();
        let path = socket.clone();
        let server = tokio::spawn(async move {
            engine
                .serve(&path, async {
                    let _ = stopped.await;
                })
                .await
        });
        for _ in 0..100 {
            if socket.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let cases = item_suite(sluis_kit::dial(&socket)).await;
        let mut out = Vec::new();
        let verdict = report(&cases, &mut out);
        print!("{}", String::from_utf8_lossy(&out));
        let _ = stop.send(());
        server.await.unwrap().unwrap();
        verdict.unwrap();
        assert!(cases.len() >= 10, "the suite ran {} cases", cases.len());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_second_run_of_the_suite_finds_the_engine_clean() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("durable.sock");
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let engine = MemoryEngine::new();
        let state = engine.clone();
        let path = socket.clone();
        let server = tokio::spawn(async move {
            engine
                .serve(&path, async {
                    let _ = stopped.await;
                })
                .await
        });
        for _ in 0..100 {
            if socket.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        for _ in 0..2 {
            let cases = item_suite(sluis_kit::dial(&socket)).await;
            report(&cases, &mut Vec::new()).unwrap();
        }
        // The suite removes what it wrote.
        assert!(state.lock().items.is_empty(), "the suite left items behind");
        let _ = stop.send(());
        server.await.unwrap().unwrap();
    }
}
