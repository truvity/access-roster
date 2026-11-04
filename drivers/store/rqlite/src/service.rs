//! The item contract over rqlite (`sluis.port.item.v2alpha1.ItemService`; store-api.md "The item
//! contract"; 0005 "Drivers" and "Engines").
//!
//! The driver sees keys, versions, bytes, expiries and index entries. It never parses a key into
//! a kind and never writes a timestamp of its own into an item: its clock only compares with
//! `expires_at` and picks candidates to sweep.

#![allow(refining_impl_trait)] // the generated trait returns `impl Encodable`; a concrete type is fine

use std::time::Duration;

use anyhow::{Context, bail};
use connectrpc::error::ErrorCode;
use connectrpc::{
    ConnectError, RequestContext, Response, Router, ServiceRequest, ServiceResult, ServiceStream,
};
use serde_json::Value;
use sluis_conformance::rules::{self, now_ms};
use sluis_kit::refusal;
use sluis_proto::sluis::port::item::v2alpha1::{
    DriverItem, ItemGetRequest, ItemGetResponse, ItemService, ItemServiceExt, QueryRequest,
    QueryResponse, TailLogRequest, TailLogResponse, TransactRequest, TransactResponse,
};
use sluis_proto::sluis::r#type::v2alpha1::IndexEntry;

use crate::client::{Level, NOT_NULL_FAILED, Outcome, Rq, first_failure, rows, unhex};
use crate::sql::{Ns, SCHEMA_VERSION};

/// How often a tail looks for new log rows (the brief: polled every 200 ms).
const TAIL_POLL: Duration = Duration::from_millis(200);

/// The driver: a client of one rqlite node and the tables of one namespace.
#[derive(Clone)]
pub struct Driver {
    rq: Rq,
    ns: Ns,
}

impl Driver {
    /// A driver over `rq` for the namespace `ns`.
    #[must_use]
    pub fn new(rq: Rq, ns: Ns) -> Self {
        Self { rq, ns }
    }

    /// The client of rqlite, for the sweeper.
    #[must_use]
    pub fn rq(&self) -> &Rq {
        &self.rq
    }

    /// The tables, for the sweeper.
    #[must_use]
    pub fn ns(&self) -> &Ns {
        &self.ns
    }

    /// Creates the schema if it is not there, and checks its version. Idempotent, so three boards
    /// may run it at once.
    ///
    /// # Errors
    ///
    /// When rqlite cannot be reached, refuses the statements, or holds another schema version.
    pub async fn ensure_schema(&self) -> anyhow::Result<()> {
        let out = self.rq.request(&self.ns.ddl(), true).await?;
        if let Some((i, _, message)) = first_failure(&out) {
            bail!("schema statement {i} failed: {message}");
        }
        self.verify_schema(Level::Linearizable).await
    }

    /// Checks that rqlite answers a linearizable read and that the schema is the one this build
    /// speaks (the work of `check`).
    ///
    /// # Errors
    ///
    /// When rqlite cannot be reached, the schema is missing, or its version differs.
    pub async fn verify_schema(&self, level: Level) -> anyhow::Result<()> {
        // `SELECT 1` proves the read path at this level; the second statement is the schema.
        let probe = crate::client::Stmt::new("SELECT 1", vec![]);
        let out = self
            .rq
            .query(level, &[probe, self.ns.schema_version()])
            .await?;
        let one = rows(&out, 0)?
            .first()
            .and_then(|r| r.first())
            .and_then(Value::as_i64);
        anyhow::ensure!(one == Some(1), "SELECT 1 did not answer 1");
        let version = rows(&out, 1)?
            .first()
            .and_then(|r| r.first())
            .and_then(Value::as_i64)
            .context("the schema is not there: run serve once")?;
        anyhow::ensure!(
            version == SCHEMA_VERSION,
            "the schema is version {version}, this driver speaks {SCHEMA_VERSION}"
        );
        Ok(())
    }

    /// The router of the item contract.
    #[must_use]
    pub fn router(self) -> Router {
        std::sync::Arc::new(self).register(Router::new())
    }

    async fn read(
        &self,
        level: Level,
        stmt: crate::client::Stmt,
    ) -> Result<Vec<Vec<Value>>, ConnectError> {
        let out = self.rq.query(level, &[stmt]).await.map_err(engine_down)?;
        rows(&out, 0).map(<[_]>::to_vec).map_err(engine_down)
    }
}

/// An engine failure: store@ fails closed on `unavailable`. The reason is logged, never sent: it
/// is rqlite's text.
fn engine_down(e: anyhow::Error) -> ConnectError {
    tracing::warn!(error = %format!("{e:#}"), "the engine failed");
    refusal(ErrorCode::Unavailable, "engine", "")
}

/// The key as the text SQLite orders. Keys are checked ASCII before they get here.
fn text(key: &[u8]) -> String {
    String::from_utf8_lossy(key).into_owned()
}

/// Items from rows of [`Ns::get`] and [`Ns::query`]: one row per index entry of an item, grouped by
/// key (the rows come in key order).
fn items(rows: &[Vec<Value>]) -> anyhow::Result<Vec<DriverItem>> {
    let mut out: Vec<DriverItem> = Vec::new();
    for r in rows {
        let [key, version, value, expires, name, index_value] = r.as_slice() else {
            bail!("a row of {} columns, want 6", r.len());
        };
        let key = key.as_str().context("key")?.as_bytes().to_vec();
        if out.last().is_none_or(|i| i.key != key) {
            out.push(DriverItem {
                version: u64::try_from(version.as_i64().context("version")?)?,
                value: unhex(value.as_str().context("value")?).context("value is not hex")?,
                expires_at: expires.as_i64().map(rules::ms_to_ts).into(),
                key,
                ..DriverItem::default()
            });
        }
        // A row without an index entry has a NULL name (entry names are never empty).
        if let (Some(name), Some(item)) = (name.as_str(), out.last_mut()) {
            item.indexes.push(IndexEntry {
                name: name.to_owned(),
                value: unhex(index_value.as_str().context("index value")?)
                    .context("index value is not hex")?,
                ..IndexEntry::default()
            });
        }
    }
    Ok(out)
}

impl ItemService for Driver {
    async fn get(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, ItemGetRequest>,
    ) -> ServiceResult<ItemGetResponse> {
        let (key, linearizable) = (request.key.to_vec(), request.linearizable);
        rules::check_key(&key, "key")?;
        // `weak` unless asked: a follower forwards to the leader, and only a deposed leader in
        // its first second can answer stale (rqlite read consistency, read 2026-11-04).
        let level = if linearizable {
            Level::Linearizable
        } else {
            Level::Weak
        };
        let found = self.read(level, self.ns.get(&text(&key), now_ms())).await?;
        let item = items(&found).map_err(engine_down)?.into_iter().next();
        let Some(item) = item else {
            return Err(refusal(ErrorCode::NotFound, "absent", ""));
        };
        Response::ok(ItemGetResponse {
            item: Some(item).into(),
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
        let after = (!req.page_token.is_empty()).then(|| text(&req.page_token));
        let index =
            (!req.index.is_empty()).then_some((req.index.as_str(), req.index_value.as_slice()));
        // One item more than the page says whether there is a next page.
        let stmt = self.ns.query(
            &text(&req.prefix),
            after.as_deref(),
            index,
            size + 1,
            now_ms(),
        );
        let mut found = items(&self.read(Level::Weak, stmt).await?).map_err(engine_down)?;
        let next_page_token = if found.len() > size {
            found.truncate(size);
            found.last().map(|i| i.key.clone()).unwrap_or_default()
        } else {
            Vec::new()
        };
        Response::ok(QueryResponse {
            items: found,
            next_page_token,
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
        let ns = &self.ns;

        // Guards first, then deletes, then puts: one request, one transaction, one Raft entry.
        let mut stmts = Vec::new();
        for (c, want) in req.conditions.iter().zip(&expected) {
            stmts.push(ns.guard(&text(&c.key), *want, now));
        }
        let guards = stmts.len();
        for d in &req.deletes {
            let key = text(&d.key);
            if d.log {
                stmts.push(ns.log_delete(&key, now));
            }
            stmts.push(ns.delete_index(&key));
            stmts.push(ns.delete_item(&key));
        }
        // The position of each put's `RETURNING` statement.
        let mut returning = Vec::with_capacity(req.puts.len());
        for p in &req.puts {
            let key = text(&p.key);
            let expires = p.expires_at.as_option().map(rules::ts_to_ms);
            stmts.push(ns.delete_index(&key));
            returning.push(stmts.len());
            stmts.push(ns.upsert(&key, &p.value, expires, now));
            let mut entries: Vec<_> = p.indexes.iter().map(|e| (&e.name, &e.value)).collect();
            entries.sort();
            entries.dedup();
            for (name, value) in entries {
                stmts.push(ns.insert_index(&key, name, value));
            }
            if p.log {
                stmts.push(ns.log_put(&key, now));
            }
        }
        if stmts.is_empty() {
            return Response::ok(TransactResponse::default());
        }

        let out = self.rq.request(&stmts, true).await.map_err(engine_down)?;
        if let Some((i, code, message)) = first_failure(&out) {
            // A guard fails with a NOT NULL constraint; anything else in the guard range, or past
            // it, is the engine and not a lost condition.
            if i < guards && code.is_some_and(|c| c == NOT_NULL_FAILED) {
                return Err(refusal(
                    ErrorCode::Aborted,
                    "version",
                    &format!("conditions[{i}]"),
                ));
            }
            return Err(engine_down(anyhow::anyhow!(
                "statement {i} failed: {message}"
            )));
        }
        let mut written = Vec::with_capacity(req.puts.len());
        for (p, at) in req.puts.iter().zip(returning) {
            let version = self.returned_version(&out, at).map_err(engine_down)?;
            written.push(DriverItem {
                key: p.key.clone(),
                version,
                value: p.value.clone(),
                expires_at: p.expires_at.clone(),
                indexes: dedup_sorted(&p.indexes),
                ..DriverItem::default()
            });
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
        let from_sequence = request.from_sequence;
        // The head is read linearizably: a resume point ahead of a lagging answer must not look
        // like a sequence the log never reached.
        let head = self
            .read(Level::Linearizable, self.ns.log_head())
            .await?
            .into_iter()
            .next()
            .and_then(|r| Some((r.first()?.as_i64()?, r.get(1)?.as_i64()?)))
            .ok_or_else(|| engine_down(anyhow::anyhow!("the log head is not readable")))?;
        let (newest, floor) = head;
        let head = newest.max(floor);
        let from = match i64::try_from(from_sequence) {
            Ok(0) => head,
            // A sequence below the floor was trimmed; one above the head was never reached (the
            // log was reset, or the watcher made it up). Either way a change could be missed.
            Ok(n) if n < floor || n > head => return Err(expired()),
            Ok(n) => n,
            Err(_) => return Err(expired()),
        };
        let driver = self.clone();
        // State: the last sequence delivered, the rows read but not yet delivered, and whether the
        // stream has failed (it ends after its error; the watcher resumes from its point).
        Response::stream_ok(futures::stream::unfold(
            (
                from,
                std::collections::VecDeque::<TailLogResponse>::new(),
                false,
            ),
            move |(mut last, mut queued, failed)| {
                let driver = driver.clone();
                async move {
                    if failed {
                        return None;
                    }
                    loop {
                        if let Some(row) = queued.pop_front() {
                            last = i64::try_from(row.sequence).unwrap_or(last);
                            return Some((Ok(row), (last, queued, false)));
                        }
                        match driver.read(Level::Weak, driver.ns.log_after(last)).await {
                            Ok(found) if found.is_empty() => tokio::time::sleep(TAIL_POLL).await,
                            Ok(found) => match log_rows(&found) {
                                Ok(rows) => queued.extend(rows),
                                Err(e) => return Some((Err(engine_down(e)), (last, queued, true))),
                            },
                            Err(e) => return Some((Err(e), (last, queued, true))),
                        }
                    }
                }
            },
        ))
    }
}

impl Driver {
    /// The version `RETURNING` gave for the statement at `at`.
    fn returned_version(&self, out: &[Outcome], at: usize) -> anyhow::Result<u64> {
        let v = rows(out, at)?
            .first()
            .and_then(|r| r.first())
            .and_then(Value::as_i64)
            .context("the write returned no version")?;
        Ok(u64::try_from(v)?)
    }
}

fn expired() -> ConnectError {
    refusal(
        ErrorCode::FailedPrecondition,
        "sequence_expired",
        "from_sequence",
    )
}

fn log_rows(found: &[Vec<Value>]) -> anyhow::Result<Vec<TailLogResponse>> {
    found
        .iter()
        .map(|r| {
            let [seq, key, version, deleted] = r.as_slice() else {
                bail!("a log row of {} columns, want 4", r.len());
            };
            Ok(TailLogResponse {
                sequence: u64::try_from(seq.as_i64().context("seq")?)?,
                key: key.as_str().context("key")?.as_bytes().to_vec(),
                version: u64::try_from(version.as_i64().context("version")?)?,
                deleted: deleted.as_i64().context("deleted")? != 0,
                ..TailLogResponse::default()
            })
        })
        .collect()
}

/// The index entries of a put as a read would show them: by name, then value, without repeats.
fn dedup_sorted(entries: &[IndexEntry]) -> Vec<IndexEntry> {
    let mut v: Vec<_> = entries
        .iter()
        .map(|e| (e.name.clone(), e.value.clone()))
        .collect();
    v.sort();
    v.dedup();
    v.into_iter()
        .map(|(name, value)| IndexEntry {
            name,
            value,
            ..IndexEntry::default()
        })
        .collect()
}
