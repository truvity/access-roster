//! The `sqlite` index driver of the indexer (ADR 0028, "Search and the index").
//!
//! One SQLite file holds the whole index of a boundary. The driver serves it on two sockets that
//! carry two contracts (`proto/sluis/port/index/`): `index` for the indexer, which can read its
//! cursor and write rows, and `index-ro` for the reader, which can only search. The read side runs
//! on connections opened read-only, so that no query can write, whatever it holds.
//!
//! What the file holds:
//!
//! - `cursor`: one row per log, the last verified checkpoint the indexer indexed to. It moves
//!   forward only, by a conditional write.
//! - `record`: one row per record, with the fixed columns of 0028 and the record once. A row is
//!   unique by project, log kind, log, tenant and the record's hash, so indexing a record twice is
//!   a no-op.
//! - `record_fts`: the full-text table, external content over `record`, `unicode61` with
//!   `remove_diacritics 2` and no stemming (0028: the same words on every driver). It holds only the
//!   columns listed in [`SEARCHABLE`].
//!
//! A query names its partitions (project and log kind) and its tenants. A query without either is
//! refused: the grant of the reader is a mandatory filter of every query (0028, "Access").

pub mod service;
pub mod suite;

use std::fmt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use rusqlite::types::Value;
use rusqlite::{Connection, OpenFlags, TransactionBehavior, params_from_iter};
use sluis_proto::sluis::port::index::v2alpha1::{
    ApplyRequest, ApplyResponse, Cursor, GetCursorRequest, GetCursorResponse, LogRef, Row,
    SearchRequest, SearchResponse,
};

/// The name of the database file below the state directory.
pub const FILE: &str = "index.sqlite";
/// The tokenizer of the full-text table (0028: `unicode61` with `remove_diacritics 2`).
pub const TOKENIZER: &str = "unicode61 remove_diacritics 2";
/// The columns of `record` that the full-text table holds, and so the only fields a word search
/// reaches. The catalogue of the first working version carries action names only (decision D-15),
/// and 0028 allows a field to be searchable only when the catalogue says so, so the set is the
/// non-personal columns: the action, the status code and the product. A person's pseudonym, a
/// subject and any free text are found by an exact filter, never by a word.
pub const SEARCHABLE: [&str; 3] = ["action", "status_code", "product"];
/// The log kinds that have an index. The usage log has none (0028, REQ-AUDIT-098).
pub const KINDS: [&str; 2] = ["audit", "issuance"];

const SCHEMA_VERSION: i64 = 1;
const DIR_MODE: u32 = 0o750;
const FILE_MODE: u32 = 0o640;
const DEFAULT_PAGE: usize = 50;
const MAX_PAGE: usize = 200;
const MAX_ROWS_PER_APPLY: usize = 1024;
const MAX_ID: usize = 128;
const MAX_TEXT: usize = 1024;
const MAX_RECORD: usize = 1 << 20;
const MAX_TENANTS: usize = 100;
const MAX_PARTITIONS: usize = 32;
const MAX_TERMS: usize = 16;
const MAX_TERM: usize = 64;
const MAX_READERS: usize = 8;
/// The version byte of a page token.
const TOKEN_V1: u8 = 1;

/// Why an operation was refused. [`service`] turns each into a Connect code and a reason.
#[derive(Debug)]
pub enum Error {
    /// A field is not acceptable; the path of the field.
    Argument(&'static str),
    /// The cursor is not where the caller read it.
    Version,
    /// The log kind has no index.
    Rule,
    /// The database failed.
    Engine(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Argument(p) => write!(f, "argument: {p}"),
            Self::Version => f.write_str("version"),
            Self::Rule => f.write_str("rule"),
            Self::Engine(e) => write!(f, "engine: {e}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<rusqlite::Error> for Error {
    fn from(e: rusqlite::Error) -> Self {
        Self::Engine(e.to_string())
    }
}

type Result<T> = std::result::Result<T, Error>;

/// The index. Cheap to clone; clones share the connections.
#[derive(Clone)]
pub struct Index {
    path: Arc<PathBuf>,
    write: Arc<Mutex<Connection>>,
    readers: Arc<Mutex<Vec<Connection>>>,
}

fn pragmas(c: &Connection, read_only: bool) -> rusqlite::Result<()> {
    c.busy_timeout(std::time::Duration::from_secs(5))?;
    if read_only {
        c.pragma_update(None, "query_only", true)?;
    }
    Ok(())
}

impl Index {
    /// Opens the index in `dir`, which must be a directory (not a symlink) owned by this process's
    /// uid and closed to others (no wider than 0750). It is checked at every start. A new file is
    /// made with the schema; a file of another schema version or another tokenizer is refused,
    /// because the index is derived data and a rebuild, not a migration, is the way (0028).
    ///
    /// # Errors
    ///
    /// Fails when the directory is not acceptable or the database cannot be opened.
    pub fn open(dir: &Path) -> anyhow::Result<Self> {
        use anyhow::{Context, bail};
        let m = std::fs::symlink_metadata(dir).context("the state directory")?;
        if !m.is_dir() {
            bail!("the state directory is not a directory (a symlink is refused)");
        }
        let me = rustix::process::geteuid().as_raw();
        if m.uid() != me {
            bail!(
                "the state directory is owned by uid {}, not by this driver's uid {me}",
                m.uid()
            );
        }
        if m.mode() & !(0o40000 | DIR_MODE) != 0 {
            bail!(
                "the state directory has mode {:o}, wider than {DIR_MODE:o}",
                m.mode() & 0o7777
            );
        }
        let path = dir.join(FILE);
        let w = Connection::open_with_flags(
            &path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .context("open the index file")?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(FILE_MODE))
            .context("set the mode of the index file")?;
        pragmas(&w, false)?;
        // WAL keeps a reader from blocking the indexer. The index is derived data and is rebuilt
        // from the log, so a lost last transaction after a power cut costs a pass, not a fact.
        let mode: String = w.pragma_update_and_check(None, "journal_mode", "WAL", |r| r.get(0))?;
        if !mode.eq_ignore_ascii_case("wal") {
            bail!("the index file would not take the WAL journal mode (it said {mode})");
        }
        w.pragma_update(None, "synchronous", "NORMAL")?;
        migrate(&w)?;
        Ok(Self {
            path: Arc::new(path),
            write: Arc::new(Mutex::new(w)),
            readers: Arc::default(),
        })
    }

    fn with_reader<T>(&self, f: impl FnOnce(&Connection) -> Result<T>) -> Result<T> {
        let pooled = self
            .readers
            .lock()
            .map_err(|_| Error::Engine("poisoned".into()))?
            .pop();
        let conn = match pooled {
            Some(c) => c,
            None => {
                let c = Connection::open_with_flags(
                    self.path.as_path(),
                    OpenFlags::SQLITE_OPEN_READ_ONLY
                        | OpenFlags::SQLITE_OPEN_NO_MUTEX
                        | OpenFlags::SQLITE_OPEN_NOFOLLOW,
                )?;
                pragmas(&c, true)?;
                c
            }
        };
        let out = f(&conn);
        if let Ok(mut pool) = self.readers.lock()
            && pool.len() < MAX_READERS
        {
            pool.push(conn);
        }
        out
    }

    /// The cursor of a log; size 0 and no root for a log never indexed.
    ///
    /// # Errors
    ///
    /// [`Error::Argument`] for a bad log, [`Error::Engine`] when the database fails.
    pub fn get_cursor(&self, req: &GetCursorRequest) -> Result<GetCursorResponse> {
        let log = check_log(req.log.as_option(), "log")?;
        let c = self
            .with_reader(|c| cursor_of(c, &log).map_err(Error::from))?
            .unwrap_or_default();
        Ok(GetCursorResponse {
            cursor: ::buffa::MessageField::some(c),
            ..GetCursorResponse::default()
        })
    }

    /// Writes the rows of a batch of one log, and, when the request carries a cursor, moves the
    /// log's cursor forward, all in one transaction. A cursor write is refused unless the cursor
    /// is where the caller read it (`expect_size`) and the new one is larger: it only moves
    /// forward, and a second indexer during a deploy cannot move it back (0028).
    ///
    /// # Errors
    ///
    /// [`Error::Version`] when the cursor moved, [`Error::Rule`] for a log kind with no index,
    /// [`Error::Argument`] for a field that is not acceptable.
    pub fn apply(&self, req: &ApplyRequest) -> Result<ApplyResponse> {
        let log = check_log(req.log.as_option(), "log")?;
        if !KINDS.contains(&log.kind.as_str()) {
            return Err(Error::Rule);
        }
        if req.rows.len() > MAX_ROWS_PER_APPLY {
            return Err(Error::Argument("rows"));
        }
        for r in &req.rows {
            check_row(r)?;
        }
        let next = match req.next.as_option() {
            None => None,
            Some(n) => {
                if n.size <= req.expect_size || req.expect_size < 0 {
                    return Err(Error::Argument("next.size"));
                }
                if n.root.len() != 32 {
                    return Err(Error::Argument("next.root"));
                }
                if n.state.len() > MAX_RECORD {
                    return Err(Error::Argument("next.state"));
                }
                Some(n)
            }
        };
        let mut guard = self
            .write
            .lock()
            .map_err(|_| Error::Engine("poisoned".into()))?;
        let tx = guard.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(n) = next {
            let have = cursor_of(&tx, &log)?.map_or(0, |c| c.size);
            if have != req.expect_size {
                return Err(Error::Version);
            }
            tx.execute(
                "INSERT INTO cursor (project, kind, log, size, root, state) VALUES (?1, ?2, ?3, ?4, ?5, ?6) \
                 ON CONFLICT (project, kind, log) DO UPDATE SET size = excluded.size, root = excluded.root, state = excluded.state",
                rusqlite::params![log.project, log.kind, log.log, n.size, n.root, n.state],
            )?;
        }
        let (mut inserted, mut duplicates) = (0i64, 0i64);
        {
            let mut ins = tx.prepare(
                "INSERT INTO record (project, kind, log, tenant, hash, seq, time_ms, recorded_ms, boundary, action, \
                 class_uid, activity_id, status_id, status_code, actor_uid, actor_type_id, trace_id, record_id, product, body) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20) \
                 ON CONFLICT (project, kind, log, tenant, hash) DO NOTHING",
            )?;
            let mut fts = tx.prepare(
                "INSERT INTO record_fts (rowid, action, status_code, product) VALUES (?1, ?2, ?3, ?4)",
            )?;
            for r in &req.rows {
                let n = ins.execute(rusqlite::params![
                    log.project,
                    log.kind,
                    log.log,
                    r.tenant,
                    r.hash,
                    r.seq,
                    r.time_ms,
                    r.recorded_ms,
                    r.boundary,
                    r.action,
                    r.class_uid,
                    r.activity_id,
                    r.status_id,
                    r.status_code,
                    r.actor_uid,
                    r.actor_type_id,
                    r.trace_id,
                    r.record_id,
                    r.product,
                    r.record,
                ])?;
                if n == 1 {
                    fts.execute(rusqlite::params![
                        tx.last_insert_rowid(),
                        r.action,
                        r.status_code,
                        r.product
                    ])?;
                    inserted += 1;
                } else {
                    duplicates += 1;
                }
            }
        }
        tx.commit()?;
        Ok(ApplyResponse {
            inserted,
            duplicates,
            ..ApplyResponse::default()
        })
    }

    /// Searches the named partitions and tenants, newest first, by keyset pages.
    ///
    /// # Errors
    ///
    /// [`Error::Argument`] for a query without partitions or tenants, or with a field that is not
    /// acceptable.
    pub fn search(&self, req: &SearchRequest) -> Result<SearchResponse> {
        let q = Query::new(req)?;
        let (sql, params) = q.sql();
        self.with_reader(|c| {
            let mut stmt = c.prepare(&sql)?;
            let mut rows = stmt.query(params_from_iter(params))?;
            let mut out: Vec<(i64, Row)> = Vec::new();
            while let Some(r) = rows.next()? {
                out.push((r.get(0)?, row_of(r)?));
            }
            let more = out.len() > q.page;
            out.truncate(q.page);
            let next = match (more, out.last()) {
                (true, Some((id, last))) => token(last.time_ms, *id),
                _ => Vec::new(),
            };
            Ok(SearchResponse {
                rows: out.into_iter().map(|(_, r)| r).collect(),
                next_page_token: next,
                ..SearchResponse::default()
            })
        })
    }

    /// Whether the database answers and has its schema (the driver's `check`).
    ///
    /// # Errors
    ///
    /// The database's error.
    pub fn ping(&self) -> Result<()> {
        self.with_reader(|c| {
            c.query_row("SELECT count(*) FROM cursor", [], |r| r.get::<_, i64>(0))?;
            Ok(())
        })
    }
}

fn migrate(c: &Connection) -> anyhow::Result<()> {
    use anyhow::bail;
    let have: i64 = c.pragma_query_value(None, "user_version", |r| r.get(0))?;
    match have {
        0 => {
            c.execute_batch(&schema())?;
            c.execute(
                "INSERT INTO meta (key, value) VALUES ('tokenizer', ?1)",
                [TOKENIZER],
            )?;
            c.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        }
        v if v == SCHEMA_VERSION => {
            let t: String =
                c.query_row("SELECT value FROM meta WHERE key = 'tokenizer'", [], |r| {
                    r.get(0)
                })?;
            if t != TOKENIZER {
                bail!(
                    "the index was made with the tokenizer {t:?}; rebuild it (0028: a tokenizer change is a rebuild)"
                );
            }
        }
        v => bail!(
            "the index file has schema version {v}; this driver has {SCHEMA_VERSION}: rebuild it"
        ),
    }
    Ok(())
}

fn schema() -> String {
    format!(
        "CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL) WITHOUT ROWID;
         CREATE TABLE cursor (
           project TEXT NOT NULL, kind TEXT NOT NULL, log TEXT NOT NULL,
           size INTEGER NOT NULL, root BLOB NOT NULL, state BLOB NOT NULL,
           PRIMARY KEY (project, kind, log)) WITHOUT ROWID;
         CREATE TABLE record (
           id INTEGER PRIMARY KEY,
           project TEXT NOT NULL, kind TEXT NOT NULL, log TEXT NOT NULL, tenant TEXT NOT NULL,
           hash BLOB NOT NULL, seq INTEGER NOT NULL,
           time_ms INTEGER NOT NULL, recorded_ms INTEGER NOT NULL,
           boundary TEXT NOT NULL, action TEXT NOT NULL,
           class_uid INTEGER NOT NULL, activity_id INTEGER NOT NULL,
           status_id INTEGER NOT NULL, status_code TEXT NOT NULL,
           actor_uid TEXT NOT NULL, actor_type_id INTEGER NOT NULL,
           trace_id TEXT NOT NULL, record_id TEXT NOT NULL, product TEXT NOT NULL,
           body BLOB NOT NULL,
           UNIQUE (project, kind, log, tenant, hash));
         CREATE INDEX record_time ON record (project, kind, tenant, time_ms DESC, id DESC);
         CREATE INDEX record_record_id ON record (project, kind, tenant, record_id);
         CREATE INDEX record_trace_id ON record (project, kind, tenant, trace_id);
         CREATE VIRTUAL TABLE record_fts USING fts5({cols}, content='record', content_rowid='id', tokenize='{TOKENIZER}');",
        cols = SEARCHABLE.join(", ")
    )
}

fn cursor_of(c: &Connection, log: &LogRef) -> rusqlite::Result<Option<Cursor>> {
    let mut stmt = c.prepare(
        "SELECT size, root, state FROM cursor WHERE project = ?1 AND kind = ?2 AND log = ?3",
    )?;
    let mut rows = stmt.query(rusqlite::params![log.project, log.kind, log.log])?;
    match rows.next()? {
        None => Ok(None),
        Some(r) => Ok(Some(Cursor {
            size: r.get(0)?,
            root: r.get(1)?,
            state: r.get(2)?,
            ..Cursor::default()
        })),
    }
}

fn row_of(r: &rusqlite::Row<'_>) -> rusqlite::Result<Row> {
    Ok(Row {
        tenant: r.get(1)?,
        hash: r.get(2)?,
        seq: r.get(3)?,
        time_ms: r.get(4)?,
        recorded_ms: r.get(5)?,
        boundary: r.get(6)?,
        action: r.get(7)?,
        class_uid: r.get(8)?,
        activity_id: r.get(9)?,
        status_id: r.get(10)?,
        status_code: r.get(11)?,
        actor_uid: r.get(12)?,
        actor_type_id: r.get(13)?,
        trace_id: r.get(14)?,
        record_id: r.get(15)?,
        product: r.get(16)?,
        record: r.get(17)?,
        ..Row::default()
    })
}

/// A name of a project, a log kind, a log, a tenant: printable, no control character, bounded.
fn name_ok(s: &str) -> bool {
    !s.is_empty() && s.len() <= MAX_ID && s.chars().all(|c| !c.is_control())
}

fn text_ok(s: &str) -> bool {
    s.len() <= MAX_TEXT && !s.contains('\0')
}

fn check_log(l: Option<&LogRef>, path: &'static str) -> Result<LogRef> {
    match l {
        Some(l) if name_ok(&l.project) && name_ok(&l.kind) && name_ok(&l.log) => Ok(l.clone()),
        _ => Err(Error::Argument(path)),
    }
}

fn check_row(r: &Row) -> Result<()> {
    if !name_ok(&r.tenant) || r.tenant == "*" {
        return Err(Error::Argument("rows.tenant"));
    }
    if r.hash.len() != 48 {
        return Err(Error::Argument("rows.hash"));
    }
    if r.record.is_empty() || r.record.len() > MAX_RECORD {
        return Err(Error::Argument("rows.record"));
    }
    if r.seq < 0 {
        return Err(Error::Argument("rows.seq"));
    }
    let texts = [
        &r.boundary,
        &r.action,
        &r.status_code,
        &r.actor_uid,
        &r.trace_id,
        &r.record_id,
        &r.product,
    ];
    if texts.iter().any(|t| !text_ok(t)) {
        return Err(Error::Argument("rows"));
    }
    Ok(())
}

/// A query after its checks.
struct Query<'a> {
    req: &'a SearchRequest,
    fts: Option<String>,
    after: Option<(i64, i64)>,
    page: usize,
}

impl<'a> Query<'a> {
    fn new(req: &'a SearchRequest) -> Result<Self> {
        if req.partitions.is_empty() || req.partitions.len() > MAX_PARTITIONS {
            return Err(Error::Argument("partitions"));
        }
        if req
            .partitions
            .iter()
            .any(|p| !name_ok(&p.project) || !KINDS.contains(&p.kind.as_str()))
        {
            return Err(Error::Argument("partitions"));
        }
        if req.tenants.is_empty()
            || req.tenants.len() > MAX_TENANTS
            || req.tenants.iter().any(|t| !name_ok(t))
        {
            return Err(Error::Argument("tenants"));
        }
        let page = match usize::try_from(req.page_size).map_err(|_| Error::Argument("page_size"))? {
            0 => DEFAULT_PAGE,
            n => n.min(MAX_PAGE),
        };
        let texts = [
            &req.action,
            &req.status_code,
            &req.actor_uid,
            &req.trace_id,
            &req.record_id,
        ];
        if texts.iter().any(|t| !text_ok(t)) {
            return Err(Error::Argument("filter"));
        }
        let fts = if req.q.trim().is_empty() {
            None
        } else {
            Some(fts_query(&req.q)?)
        };
        let after = if req.page_token.is_empty() {
            None
        } else {
            Some(parse_token(&req.page_token)?)
        };
        Ok(Self {
            req,
            fts,
            after,
            page,
        })
    }

    fn sql(&self) -> (String, Vec<Value>) {
        let r = self.req;
        let mut p: Vec<Value> = Vec::new();
        let push = |p: &mut Vec<Value>, v: Value| {
            p.push(v);
            p.len()
        };
        let mut sql = String::from(
            "SELECT id, tenant, hash, seq, time_ms, recorded_ms, boundary, action, class_uid, activity_id, status_id, \
             status_code, actor_uid, actor_type_id, trace_id, record_id, product, body FROM record WHERE (",
        );
        for (i, part) in r.partitions.iter().enumerate() {
            if i > 0 {
                sql.push_str(" OR ");
            }
            let a = push(&mut p, Value::Text(part.project.clone()));
            let b = push(&mut p, Value::Text(part.kind.clone()));
            sql.push_str(&format!("(project = ?{a} AND kind = ?{b})"));
        }
        sql.push(')');
        if !r.tenants.iter().any(|t| t == "*") {
            let marks: Vec<String> = r
                .tenants
                .iter()
                .map(|t| format!("?{}", push(&mut p, Value::Text(t.clone()))))
                .collect();
            sql.push_str(&format!(" AND tenant IN ({})", marks.join(", ")));
        }
        let eq = |sql: &mut String, p: &mut Vec<Value>, col: &str, v: Value| {
            let n = push(p, v);
            sql.push_str(&format!(" AND {col} = ?{n}"));
        };
        if !r.action.is_empty() {
            eq(&mut sql, &mut p, "action", Value::Text(r.action.clone()));
        }
        if !r.status_code.is_empty() {
            eq(
                &mut sql,
                &mut p,
                "status_code",
                Value::Text(r.status_code.clone()),
            );
        }
        if r.status_id != 0 {
            eq(&mut sql, &mut p, "status_id", Value::Integer(r.status_id));
        }
        if !r.actor_uid.is_empty() {
            eq(
                &mut sql,
                &mut p,
                "actor_uid",
                Value::Text(r.actor_uid.clone()),
            );
        }
        if !r.trace_id.is_empty() {
            eq(
                &mut sql,
                &mut p,
                "trace_id",
                Value::Text(r.trace_id.clone()),
            );
        }
        if !r.record_id.is_empty() {
            eq(
                &mut sql,
                &mut p,
                "record_id",
                Value::Text(r.record_id.clone()),
            );
        }
        if r.from_ms != 0 {
            let n = push(&mut p, Value::Integer(r.from_ms));
            sql.push_str(&format!(" AND time_ms >= ?{n}"));
        }
        if r.to_ms != 0 {
            let n = push(&mut p, Value::Integer(r.to_ms));
            sql.push_str(&format!(" AND time_ms < ?{n}"));
        }
        if let Some(m) = &self.fts {
            let n = push(&mut p, Value::Text(m.clone()));
            sql.push_str(&format!(
                " AND id IN (SELECT rowid FROM record_fts WHERE record_fts MATCH ?{n})"
            ));
        }
        if let Some((t, id)) = self.after {
            let (a, b) = (
                push(&mut p, Value::Integer(t)),
                push(&mut p, Value::Integer(id)),
            );
            sql.push_str(&format!(
                " AND (time_ms < ?{a} OR (time_ms = ?{a} AND id < ?{b}))"
            ));
        }
        sql.push_str(&format!(
            " ORDER BY time_ms DESC, id DESC LIMIT {}",
            self.page + 1
        ));
        (sql, p)
    }
}

/// Turns the words of a query into an FTS5 expression of quoted phrases, so that no FTS5 operator,
/// column filter or special character of the person's text means anything: each word is a phrase
/// in double quotes, a trailing `*` makes it a prefix, and the words are all required. There is no
/// substring search (0028).
fn fts_query(q: &str) -> Result<String> {
    let mut terms = Vec::new();
    for w in q.split_whitespace() {
        let (word, prefix) = match w.strip_suffix('*') {
            Some(rest) => (rest, true),
            None => (w, false),
        };
        let word: String = word.chars().filter(|c| *c != '"').collect();
        if !word.chars().any(char::is_alphanumeric) {
            continue;
        }
        if word.len() > MAX_TERM {
            return Err(Error::Argument("q"));
        }
        terms.push(format!("\"{word}\"{}", if prefix { "*" } else { "" }));
    }
    if terms.is_empty() || terms.len() > MAX_TERMS {
        return Err(Error::Argument("q"));
    }
    Ok(terms.join(" "))
}

fn token(time_ms: i64, id: i64) -> Vec<u8> {
    let mut t = vec![TOKEN_V1];
    t.extend_from_slice(&time_ms.to_be_bytes());
    t.extend_from_slice(&id.to_be_bytes());
    t
}

fn parse_token(t: &[u8]) -> Result<(i64, i64)> {
    if t.len() != 17 || t[0] != TOKEN_V1 {
        return Err(Error::Argument("page_token"));
    }
    let (mut a, mut b) = ([0u8; 8], [0u8; 8]);
    a.copy_from_slice(&t[1..9]);
    b.copy_from_slice(&t[9..17]);
    Ok((i64::from_be_bytes(a), i64::from_be_bytes(b)))
}
