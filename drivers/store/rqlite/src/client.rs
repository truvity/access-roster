//! A small client of rqlite's HTTP API (https://rqlite.io/docs/api/api/), read 2026-11-04 against
//! v10.6.6: the Unified Endpoint `/db/request` for writes (it returns the rows of `RETURNING`)
//! and `/db/query` for reads, statements as JSON arrays `["SQL", p1, p2]`, and `/status`.
//!
//! Only the driver talks to rqlite (0005 "Engines"); nothing else in the repository does.

use std::time::Duration;

use anyhow::{Context, bail};
use base64::Engine as _;
use bytes::Bytes;
use http::{HeaderValue, Method, Request, header};
use http_body_util::{BodyExt, Full};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use serde_json::Value;

/// How long a call to rqlite may take. rqlite's own forwarding timeout is 30 s.
const CALL: Duration = Duration::from_secs(35);

/// A statement parameter. Numbers and text only: bytes travel as hex text (`unhex(?)` and
/// `hex(x)` in the SQL), because a BLOB comes back from `/db/query` as base64 text that cannot
/// be told from a string (rqlite docs, "BLOB data").
#[derive(Clone, Debug, PartialEq)]
pub enum Param {
    /// SQL NULL.
    Null,
    /// An integer.
    Int(i64),
    /// Text.
    Text(String),
}

/// One SQL statement with its parameters.
#[derive(Clone, Debug, PartialEq)]
pub struct Stmt {
    /// The SQL, with `?` placeholders.
    pub sql: String,
    /// The parameters, in order.
    pub params: Vec<Param>,
}

impl Stmt {
    /// A statement.
    pub fn new(sql: impl Into<String>, params: Vec<Param>) -> Self {
        Self {
            sql: sql.into(),
            params,
        }
    }

    fn json(&self) -> Value {
        let mut v = Vec::with_capacity(1 + self.params.len());
        v.push(Value::String(self.sql.clone()));
        v.extend(self.params.iter().map(|p| match p {
            Param::Null => Value::Null,
            Param::Int(i) => Value::from(*i),
            Param::Text(s) => Value::String(s.clone()),
        }));
        Value::Array(v)
    }
}

/// What one statement did.
#[derive(Clone, Debug)]
pub enum Outcome {
    /// It ran: the rows it returned (a query, or `RETURNING`) and the rows it changed.
    Done {
        /// The rows, each a list of JSON values.
        rows: Vec<Vec<Value>>,
        /// `rows_affected` of a write; 0 otherwise.
        affected: i64,
    },
    /// It failed.
    Failed {
        /// SQLite's extended result code, when rqlite sent `error_v2`.
        code: Option<i64>,
        /// rqlite's message. It names tables and columns, never a value.
        message: String,
    },
}

/// SQLite's `SQLITE_CONSTRAINT_NOTNULL`: the code of a failed guard (sqlite.org/rescode.html).
pub const NOT_NULL_FAILED: i64 = 1299;

/// The read consistency of a query (https://rqlite.io/docs/api/read-consistency/).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Level {
    /// The default: the leader answers, and a follower forwards. A deposed leader can answer
    /// stale for under a second, so this is not strictly linearizable.
    Weak,
    /// The leader confirms its leadership with a quorum, so the read reflects every write that was
    /// acknowledged before it.
    Linearizable,
}

impl Level {
    fn name(self) -> &'static str {
        match self {
            Level::Weak => "weak",
            Level::Linearizable => "linearizable",
        }
    }
}

/// A client of one rqlite node.
#[derive(Clone)]
pub struct Rq {
    http: Client<HttpConnector, Full<Bytes>>,
    base: String,
    auth: Option<HeaderValue>,
}

impl Rq {
    /// A client of `url` (`http://host:port`). `basic_auth` is `user:password`.
    ///
    /// # Errors
    ///
    /// When the URL is not a plain `http://` address, or the credentials do not make a header.
    pub fn new(url: &str, basic_auth: Option<&str>) -> anyhow::Result<Self> {
        // planned: TLS and auth for the rqlite client (D-13)
        let base = url.trim_end_matches('/');
        let rest = base.strip_prefix("http://").with_context(
            || "--rqlite-url: only an http:// address is served tonight (no TLS client yet)",
        )?;
        if rest.is_empty() || rest.contains('/') || rest.contains('?') || rest.contains('@') {
            bail!("--rqlite-url: want http://HOST:PORT");
        }
        let auth = basic_auth
            .map(|c| {
                let token = base64::engine::general_purpose::STANDARD.encode(c.trim_end());
                HeaderValue::from_str(&format!("Basic {token}")).map(|mut v| {
                    v.set_sensitive(true);
                    v
                })
            })
            .transpose()
            .context("--basic-auth-file: not a usable credential")?;
        let mut connector = HttpConnector::new();
        connector.set_nodelay(true);
        connector.set_connect_timeout(Some(Duration::from_secs(5)));
        Ok(Self {
            http: Client::builder(TokioExecutor::new()).build(connector),
            base: base.to_owned(),
            auth,
        })
    }

    async fn call(&self, method: Method, path: &str, body: Option<Value>) -> anyhow::Result<Value> {
        let mut req = Request::builder()
            .method(method)
            .uri(format!("{}{path}", self.base));
        if let Some(a) = &self.auth {
            req = req.header(header::AUTHORIZATION, a.clone());
        }
        let payload = match body {
            Some(b) => {
                req = req.header(header::CONTENT_TYPE, "application/json");
                Bytes::from(serde_json::to_vec(&b)?)
            }
            None => Bytes::new(),
        };
        let req = req.body(Full::new(payload))?;
        let (status, bytes) = tokio::time::timeout(CALL, async {
            let res = self
                .http
                .request(req)
                .await
                .context("rqlite is not reachable")?;
            let status = res.status();
            let bytes = res
                .into_body()
                .collect()
                .await
                .context("rqlite answer")?
                .to_bytes();
            anyhow::Ok((status, bytes))
        })
        .await
        .context("rqlite did not answer in time")??;
        if !status.is_success() {
            // The body of an error is rqlite's text ("leader not found"), not data of ours.
            let text = String::from_utf8_lossy(&bytes);
            bail!(
                "rqlite answered {status}: {}",
                text.trim().chars().take(200).collect::<String>()
            );
        }
        serde_json::from_slice(&bytes).context("rqlite answered something that is not JSON")
    }

    fn outcomes(answer: &Value, want: usize) -> anyhow::Result<Vec<Outcome>> {
        let results = answer
            .get("results")
            .and_then(Value::as_array)
            .context("rqlite answer has no results")?;
        let mut out = Vec::with_capacity(results.len());
        for r in results {
            // rqlite 10.6 writes both `error` (deprecated) and `error_v2` by default.
            if let Some(message) = r
                .get("error")
                .or_else(|| r.pointer("/error_v2/message"))
                .and_then(Value::as_str)
            {
                out.push(Outcome::Failed {
                    code: r
                        .pointer("/error_v2/sqlite/extended_code")
                        .and_then(Value::as_i64),
                    message: message.to_owned(),
                });
                continue;
            }
            let rows = r
                .get("values")
                .and_then(Value::as_array)
                .map(|vs| {
                    vs.iter()
                        .map(|row| row.as_array().cloned().unwrap_or_default())
                        .collect()
                })
                .unwrap_or_default();
            out.push(Outcome::Done {
                rows,
                affected: r.get("rows_affected").and_then(Value::as_i64).unwrap_or(0),
            });
        }
        // Processing stops at the first failed statement of a transaction, so a short answer is
        // fine when it ends in a failure; anything else short is a broken answer.
        if out.len() != want && !matches!(out.last(), Some(Outcome::Failed { .. })) {
            bail!(
                "rqlite answered {} results for {want} statements",
                out.len()
            );
        }
        Ok(out)
    }

    /// Runs read statements at `level`.
    ///
    /// # Errors
    ///
    /// When rqlite cannot be reached or answers an HTTP error.
    pub async fn query(&self, level: Level, stmts: &[Stmt]) -> anyhow::Result<Vec<Outcome>> {
        let body = Value::Array(stmts.iter().map(Stmt::json).collect());
        let path = format!("/db/query?level={}", level.name());
        Self::outcomes(
            &self.call(Method::POST, &path, Some(body)).await?,
            stmts.len(),
        )
    }

    /// Runs write statements through the Unified Endpoint, in one transaction when `transaction`
    /// is set: all of them apply or none does, and processing stops at the first failure.
    ///
    /// # Errors
    ///
    /// When rqlite cannot be reached or answers an HTTP error. A failed statement is an
    /// [`Outcome::Failed`], not an error.
    pub async fn request(&self, stmts: &[Stmt], transaction: bool) -> anyhow::Result<Vec<Outcome>> {
        let body = Value::Array(stmts.iter().map(Stmt::json).collect());
        let path = if transaction {
            "/db/request?transaction"
        } else {
            "/db/request"
        };
        Self::outcomes(
            &self.call(Method::POST, path, Some(body)).await?,
            stmts.len(),
        )
    }

    /// Whether this node is the Raft leader (`/status`, `store.raft.state`).
    ///
    /// # Errors
    ///
    /// When rqlite cannot be reached or answers something unexpected.
    pub async fn is_leader(&self) -> anyhow::Result<bool> {
        let status = self.call(Method::GET, "/status", None).await?;
        let state = status
            .pointer("/store/raft/state")
            .and_then(Value::as_str)
            .context("/status has no store.raft.state")?;
        Ok(state == "Leader")
    }
}

/// The first failed statement of an answer, if any.
#[must_use]
pub fn first_failure(outcomes: &[Outcome]) -> Option<(usize, Option<i64>, &str)> {
    outcomes.iter().enumerate().find_map(|(i, o)| match o {
        Outcome::Failed { code, message } => Some((i, *code, message.as_str())),
        Outcome::Done { .. } => None,
    })
}

/// The rows of statement `i`, or an error when it failed or is missing.
///
/// # Errors
///
/// When the statement failed or the answer is short.
pub fn rows(outcomes: &[Outcome], i: usize) -> anyhow::Result<&[Vec<Value>]> {
    match outcomes.get(i) {
        Some(Outcome::Done { rows, .. }) => Ok(rows),
        Some(Outcome::Failed { message, .. }) => bail!("statement {i} failed: {message}"),
        None => bail!("statement {i} has no result"),
    }
}

/// Lower-case hex of bytes (the form `unhex(?)` takes).
#[must_use]
pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from(DIGITS[usize::from(b >> 4)]));
        s.push(char::from(DIGITS[usize::from(b & 15)]));
    }
    s
}

/// Bytes of a hex text, in either case (SQLite's `hex()` writes upper case).
#[must_use]
pub fn unhex(text: &str) -> Option<Vec<u8>> {
    let digit = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    };
    let raw = text.as_bytes();
    if !raw.len().is_multiple_of(2) {
        return None;
    }
    raw.chunks(2)
        .map(|p| Some(digit(p[0])? << 4 | digit(p[1])?))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trips_both_cases() {
        let all: Vec<u8> = (0..=255).collect();
        assert_eq!(unhex(&hex(&all)).unwrap(), all);
        assert_eq!(unhex("00FFaB").unwrap(), [0, 255, 0xab]);
        assert_eq!(unhex("").unwrap(), Vec::<u8>::new());
        assert!(unhex("abc").is_none() && unhex("zz").is_none());
    }

    #[test]
    fn a_statement_is_a_json_array_of_sql_and_parameters() {
        let s = Stmt::new(
            "SELECT ?, ?, ?",
            vec![Param::Null, Param::Int(7), Param::Text("a".into())],
        );
        assert_eq!(s.json().to_string(), r#"["SELECT ?, ?, ?",null,7,"a"]"#);
    }

    #[test]
    fn only_a_plain_http_address_is_taken() {
        assert!(Rq::new("http://127.0.0.1:4001", None).is_ok());
        assert!(Rq::new("http://127.0.0.1:4001/", None).is_ok());
        for bad in [
            "https://x:4001",
            "127.0.0.1:4001",
            "http://",
            "http://u:p@x:1",
            "http://x:1/db",
        ] {
            assert!(Rq::new(bad, None).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_short_answer_is_fine_only_when_it_ends_in_a_failure() {
        let failed = serde_json::json!({"results":[{"rows_affected":1},{"error":"x","error_v2":{"sqlite":{"extended_code":1299}}}]});
        let out = Rq::outcomes(&failed, 3).unwrap();
        assert_eq!(first_failure(&out), Some((1, Some(1299), "x")));
        let short = serde_json::json!({"results":[{"rows_affected":1}]});
        assert!(Rq::outcomes(&short, 3).is_err());
    }
}
