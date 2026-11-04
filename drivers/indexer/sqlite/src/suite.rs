//! The index port suite (REQ-TEST-009: one conformance suite covers the index port). `conformance`
//! runs it against a temporary directory. A case that fails is the error; there is no skip.
//!
//! The suite holds what every index driver must do, whatever its engine (0028): the cursor moves
//! forward only, indexing is idempotent by record hash, a query names its partitions and its
//! tenants, tenants and partitions never mix, the usage log has no index, word search is
//! `unicode61` with `remove_diacritics 2` without stemming and without substring search, only the
//! searchable columns are reached by a word, and the pages of a query are keyset pages.

use std::os::unix::fs::PermissionsExt;

use anyhow::{Result, ensure};
use sluis_proto::sluis::port::index::v2alpha1::{
    ApplyRequest, Cursor, GetCursorRequest, LogRef, Partition, Row, SearchRequest,
};

use crate::{Error, FILE, Index, TOKENIZER};

macro_rules! refused {
    ($e:expr, $want:pat) => {{
        let got = $e.map(|_| ());
        ensure!(
            matches!(got, Err($want)),
            "{}: answered {got:?}",
            stringify!($e)
        )
    }};
}

fn log(project: &str, kind: &str) -> LogRef {
    LogRef {
        project: project.into(),
        kind: kind.into(),
        log: "main".into(),
        ..LogRef::default()
    }
}

/// A row. `n` makes the hash, the record id and the sequence; `time_ms` orders it.
fn row(tenant: &str, action: &str, n: u8, time_ms: i64) -> Row {
    Row {
        tenant: tenant.into(),
        hash: vec![n; 48],
        seq: i64::from(n),
        time_ms,
        recorded_ms: time_ms + 1,
        boundary: "dev".into(),
        action: action.into(),
        class_uid: 6003,
        activity_id: 99,
        status_id: 1,
        status_code: "ok".into(),
        actor_uid: format!("p1.202611.abcdef{n}@dev"),
        actor_type_id: 3,
        trace_id: format!("trace-{n}"),
        record_id: format!("rec-{n}"),
        product: "sluis".into(),
        record: format!("{{\"n\":{n}}}").into_bytes(),
        ..Row::default()
    }
}

fn apply(
    i: &Index,
    p: &str,
    kind: &str,
    expect: i64,
    next: Option<i64>,
    rows: Vec<Row>,
) -> Result<(i64, i64), Error> {
    let r = i.apply(&ApplyRequest {
        log: ::buffa::MessageField::some(log(p, kind)),
        expect_size: expect,
        next: match next {
            Some(size) => ::buffa::MessageField::some(Cursor {
                size,
                root: vec![size as u8; 32],
                state: b"frontier".to_vec(),
                ..Cursor::default()
            }),
            None => ::buffa::MessageField::none(),
        },
        rows,
        ..ApplyRequest::default()
    })?;
    Ok((r.inserted, r.duplicates))
}

fn query(partitions: &[(&str, &str)], tenants: &[&str]) -> SearchRequest {
    SearchRequest {
        partitions: partitions
            .iter()
            .map(|(p, k)| Partition {
                project: (*p).into(),
                kind: (*k).into(),
                ..Partition::default()
            })
            .collect(),
        tenants: tenants.iter().map(|t| (*t).into()).collect(),
        ..SearchRequest::default()
    }
}

fn found(i: &Index, mut q: SearchRequest, words: &str) -> Result<Vec<String>, Error> {
    q.q = words.into();
    Ok(i.search(&q)?
        .rows
        .into_iter()
        .map(|r| r.record_id)
        .collect())
}

/// Runs every case in a fresh directory of mode 0750.
///
/// # Errors
///
/// The first case that fails.
pub fn run_temp() -> Result<()> {
    let dir = tempfile::tempdir()?;
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o750))?;

    // A directory that is open to others, or a symlink, is refused at the start.
    let wide = tempfile::tempdir()?;
    std::fs::set_permissions(wide.path(), std::fs::Permissions::from_mode(0o770))?;
    ensure!(
        Index::open(wide.path()).is_err(),
        "a directory of mode 0770 was accepted"
    );
    let link = dir.path().join("dir-link");
    std::os::unix::fs::symlink(dir.path(), &link)?;
    ensure!(
        Index::open(&link).is_err(),
        "a symlink as the directory was accepted"
    );
    std::fs::remove_file(&link)?;
    println!("ok: directory checks");

    let i = Index::open(dir.path())?;
    let mode = std::fs::metadata(dir.path().join(FILE))?
        .permissions()
        .mode()
        & 0o777;
    ensure!(mode == 0o640, "the index file has mode {mode:o}, want 640");
    // The tokenizer and the full-text table are the ones 0028 names.
    let t: String = i.with_reader(|c| {
        Ok(
            c.query_row("SELECT value FROM meta WHERE key = 'tokenizer'", [], |r| {
                r.get(0)
            })?,
        )
    })?;
    ensure!(
        t == TOKENIZER && TOKENIZER == "unicode61 remove_diacritics 2",
        "the tokenizer is {t:?}"
    );
    drop(i);
    ensure!(
        Index::open(dir.path()).is_ok(),
        "the index did not open a second time"
    );
    let i = Index::open(dir.path())?;
    println!("ok: the file, its mode and its tokenizer");

    // The read side cannot write, whatever it is asked.
    let wrote = i.with_reader(|c| Ok(c.execute("DELETE FROM record", [])?));
    ensure!(wrote.is_err(), "a read connection could write");
    println!("ok: the read side is read-only");

    // The cursor moves forward only, by a conditional write.
    let get = |p: &str, k: &str| {
        i.get_cursor(&GetCursorRequest {
            log: ::buffa::MessageField::some(log(p, k)),
            ..GetCursorRequest::default()
        })
    };
    ensure!(
        get("sluis", "audit")?
            .cursor
            .as_option()
            .is_some_and(|c| c.size == 0 && c.root.is_empty()),
        "a new log has a cursor"
    );
    apply(
        &i,
        "sluis",
        "audit",
        0,
        Some(2),
        vec![
            row("acme", "token.exchange", 1, 1000),
            row("acme", "token.sign", 2, 2000),
        ],
    )?;
    ensure!(
        get("sluis", "audit")?
            .cursor
            .as_option()
            .is_some_and(|c| c.size == 2 && c.state == b"frontier"),
        "the cursor did not move"
    );
    refused!(
        apply(&i, "sluis", "audit", 0, Some(5), vec![]),
        Error::Version
    );
    refused!(
        apply(&i, "sluis", "audit", 2, Some(2), vec![]),
        Error::Argument("next.size")
    );
    refused!(
        apply(&i, "sluis", "audit", 2, Some(1), vec![]),
        Error::Argument("next.size")
    );
    ensure!(
        get("sluis", "audit")?
            .cursor
            .as_option()
            .is_some_and(|c| c.size == 2),
        "a refused write moved the cursor"
    );
    // Rows alone, without a cursor, are accepted: a long batch is sent in several calls.
    apply(
        &i,
        "sluis",
        "audit",
        0,
        None,
        vec![row("acme", "token.refused", 3, 3000)],
    )?;
    ensure!(
        get("sluis", "audit")?
            .cursor
            .as_option()
            .is_some_and(|c| c.size == 2),
        "rows alone moved the cursor"
    );
    println!("ok: the cursor moves forward only");

    // Indexing is idempotent by record hash: a repeat is counted and changes nothing.
    let (ins, dup) = apply(
        &i,
        "sluis",
        "audit",
        2,
        Some(3),
        vec![
            row("acme", "token.exchange", 1, 1000),
            row("acme", "key.sign", 4, 4000),
        ],
    )?;
    ensure!(
        (ins, dup) == (1, 1),
        "a repeat inserted {ins} and repeated {dup}, want 1 and 1"
    );
    let all = found(&i, query(&[("sluis", "audit")], &["acme"]), "")?;
    ensure!(all.len() == 4, "{} rows, want 4", all.len());
    ensure!(
        found(&i, query(&[("sluis", "audit")], &["acme"]), "exchange")?.len() == 1,
        "a repeat made a second full-text row"
    );
    println!("ok: indexing is idempotent by hash");

    // The usage log has no index; the kinds are closed.
    refused!(
        apply(
            &i,
            "sluis",
            "usage",
            0,
            Some(1),
            vec![row("acme", "x", 9, 9)]
        ),
        Error::Rule
    );
    refused!(
        i.search(&query(&[("sluis", "usage")], &["acme"])),
        Error::Argument("partitions")
    );
    println!("ok: no index for the usage log");

    // A query names its partitions and its tenants.
    refused!(
        i.search(&query(&[], &["acme"])),
        Error::Argument("partitions")
    );
    refused!(
        i.search(&query(&[("sluis", "audit")], &[])),
        Error::Argument("tenants")
    );
    // Rows with no usable tenant, or a hash of the wrong size, are refused.
    refused!(
        apply(&i, "sluis", "audit", 0, None, vec![row("*", "x", 8, 8)]),
        Error::Argument("rows.tenant")
    );
    refused!(
        apply(
            &i,
            "sluis",
            "audit",
            0,
            None,
            vec![Row {
                hash: vec![1; 3],
                ..row("acme", "x", 8, 8)
            }]
        ),
        Error::Argument("rows.hash")
    );
    println!("ok: partitions and tenants are mandatory");

    // Tenants and partitions never mix.
    apply(
        &i,
        "sluis",
        "audit",
        0,
        None,
        vec![row("globex", "token.exchange", 5, 5000)],
    )?;
    apply(
        &i,
        "other",
        "audit",
        0,
        None,
        vec![row("acme", "token.exchange", 6, 6000)],
    )?;
    apply(
        &i,
        "sluis",
        "issuance",
        0,
        None,
        vec![row("acme", "cert.issue", 7, 7000)],
    )?;
    let ids = |q: SearchRequest| -> Result<Vec<String>, Error> { found(&i, q, "") };
    ensure!(
        ids(query(&[("sluis", "audit")], &["globex"]))? == ["rec-5"],
        "tenant globex sees other rows"
    );
    ensure!(
        ids(query(&[("sluis", "audit")], &["acme"]))?.len() == 4,
        "tenant acme sees another tenant's rows"
    );
    ensure!(
        ids(query(&[("sluis", "audit")], &["acme", "globex"]))?.len() == 5,
        "two tenants do not see both"
    );
    ensure!(
        ids(query(&[("sluis", "audit")], &["*"]))?.len() == 5,
        "* does not see every tenant"
    );
    ensure!(
        ids(query(&[("other", "audit")], &["*"]))? == ["rec-6"],
        "partition other sees sluis rows"
    );
    ensure!(
        ids(query(&[("sluis", "issuance")], &["acme"]))? == ["rec-7"],
        "log kinds mix"
    );
    ensure!(
        ids(query(&[("sluis", "audit"), ("other", "audit")], &["acme"]))?.len() == 5,
        "two partitions do not both answer"
    );
    ensure!(
        ids(query(&[("sluis", "audit")], &["nobody"]))?.is_empty(),
        "an unknown tenant sees rows"
    );
    // The same hash in another tenant is another row.
    apply(
        &i,
        "sluis",
        "audit",
        0,
        None,
        vec![row("globex", "token.exchange", 1, 1000)],
    )?;
    ensure!(
        ids(query(&[("sluis", "audit")], &["globex"]))?.len() == 2,
        "a hash of another tenant was a repeat"
    );
    println!("ok: tenants and partitions do not mix");

    // Filters.
    let mut q = query(&[("sluis", "audit")], &["acme"]);
    q.action = "key.sign".into();
    ensure!(found(&i, q, "")? == ["rec-4"], "the action filter");
    let mut q = query(&[("sluis", "audit")], &["acme"]);
    q.trace_id = "trace-2".into();
    ensure!(found(&i, q, "")? == ["rec-2"], "the trace filter");
    let mut q = query(&[("sluis", "audit")], &["acme"]);
    q.record_id = "rec-3".into();
    ensure!(found(&i, q, "")? == ["rec-3"], "the record filter");
    let mut q = query(&[("sluis", "audit")], &["acme"]);
    q.actor_uid = "p1.202611.abcdef2@dev".into();
    ensure!(found(&i, q, "")? == ["rec-2"], "the actor filter");
    let mut q = query(&[("sluis", "audit")], &["acme"]);
    (q.from_ms, q.to_ms) = (2000, 4000);
    ensure!(
        found(&i, q, "")? == ["rec-3", "rec-2"],
        "the time window is [from, to), newest first"
    );
    println!("ok: filters");

    words(&i)?;
    pages(&i)?;
    Ok(())
}

/// Word search: `unicode61` with `remove_diacritics 2`, no stemming, prefixes, no substrings, and only
/// the searchable columns.
fn words(i: &Index) -> Result<()> {
    let base = || query(&[("words", "audit")], &["acme"]);
    apply(
        i,
        "words",
        "audit",
        0,
        None,
        vec![
            row("acme", "café.login", 1, 10),
            row("acme", "user.logged", 2, 20),
            row("acme", "Sign-In", 3, 30),
            Row {
                status_code: "denied".into(),
                ..row("acme", "other", 4, 40)
            },
        ],
    )?;
    ensure!(
        found(i, base(), "cafe")? == ["rec-1"],
        "a word without its accent does not find the accented one"
    );
    ensure!(
        found(i, base(), "CAFÉ")? == ["rec-1"],
        "case and accent are not folded"
    );
    ensure!(
        found(i, base(), "login")? == ["rec-1"],
        "login finds logged (stemming) or not login"
    );
    ensure!(found(i, base(), "logged")? == ["rec-2"], "logged");
    ensure!(
        found(i, base(), "log*")? == ["rec-2", "rec-1"],
        "a prefix finds both, newest first"
    );
    ensure!(
        found(i, base(), "ogin")?.is_empty(),
        "a substring found a word"
    );
    ensure!(
        found(i, base(), "sign in")? == ["rec-3"],
        "a hyphen is a word break"
    );
    ensure!(
        found(i, base(), "denied")? == ["rec-4"],
        "the status code is searchable"
    );
    ensure!(
        found(i, base(), "sluis")?.len() == 4,
        "the product is searchable"
    );
    // Words that are FTS5 syntax are only words.
    for q in [
        "login OR logged",
        "NOT login",
        "action:login",
        "\"login",
        "login*logged",
        "NEAR(login logged)",
        "-login",
    ] {
        let got = found(i, base(), q);
        ensure!(
            !matches!(got, Ok(ref r) if r.len() > 1) && !matches!(got, Err(Error::Engine(_))),
            "{q:?} acted as an operator or broke the query: {got:?}"
        );
    }
    refused!(found(i, base(), "!!! ???"), Error::Argument("q"));
    // The actor and the trace are not full-text columns: a word of them finds nothing.
    ensure!(
        found(i, base(), "abcdef1")?.is_empty(),
        "a word of the actor uid was searchable"
    );
    ensure!(
        found(i, base(), "trace")?.is_empty(),
        "a word of the trace id was searchable"
    );
    println!("ok: word search");
    Ok(())
}

/// Keyset pages: newest first, no row twice or lost, and a new row does not shift the next page.
fn pages(i: &Index) -> Result<()> {
    apply(
        i,
        "pages",
        "audit",
        0,
        None,
        (1..=5u8)
            .map(|n| row("acme", "page.row", n, i64::from(n) * 100))
            .collect(),
    )?;
    let mut q = query(&[("pages", "audit")], &["acme"]);
    q.page_size = 2;
    let first = i.search(&q)?;
    let ids = |r: &sluis_proto::sluis::port::index::v2alpha1::SearchResponse| {
        r.rows
            .iter()
            .map(|x| x.record_id.clone())
            .collect::<Vec<_>>()
    };
    ensure!(
        ids(&first) == ["rec-5", "rec-4"] && !first.next_page_token.is_empty(),
        "page 1: {:?}",
        ids(&first)
    );
    // A newer row arrives between the pages: the next page does not move.
    apply(
        i,
        "pages",
        "audit",
        0,
        None,
        vec![row("acme", "page.row", 6, 600)],
    )?;
    q.page_token = first.next_page_token;
    let second = i.search(&q)?;
    ensure!(
        ids(&second) == ["rec-3", "rec-2"] && !second.next_page_token.is_empty(),
        "page 2: {:?}",
        ids(&second)
    );
    q.page_token = second.next_page_token;
    let third = i.search(&q)?;
    ensure!(
        ids(&third) == ["rec-1"] && third.next_page_token.is_empty(),
        "page 3: {:?}",
        ids(&third)
    );
    q.page_token = vec![9, 9];
    refused!(i.search(&q), Error::Argument("page_token"));
    println!("ok: keyset pages");
    Ok(())
}
