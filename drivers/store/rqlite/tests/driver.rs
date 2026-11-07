//! The rqlite driver against a real rqlite 10.6.6: a pinned release binary that the test starts
//! as a plain process on a temporary data directory and free loopback ports (`just rqlite-fetch`
//! puts it in `.cache/rqlite`). No container.
//!
//! Without the binary a test prints `SKIP: rqlited not fetched; run just rqlite-fetch` and
//! returns, which is "not run", never a pass; `SLUIS_REQUIRE_RQLITED=1` (set by `just check-code`)
//! turns the missing binary into a failure.

#![allow(clippy::unwrap_used, clippy::expect_used)] // a failed unwrap in a test is the failure

use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::Duration;

use connectrpc::error::ErrorCode;
use sluis_kit::{Allow, Identities, ServerConfig, dial, refusal_reason};
use sluis_proto::sluis::port::item::v2alpha1::{
    ItemServiceClient, Put, TailLogRequest, TransactRequest,
};
use sluis_rqlite::Driver;
use sluis_rqlite::client::{Level, Param, Rq, Stmt};
use sluis_rqlite::sql::Ns;
use sluis_rqlite::sweeper;

fn rqlited() -> Option<PathBuf> {
    let arch = match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => panic!("no rqlite release for {other}"),
    };
    let bin = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .join(".cache/rqlite")
        .join(format!("linux-{arch}/rqlited"));
    if bin.is_file() {
        return Some(bin);
    }
    assert!(
        std::env::var_os("SLUIS_REQUIRE_RQLITED").is_none(),
        "rqlited is not fetched ({}) and the test is required to run: run just rqlite-fetch",
        bin.display()
    );
    println!("SKIP: rqlited not fetched; run just rqlite-fetch");
    None
}

/// A running rqlited that dies with the test.
struct Node {
    child: Child,
    url: String,
    _dir: tempfile::TempDir,
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn free_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

/// Starts a one-node rqlited and waits for it to lead.
///
/// The ports are asked of the system and released before rqlited binds them, so another process of this host (a test
/// binary in parallel, a build) may take one in between: rqlited then exits at once with "address already in use". That
/// is the only thing started again, with new ports. A node that is alive and does not lead in 30 seconds, or one that
/// exits for another reason, fails the test, and the panic carries what rqlited wrote.
async fn start_node(bin: &Path, auth: Option<(&str, &str)>) -> Node {
    for attempt in 1..=5 {
        match try_start_node(bin, auth).await {
            Ok(node) => return node,
            Err(why) if attempt < 5 && why.contains("address already in use") => {
                eprintln!("rqlited start {attempt}: a port was taken; starting again");
            }
            Err(why) => panic!("rqlited did not become the leader of its one-node cluster: {why}"),
        }
    }
    unreachable!("the last attempt returns or panics")
}

/// What rqlited said last, for a failure.
fn said(log: &Path) -> String {
    let said = std::fs::read_to_string(log).unwrap_or_default();
    let tail: Vec<&str> = said.lines().rev().take(5).collect();
    tail.into_iter().rev().collect::<Vec<_>>().join(" | ")
}

async fn try_start_node(bin: &Path, auth: Option<(&str, &str)>) -> Result<Node, String> {
    let dir = tempfile::tempdir().unwrap();
    let (http, mut raft) = (free_port(), free_port());
    while raft == http {
        raft = free_port();
    }
    let log = dir.path().join("rqlited.log");
    let mut cmd = Command::new(bin);
    cmd.args(["-node-id", "n1"])
        .arg("-http-addr")
        .arg(format!("127.0.0.1:{http}"))
        .arg("-raft-addr")
        .arg(format!("127.0.0.1:{raft}"));
    if let Some((user, password)) = auth {
        let file = dir.path().join("auth.json");
        std::fs::write(
            &file,
            format!(r#"[{{"username":"{user}","password":"{password}","perms":["all"]}}]"#),
        )
        .unwrap();
        cmd.arg("-auth").arg(file);
    }
    let out = std::fs::File::create(&log).unwrap();
    let child = cmd
        .arg(dir.path().join("data"))
        .stdout(out.try_clone().unwrap())
        .stderr(out)
        .spawn()
        .expect("start rqlited");
    let mut node = Node {
        child,
        url: format!("http://127.0.0.1:{http}"),
        _dir: dir,
    };
    let creds = auth.map(|(u, p)| format!("{u}:{p}"));
    let rq = Rq::new(&node.url, creds.as_deref()).unwrap();
    for _ in 0..300 {
        // A node that has exited is not the one that answers: another process may hold the port.
        if let Some(status) = node.child.try_wait().unwrap() {
            return Err(format!("it exited with {status}: {}", said(&log)));
        }
        if rq.is_leader().await.unwrap_or(false) {
            return Ok(node);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Err(format!(
        "it was alive and led nothing in 30 s: {}",
        said(&log)
    ))
}

struct Served {
    socket: PathBuf,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<anyhow::Result<()>>,
    _dir: tempfile::TempDir,
}

impl Served {
    async fn stop(mut self) {
        let _ = self.stop.take().map(|s| s.send(()));
        self.task.await.unwrap().unwrap();
    }
}

/// Serves `driver` on a temporary socket, with this process's uid as the owner `store`.
async fn serve(driver: &Driver) -> Served {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("durable.sock");
    let me = rustix::process::geteuid().as_raw();
    let identities = Identities::with(0, move |uid| (uid == me).then_some(("store", 0)));
    let cfg = ServerConfig {
        actor: "driver-store-rqlite",
        boundary: "dev".into(),
        socket: socket.clone(),
        mode: 0o600,
        socket_gid: None,
        allow: Allow::OwnerOnly("store"),
        default_deadline: Duration::from_secs(30),
    };
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let router = driver.clone().router();
    let task = tokio::spawn(sluis_kit::serve_with(
        cfg,
        router,
        async {
            let _ = stopped.await;
        },
        identities,
    ));
    for _ in 0..100 {
        if socket.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    Served {
        socket,
        stop: Some(stop),
        task,
        _dir: dir,
    }
}

fn driver(node: &Node, ns: &str) -> Driver {
    Driver::new(Rq::new(&node.url, None).unwrap(), Ns::new(ns).unwrap())
}

fn rqlite_command(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_rqlite"))
        .args(args)
        .output()
        .expect("run the rqlite binary")
}

/// verifies: REQ-DATA-101, REQ-DATA-102, REQ-DATA-055, REQ-DATA-063, REQ-DATA-098, REQ-DATA-113, REQ-DATA-114, REQ-DATA-115
/// The suite includes the log head of a query: never 0, and a tail from it misses nothing written after the page.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_driver_passes_the_item_suite_on_both_ports() {
    let Some(bin) = rqlited() else { return };
    let node = start_node(&bin, None).await;
    for ns in ["durable", "temp"] {
        let d = driver(&node, ns);
        d.ensure_schema().await.unwrap();
        d.ensure_schema().await.expect("the schema is idempotent");
        let served = serve(&d).await;

        let cases = sluis_conformance::item_suite(dial(&served.socket)).await;
        let mut out = Vec::new();
        let verdict = sluis_conformance::report(&cases, &mut out);
        print!("[{ns}]\n{}", String::from_utf8_lossy(&out));
        verdict.unwrap();
        assert!(cases.len() >= 10);

        // The command of the binary does the same over the socket, and a second run finds the
        // engine clean.
        let run = rqlite_command(&["conformance", "--socket", served.socket.to_str().unwrap()]);
        assert!(
            run.status.success(),
            "rqlite conformance: {}{}",
            String::from_utf8_lossy(&run.stdout),
            String::from_utf8_lossy(&run.stderr)
        );
        assert!(String::from_utf8_lossy(&run.stdout).contains("0 failed"));

        // What the suite wrote is gone from the tables, not only hidden.
        let rq = Rq::new(&node.url, None).unwrap();
        let counts = rq
            .query(
                Level::Linearizable,
                &[
                    Stmt::new(format!("SELECT COUNT(*) FROM {}_items", ns), vec![]),
                    Stmt::new(format!("SELECT COUNT(*) FROM {}_index", ns), vec![]),
                    Stmt::new(format!("SELECT COUNT(*) FROM {}_guard", ns), vec![]),
                ],
            )
            .await
            .unwrap();
        for (i, what) in ["items", "index entries", "guard rows"].iter().enumerate() {
            let n = sluis_rqlite::client::rows(&counts, i).unwrap()[0][0]
                .as_i64()
                .unwrap();
            if n != 0 {
                // Name what is left (key, expiry, version), so that the next failure says which case left it.
                let left = rq
                    .query(
                        Level::Linearizable,
                        &[Stmt::new(
                            format!(
                                "SELECT key, expires_at, version FROM {}_items ORDER BY key LIMIT 10",
                                ns
                            ),
                            vec![],
                        )],
                    )
                    .await
                    .map(|r| format!("{:?}", sluis_rqlite::client::rows(&r, 0)))
                    .unwrap_or_default();
                panic!("{ns}: the suite left {n} {what}; items now: {left}");
            }
        }
        served.stop().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_two_ports_do_not_see_each_other() {
    let Some(bin) = rqlited() else { return };
    let node = start_node(&bin, None).await;
    let (durable, temp) = (driver(&node, "durable"), driver(&node, "temp"));
    durable.ensure_schema().await.unwrap();
    temp.ensure_schema().await.unwrap();
    let (a, b) = (serve(&durable).await, serve(&temp).await);
    let write = |socket: PathBuf| async move {
        let c = dial(&socket);
        let rpc = ItemServiceClient::new(c.transport(), c.config());
        rpc.transact(TransactRequest {
            puts: vec![Put {
                key: b"ns/only-here".to_vec(),
                value: b"v".to_vec(),
                ..Put::default()
            }],
            ..TransactRequest::default()
        })
        .await
        .unwrap();
    };
    write(a.socket.clone()).await;
    let c = dial(&b.socket);
    let rpc = ItemServiceClient::new(c.transport(), c.config());
    let err = rpc
        .get(sluis_proto::sluis::port::item::v2alpha1::ItemGetRequest {
            key: b"ns/only-here".to_vec(),
            linearizable: true,
            ..Default::default()
        })
        .await
        .map(|_| ())
        .expect_err("the other port holds nothing");
    assert_eq!(err.code, ErrorCode::NotFound);
    a.stop().await;
    b.stop().await;
}

/// verifies: REQ-DATA-062, REQ-DATA-101
/// The sweeper writes a delete row for the expiry of an item that was written with a log row, so that a watcher sees
/// expiry as a delete; it trims the log to the retention; and it never frees a lease.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_sweeper_frees_expired_items_and_trims_the_log_but_never_a_lease() {
    let Some(bin) = rqlited() else { return };
    let node = start_node(&bin, None).await;
    let d = driver(&node, "durable");
    d.ensure_schema().await.unwrap();
    let served = serve(&d).await;
    let c = dial(&served.socket);
    let rpc = ItemServiceClient::new(c.transport(), c.config());
    let now = sluis_conformance::rules::now_ms();
    let put = |key: &str, expires: Option<i64>, index: bool| Put {
        key: key.as_bytes().to_vec(),
        value: b"v".to_vec(),
        expires_at: expires.map(sluis_conformance::rules::ms_to_ts).into(),
        indexes: if index {
            vec![sluis_proto::sluis::r#type::v2alpha1::IndexEntry {
                name: "n".into(),
                value: b"v".to_vec(),
                ..Default::default()
            }]
        } else {
            vec![]
        },
        log: true,
        ..Put::default()
    };
    rpc.transact(TransactRequest {
        puts: vec![
            put("sweep/expired", Some(now - 60_000), true),
            put("sweep/live", Some(now + 3_600_000), true),
            // A lease has no expiry at the driver: it is never swept.
            put("sweep/lease", None, false),
        ],
        ..TransactRequest::default()
    })
    .await
    .unwrap();
    let epoch = d.log_epoch().await.unwrap();
    // A second logged write, so the first rows can be trimmed and a later one kept.
    tokio::time::sleep(Duration::from_millis(30)).await;

    // A sweep that trims nothing (the retention is an hour): the expired item is freed, and its expiry
    // is a delete row of the log, because it was written with one (a watcher sees expiry as a delete).
    let freed = sweeper::sweep_once(&d, Duration::from_secs(3600))
        .await
        .unwrap();
    assert_eq!(freed, 1, "the sweeper frees the one expired item");
    let swept = d
        .poll(4, epoch)
        .await
        .unwrap()
        .expect("the sweep wrote a row of the log");
    assert_eq!(
        swept
            .iter()
            .map(|r| (r.key.clone(), r.version, r.deleted))
            .collect::<Vec<_>>(),
        vec![(b"sweep/expired".to_vec(), 1, true)],
        "the expiry of a logged item is a delete row, and the live and the lease items write none"
    );
    // The sweep is idempotent: the item is gone, so there is nothing to log again.
    assert_eq!(
        sweeper::sweep_once(&d, Duration::from_secs(3600))
            .await
            .unwrap(),
        0
    );
    assert!(
        d.poll(5, epoch).await.unwrap().is_none(),
        "no second delete row"
    );

    // Now a sweep with a retention that trims every row (the marker, the three writes, the expiry).
    tokio::time::sleep(Duration::from_millis(30)).await;
    sweeper::sweep_once(&d, Duration::from_millis(1))
        .await
        .unwrap();

    let rq = Rq::new(&node.url, None).unwrap();
    let out = rq
        .query(
            Level::Linearizable,
            &[
                Stmt::new("SELECT key FROM durable_items ORDER BY key", vec![]),
                Stmt::new("SELECT key FROM durable_index ORDER BY key", vec![]),
                Stmt::new("SELECT COUNT(*) FROM durable_log", vec![]),
            ],
        )
        .await
        .unwrap();
    let keys = |i| -> Vec<String> {
        sluis_rqlite::client::rows(&out, i)
            .unwrap()
            .iter()
            .map(|r| r[0].as_str().unwrap().to_owned())
            .collect()
    };
    assert_eq!(keys(0), ["sweep/lease", "sweep/live"]);
    assert_eq!(
        keys(1),
        ["sweep/live"],
        "the index entries of the expired item are freed too"
    );
    // The rows were trimmed.
    let logged = sluis_rqlite::client::rows(&out, 2).unwrap()[0][0]
        .as_i64()
        .unwrap();
    assert_eq!(logged, 0, "every row is older than the retention");

    // A sequence the trim dropped is `sequence_expired`; one at the floor is fine.
    rpc.transact(TransactRequest {
        puts: vec![put("sweep/after", None, false)],
        ..TransactRequest::default()
    })
    .await
    .unwrap();
    // A tail that fell behind the retention is refused, not skipped ahead: rows 1..=5 are gone (the marker, the
    // three writes, the expiry), so a tail at 1 to 4 has missed rows, one at the floor (5) has not, and the later
    // row is next.
    for behind in [1, 2, 3, 4] {
        let err = d
            .poll(behind, epoch)
            .await
            .map(|_| ())
            .expect_err("a tail behind the floor");
        assert_eq!(err.code, ErrorCode::FailedPrecondition, "behind {behind}");
        assert_eq!(refusal_reason(&err).as_deref(), Some("sequence_expired"));
    }
    let next = d
        .poll(5, epoch)
        .await
        .unwrap()
        .expect("the row after the floor");
    assert_eq!(next.len(), 1);
    assert!(
        d.poll(6, epoch).await.unwrap().is_none(),
        "at the head there is nothing yet"
    );

    // A server stream carries its refusal in the first message, not in the call.
    let tail = |from_sequence| {
        let rpc = &rpc;
        async move {
            let mut s = rpc
                .tail_log(TailLogRequest {
                    from_sequence,
                    log_epoch: epoch,
                    ..Default::default()
                })
                .await?;
            tokio::time::timeout(Duration::from_millis(600), s.message())
                .await
                .map_or(Ok(None), |m| m.map(|m| m.map(|m| m.to_owned_message())))
        }
    };
    let expired = tail(1)
        .await
        .map(|_| ())
        .expect_err("sequence 1 was trimmed");
    assert_eq!(expired.code, ErrorCode::FailedPrecondition);
    assert_eq!(
        refusal_reason(&expired).as_deref(),
        Some("sequence_expired")
    );
    // The floor itself is held: from 5 (the newest row trimmed) the log yields the row written after, and from the
    // head it is quiet.
    let row = tail(5)
        .await
        .unwrap()
        .expect("a tail from the floor gets the later row");
    assert_eq!(
        (row.sequence, row.key.as_slice()),
        (6, b"sweep/after".as_slice())
    );
    assert!(tail(6).await.unwrap().is_none(), "nothing after the head");
    served.stop().await;
}

/// Drops the tables of a namespace, as a reset of the database or a restore into a new one starts from nothing.
async fn drop_tables(node: &Node, tables: &[&str]) {
    let rq = Rq::new(&node.url, None).unwrap();
    let stmts: Vec<Stmt> = tables
        .iter()
        .map(|t| Stmt::new(format!("DROP TABLE IF EXISTS durable_{t}"), vec![]))
        .collect();
    let out = rq.request(&stmts, true).await.unwrap();
    assert!(
        sluis_rqlite::client::first_failure(&out).is_none(),
        "{out:?}"
    );
}

/// A reset of the whole database in one transaction: the tables go and the schema is made again with no moment between, so
/// that a stream that is open polls the old log or the new one and never a database with no tables, which it would end
/// on with `engine` and not with the refusal of an epoch the test is about.
async fn reset_database(node: &Node, ns: &str) {
    let epoch = i64::try_from(sluis_conformance::rules::new_log_epoch().unwrap()).unwrap();
    let mut stmts: Vec<Stmt> = ["items", "index", "log", "meta", "guard"]
        .iter()
        .map(|t| Stmt::new(format!("DROP TABLE IF EXISTS {ns}_{t}"), vec![]))
        .collect();
    stmts.extend(Ns::new(ns).unwrap().ddl(epoch));
    let rq = Rq::new(&node.url, None).unwrap();
    let out = rq.request(&stmts, true).await.unwrap();
    assert!(
        sluis_rqlite::client::first_failure(&out).is_none(),
        "{out:?}"
    );
}

fn logged(key: &str) -> TransactRequest {
    TransactRequest {
        puts: vec![Put {
            key: key.as_bytes().to_vec(),
            value: b"v".to_vec(),
            log: true,
            ..Put::default()
        }],
        ..TransactRequest::default()
    }
}

/// verifies: REQ-DATA-114
/// The floor of a log belongs to it. A log table made again alone (the meta table stays) begins at sequence 1 with a floor of
/// 0, not at the floor the old log trimmed to: that floor would stand above the new rows, put the head at the old number and
/// hide the first rows of the new log from a watcher, under a valid new epoch.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_log_made_again_after_a_trim_does_not_keep_the_floor_of_the_old_one() {
    let Some(bin) = rqlited() else { return };
    let node = start_node(&bin, None).await;
    let d = driver(&node, "durable");
    d.ensure_schema().await.unwrap();
    let served = serve(&d).await;
    let c = dial(&served.socket);
    let rpc = ItemServiceClient::new(c.transport(), c.config());
    for i in 0..5 {
        rpc.transact(logged(&format!("floor/a{i}"))).await.unwrap();
    }
    // Trim every row (the marker and five writes): the floor is 6.
    tokio::time::sleep(Duration::from_millis(30)).await;
    sweeper::sweep_once(&d, Duration::from_millis(1))
        .await
        .unwrap();
    let e1 = d.log_epoch().await.unwrap();
    assert!(
        d.poll(1, e1).await.is_err(),
        "the trim moved the floor above the start of the old log"
    );

    drop_tables(&node, &["log"]).await;
    d.ensure_schema().await.unwrap();
    let e2 = d.log_epoch().await.unwrap();
    assert_ne!(e2, e1);
    for i in 0..2 {
        rpc.transact(logged(&format!("floor/b{i}"))).await.unwrap();
    }
    let head = rpc
        .query(sluis_proto::sluis::port::item::v2alpha1::QueryRequest {
            prefix: b"floor/".to_vec(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_owned();
    assert_eq!(
        (head.log_epoch, head.log_head),
        (e2, 3),
        "the head of the new log is its newest row (the marker and two writes), not the old floor"
    );
    let rows = d
        .poll(1, e2)
        .await
        .unwrap()
        .expect("the new log's rows after its marker are delivered");
    assert_eq!(
        rows.iter().map(|r| r.sequence).collect::<Vec<_>>(),
        [2, 3],
        "no row of the new log is hidden"
    );
    served.stop().await;
}

/// verifies: REQ-DATA-114, REQ-DATA-115
/// A log that is made again (the database reset, or a restore into a new one) has another epoch, and a point saved
/// before it is refused even after the new log has grown past the saved sequence, where without the epoch the same number
/// would name another position and the rows between would be skipped without a word. An epoch lives in the database with
/// the log, so a second start or a second node keeps it; a log table made again alone gets a new one; and a database whose
/// epoch row is gone fails closed until the schema is made again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_log_made_again_has_another_epoch_and_a_point_saved_before_it_is_refused() {
    let Some(bin) = rqlited() else { return };
    let node = start_node(&bin, None).await;
    let d = driver(&node, "durable");
    d.ensure_schema().await.unwrap();
    let e1 = d.log_epoch().await.unwrap();
    assert!(
        e1 != 0 && e1 < 1 << 63,
        "a nonzero epoch that fits a signed column: {e1}"
    );
    // Run again, and by a second node of the cluster: the log is not new, so its epoch stays.
    d.ensure_schema().await.unwrap();
    driver(&node, "durable").ensure_schema().await.unwrap();
    assert_eq!(
        d.log_epoch().await.unwrap(),
        e1,
        "a second start keeps the epoch of the log"
    );
    // The temp port has a log of its own.
    let temp = driver(&node, "temp");
    temp.ensure_schema().await.unwrap();
    assert_ne!(temp.log_epoch().await.unwrap(), e1, "two logs, two epochs");

    let served = serve(&d).await;
    let c = dial(&served.socket);
    let rpc = ItemServiceClient::new(c.transport(), c.config());
    for i in 0..5 {
        rpc.transact(logged(&format!("epoch/a{i}"))).await.unwrap();
    }
    let page = |rpc: &ItemServiceClient<sluis_kit::Transport>| {
        let rpc = rpc.clone();
        async move {
            rpc.query(sluis_proto::sluis::port::item::v2alpha1::QueryRequest {
                prefix: b"epoch/".to_vec(),
                page_size: 1,
                ..Default::default()
            })
            .await
            .unwrap()
            .into_owned()
        }
    };
    let saved = page(&rpc).await;
    assert_eq!(
        saved.log_epoch, e1,
        "a query names the epoch of the log with its head"
    );
    assert!(
        saved.log_head >= 6,
        "the marker and five writes: {}",
        saved.log_head
    );
    let tail = |from_sequence: u64, log_epoch: u64| {
        let rpc = rpc.clone();
        async move {
            let mut s = rpc
                .tail_log(TailLogRequest {
                    from_sequence,
                    log_epoch,
                    ..Default::default()
                })
                .await?;
            tokio::time::timeout(Duration::from_secs(5), s.message())
                .await
                .map_or(Ok(None), |m| m.map(|m| m.map(|m| m.to_owned_message())))
        }
    };
    // The point as saved is good now, and a stream opened with it is quiet at the head.
    assert!(tail(saved.log_head, e1).await.is_ok());
    // A stream that is open when the log is made again ends with the refusal, and delivers nothing of the new log.
    let mut open = rpc
        .tail_log(TailLogRequest {
            from_sequence: saved.log_head,
            log_epoch: e1,
            ..Default::default()
        })
        .await
        .unwrap();

    // The reset: every table goes, the schema is made again.
    reset_database(&node, "durable").await;
    let e2 = d.log_epoch().await.unwrap();
    assert_ne!(e2, e1, "a log made again has another epoch");
    for i in 0..10 {
        rpc.transact(logged(&format!("epoch/b{i}"))).await.unwrap();
    }
    let now = page(&rpc).await;
    assert_eq!(now.log_epoch, e2);
    assert!(
        now.log_head >= saved.log_head,
        "the new log has grown past the saved sequence ({} >= {}): the numbers are reused",
        now.log_head,
        saved.log_head
    );
    for (what, epoch) in [("the epoch of the old log", e1), ("no epoch", 0)] {
        let err = tail(saved.log_head, epoch)
            .await
            .map(|_| ())
            .expect_err(what);
        assert_eq!(err.code, ErrorCode::FailedPrecondition, "{what}");
        assert_eq!(
            refusal_reason(&err).as_deref(),
            Some("sequence_expired"),
            "{what}"
        );
    }
    // The same sequence under the epoch of the new log is a position in it.
    assert!(tail(saved.log_head, e2).await.is_ok());
    let end = tokio::time::timeout(Duration::from_secs(5), open.message())
        .await
        .expect("the old stream ends within five seconds")
        .map(|_| ())
        .expect_err("the old stream is refused, it delivers no row of the new log");
    assert_eq!(refusal_reason(&end).as_deref(), Some("sequence_expired"));

    // Only the log table made again: the counter is gone with it, so the epoch is new although the meta table stayed.
    drop_tables(&node, &["log"]).await;
    d.ensure_schema().await.unwrap();
    let e3 = d.log_epoch().await.unwrap();
    assert!(
        e3 != e2 && e3 != e1,
        "a log table made again alone has another epoch"
    );

    // A database whose epoch row is gone (an operator removes it after loading a database file, to make a new epoch) fails
    // closed, and the schema makes a new one.
    let rq = Rq::new(&node.url, None).unwrap();
    let out = rq
        .request(
            &[Stmt::new(
                "DELETE FROM durable_meta WHERE name = 'log_epoch'",
                vec![],
            )],
            true,
        )
        .await
        .unwrap();
    assert!(sluis_rqlite::client::first_failure(&out).is_none());
    assert!(
        d.log_epoch().await.is_err(),
        "a log with no epoch is not read"
    );
    let err = rpc
        .query(sluis_proto::sluis::port::item::v2alpha1::QueryRequest {
            prefix: b"epoch/".to_vec(),
            ..Default::default()
        })
        .await
        .map(|_| ())
        .expect_err("no position without an epoch");
    assert_eq!(err.code, ErrorCode::Unavailable);
    d.ensure_schema().await.unwrap();
    let e4 = d.log_epoch().await.unwrap();
    assert!(![e1, e2, e3].contains(&e4));
    served.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn check_and_version_and_the_basic_authentication() {
    let Some(bin) = rqlited() else { return };
    let version = rqlite_command(&["version"]);
    assert!(version.status.success());
    assert!(String::from_utf8_lossy(&version.stdout).starts_with("rqlite "));

    let password = format!(
        "pw-{}-{:x}",
        std::process::id(),
        sluis_conformance::rules::now_ms()
    );
    let node = start_node(&bin, Some(("sluis", &password))).await;
    let creds = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(creds.path(), format!("sluis:{password}\n")).unwrap();
    let args = |extra: &[&'static str]| {
        let mut a = vec![
            "check",
            "--rqlite-url",
            node.url.as_str(),
            "--namespace",
            "durable",
        ];
        a.extend_from_slice(extra);
        a.into_iter().map(str::to_owned).collect::<Vec<_>>()
    };
    let check = |a: Vec<String>| {
        Command::new(env!("CARGO_BIN_EXE_rqlite"))
            .args(a)
            .output()
            .unwrap()
    };

    // Without the schema `check` refuses (3); it creates nothing.
    let mut with_creds = args(&[]);
    with_creds.extend([
        "--basic-auth-file".into(),
        creds.path().to_str().unwrap().into(),
    ]);
    assert_eq!(
        check(with_creds.clone()).status.code(),
        Some(3),
        "no schema yet"
    );
    let authed = Driver::new(
        Rq::new(&node.url, Some(&format!("sluis:{password}"))).unwrap(),
        Ns::new("durable").unwrap(),
    );
    authed.ensure_schema().await.unwrap();
    assert_eq!(
        check(with_creds).status.code(),
        Some(0),
        "schema and credential are right"
    );
    // No credential: rqlite refuses, and so does `check`.
    assert_eq!(check(args(&[])).status.code(), Some(3), "no credential");
    // Nothing listens there.
    let dead = format!("http://127.0.0.1:{}", free_port());
    let out = check(vec![
        "check".into(),
        "--rqlite-url".into(),
        dead,
        "--namespace".into(),
        "durable".into(),
    ]);
    assert_eq!(out.status.code(), Some(3), "rqlite is not reachable");
    // Flags that are wrong are a usage or failure exit, never a pass.
    let out = rqlite_command(&["check", "--namespace", "durable"]);
    assert_eq!(out.status.code(), Some(1), "--rqlite-url is required");
    let _ = (Param::Null,);
}

/// An engine that is down is `unavailable` with the reason `engine`, on every call, and the
/// refusal shows nothing of rqlite's text. This test needs no rqlited.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_dead_engine_is_unavailable_engine() {
    let dead = Driver::new(
        Rq::new(&format!("http://127.0.0.1:{}", free_port()), None).unwrap(),
        Ns::new("durable").unwrap(),
    );
    let served = serve(&dead).await;
    let c = dial(&served.socket);
    let rpc = ItemServiceClient::new(c.transport(), c.config());
    let gone = |e: connectrpc::ConnectError| {
        assert_eq!(e.code, ErrorCode::Unavailable);
        assert_eq!(refusal_reason(&e).as_deref(), Some("engine"));
        assert_eq!(
            e.message.as_deref(),
            Some("engine"),
            "the message is the reason only"
        );
    };
    gone(
        rpc.get(sluis_proto::sluis::port::item::v2alpha1::ItemGetRequest {
            key: b"a/b".to_vec(),
            ..Default::default()
        })
        .await
        .map(|_| ())
        .expect_err("get"),
    );
    gone(
        rpc.transact(TransactRequest {
            puts: vec![Put {
                key: b"a/b".to_vec(),
                ..Put::default()
            }],
            ..TransactRequest::default()
        })
        .await
        .map(|_| ())
        .expect_err("transact"),
    );
    gone(
        rpc.query(sluis_proto::sluis::port::item::v2alpha1::QueryRequest::default())
            .await
            .map(|_| ())
            .expect_err("query"),
    );
    // A linearizable query that rqlite cannot answer is refused like the others, and is not answered at a weaker level.
    gone(
        rpc.query(sluis_proto::sluis::port::item::v2alpha1::QueryRequest {
            linearizable: true,
            ..Default::default()
        })
        .await
        .map(|_| ())
        .expect_err("linearizable query"),
    );
    served.stop().await;
}

/// `--socket-gid` of zero or of text is refused before the socket exists, and before rqlite is
/// waited for. This test needs no rqlited.
#[test]
fn serve_refuses_a_socket_gid_of_zero_or_text_before_it_listens() {
    let run = tempfile::tempdir().unwrap();
    for gid in ["0", "wheel"] {
        let sock = run.path().join("x.sock");
        let out = Command::new(env!("CARGO_BIN_EXE_rqlite"))
            .args(["serve", "--socket"])
            .arg(&sock)
            .args(["--socket-gid", gid])
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(1), "{gid}");
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("--socket-gid"),
            "{gid}"
        );
        assert!(!sock.exists());
    }
}

/// A TCP proxy in front of one rqlited that records the `level` of every query that passes through it, so that a test
/// can tell which read consistency the driver asked rqlite for.
struct Proxy {
    url: String,
    levels: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Proxy {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn proxy(target: &str) -> Proxy {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let target = target.trim_start_matches("http://").to_owned();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let levels = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let seen = levels.clone();
    let task = tokio::spawn(async move {
        loop {
            let Ok((mut client, _)) = listener.accept().await else {
                return;
            };
            let Ok(server) = tokio::net::TcpStream::connect(&target).await else {
                continue;
            };
            let seen = seen.clone();
            tokio::spawn(async move {
                let (mut sr, mut sw) = server.into_split();
                let (mut cr, mut cw) = client.split();
                let up = async {
                    let mut buf = vec![0u8; 16 * 1024];
                    loop {
                        let n = cr.read(&mut buf).await?;
                        if n == 0 {
                            return std::io::Result::Ok(());
                        }
                        let text = String::from_utf8_lossy(&buf[..n]).into_owned();
                        for part in text.split("/db/query?level=").skip(1) {
                            let level: String = part
                                .chars()
                                .take_while(|c| c.is_ascii_alphabetic())
                                .collect();
                            seen.lock().unwrap().push(level);
                        }
                        sw.write_all(&buf[..n]).await?;
                    }
                };
                let down = tokio::io::copy(&mut sr, &mut cw);
                let _ = tokio::join!(up, down);
            });
        }
    });
    Proxy { url, levels, task }
}

/// verifies: REQ-DATA-113
/// The driver asks rqlite for the read level the query asked for: a query that does not ask is read at `weak`, as it was
/// before the field, so nothing else changes in cost; a linearizable one is read at `linearizable`, and rqlite itself
/// confirms leadership with a quorum before it answers. A write that was acknowledged is in the next linearizable
/// listing. The driver never answers one level for the other.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_query_is_read_at_the_level_it_asked_for() {
    use sluis_proto::sluis::port::item::v2alpha1::QueryRequest;
    let Some(bin) = rqlited() else { return };
    let node = start_node(&bin, None).await;
    let px = proxy(&node.url).await;
    let d = Driver::new(Rq::new(&px.url, None).unwrap(), Ns::new("durable").unwrap());
    d.ensure_schema().await.unwrap();
    let served = serve(&d).await;
    let c = dial(&served.socket);
    let rpc = ItemServiceClient::new(c.transport(), c.config());
    let levels_after = |from: usize| px.levels.lock().unwrap()[from..].to_vec();

    for i in 0..20u8 {
        let key = format!("lin/{i:02}").into_bytes();
        rpc.transact(TransactRequest {
            puts: vec![Put {
                key: key.clone(),
                value: b"v".to_vec(),
                ..Put::default()
            }],
            ..TransactRequest::default()
        })
        .await
        .unwrap();
        let from = px.levels.lock().unwrap().len();
        let weak = rpc
            .query(QueryRequest {
                prefix: b"lin/".to_vec(),
                page_size: 100,
                ..QueryRequest::default()
            })
            .await
            .unwrap()
            .into_owned();
        assert_eq!(levels_after(from), ["weak"], "a query that does not ask");
        let from = px.levels.lock().unwrap().len();
        let strong = rpc
            .query(QueryRequest {
                prefix: b"lin/".to_vec(),
                page_size: 100,
                linearizable: true,
                ..QueryRequest::default()
            })
            .await
            .unwrap()
            .into_owned();
        assert_eq!(levels_after(from), ["linearizable"], "a query that asks");
        assert_eq!(
            strong.items.len(),
            usize::from(i) + 1,
            "a linearizable listing after {} acknowledged writes",
            i + 1
        );
        assert!(weak.items.len() <= strong.items.len());
    }
    served.stop().await;
}
