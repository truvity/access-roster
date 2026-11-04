//! The rqlite driver against a real rqlite 10.6.6: a pinned release binary that the test starts
//! as a plain process on a temporary data directory and free loopback ports (`just rqlite-fetch`
//! puts it in `.cache/rqlite`). No container.
//!
//! Without the binary a test prints `SKIP: rqlited not fetched; run just rqlite-fetch` and
//! returns, which is "not run", never a pass; `SLUIS_REQUIRE_RQLITED=1` (set by `just check-code`)
//! turns the missing binary into a failure.

#![allow(clippy::unwrap_used, clippy::expect_used)] // a failed unwrap in a test is the failure

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
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

async fn start_node(bin: &Path, auth: Option<(&str, &str)>) -> Node {
    let dir = tempfile::tempdir().unwrap();
    let (http, raft) = (free_port(), free_port());
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
    let child = cmd
        .arg(dir.path().join("data"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("start rqlited");
    let node = Node {
        child,
        url: format!("http://127.0.0.1:{http}"),
        _dir: dir,
    };
    let creds = auth.map(|(u, p)| format!("{u}:{p}"));
    let rq = Rq::new(&node.url, creds.as_deref()).unwrap();
    for _ in 0..300 {
        if rq.is_leader().await.unwrap_or(false) {
            return node;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("rqlited did not become the leader of its one-node cluster");
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
            assert_eq!(n, 0, "{ns}: the suite left {n} {what}");
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
    // A second logged write, so the first rows can be trimmed and a later one kept.
    tokio::time::sleep(Duration::from_millis(30)).await;

    let freed = sweeper::sweep_once(&d, Duration::from_millis(1))
        .await
        .unwrap();
    assert_eq!(freed, 1, "the sweeper frees the one expired item");

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
    // Sweeping an expired item wrote no log row, and the old rows were trimmed.
    let logged = sluis_rqlite::client::rows(&out, 2).unwrap()[0][0]
        .as_i64()
        .unwrap();
    assert_eq!(logged, 0, "the three writes are older than the retention");

    // A sequence the trim dropped is `sequence_expired`; one at the floor is fine.
    rpc.transact(TransactRequest {
        puts: vec![put("sweep/after", None, false)],
        ..TransactRequest::default()
    })
    .await
    .unwrap();
    // A tail that fell behind the retention is refused, not skipped ahead: rows 1..=3 are gone, so
    // a tail at 1 or 2 has missed rows, one at the floor (3) has not, and the later row is next.
    for behind in [0, 1, 2] {
        let err = d
            .poll(behind)
            .await
            .map(|_| ())
            .expect_err("a tail behind the floor");
        assert_eq!(err.code, ErrorCode::FailedPrecondition, "behind {behind}");
        assert_eq!(refusal_reason(&err).as_deref(), Some("sequence_expired"));
    }
    let next = d.poll(3).await.unwrap().expect("the row after the floor");
    assert_eq!(next.len(), 1);
    assert!(
        d.poll(4).await.unwrap().is_none(),
        "at the head there is nothing yet"
    );

    // A server stream carries its refusal in the first message, not in the call.
    let tail = |from_sequence| {
        let rpc = &rpc;
        async move {
            let mut s = rpc
                .tail_log(TailLogRequest {
                    from_sequence,
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
    // The floor itself is held: from 3 (the newest row of the three writes) the log yields the
    // row written after, and from the head it is quiet.
    let row = tail(3)
        .await
        .unwrap()
        .expect("a tail from the floor gets the later row");
    assert_eq!(
        (row.sequence, row.key.as_slice()),
        (4, b"sweep/after".as_slice())
    );
    assert!(tail(4).await.unwrap().is_none(), "nothing after the head");
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
