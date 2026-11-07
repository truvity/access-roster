#![allow(clippy::unwrap_used, clippy::expect_used)] // a failed unwrap in a test is the failure
//! The engine client of store@ against an engine that passes the item suite: the change log of a driver, read through
//! the Connect client, is what `Watch` is built on.

use std::time::Duration;

use sluis_conformance::memory::MemoryEngine;
use sluis_kit::dial;
use sluis_proto::sluis::port::item::v2alpha1::{Put, QueryRequest, TransactRequest};
use store::engine::{DriverEngine, EngineError, ItemEngine};

async fn serve() -> (tempfile::TempDir, MemoryEngine, DriverEngine) {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("durable.sock");
    let engine = MemoryEngine::new();
    let e = engine.clone();
    let path = socket.clone();
    tokio::spawn(async move { e.serve(&path, std::future::pending()).await });
    for _ in 0..200 {
        if socket.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let client = dial(&socket);
    (dir, engine, DriverEngine::new(&client, "durable"))
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

/// verifies: REQ-DATA-102
/// A page of a query names the head of the log, never 0; a tail from it is given the rows written after it, and one
/// from a sequence the log has not reached is `SequenceExpired`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_tail_of_a_driver_is_read_from_the_head_of_a_query() {
    let (_dir, _engine, e) = serve().await;
    let page = e
        .query(QueryRequest {
            prefix: b"dev/-/x/".to_vec(),
            page_size: 1,
            ..QueryRequest::default()
        })
        .await
        .unwrap();
    let (head, epoch) = (page.log_head, page.log_epoch);
    assert!(head >= 1 && epoch != 0);
    let mut rows = e.tail_log(head, epoch).await.unwrap();
    e.transact(logged("dev/-/x/a")).await.unwrap();
    let row = tokio::time::timeout(Duration::from_secs(5), rows.recv())
        .await
        .expect("a row within five seconds")
        .expect("the tail is open")
        .unwrap();
    assert_eq!(
        (row.key.as_slice(), row.sequence > head),
        (b"dev/-/x/a".as_slice(), true)
    );
    drop(rows);

    // A sequence the log has not reached comes back as the first thing the stream says.
    let mut beyond = e
        .tail_log(head + 1000, epoch)
        .await
        .map(Some)
        .unwrap_or(None);
    let err = match beyond.as_mut() {
        None => EngineError::SequenceExpired,
        Some(r) => tokio::time::timeout(Duration::from_secs(5), r.recv())
            .await
            .expect("the refusal within five seconds")
            .expect("the refusal is sent")
            .expect_err("a refusal"),
    };
    assert_eq!(err, EngineError::SequenceExpired);
}
