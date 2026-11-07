#![allow(clippy::unwrap_used, clippy::expect_used)] // a failed unwrap in a test is the failure
//! A refused reload leaves a failure fact and a journal line, once per refused digest (ADR 0005, "A failed reload";
//! REQ-DATA-084). The documents are the local installation's, signed here and read through the real `file` driver.

mod common;
mod config_support;

use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::time::Duration;

use config_support::{Pipeline, bootstrap, put, serve_driver, up, write_local};
use sluis_kit::dial;
use store::config::{ConfigSnapshot, Loader};
use store::grant::KeyOpener;
use store::secret::NoSecrets;
use store::service::{Deps, Service};

/// A journal that keeps what is written to it.
#[derive(Clone, Default)]
struct Journal(Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for Journal {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Journal {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
    }
}

/// verifies: REQ-DATA-084
#[tokio::test]
async fn a_refused_reload_is_one_failure_fact_and_one_journal_line_per_digest() {
    let journal = Journal::default();
    let w = journal.clone();
    let _guard = tracing::subscriber::set_default(
        tracing_subscriber::fmt()
            .with_writer(move || w.clone())
            .with_ansi(false)
            .finish(),
    );
    let (docs, sock) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let path = sock.path().join("config-source.sock");
    let _stop = serve_driver(&path, docs.path());
    up(&path).await;
    let pipeline = Pipeline::new("publisher-1");
    write_local(docs.path(), &pipeline, 1);
    let loader = Loader::start(
        &dial(&path),
        &bootstrap(vec![pipeline.publisher(&[])]),
        Duration::from_millis(300),
    )
    .await
    .unwrap();

    let sink = common::RecSink::default();
    let clock = Arc::new(AtomicU64::new(common::T0));
    let svc = Service::new(Deps {
        boundary: "dev".into(),
        durable: common::Mem::with_clock(Arc::clone(&clock)),
        temp: common::Mem::with_clock(Arc::clone(&clock)),
        grants: KeyOpener::new(&dial(std::path::Path::new("/nonexistent/key.sock"))),
        config: Arc::clone(&loader) as Arc<dyn ConfigSnapshot>,
        secrets: Arc::new(NoSecrets),
        audit: sink.clone(),
        clock: Arc::new(std::time::SystemTime::now),
    });

    const MARK: &str = "zq-marker-77c1";
    let bad = format!("default:\n  cache_ttl: {MARK}\n");
    put(
        docs.path(),
        "key-plan",
        &pipeline.sign("key-plan", bad.as_bytes(), 2),
    );
    for _ in 0..3 {
        svc.announce_reload(&loader.reload().await).await;
    }
    let facts = sink.events.lock().unwrap().clone();
    assert_eq!(facts.len(), 1, "one failure fact for one refused digest");
    assert_eq!(
        (facts[0].action, facts[0].failure),
        ("store.reload.refused", true)
    );
    let text = journal.text();
    assert_eq!(
        text.matches("config reload refused").count(),
        1,
        "one journal line: {text}"
    );
    assert!(text.contains("ERROR") && text.contains("KeyPlan"), "{text}");
    assert!(!text.contains(MARK), "no value in the journal: {text}");
}
