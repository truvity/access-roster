//! A SIGTERM ends the back-off sleep at once. This is its own test binary (so its own process): the signal goes to the
//! process, and the handler `shutdown_signal` installs is what keeps it alive.

use std::time::{Duration, Instant};

use sluis_kit::backoff::{ENV_FILE, Guard, Outcome};
use sluis_kit::cli::shutdown_signal;

/// verifies: REQ-DEPLOY-051
#[tokio::test]
async fn sigterm_ends_the_real_sleep() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("restarts");
    // Four failures in a row already: the next sleep is 30 s.
    std::fs::write(&file, "4\n").unwrap();
    let f = file.to_string_lossy().into_owned();
    let env = move |k: &str| match k {
        "INVOCATION_ID" => Some("x".to_owned()),
        ENV_FILE => Some(f.clone()),
        _ => None,
    };
    let mut guard = Guard::new(env, None).unwrap();
    guard.begin();
    let start = Instant::now();
    let task = tokio::spawn(async move { guard.failed(shutdown_signal()).await });
    // Let the task reach its sleep, which is after it has installed the signal handler.
    tokio::time::sleep(Duration::from_millis(300)).await;
    rustix::process::kill_process(rustix::process::getpid(), rustix::process::Signal::TERM)
        .unwrap();
    let out = tokio::time::timeout(Duration::from_secs(10), task)
        .await
        .expect("SIGTERM did not end the sleep")
        .unwrap();
    assert_eq!(out, Outcome::Interrupted(Duration::from_secs(30)));
    assert!(
        start.elapsed() < Duration::from_secs(5),
        "{:?}",
        start.elapsed()
    );
}
