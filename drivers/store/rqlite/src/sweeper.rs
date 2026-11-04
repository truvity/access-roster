//! The sweeper (0005 "Time to live"): on rqlite's leader only, it frees the space of expired items
//! and trims the change log. Correctness never depends on it: a read checks the expiry itself.
//!
//! An item with no `expires_at` is never swept, which is what a `Lease` relies on (0005 "Leases").
//! Expiry is not a change, so a swept item leaves no log row: the read already hid it.

use std::time::Duration;

use anyhow::bail;
use sluis_conformance::rules::now_ms;

use crate::client::{Outcome, first_failure};
use crate::service::Driver;

/// Items freed in one transaction.
pub const BATCH: i64 = 500;
/// Batches one tick may run, so a very large backlog does not hold the loop for ever.
const MAX_BATCHES: usize = 200;

/// Runs one sweep if this node is the leader, and returns how many items it freed (0 on a node
/// that is not the leader).
///
/// # Errors
///
/// When rqlite cannot be reached or refuses a statement.
pub async fn sweep_once(driver: &Driver, retention: Duration) -> anyhow::Result<usize> {
    if !driver.rq().is_leader().await? {
        return Ok(0);
    }
    let ns = driver.ns();
    let mut freed = 0usize;
    for _ in 0..MAX_BATCHES {
        let out = driver
            .rq()
            .request(&ns.sweep_expired(now_ms(), BATCH), true)
            .await?;
        if let Some((i, _, message)) = first_failure(&out) {
            bail!("sweep statement {i} failed: {message}");
        }
        let Some(Outcome::Done { affected, .. }) = out.get(1) else {
            bail!("the sweep answered no result");
        };
        freed += usize::try_from(*affected).unwrap_or(0);
        if *affected < BATCH {
            break;
        }
    }
    let retention_ms = i64::try_from(retention.as_millis()).unwrap_or(i64::MAX);
    let out = driver
        .rq()
        .request(&ns.trim_log(now_ms().saturating_sub(retention_ms)), true)
        .await?;
    if let Some((i, _, message)) = first_failure(&out) {
        bail!("log trim statement {i} failed: {message}");
    }
    Ok(freed)
}

/// Sweeps every `interval` until the task is dropped. A failed sweep is logged and tried again at
/// the next tick: the node may just have lost its leadership.
pub async fn run(driver: Driver, interval: Duration, retention: Duration) {
    let mut tick = tokio::time::interval(interval);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        match sweep_once(&driver, retention).await {
            Ok(0) => {}
            Ok(n) => tracing::info!(freed = n, "swept expired items"),
            Err(e) => tracing::warn!(error = %format!("{e:#}"), "sweep failed"),
        }
    }
}
