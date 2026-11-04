//! What store@ tells the audit log, behind a small trait (the WP-10 emitter is wired in behind it).
//!
//! store@ audits `store.start` and every refusal. It does not audit writes: the actor that owns a
//! write audits its own action (BRIEF-WP-06). An emit that fails never fails the call.

use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// One fact for the audit log. A field value is a closed word or a name of the registry; never a
/// value of an item and never an id (an id can be a keyed hash).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditEvent {
    /// `metadata.event_code`: `store.start` or `store.refused`.
    pub action: &'static str,
    /// A refusal is a failure; a start is a success.
    pub failure: bool,
    /// The closed reason of a refusal (`status_code`); empty on success.
    pub reason: String,
    /// `unmapped.sluis` fields, in order.
    pub fields: Vec<(&'static str, String)>,
}

/// Where audit facts go.
pub trait AuditSink: Send + Sync + 'static {
    /// Emits without waiting for durability. An `Err` is logged and counted by the caller.
    fn emit(&self, event: AuditEvent) -> impl Future<Output = Result<(), String>> + Send;
}

/// How long an emit may hold up an answer.
const EMIT_TIMEOUT: Duration = Duration::from_millis(500);

/// A sink plus the count of facts it failed to take.
pub struct Auditor<A> {
    sink: A,
    failed: AtomicU64,
}

impl<A: AuditSink> Auditor<A> {
    #[must_use]
    pub fn new(sink: A) -> Self {
        Self {
            sink,
            failed: AtomicU64::new(0),
        }
    }

    /// Emits a fact. A failed or slow emit is logged and counted, and the call still answers
    /// (ADR 0028: blocking emits are for credential changes, which store@ does not make).
    pub async fn emit(&self, event: AuditEvent) {
        let action = event.action;
        match tokio::time::timeout(EMIT_TIMEOUT, self.sink.emit(event)).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => self.failure(action, &e),
            Err(_) => self.failure(action, "timeout"),
        }
    }

    fn failure(&self, action: &str, why: &str) {
        let n = self.failed.fetch_add(1, Ordering::Relaxed) + 1;
        tracing::error!(action, why, failed_total = n, "audit emit failed");
    }

    /// The facts that could not be emitted since start.
    #[must_use]
    pub fn failed(&self) -> u64 {
        self.failed.load(Ordering::Relaxed)
    }
}

/// Logs the fact as a structured line and nothing else. It stands in until the emitter of
/// `sluis-audit` is wired (WP-10).
pub struct LogSink;

impl AuditSink for LogSink {
    async fn emit(&self, event: AuditEvent) -> Result<(), String> {
        tracing::info!(action = event.action, failure = event.failure, reason = %event.reason, fields = ?event.fields, "audit");
        Ok(())
    }
}
