//! What store@ tells the audit log: `store.start` and every refusal.
//!
//! store@ does not audit writes: the actor that owns a write audits its own action. An emit that
//! fails never fails the call. The facts go through the trait [`AuditSink`]; [`EmitterSink`] is the
//! real one, over the emitter of `sluis-audit`, and the tests use a recording sink.

use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// One fact for the audit log. A field value is a closed word or a name of the registry; never a
/// value of an item and never an id (an id can be a keyed hash).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditEvent {
    /// `metadata.event_code`: `store.start`, `store.refused`, `store.reload` or `store.reload.refused`.
    pub action: &'static str,
    /// A refusal is a failure; a start is a success.
    pub failure: bool,
    /// The closed reason of a refusal (`status_code`); empty on success.
    pub reason: String,
    /// `unmapped.sluis` fields, in order.
    pub fields: Vec<(&'static str, String)>,
    /// `metadata.correlation_uid`: the correlation id of the call being served, when there is one.
    pub correlation_id: Option<String>,
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

/// OCSF's API Activity class (6003) and its activity 99, Other: the class of a non-identity action
/// (BRIEF-WP-10; 0030 "The class mapping"). Activity 99 needs a name.
const CLASS_API_ACTIVITY: u32 = 6003;
const ACTIVITY_OTHER: u32 = 99;

/// The emitter of `sluis-audit`, inside this process, over the emit socket of the audit transport.
pub struct EmitterSink(pub sluis_audit::Emitter);

impl EmitterSink {
    /// The OCSF event of a fact. Status is set explicitly: the library defaults to success.
    #[must_use]
    pub fn event(e: AuditEvent) -> sluis_audit::Event {
        let name = match e.action {
            "store.start" => "Start",
            "store.reload" => "Reload",
            _ => "Refuse",
        };
        sluis_audit::Event {
            action: sluis_audit::Action {
                name: e.action.to_owned(),
                class_uid: CLASS_API_ACTIVITY,
                activity_id: ACTIVITY_OTHER,
                activity_name: name.to_owned(),
            },
            status: if e.failure {
                sluis_audit::Status::Failure
            } else {
                sluis_audit::Status::Success
            },
            status_code: e.reason,
            sluis: e
                .fields
                .into_iter()
                .map(|(k, v)| (k.to_owned(), serde_json::Value::String(v)))
                .collect(),
            correlation_id: e.correlation_id,
            // No Subject: a refusal names the calling actor in `unmapped.sluis`, never a person.
            // Tenant stays empty: the record belongs to the operator's own tenant (0029).
            ..sluis_audit::Event::default()
        }
    }
}

impl AuditSink for EmitterSink {
    /// Non-blocking: store@ makes no credential change, and blocking emits are for those (0028).
    async fn emit(&self, event: AuditEvent) -> Result<(), String> {
        self.0
            .emit(Self::event(event))
            .await
            .map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn emitter() -> sluis_audit::Emitter {
        sluis_audit::Emitter::new(sluis_audit::Config {
            actor: "store".into(),
            boundary: "dev".into(),
            release: "0.0.0".into(),
            transport_socket: "/nonexistent/emit.sock".into(),
            key_socket: None,
            now: None,
        })
        .unwrap()
    }

    #[tokio::test]
    async fn a_refusal_is_an_ocsf_record_the_emitter_accepts() {
        let ev = AuditEvent {
            action: "store.refused",
            failure: true,
            reason: "grant".into(),
            fields: vec![
                ("caller", "session".into()),
                ("kind", "Person".into()),
                ("verb", "create".into()),
            ],
            correlation_id: Some("req-1".into()),
        };
        let (bytes, uid) = emitter().record(EmitterSink::event(ev)).await.unwrap();
        let r: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(r["class_uid"], 6003);
        assert_eq!(r["activity_id"], 99);
        assert_eq!(r["activity_name"], "Refuse");
        assert_eq!(r["status_id"], 2, "a refusal is a failure, set explicitly");
        assert_eq!(r["status_code"], "grant");
        assert_eq!(r["metadata"]["event_code"], "store.refused");
        assert_eq!(r["metadata"]["correlation_uid"], "req-1");
        assert_eq!(r["metadata"]["uid"], uid);
        assert_eq!(r["actor"]["user"]["uid"], "store@dev");
        assert_eq!(r["unmapped"]["sluis"]["caller"], "session");
        assert_eq!(r["unmapped"]["sluis"]["verb"], "create");
        assert!(r.get("user").is_none(), "no person is named");
    }

    #[tokio::test]
    async fn the_start_is_a_success_named_start() {
        let ev = AuditEvent {
            action: "store.start",
            failure: false,
            reason: String::new(),
            fields: vec![("boundary", "dev".into()), ("durable", "rqlite".into())],
            correlation_id: None,
        };
        let (bytes, _) = emitter().record(EmitterSink::event(ev)).await.unwrap();
        let r: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            (r["activity_name"].as_str(), r["status_id"].as_i64()),
            (Some("Start"), Some(1))
        );
        assert!(r.get("status_code").is_none());
    }
}
