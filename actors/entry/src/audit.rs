//! The audit of every request (ADR 0028 "Four pieces"; 0030 "The class mapping").
//!
//! One record per request, answered or refused, through the emitter of the kit. The record names
//! the route, the method class, the HTTP status and a closed reason. It never holds a path, a
//! query, a header, a cookie or a parameter value: those come from outside and `entry` does not
//! repeat them. The correlation id of the request is in `metadata.correlation_uid`.
//!
//! `entry` has no credential or administrative change to record, so it uses the non-blocking
//! `emit`: the transport has accepted the record when the answer leaves. A failed emit is logged
//! with its Connect code and does not turn an answer into a refusal; the spool is the durable
//! buffer, and a down spool is an alarm, not a reason to stop the edge.

use serde_json::{Map, Value};
use sluis_audit::{Action, Config, Emitter, Event, Status};

/// OCSF class 6003, API Activity.
const API_ACTIVITY: u32 = 6003;

/// What the audit record says about a request.
pub(crate) struct Request<'a> {
    pub route: &'a str,
    pub method: &'a http::Method,
    pub status: u16,
    /// Empty when the request was answered.
    pub reason: &'a str,
    /// `grant_type` of a token request, when it is one of the closed list; otherwise empty.
    pub grant: &'a str,
    pub correlation: &'a str,
}

pub(crate) struct Auditor {
    emitter: Emitter,
}

impl Auditor {
    pub(crate) fn new(cfg: Config) -> anyhow::Result<Self> {
        let emitter =
            Emitter::new(cfg).map_err(|e| anyhow::anyhow!("audit emitter: {}", e.code.as_str()))?;
        Ok(Self { emitter })
    }

    pub(crate) async fn request(&self, r: Request<'_>) {
        let (activity_id, activity_name) =
            if r.method == http::Method::GET || r.method == http::Method::HEAD {
                (2, "") // Read
            } else if r.method == http::Method::POST {
                (1, "") // Create
            } else {
                (99, "Other")
            };
        let mut sluis = Map::new();
        sluis.insert("route".into(), Value::from(r.route));
        sluis.insert("http_status".into(), Value::from(r.status));
        if !r.grant.is_empty() {
            sluis.insert("grant_type".into(), Value::from(r.grant));
        }
        let ev = Event {
            action: Action {
                name: format!("entry.{}", r.route),
                class_uid: API_ACTIVITY,
                activity_id,
                activity_name: activity_name.into(),
            },
            status: if r.status < 400 {
                Status::Success
            } else {
                Status::Failure
            },
            status_code: r.reason.into(),
            sluis,
            correlation_id: Some(r.correlation.into()),
            ..Event::default()
        };
        if let Err(e) = self.emitter.emit(ev).await {
            tracing::warn!(code = e.code.as_str(), route = r.route, "audit emit failed");
        }
    }
}
