//! The audit emitter library (ADR 0028 "Four pieces"): it lives inside each emitting process,
//! holds no credential, and from one call builds one message, an OCSF 1.9.0 audit record as
//! RFC 8785 canonical JSON (ADR 0030 "The record format"), then hands it to the audit transport on
//! the emit socket.
//!
//! A person is never named in a record. The emitter asks key@ for `Mac` under the tenant's
//! pseudonym key before the record leaves the process (ADR 0029 "Pseudonyms"), so a [`Subject`]
//! becomes `p1.<YYYYMM>.<first 128 bits of the MAC>`.
//!
//! [`Emitter::emit`] hands the message over and returns; [`Emitter::emit_blocking`] returns only
//! when the transport says the message is durable (ADR 0029 "Sealing"). Delivery is at least once
//! and the writer removes a repeat by `metadata.uid`. The library keeps no queue and does not
//! retry: the spool driver behind the socket is the durable buffer, and a failure is returned to
//! the caller, who logs it.
//!
//! The Go package `kits/go/audit` produces the same bytes from the same input
//! (`kits/conformance/audit`).

mod canonical;
mod record;
mod uuid;

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use connectrpc::ConnectError;
use connectrpc::error::ErrorCode;
use serde_json::{Map, Value};
use sluis_kit::{Transport, dial, refusal};
use sluis_proto::sluis::key::v2alpha1::{KeyServiceClient, MacRequest};
use sluis_proto::sluis::port::transport::v2alpha1::{
    AuditMessage, EmitRequest, TransportServiceClient,
};

pub use canonical::canonical;
pub use uuid::new_uuid_v7;

/// The result of every call: a Connect error with the `Refusal` detail (contracts.md "Errors").
pub type Result<T> = std::result::Result<T, ConnectError>;

/// The OCSF release every record pins (0030: the first release pins 1.9.0).
pub const OCSF_VERSION: &str = "1.9.0";
/// The longest string a record may carry, in bytes (0029: free text is bounded).
pub const STRING_MAX: usize = 1024;
/// The largest record, in bytes.
pub const RECORD_MAX: usize = 16 << 10;

const PSEUDONYM_PURPOSE: &str = "pseudonym";
const PSEUDONYM_LABEL: &str = "sluis-pseudonym-v1";
const PSEUDONYM_BYTES: usize = 16;

/// OCSF's `status_id`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(i64)]
pub enum Status {
    /// The action succeeded.
    #[default]
    Success = 1,
    /// The action failed.
    Failure = 2,
}

/// One row of an actor's action table (0030: the table is code).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Action {
    /// `metadata.event_code`, e.g. `key.sign`.
    pub name: String,
    /// The OCSF class, e.g. 6003 API Activity.
    pub class_uid: u32,
    /// The OCSF activity within the class, e.g. 99 Other.
    pub activity_id: u32,
    /// `activity_name`. Required when `activity_id` is 99 (0030: "activity_name only for activity
    /// 99 or where the table names one"), e.g. `Sign` or `Open` for key use.
    pub activity_name: String,
}

/// The person or external actor an event concerns.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Subject {
    /// The tenant whose pseudonym key is used.
    pub tenant: String,
    /// The kind of identity (0029 "Pseudonyms"), e.g. `person`, `workload` or `client`. It is part
    /// of the pseudonym's input, so the same identifier of two kinds gives two pseudonyms. Required.
    pub kind: String,
    /// The stable identifier of that kind: the sluis subject of a person; the upstream's issuer and
    /// subject for an identity sluis has assigned no subject; the SPIFFE ID or client id of a
    /// workload or client; a product's own subject id for a person of a product. The emitter turns
    /// it into a pseudonym and never sends it.
    pub value: String,
}

/// The outcome of a policy decision: OCSF's `security_control` `action_id`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i64)]
pub enum Decision {
    /// Allowed (`action_id` 1).
    Allowed = 1,
    /// Denied (`action_id` 2).
    Denied = 2,
}

impl Decision {
    pub(crate) fn caption(self) -> &'static str {
        match self {
            Decision::Allowed => "Allowed",
            Decision::Denied => "Denied",
        }
    }
}

/// The decision that gated an action (0030 "The class mapping": part of the record of the action).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PolicyRef {
    /// The decision id: `policy.uid`. Required, because the OCSF policy object needs a uid; a
    /// digest or a list of policies without one is refused.
    pub decision_id: String,
    /// The digest of the policy bundle: `policy.version`.
    pub digest: String,
    /// The policies that took part: `authorizations[].policy.uid`.
    pub policy_ids: Vec<String>,
    /// `action_id` and `authorizations[].decision`; `None` records none.
    pub decision: Option<Decision>,
}

/// One audit event.
#[derive(Clone, Debug, Default)]
pub struct Event {
    /// The action.
    pub action: Action,
    /// The outcome.
    pub status: Status,
    /// A closed reason, e.g. `grant`; empty on success.
    pub status_code: String,
    /// `metadata.tenant_uid`; empty is the operator's own tenant (the writer fills it).
    pub tenant: String,
    /// The person concerned, as `user.uid` (a pseudonym).
    pub subject: Option<Subject>,
    /// The decision that gated this action.
    pub policy: Option<PolicyRef>,
    /// `unmapped.sluis`: strings, booleans, integers within +-(2^53-1), lists of strings and nested
    /// objects. A float, a null or a list of anything else is refused.
    pub sluis: Map<String, Value>,
    /// The correlation id for `metadata.correlation_uid`. When `None`, the emitter takes
    /// `sluis_kit::correlation::current()`, the id of the call being served, so a handler need not
    /// pass it. An id that is not 1 to 64 characters of `[A-Za-z0-9_-]` is dropped.
    pub correlation_id: Option<String>,
}

/// What an [`Emitter`] needs.
#[derive(Clone, Debug)]
pub struct Config {
    /// The emitting actor's registry name (or a product's service name).
    pub actor: String,
    /// The boundary.
    pub boundary: String,
    /// The release (`sluis_version`).
    pub release: String,
    /// The emit socket: `/run/sluis/audit/<boundary>/emit.sock`.
    pub transport_socket: PathBuf,
    /// key@'s socket for this caller; `None` for an actor with no pseudonym rule, which then cannot
    /// send a [`Subject`].
    pub key_socket: Option<PathBuf>,
    /// The clock; `None` is the system clock. A test injects one.
    pub now: Option<fn() -> SystemTime>,
}

/// Builds audit messages and hands them to the transport. It is cheap to clone and safe to share.
#[derive(Clone)]
pub struct Emitter {
    actor: String,
    boundary: String,
    release: String,
    transport: TransportServiceClient<Transport>,
    keys: Option<KeyServiceClient<Transport>>,
    now: fn() -> SystemTime,
}

fn valid_correlation(id: &str) -> bool {
    (1..=64).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

fn unix_ms(t: SystemTime) -> i64 {
    t.duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_millis()).ok())
        .unwrap_or(0)
}

/// `YYYYMM` of a Unix time in milliseconds, in UTC (days to civil date by Howard Hinnant's
/// algorithm).
fn epoch_of(ms: i64) -> String {
    let z = ms.div_euclid(86_400_000) + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}{month:02}")
}

impl Emitter {
    /// Returns an emitter. Nothing is dialled until the first call, so a transport that is not up
    /// yet does not fail construction.
    ///
    /// # Errors
    ///
    /// `invalid_argument` when the actor, the boundary or the release is empty or too long.
    pub fn new(cfg: Config) -> Result<Self> {
        for (v, path) in [
            (&cfg.actor, "actor"),
            (&cfg.boundary, "boundary"),
            (&cfg.release, "release"),
        ] {
            if v.is_empty() {
                return Err(refusal(ErrorCode::InvalidArgument, "schema", path));
            }
            if v.len() > STRING_MAX {
                return Err(refusal(ErrorCode::InvalidArgument, "bound", path));
            }
        }
        let t = dial(&cfg.transport_socket);
        let keys = cfg.key_socket.as_deref().map(|p| {
            let k = dial(p);
            KeyServiceClient::new(k.transport(), k.config())
        });
        Ok(Self {
            actor: cfg.actor,
            boundary: cfg.boundary,
            release: cfg.release,
            transport: TransportServiceClient::new(t.transport(), t.config()),
            keys,
            now: cfg.now.unwrap_or(SystemTime::now),
        })
    }

    /// Hands the event to the transport and returns once the transport has accepted it
    /// (`EmitRequest.blocking` is false). An error is returned to the caller; the library neither
    /// buffers nor retries.
    ///
    /// # Errors
    ///
    /// A refusal of the event, key@'s error, or the transport's.
    pub async fn emit(&self, ev: Event) -> Result<()> {
        self.send(ev, false).await
    }

    /// Returns only when the transport says the message is durable (ADR 0029 "Sealing";
    /// `blocking` is true). The caller decides what a failure means; the library does not retry.
    ///
    /// # Errors
    ///
    /// As [`emit`](Self::emit).
    pub async fn emit_blocking(&self, ev: Event) -> Result<()> {
        self.send(ev, true).await
    }

    async fn send(&self, ev: Event, blocking: bool) -> Result<()> {
        let (record, uid) = self.record(ev).await?;
        let req = EmitRequest {
            message: AuditMessage {
                uid,
                record,
                ..AuditMessage::default()
            }
            .into(),
            blocking,
            ..EmitRequest::default()
        };
        self.transport.emit(req).await?;
        Ok(())
    }

    /// Builds the message of an event without sending it: the record as RFC 8785 bytes, and its
    /// `metadata.uid`. Tests and the command line use it.
    ///
    /// # Errors
    ///
    /// A refusal of the event, or key@'s error.
    pub async fn record(&self, ev: Event) -> Result<(Vec<u8>, String)> {
        record::validate_event(&ev)?;
        let time_ms = unix_ms((self.now)());
        let pseudonym = match &ev.subject {
            Some(s) => Some(self.pseudonym(s, time_ms).await?),
            None => None,
        };
        let uid = new_uuid_v7(time_ms);
        let ambient = sluis_kit::correlation::current();
        let correlation = ev
            .correlation_id
            .as_deref()
            .or(ambient.as_deref())
            .filter(|c| valid_correlation(c));
        let rec = record::build_record(&record::RecordInput {
            actor: &self.actor,
            boundary: &self.boundary,
            release: &self.release,
            uid: &uid,
            time_ms,
            correlation,
            pseudonym: pseudonym.as_deref(),
            ev: &ev,
        })?;
        Ok((rec, uid))
    }

    /// Asks key@ for the `Mac` of the subject under the tenant's pseudonym key, with the epoch of
    /// the record's month, and formats it by ADR 0029 "Pseudonyms":
    /// `p1.<YYYYMM>.<first 128 bits, base64url, no padding>`.
    async fn pseudonym(&self, s: &Subject, time_ms: i64) -> Result<String> {
        let Some(keys) = &self.keys else {
            // Never fall back to the raw subject.
            return Err(refusal(ErrorCode::FailedPrecondition, "keys", "subject"));
        };
        let epoch = epoch_of(time_ms);
        let resp = keys
            .mac(MacRequest {
                purpose: PSEUDONYM_PURPOSE.into(),
                tenant: s.tenant.clone(),
                label: PSEUDONYM_LABEL.into(),
                input: pseudonym_input(&self.boundary, s),
                epoch: epoch.clone(),
                ..MacRequest::default()
            })
            .await?
            .into_owned();
        let mac: &[u8] = &resp.mac;
        if mac.len() < PSEUDONYM_BYTES {
            return Err(refusal(ErrorCode::Internal, "schema", "subject"));
        }
        Ok(format_pseudonym(&epoch, mac))
    }
}

/// The `Mac` input of a pseudonym (0029 "Pseudonyms"): the boundary, the tenant, the kind of
/// identity and its identifier, each with a 4-byte big-endian length in front. The label
/// `sluis-pseudonym-v1` is the request's label, which key@ binds in. The length prefixes make the
/// parts unambiguous: ("ab","c") and ("a","bc") differ.
pub(crate) fn pseudonym_input(boundary: &str, s: &Subject) -> Vec<u8> {
    let mut b = Vec::new();
    for part in [boundary, &s.tenant, &s.kind, &s.value] {
        // Every part is at most STRING_MAX bytes (checked before this is called).
        b.extend_from_slice(&u32::try_from(part.len()).unwrap_or(u32::MAX).to_be_bytes());
        b.extend_from_slice(part.as_bytes());
    }
    b
}

/// `p1.<epoch>.<first 128 bits of the MAC, base64url, no padding>`; `mac` holds at least 16 bytes.
fn format_pseudonym(epoch: &str, mac: &[u8]) -> String {
    format!(
        "p1.{epoch}.{}",
        URL_SAFE_NO_PAD.encode(&mac[..PSEUDONYM_BYTES])
    )
}

#[cfg(test)]
mod tests;
