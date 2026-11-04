//! Uniform refusals at the edge (contracts.md "Uniform refusals at the edge").
//!
//! Every refusal that `entry` makes, and every error an actor behind it returns, becomes one fixed
//! body per HTTP status. Nothing from inside reaches it: not the reason, not the field path, not a
//! message. The reason goes to the audit record. The correlation id is in the
//! `Sluis-Correlation-Id` header of the response.
//!
//! The body is RFC 9457 problem details whose `type` is a fixed URN. For the statuses a client of
//! RFC 6749 section 5.2 reads (400, 401, 403, 500, 503) it also holds the standard's `error` and a
//! fixed `error_description`, so one body is both.

use connectrpc::error::ErrorCode;

/// A refusal: the HTTP status, the reason for the audit record, and the methods to offer on a 405.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Refuse {
    pub status: u16,
    /// From a closed list of this crate (a field path or a code, never a value).
    pub reason: &'static str,
    /// The `Allow` header of a 405.
    pub allow: Option<&'static str>,
}

impl Refuse {
    pub(crate) const fn new(status: u16, reason: &'static str) -> Self {
        Self {
            status,
            reason,
            allow: None,
        }
    }

    pub(crate) const fn method(allow: &'static str) -> Self {
        Self {
            status: 405,
            reason: "method",
            allow: Some(allow),
        }
    }

    /// An error returned by an actor behind `entry`, by the table of contracts.md "Connect codes".
    pub(crate) fn rpc(code: ErrorCode) -> Self {
        let (status, reason) = match code {
            ErrorCode::InvalidArgument => (400, "rpc_invalid_argument"),
            ErrorCode::FailedPrecondition => (400, "rpc_failed_precondition"),
            ErrorCode::Unauthenticated => (401, "rpc_unauthenticated"),
            ErrorCode::PermissionDenied => (403, "rpc_permission_denied"),
            ErrorCode::NotFound => (404, "rpc_not_found"),
            ErrorCode::AlreadyExists => (409, "rpc_already_exists"),
            ErrorCode::Aborted => (409, "rpc_aborted"),
            ErrorCode::ResourceExhausted => (429, "rpc_resource_exhausted"),
            ErrorCode::Unimplemented => (501, "rpc_unimplemented"),
            ErrorCode::Unavailable => (503, "rpc_unavailable"),
            ErrorCode::DeadlineExceeded => (504, "rpc_deadline_exceeded"),
            _ => (500, "rpc_internal"),
        };
        Self::new(status, reason)
    }
}

/// The fixed body of a status. A status with no row answers as 500.
pub(crate) fn body(status: u16) -> &'static str {
    match status {
        400 => {
            r#"{"error":"invalid_request","error_description":"invalid request","status":400,"title":"Invalid request","type":"urn:sluis:problem:invalid-request"}"#
        }
        401 => {
            r#"{"error":"invalid_client","error_description":"not authorised","status":401,"title":"Not authorised","type":"urn:sluis:problem:unauthenticated"}"#
        }
        403 => {
            r#"{"error":"access_denied","error_description":"not authorised","status":403,"title":"Not authorised","type":"urn:sluis:problem:forbidden"}"#
        }
        404 => r#"{"status":404,"title":"Not found","type":"urn:sluis:problem:not-found"}"#,
        405 => {
            r#"{"status":405,"title":"Method not allowed","type":"urn:sluis:problem:method-not-allowed"}"#
        }
        409 => r#"{"status":409,"title":"Conflict","type":"urn:sluis:problem:conflict"}"#,
        413 => r#"{"status":413,"title":"Request too large","type":"urn:sluis:problem:too-large"}"#,
        415 => {
            r#"{"status":415,"title":"Unsupported media type","type":"urn:sluis:problem:unsupported-media-type"}"#
        }
        429 => {
            r#"{"status":429,"title":"Too many requests","type":"urn:sluis:problem:rate-limited"}"#
        }
        501 => {
            r#"{"status":501,"title":"Not implemented","type":"urn:sluis:problem:not-implemented"}"#
        }
        503 => {
            r#"{"error":"temporarily_unavailable","error_description":"try again later","status":503,"title":"Unavailable","type":"urn:sluis:problem:unavailable"}"#
        }
        504 => {
            r#"{"status":504,"title":"Deadline exceeded","type":"urn:sluis:problem:deadline-exceeded"}"#
        }
        _ => {
            r#"{"error":"server_error","error_description":"server error","status":500,"title":"Server error","type":"urn:sluis:problem:server-error"}"#
        }
    }
}

/// The status a body is sent with: one with a row of its own, or 500.
pub(crate) fn status_of(status: u16) -> u16 {
    if matches!(
        status,
        400 | 401 | 403 | 404 | 405 | 409 | 413 | 415 | 429 | 501 | 503 | 504
    ) {
        status
    } else {
        500
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_body_is_json_with_its_own_status_and_no_variable_part() {
        for s in [
            400, 401, 403, 404, 405, 409, 413, 415, 429, 500, 501, 503, 504,
        ] {
            let v: serde_json::Value = serde_json::from_str(body(s)).unwrap();
            assert_eq!(v["status"], s, "{s}");
            assert!(
                v["type"]
                    .as_str()
                    .unwrap()
                    .starts_with("urn:sluis:problem:")
            );
            assert_eq!(status_of(s), s);
        }
        assert_eq!(status_of(418), 500);
        assert_eq!(body(418), body(500));
    }

    #[test]
    fn the_codes_map_as_contracts_md_says() {
        let table = [
            (ErrorCode::InvalidArgument, 400),
            (ErrorCode::Unauthenticated, 401),
            (ErrorCode::PermissionDenied, 403),
            (ErrorCode::NotFound, 404),
            (ErrorCode::AlreadyExists, 409),
            (ErrorCode::Aborted, 409),
            (ErrorCode::FailedPrecondition, 400),
            (ErrorCode::ResourceExhausted, 429),
            (ErrorCode::DeadlineExceeded, 504),
            (ErrorCode::Unimplemented, 501),
            (ErrorCode::Unavailable, 503),
            (ErrorCode::Internal, 500),
            (ErrorCode::DataLoss, 500),
        ];
        for (c, s) in table {
            assert_eq!(Refuse::rpc(c).status, s, "{c:?}");
        }
    }
}
