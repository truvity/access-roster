//! RFC 8785 (JCS) canonical JSON over the values a sluis record may hold.
//!
//! The canonical form itself (member order by UTF-16 code units, string escapes, number text, no
//! insignificant whitespace) comes from the `serde_json_canonicalizer` crate: sluis implements no
//! protocol of an external standard itself (REQ-SEC-018). What this module adds is the sluis
//! profile, checked before the crate sees the value: null, booleans, strings, integers within
//! +-(2^53-1), arrays and objects, nested at most [`MAX_DEPTH`] deep. A float is refused (0030
//! "Canonical rules"), so the crate never formats a number other than an integer.

use connectrpc::ConnectError;
use connectrpc::error::ErrorCode;
use serde_json::Value;
use sluis_kit::refusal;

use crate::Result;

/// 2^53-1, the largest integer a record may carry.
pub(crate) const MAX_SAFE_INT: i64 = (1 << 53) - 1;
/// How deep a value may nest.
pub(crate) const MAX_DEPTH: usize = 16;

pub(crate) fn invalid(reason: &str, path: &str) -> ConnectError {
    refusal(ErrorCode::InvalidArgument, reason, path)
}

/// Returns `v` as RFC 8785 canonical JSON.
///
/// # Errors
///
/// `invalid_argument` with reason `schema` for a float, and `bound` for an integer outside
/// +-(2^53-1) or a value nested deeper than the bound. The error names a field path, never a value.
pub fn canonical(v: &Value) -> Result<Vec<u8>> {
    check_profile(v, "", 0)?;
    // The profile check leaves the crate nothing it can refuse; if it does, the value has no
    // canonical form.
    serde_json_canonicalizer::to_vec(v).map_err(|_| invalid("schema", ""))
}

/// The sluis profile: what a record may hold, on top of what RFC 8785 allows. Members are visited
/// in byte order of their names, so the first refusal does not depend on the map's order.
fn check_profile(v: &Value, path: &str, depth: usize) -> Result<()> {
    if depth > MAX_DEPTH {
        return Err(invalid("bound", path));
    }
    match v {
        Value::Null | Value::Bool(_) | Value::String(_) => {}
        Value::Number(n) => {
            let i = if let Some(i) = n.as_i64() {
                i
            } else if n.is_u64() {
                // Above i64::MAX, hence above the bound.
                return Err(invalid("bound", path));
            } else {
                return Err(invalid("schema", path));
            };
            if !(-MAX_SAFE_INT..=MAX_SAFE_INT).contains(&i) {
                return Err(invalid("bound", path));
            }
        }
        Value::Array(a) => {
            for (i, e) in a.iter().enumerate() {
                check_profile(e, &format!("{path}[{i}]"), depth + 1)?;
            }
        }
        Value::Object(m) => {
            let mut members: Vec<(&String, &Value)> = m.iter().collect();
            members.sort_by(|a, b| a.0.cmp(b.0));
            for (k, e) in members {
                let p = if path.is_empty() {
                    k.clone()
                } else {
                    format!("{path}.{k}")
                };
                check_profile(e, &p, depth + 1)?;
            }
        }
    }
    Ok(())
}
