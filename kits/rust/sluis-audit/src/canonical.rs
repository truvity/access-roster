//! RFC 8785 (JCS) canonical JSON over the values a sluis record may hold.
//!
//! The allowed values are null, booleans, strings, integers within +-(2^53-1), arrays and objects. A
//! float is refused (0030 "Canonical rules"), so the number formatting of RFC 8785 section 3.2.2.3
//! reduces to the decimal digits of an integer.

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
    let mut out = Vec::new();
    write_value(&mut out, v, "", 0)?;
    Ok(out)
}

fn write_value(out: &mut Vec<u8>, v: &Value, path: &str, depth: usize) -> Result<()> {
    if depth > MAX_DEPTH {
        return Err(invalid("bound", path));
    }
    match v {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(b) => out.extend_from_slice(if *b { b"true" } else { b"false" }),
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
            out.extend_from_slice(i.to_string().as_bytes());
        }
        Value::String(s) => write_string(out, s),
        Value::Array(a) => {
            out.push(b'[');
            for (i, e) in a.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_value(out, e, &format!("{path}[{i}]"), depth + 1)?;
            }
            out.push(b']');
        }
        Value::Object(m) => {
            // RFC 8785 section 3.2.3: members sorted by the UTF-16 code units of their names.
            let mut members: Vec<(Vec<u16>, &String, &Value)> = m
                .iter()
                .map(|(k, v)| (k.encode_utf16().collect(), k, v))
                .collect();
            members.sort_by(|a, b| a.0.cmp(&b.0));
            out.push(b'{');
            for (i, (_, k, v)) in members.into_iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_string(out, k);
                out.push(b':');
                let p = if path.is_empty() {
                    k.clone()
                } else {
                    format!("{path}.{k}")
                };
                write_value(out, v, &p, depth + 1)?;
            }
            out.push(b'}');
        }
    }
    Ok(())
}

const HEX: &[u8; 16] = b"0123456789abcdef";

/// RFC 8785 section 3.2.2.2: the short escapes for backspace, tab, line feed, form feed and
/// carriage return, `\"` and `\\`, `\u00xx` in lower case for the other control characters, and
/// every other character as itself in UTF-8.
fn write_string(out: &mut Vec<u8>, s: &str) {
    out.push(b'"');
    for &c in s.as_bytes() {
        match c {
            b'"' => out.extend_from_slice(br#"\""#),
            b'\\' => out.extend_from_slice(br"\\"),
            0x08 => out.extend_from_slice(br"\b"),
            b'\t' => out.extend_from_slice(br"\t"),
            b'\n' => out.extend_from_slice(br"\n"),
            0x0c => out.extend_from_slice(br"\f"),
            b'\r' => out.extend_from_slice(br"\r"),
            c if c < 0x20 => {
                out.extend_from_slice(br"\u00");
                out.push(HEX[usize::from(c >> 4)]);
                out.push(HEX[usize::from(c & 0xf)]);
            }
            c => out.push(c),
        }
    }
    out.push(b'"');
}
