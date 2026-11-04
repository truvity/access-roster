//! The audit front's one route: `POST /sluis.reader.v2alpha1.ReaderService/Search` (ADR 0028 "The audit
//! front"; the Connect protocol's unary call over HTTP, with the JSON codec).
//!
//! `entry` parses the body against the closed list of `SearchRequest` and builds the typed request, calls the
//! reader, and writes the typed answer as the JSON of the contract (proto3 JSON: lowerCamelCase names, 64-bit
//! integers as strings, bytes as base64). It decides nothing about who may read what: that is the reader's
//! and `policy`'s, and key@'s. A refusal behind it is the fixed body of its status, like every other route.

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use serde_json::{Map, Value, json};
use sluis_proto::sluis::reader::v2alpha1::{SearchRequest, SearchResponse};

use crate::params::Bad;

/// The path of the call.
pub(crate) const PATH: &str = "/sluis.reader.v2alpha1.ReaderService/Search";

/// The largest request body.
pub(crate) const BODY_MAX: usize = 16 * 1024;

fn camel(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut up = false;
    for c in name.chars() {
        if c == '_' {
            up = true;
        } else if up {
            out.extend(c.to_uppercase());
            up = false;
        } else {
            out.push(c);
        }
    }
    out
}

/// The member `name` of the body, by its proto name or its JSON name (both are valid proto3 JSON), once.
fn member<'a>(o: &'a Map<String, Value>, name: &str) -> Result<Option<&'a Value>, Bad> {
    let (a, b) = (o.get(name), o.get(&camel(name)));
    match (a, b) {
        (Some(_), Some(_)) if camel(name) != name => Err(Bad::Duplicate),
        (Some(v), _) | (None, Some(v)) => Ok(Some(v)),
        (None, None) => Ok(None),
    }
}

fn text(o: &Map<String, Value>, name: &str) -> Result<String, Bad> {
    match member(o, name)? {
        None | Some(Value::Null) => Ok(String::new()),
        Some(Value::String(s)) if !s.chars().any(char::is_control) => Ok(s.clone()),
        Some(_) => Err(Bad::Syntax),
    }
}

/// A 64-bit or 32-bit integer: a JSON number, or a string of decimal digits (proto3 JSON writes 64-bit integers
/// as strings).
fn int(o: &Map<String, Value>, name: &str) -> Result<i64, Bad> {
    match member(o, name)? {
        None | Some(Value::Null) => Ok(0),
        Some(Value::Number(n)) => n.as_i64().ok_or(Bad::Syntax),
        Some(Value::String(s)) if !s.is_empty() && s.len() <= 19 => {
            s.parse::<i64>().map_err(|_| Bad::Syntax)
        }
        Some(_) => Err(Bad::Syntax),
    }
}

/// The typed request of a body.
///
/// # Errors
///
/// [`Bad`]: not JSON, not an object, a member off the closed list `allowed`, one sent twice, or of the wrong
/// type. The text of the body is never reported.
pub(crate) fn request(body: &[u8], allowed: &[&str]) -> Result<SearchRequest, Bad> {
    let Value::Object(o) = serde_json::from_slice::<Value>(body).map_err(|_| Bad::Syntax)? else {
        return Err(Bad::Syntax);
    };
    if !o
        .keys()
        .all(|k| allowed.iter().any(|a| *a == k || camel(a) == *k))
    {
        return Err(Bad::Unknown);
    }
    let tenants = match member(&o, "tenants")? {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(a)) => a
            .iter()
            .map(|t| match t {
                Value::String(s) if !s.chars().any(char::is_control) => Ok(s.clone()),
                _ => Err(Bad::Syntax),
            })
            .collect::<Result<_, _>>()?,
        Some(_) => return Err(Bad::Syntax),
    };
    let page_token = match member(&o, "page_token")? {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::String(s)) => STANDARD
            .decode(s)
            .or_else(|_| STANDARD_NO_PAD.decode(s))
            .map_err(|_| Bad::Syntax)?,
        Some(_) => return Err(Bad::Syntax),
    };
    Ok(SearchRequest {
        tenants,
        project: text(&o, "project")?,
        q: text(&o, "q")?,
        action: text(&o, "action")?,
        status_code: text(&o, "status_code")?,
        status_id: int(&o, "status_id")?,
        actor_uid: text(&o, "actor_uid")?,
        trace_id: text(&o, "trace_id")?,
        record_id: text(&o, "record_id")?,
        from_ms: int(&o, "from_ms")?,
        to_ms: int(&o, "to_ms")?,
        page_size: i32::try_from(int(&o, "page_size")?).map_err(|_| Bad::Syntax)?,
        page_token,
        ..SearchRequest::default()
    })
}

/// The JSON of an answer.
pub(crate) fn response(r: &SearchResponse) -> Vec<u8> {
    let hits: Vec<Value> = r
        .hits
        .iter()
        .map(|h| {
            json!({
                "tenant": h.tenant,
                "project": h.project,
                "kind": h.kind,
                "log": h.log,
                "seq": h.seq.to_string(),
                "timeMs": h.time_ms.to_string(),
                "recordedMs": h.recorded_ms.to_string(),
                "action": h.action,
                "statusCode": h.status_code,
                "actorUid": h.actor_uid,
                "traceId": h.trace_id,
                "recordId": h.record_id,
                "record": h.record,
            })
        })
        .collect();
    serde_json::to_vec(&json!({
        "hits": hits,
        "nextPageToken": STANDARD.encode(&r.next_page_token),
    }))
    .unwrap_or_else(|_| br#"{"hits":[],"nextPageToken":""}"#.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routes;

    fn ok(body: &str) -> SearchRequest {
        request(body.as_bytes(), routes::SEARCH).unwrap()
    }

    fn bad(body: &str) -> Bad {
        request(body.as_bytes(), routes::SEARCH).unwrap_err()
    }

    #[test]
    fn a_request_is_read_by_proto_names_and_by_json_names() {
        let r = ok(
            r#"{"tenants":["acme"],"action":"signer.sign","from_ms":"1700000000000","pageSize":25,"statusCode":"ok"}"#,
        );
        assert_eq!(r.tenants, ["acme"]);
        assert_eq!(
            (
                r.action.as_str(),
                r.from_ms,
                r.page_size,
                r.status_code.as_str()
            ),
            ("signer.sign", 1_700_000_000_000, 25, "ok")
        );
        assert_eq!(ok("{}"), SearchRequest::default());
    }

    #[test]
    fn a_page_token_is_base64() {
        assert_eq!(ok(r#"{"page_token":"AQID"}"#).page_token, [1, 2, 3]);
        assert_eq!(ok(r#"{"pageToken":"AQID"}"#).page_token, [1, 2, 3]);
        assert_eq!(bad(r#"{"page_token":"%%%"}"#), Bad::Syntax);
    }

    #[test]
    fn what_the_contract_does_not_have_is_refused() {
        assert_eq!(bad(r#"{"tenant":"acme"}"#), Bad::Unknown);
        assert_eq!(bad(r#"{"tenants":["a"],"admin":true}"#), Bad::Unknown);
        assert_eq!(bad(r#"{"tenants":"acme"}"#), Bad::Syntax);
        assert_eq!(bad(r#"{"tenants":[1]}"#), Bad::Syntax);
        assert_eq!(bad(r#"{"q":3}"#), Bad::Syntax);
        assert_eq!(bad(r#"{"from_ms":1.5}"#), Bad::Syntax);
        assert_eq!(bad(r#"{"from_ms":"x"}"#), Bad::Syntax);
        assert_eq!(bad(r#"{"page_size":4294967296}"#), Bad::Syntax);
        assert_eq!(bad(r#"{"page_size":10,"pageSize":10}"#), Bad::Duplicate);
        assert_eq!(bad("[]"), Bad::Syntax);
        assert_eq!(bad("not json"), Bad::Syntax);
        assert_eq!(bad(r#"{"q":"a\u0001b"}"#), Bad::Syntax);
    }

    #[test]
    fn an_answer_is_proto3_json() {
        let r = SearchResponse {
            hits: vec![sluis_proto::sluis::reader::v2alpha1::Hit {
                seq: 9,
                time_ms: 1_700_000_000_000,
                record: "{\"a\":1}".into(),
                ..Default::default()
            }],
            next_page_token: vec![1, 2, 3],
            ..Default::default()
        };
        let v: Value = serde_json::from_slice(&response(&r)).unwrap();
        assert_eq!(v["hits"][0]["seq"], "9");
        assert_eq!(v["hits"][0]["timeMs"], "1700000000000");
        assert_eq!(v["hits"][0]["record"], "{\"a\":1}");
        assert_eq!(v["nextPageToken"], "AQID");
    }
}
