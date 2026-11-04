//! The rules of the item contract that every engine applies in the same way, written once so that
//! the engines and the suite cannot drift apart (store-api.md "The item contract").
//!
//! The reasons are the ones of the closed list in store-api.md "Refusals": a bad key or page token
//! is `invalid_argument` with `address`, a bad batch is `invalid_argument` with `batch`.

use buffa_types::google::protobuf::Timestamp;
use connectrpc::ConnectError;
use connectrpc::error::ErrorCode;
use sluis_kit::refusal;
// The generated oneof of `Condition.expect` lives in the package's `__buffa::oneof` module.
use sluis_proto::sluis::port::item::v2alpha1::__buffa::oneof::condition::Expect;
use sluis_proto::sluis::port::item::v2alpha1::TransactRequest;

/// The most items one page of `Query` holds (the brief of the driver, store-api.md).
pub const MAX_PAGE: usize = 500;
/// The page size of a `Query` that names none.
pub const DEFAULT_PAGE: usize = 100;
/// The most operations (conditions, puts and deletes together) one `Transact` carries. store@
/// refuses a batch of more than 64 operations; a driver is lenient to a limit of its own.
pub const MAX_OPS: usize = 256;
/// The longest key a driver takes (the address is at most 300 bytes, store-api.md "Address encoding").
pub const MAX_KEY: usize = 512;

/// A key is the address as text: printable ASCII without a space. A driver does not parse it into
/// kinds; it only needs a text it can order and take a prefix of byte by byte.
///
/// # Errors
///
/// `invalid_argument` with the reason `address` and `path` as the field path.
pub fn check_key(key: &[u8], path: &str) -> Result<(), ConnectError> {
    if key.is_empty() || key.len() > MAX_KEY || !key.iter().all(|b| (0x21..=0x7e).contains(b)) {
        return Err(refusal(ErrorCode::InvalidArgument, "address", path));
    }
    Ok(())
}

/// The page size of a `Query`: 0 is the default, more than [`MAX_PAGE`] is [`MAX_PAGE`].
///
/// # Errors
///
/// `invalid_argument` with the reason `batch` for a negative size.
pub fn page_size(n: i32) -> Result<usize, ConnectError> {
    match usize::try_from(n) {
        Ok(0) => Ok(DEFAULT_PAGE),
        Ok(n) => Ok(n.min(MAX_PAGE)),
        Err(_) => Err(refusal(ErrorCode::InvalidArgument, "batch", "page_size")),
    }
}

/// The page token is the last key of the previous page, so it must be a key under the prefix.
///
/// # Errors
///
/// `invalid_argument` with the reason `address` and the field path `page_token`.
pub fn check_token(token: &[u8], prefix: &[u8]) -> Result<(), ConnectError> {
    if token.is_empty() {
        return Ok(());
    }
    check_key(token, "page_token")?;
    if !token.starts_with(prefix) {
        return Err(refusal(ErrorCode::InvalidArgument, "address", "page_token"));
    }
    Ok(())
}

/// The smallest key that is greater than every key starting with `prefix`: the last byte plus one.
/// Keys are printable ASCII ([`check_key`]), so a prefix of those never ends in 0xff; `None` for
/// an empty prefix (no upper bound).
#[must_use]
pub fn prefix_successor(prefix: &[u8]) -> Option<Vec<u8>> {
    let (last, rest) = prefix.split_last()?;
    let mut end = rest.to_vec();
    end.push(last.saturating_add(1));
    Some(end)
}

/// Milliseconds since the epoch of a timestamp (the engines keep expiry in milliseconds).
#[must_use]
pub fn ts_to_ms(t: &Timestamp) -> i64 {
    t.seconds
        .saturating_mul(1000)
        .saturating_add(i64::from(t.nanos).div_euclid(1_000_000))
}

/// The timestamp of a number of milliseconds since the epoch.
#[must_use]
pub fn ms_to_ts(ms: i64) -> Timestamp {
    Timestamp {
        seconds: ms.div_euclid(1000),
        nanos: i32::try_from(ms.rem_euclid(1000) * 1_000_000).unwrap_or(0),
        ..Timestamp::default()
    }
}

/// The clock of an engine, in milliseconds since the epoch. An engine uses it only to compare
/// with an expiry that store@ set (0005 "Time to live"); it never writes it into an item.
#[must_use]
pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

/// What a condition expects of its key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Expected {
    /// The key must not exist.
    Absent,
    /// The key must be at this version.
    Version(u64),
}

/// Checks a `Transact` request as an engine would before it touches the data, and returns what
/// each condition expects, in order.
///
/// # Errors
///
/// `invalid_argument` with `address` for a bad key, `batch` for too many operations, a condition
/// that expects nothing, a key written twice, or an index entry without a name.
pub fn check_transact(req: &TransactRequest) -> Result<Vec<Expected>, ConnectError> {
    let batch = |path: String| refusal(ErrorCode::InvalidArgument, "batch", &path);
    if req.conditions.len() + req.puts.len() + req.deletes.len() > MAX_OPS {
        return Err(batch("conditions".into()));
    }
    let mut expected = Vec::with_capacity(req.conditions.len());
    for (i, c) in req.conditions.iter().enumerate() {
        check_key(&c.key, &format!("conditions[{i}].key"))?;
        expected.push(match &c.expect {
            Some(Expect::Absent(true)) => Expected::Absent,
            Some(Expect::Version(v)) => Expected::Version(*v),
            // `absent: false` and no expectation say nothing a driver could enforce.
            _ => return Err(batch(format!("conditions[{i}].expect"))),
        });
    }
    let mut written = std::collections::BTreeSet::new();
    for (i, p) in req.puts.iter().enumerate() {
        check_key(&p.key, &format!("puts[{i}].key"))?;
        if !written.insert(p.key.as_slice()) {
            return Err(batch(format!("puts[{i}].key")));
        }
        for (j, e) in p.indexes.iter().enumerate() {
            if e.name.is_empty() {
                return Err(refusal(
                    ErrorCode::InvalidArgument,
                    "index",
                    &format!("puts[{i}].indexes[{j}].name"),
                ));
            }
        }
    }
    for (i, d) in req.deletes.iter().enumerate() {
        check_key(&d.key, &format!("deletes[{i}].key"))?;
        if !written.insert(d.key.as_slice()) {
            return Err(batch(format!("deletes[{i}].key")));
        }
    }
    Ok(expected)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn successor_of_a_prefix() {
        assert_eq!(prefix_successor(b"a/b/"), Some(b"a/b0".to_vec()));
        assert_eq!(prefix_successor(b""), None);
        assert!(b"a/b/zzz".as_slice() < prefix_successor(b"a/b/").unwrap().as_slice());
    }

    #[test]
    fn keys_are_printable_ascii() {
        assert!(check_key(b"prod/-/lease/a.b_c-d", "key").is_ok());
        for bad in [&b""[..], b"a b", b"a\x00b", "é".as_bytes(), &[b'a'; 513]] {
            assert!(check_key(bad, "key").is_err());
        }
    }

    #[test]
    fn timestamps_round_trip_at_a_millisecond() {
        for ms in [0, 1, 999, 1000, 1_700_000_123_456, -1_500] {
            assert_eq!(ts_to_ms(&ms_to_ts(ms)), ms);
        }
    }

    #[test]
    fn page_sizes() {
        assert_eq!(page_size(0).unwrap(), DEFAULT_PAGE);
        assert_eq!(page_size(7).unwrap(), 7);
        assert_eq!(page_size(100_000).unwrap(), MAX_PAGE);
        assert!(page_size(-1).is_err());
    }
}
