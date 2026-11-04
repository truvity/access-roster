//! Address encoding (store-api.md "Address encoding") and the key a driver sees.
//!
//! The wire carries a kind segment, a tenant (empty for none) and an id; the boundary is the
//! store's own. The key at a driver is `<boundary>/<tenant | ->/<kind>/<id>` in ASCII.

const PART_MAX: usize = 128;
const ADDRESS_MAX: usize = 300;

/// A part is 1 to 128 characters of lower-case letters, digits, `-`, `_` and `.`, and never `.`
/// or `..`.
#[must_use]
pub fn valid_part(p: &str) -> bool {
    !p.is_empty()
        && p.len() <= PART_MAX
        && p != "."
        && p != ".."
        && p.bytes()
            .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.'))
}

/// The index of the first invalid part of an id, or None when the id is valid: one or more parts
/// separated by `/`.
#[must_use]
pub fn invalid_id_part(id: &str) -> Option<usize> {
    id.split('/').position(|p| !valid_part(p))
}

/// The key at the driver. The caller has validated every part; `tenant` is empty for none.
#[must_use]
pub fn key(boundary: &str, tenant: &str, segment: &str, id: &str) -> Vec<u8> {
    let t = if tenant.is_empty() { "-" } else { tenant };
    format!("{boundary}/{t}/{segment}/{id}").into_bytes()
}

/// The key prefix that lists the items of a kind in a tenant, ending in `/` (and in
/// `<owner>/` for a self-scoped listing).
#[must_use]
pub fn prefix(boundary: &str, tenant: &str, segment: &str, id_prefix: &str) -> Vec<u8> {
    let mut k = key(boundary, tenant, segment, "");
    k.extend_from_slice(id_prefix.as_bytes());
    k
}

/// Whether the whole address is within 300 bytes.
#[must_use]
pub fn within_limit(boundary: &str, tenant: &str, segment: &str, id: &str) -> bool {
    key(boundary, tenant, segment, id).len() <= ADDRESS_MAX
}

/// Checks a whole address as text, `<boundary>/<tenant | ->/<kind>/<id>`: the vectors of
/// store-api.md. Returns the path of the part at fault.
///
/// # Errors
///
/// The name of the part at fault: `address`, `boundary`, `tenant`, `kind` or `id`.
pub fn validate_text(address: &str) -> Result<(), &'static str> {
    if address.len() > ADDRESS_MAX {
        return Err("address");
    }
    let mut it = address.splitn(4, '/');
    for name in ["boundary", "tenant", "kind"] {
        if !it.next().is_some_and(valid_part) {
            return Err(name);
        }
    }
    match it.next() {
        Some(id) if invalid_id_part(id).is_none() => Ok(()),
        _ => Err("id"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_vectors_of_store_api() {
        for ok in [
            "prod/acme/session-chain/q7x2m5nt4kz3c6vdp9ba8hwrfe",
            "prod/acme/data-key-wrap/data/1/board-a",
            "prod/-/lease/adapter-github/sync",
        ] {
            assert_eq!(validate_text(ok), Ok(()), "{ok}");
        }
        assert_eq!(validate_text("prod/Acme/person/x"), Err("tenant"));
        assert_eq!(validate_text("prod/acme/person/../x"), Err("id"));
        assert_eq!(validate_text("prod/acme/person//x"), Err("id"));
        assert_eq!(validate_text("prod/acme/person/x/"), Err("id"));
        assert_eq!(validate_text("prod/acme/person/a b"), Err("id"));
        assert_eq!(validate_text("prod/acme/person"), Err("id"));
        let long = "a".repeat(129);
        assert_eq!(
            validate_text(&format!("prod/acme/person/{long}")),
            Err("id")
        );
        // 301 bytes, each part valid
        let id = format!("{}/{}", "a".repeat(128), "b".repeat(128));
        assert_eq!(validate_text(&format!("prod/acme/person/{id}")), Ok(()));
        assert_eq!(
            validate_text(&format!("prod/acme/person/{id}/{}", "c".repeat(40))),
            Err("address")
        );
    }

    #[test]
    fn the_key_carries_a_dash_for_no_tenant() {
        assert_eq!(key("dev", "", "lease", "a/b"), b"dev/-/lease/a/b");
        assert_eq!(key("dev", "acme", "person", "x"), b"dev/acme/person/x");
        assert_eq!(prefix("dev", "", "lease", "a/"), b"dev/-/lease/a/");
        assert_eq!(prefix("dev", "acme", "person", ""), b"dev/acme/person/");
    }

    #[test]
    fn the_whole_address_is_bounded() {
        let id = format!("{}/{}", "a".repeat(128), "b".repeat(128));
        assert!(within_limit("dev", "acme", "person", &id));
        assert!(!within_limit(
            "dev",
            "acme",
            "person",
            &format!("{id}/{}", "c".repeat(40))
        ));
    }
}
