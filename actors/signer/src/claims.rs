//! The claims a caller asks `signer` to sign (ADR 0020 "The claims of a token").
//!
//! A token carries a fixed set of claims and a claim outside the set is not issued. The check is in
//! two parts: the shape here, which needs no config, and the facts against the config (the issuer,
//! the audience, the lifetime), which the service decides with the values this module hands it.
//! The payload that is signed is built from the claims that passed, never from the caller's bytes,
//! so what was checked is what is signed: a repeated member, an escape or a number written another
//! way cannot make the two differ.
//!
//! Every refusal names a field path of the closed list below and never a value.

use std::collections::BTreeSet;

use serde_json::{Map, Value};

/// The most bytes of claims a caller may send.
pub const CLAIMS_MAX: usize = 16 << 10;
/// The longest lifetime of any token (ADR 0020 "Lifetimes": the built-in maximum of one hour).
pub const HARD_CAP_SECS: i64 = 3600;
/// How far `iat` may be from the clock of `signer`, in seconds. A caller signs at once, so a larger
/// gap is a caller that tries to move the window of the lifetime.
pub const IAT_SKEW_SECS: i64 = 60;
/// The largest integer a JSON number may carry without loss (RFC 7493 section 2.2).
const SAFE_INT: i64 = (1 << 53) - 1;

/// The type of the token: the `typ` header of the JWS.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Typ {
    /// An ID token (OpenID Connect Core 1.0 section 2): `typ` is `JWT`.
    Id,
    /// A JWT access token (RFC 9068 section 2.1): `typ` is `at+jwt`.
    Access,
}

impl Typ {
    /// The value of the header, or `None` for a type `signer` does not issue.
    #[must_use]
    pub fn parse(typ: &str) -> Option<Self> {
        match typ {
            "JWT" => Some(Self::Id),
            "at+jwt" => Some(Self::Access),
            _ => None,
        }
    }

    /// The `typ` header.
    #[must_use]
    pub fn header(self) -> &'static str {
        match self {
            Self::Id => "JWT",
            Self::Access => "at+jwt",
        }
    }
}

/// A claim that does not fit: the path of the field, never its value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bad(pub &'static str);

/// The shape of one claim.
#[derive(Clone, Copy)]
enum Shape {
    /// A non-empty string without control characters, at most this many bytes.
    Text(usize),
    /// A whole number between 0 and 2^53 - 1.
    Time,
    /// A boolean.
    Flag,
    /// An array of authentication method references (RFC 8176): short non-empty strings.
    Methods,
    /// An array of grant names, `<scope>:<thing>:<role>` (ADR 0020 "Grant names and the vocabulary").
    Groups,
}

/// How a claim may appear in a token of a type.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Need {
    Required,
    Optional,
    Never,
}

/// One row of the table of ADR 0020: a claim, its shape, and its presence in each type.
struct Claim {
    name: &'static str,
    path: &'static str,
    shape: Shape,
    id: Need,
    access: Need,
}

use Need::{Never, Optional, Required};
use Shape::{Flag, Groups, Methods, Text, Time};

/// The table of ADR 0020 "The claims of a token". `cnf` is not here: the first working version issues
/// bearer tokens only (ADR 0020 "Binding"), so a token that asks for a confirmation key is refused as
/// a claim outside the set that can be issued.
const TABLE: &[Claim] = &[
    Claim {
        name: "iss",
        path: "claims.iss",
        shape: Text(512),
        id: Required,
        access: Required,
    },
    Claim {
        name: "sub",
        path: "claims.sub",
        shape: Text(512),
        id: Required,
        access: Required,
    },
    Claim {
        name: "aud",
        path: "claims.aud",
        shape: Text(512),
        id: Required,
        access: Required,
    },
    Claim {
        name: "exp",
        path: "claims.exp",
        shape: Time,
        id: Required,
        access: Required,
    },
    Claim {
        name: "iat",
        path: "claims.iat",
        shape: Time,
        id: Required,
        access: Required,
    },
    Claim {
        name: "jti",
        path: "claims.jti",
        shape: Text(128),
        id: Never,
        access: Required,
    },
    Claim {
        name: "client_id",
        path: "claims.client_id",
        shape: Text(512),
        id: Never,
        access: Required,
    },
    Claim {
        name: "nonce",
        path: "claims.nonce",
        shape: Text(512),
        id: Optional,
        access: Never,
    },
    Claim {
        name: "auth_time",
        path: "claims.auth_time",
        shape: Time,
        id: Optional,
        access: Optional,
    },
    Claim {
        name: "acr",
        path: "claims.acr",
        shape: Text(256),
        id: Optional,
        access: Optional,
    },
    Claim {
        name: "amr",
        path: "claims.amr",
        shape: Methods,
        id: Optional,
        access: Optional,
    },
    Claim {
        name: "sid",
        path: "claims.sid",
        shape: Text(128),
        id: Optional,
        access: Optional,
    },
    Claim {
        name: "groups",
        path: "claims.groups",
        shape: Groups,
        id: Optional,
        access: Optional,
    },
    Claim {
        name: "email",
        path: "claims.email",
        shape: Text(320),
        id: Optional,
        access: Never,
    },
    Claim {
        name: "email_verified",
        path: "claims.email_verified",
        shape: Flag,
        id: Optional,
        access: Never,
    },
    Claim {
        name: "name",
        path: "claims.name",
        shape: Text(512),
        id: Optional,
        access: Never,
    },
    Claim {
        name: "preferred_username",
        path: "claims.preferred_username",
        shape: Text(512),
        id: Optional,
        access: Never,
    },
];

/// Claims that passed the shape check.
#[derive(Debug)]
pub struct Shaped {
    /// The members, in a fixed order.
    members: Map<String, Value>,
    /// The type of the token.
    pub typ: Typ,
    /// `iss`.
    pub issuer: String,
    /// `aud`: exactly one client id (ADR 0017 "Audiences").
    pub audience: String,
    /// `client_id` of an access token.
    pub client_id: Option<String>,
    /// `iat` in seconds.
    pub iat: i64,
    /// `exp` in seconds.
    pub exp: i64,
}

impl Shaped {
    /// The payload of the JWS: the checked members as a JSON object (RFC 7519 section 7.1).
    #[must_use]
    pub fn payload(&self) -> Vec<u8> {
        serde_json::to_vec(&self.members).unwrap_or_default()
    }
}

/// Checks the shape of `claims_json` for a token of type `typ`.
///
/// # Errors
///
/// The path of the first claim that does not fit: a claim outside the set (`claims`), a missing or
/// forbidden one, or one of the wrong shape.
pub fn shape(typ: Typ, claims_json: &[u8]) -> Result<Shaped, Bad> {
    if claims_json.len() > CLAIMS_MAX {
        return Err(Bad("claims_json"));
    }
    let Ok(Value::Object(members)) = serde_json::from_slice::<Value>(claims_json) else {
        return Err(Bad("claims_json"));
    };
    // A claim outside the set is not issued. The name of the offender is the caller's string: the
    // path stays `claims` and never repeats it.
    if members.keys().any(|k| !TABLE.iter().any(|c| c.name == k)) {
        return Err(Bad("claims"));
    }
    for c in TABLE {
        let need = match typ {
            Typ::Id => c.id,
            Typ::Access => c.access,
        };
        match (members.get(c.name), need) {
            (None, Required) => return Err(Bad(c.path)),
            (Some(_), Never) => return Err(Bad(c.path)),
            (Some(v), _) if !fits(c.shape, v) => return Err(Bad(c.path)),
            _ => {}
        }
    }
    let text = |name: &str| members.get(name).and_then(Value::as_str).map(str::to_owned);
    let time = |name: &str| members.get(name).and_then(Value::as_i64);
    let (Some(issuer), Some(audience), Some(iat), Some(exp)) =
        (text("iss"), text("aud"), time("iat"), time("exp"))
    else {
        // Unreachable: the table made all four required and checked their shape.
        return Err(Bad("claims"));
    };
    Ok(Shaped {
        client_id: text("client_id"),
        members,
        typ,
        issuer,
        audience,
        iat,
        exp,
    })
}

fn fits(shape: Shape, v: &Value) -> bool {
    match shape {
        Shape::Text(max) => v.as_str().is_some_and(|s| text_ok(s, max)),
        Shape::Time => v.as_i64().is_some_and(|n| (0..=SAFE_INT).contains(&n)),
        Shape::Flag => v.is_boolean(),
        Shape::Methods => v.as_array().is_some_and(|a| {
            a.len() <= 16 && a.iter().all(|m| m.as_str().is_some_and(|s| text_ok(s, 64)))
        }),
        Shape::Groups => v.as_array().is_some_and(|a| {
            let mut seen = BTreeSet::new();
            a.len() <= 512
                && a.iter()
                    .all(|g| g.as_str().is_some_and(grant_name) && seen.insert(g.as_str()))
        }),
    }
}

fn text_ok(s: &str, max: usize) -> bool {
    !s.is_empty() && s.len() <= max && !s.chars().any(char::is_control)
}

/// A grant name is `<scope>:<thing>:<role>`, each segment a non-empty string of ASCII letters,
/// digits, `-` and `_` (ADR 0020 "Grant names and the vocabulary"). A wildcard is refused in a token.
fn grant_name(s: &str) -> bool {
    let mut parts = s.split(':');
    let segment = |p: Option<&str>| {
        p.is_some_and(|p| {
            !p.is_empty()
                && p.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
    };
    segment(parts.next())
        && segment(parts.next())
        && segment(parts.next())
        && parts.next().is_none()
}

/// Checks that `iss` is the issuer URL of the boundary (ADR 0017 "Issuers": `iss` is the issuer URL).
///
/// # Errors
///
/// `claims.iss` when it is not.
pub fn check_issuer(c: &Shaped, issuer: &str) -> Result<(), Bad> {
    if c.issuer == issuer {
        Ok(())
    } else {
        Err(Bad("claims.iss"))
    }
}

/// The lifetime cap in seconds: the earliest of the built-in maximum, the issuer's lifetime for the
/// type and the audience client's `ttl_cap` (ADR 0020 "Lifetimes"). A value of zero or less is no
/// value; the built-in maximum then stands.
#[must_use]
pub fn cap_secs(issuer_lifetime: Option<i64>, client_ttl_cap: Option<i64>) -> i64 {
    [Some(HARD_CAP_SECS), issuer_lifetime, client_ttl_cap]
        .into_iter()
        .flatten()
        .filter(|s| *s > 0)
        .min()
        .unwrap_or(HARD_CAP_SECS)
}

/// Checks `iat` and `exp` against the clock and the cap. `iat` must be now, give or take the skew,
/// so a caller cannot move the window; the token must not be over already; and `exp - iat` must not
/// pass the cap (RFC 7519 sections 4.1.4 and 4.1.6).
///
/// # Errors
///
/// `claims.iat` or `claims.exp`.
pub fn check_time(c: &Shaped, now: i64, cap: i64) -> Result<(), Bad> {
    if (c.iat - now).abs() > IAT_SKEW_SECS {
        return Err(Bad("claims.iat"));
    }
    if c.exp <= c.iat || c.exp <= now || c.exp - c.iat > cap {
        return Err(Bad("claims.exp"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn id(extra: Value) -> Vec<u8> {
        let mut m = json!({
            "iss": "https://sluis.dev.local.test", "sub": "p-1", "aud": "sluis-cli",
            "iat": 1000, "exp": 1600
        });
        if let (Some(m), Value::Object(e)) = (m.as_object_mut(), extra) {
            m.extend(e);
        }
        serde_json::to_vec(&m).unwrap()
    }

    fn access(extra: Value) -> Vec<u8> {
        let mut m = json!({
            "iss": "https://sluis.dev.local.test", "sub": "p-1", "aud": "example-app",
            "iat": 1000, "exp": 1600, "jti": "j-1", "client_id": "sluis-cli"
        });
        if let (Some(m), Value::Object(e)) = (m.as_object_mut(), extra) {
            m.extend(e);
        }
        serde_json::to_vec(&m).unwrap()
    }

    #[test]
    fn a_complete_token_of_each_type_passes() {
        let c = shape(
            Typ::Id,
            &id(
                json!({"nonce": "n", "auth_time": 990, "amr": ["pwd", "otp"],
            "groups": ["dev:app:admin"], "email": "a@example.com", "email_verified": true}),
            ),
        )
        .unwrap();
        assert_eq!(
            (c.audience.as_str(), c.iat, c.exp),
            ("sluis-cli", 1000, 1600)
        );
        let c = shape(
            Typ::Access,
            &access(json!({"sid": "s", "groups": ["all:x:operator"]})),
        )
        .unwrap();
        assert_eq!(c.client_id.as_deref(), Some("sluis-cli"));
    }

    #[test]
    fn the_payload_is_built_from_the_checked_members() {
        // A repeated member: the last one wins in the parse, and the payload holds one.
        let raw = br#"{"iss":"a","iss":"https://sluis.dev.local.test","sub":"p","aud":"c","iat":1,"exp":2,"nonce":"n"}"#;
        let c = shape(Typ::Id, raw).unwrap();
        let p: Value = serde_json::from_slice(&c.payload()).unwrap();
        assert_eq!(p["iss"], "https://sluis.dev.local.test");
        assert_eq!(p["nonce"], "n");
        assert_eq!(p.as_object().unwrap().len(), 6);
    }

    #[test]
    fn a_claim_outside_the_set_is_not_issued() {
        for extra in [
            json!({"scope": "x"}),
            json!({"cnf": {"jkt": "x"}}),
            json!({"azp": "x"}),
            json!({"act": {}}),
        ] {
            assert_eq!(
                shape(Typ::Id, &id(extra.clone())).unwrap_err(),
                Bad("claims"),
                "{extra}"
            );
        }
    }

    #[test]
    fn a_claim_that_the_type_does_not_carry_is_refused() {
        assert_eq!(
            shape(Typ::Id, &id(json!({"jti": "x"}))).unwrap_err(),
            Bad("claims.jti")
        );
        assert_eq!(
            shape(Typ::Id, &id(json!({"client_id": "x"}))).unwrap_err(),
            Bad("claims.client_id")
        );
        assert_eq!(
            shape(Typ::Access, &access(json!({"nonce": "x"}))).unwrap_err(),
            Bad("claims.nonce")
        );
        assert_eq!(
            shape(Typ::Access, &access(json!({"email": "a@example.com"}))).unwrap_err(),
            Bad("claims.email")
        );
        assert_eq!(
            shape(Typ::Access, &access(json!({"name": "A"}))).unwrap_err(),
            Bad("claims.name")
        );
    }

    #[test]
    fn a_missing_required_claim_is_refused() {
        for name in ["iss", "sub", "aud", "exp", "iat"] {
            let mut m: Value = serde_json::from_slice(&id(json!({}))).unwrap();
            m.as_object_mut().unwrap().remove(name);
            let e = shape(Typ::Id, &serde_json::to_vec(&m).unwrap()).unwrap_err();
            assert_eq!(e.0, format!("claims.{name}"));
        }
        for name in ["jti", "client_id"] {
            let mut m: Value = serde_json::from_slice(&access(json!({}))).unwrap();
            m.as_object_mut().unwrap().remove(name);
            assert_eq!(
                shape(Typ::Access, &serde_json::to_vec(&m).unwrap())
                    .unwrap_err()
                    .0,
                format!("claims.{name}")
            );
        }
    }

    #[test]
    fn a_claim_of_the_wrong_shape_is_refused() {
        let bad = [
            ("iss", json!(1)),
            ("aud", json!(["a", "b"])),
            ("aud", json!("")),
            ("sub", json!(null)),
            ("exp", json!(1600.5)),
            ("exp", json!("1600")),
            ("exp", json!(-1)),
            ("iat", json!(1.0e3)),
            ("exp", json!(9_007_199_254_740_993_i64)),
            ("auth_time", json!(true)),
            ("amr", json!("pwd")),
            ("amr", json!([1])),
            ("groups", json!("a:b:c")),
            ("groups", json!(["a:b"])),
            ("groups", json!(["a:b:c:d"])),
            ("groups", json!(["*:b:c"])),
            ("groups", json!(["a:b:c", "a:b:c"])),
            ("groups", json!([""])),
            ("sub", json!("a\nb")),
            ("email_verified", json!("true")),
        ];
        for (name, v) in bad {
            let e = shape(Typ::Id, &id(json!({ name: v.clone() }))).unwrap_err();
            assert_eq!(e.0, format!("claims.{name}"), "{name}: {v}");
        }
    }

    #[test]
    fn the_input_must_be_one_bounded_json_object() {
        for raw in [&b"[]"[..], b"1", b"null", b"{", b"", b"{} {}"] {
            assert_eq!(shape(Typ::Id, raw).unwrap_err(), Bad("claims_json"));
        }
        let big = vec![b' '; CLAIMS_MAX + 1];
        assert_eq!(shape(Typ::Id, &big).unwrap_err(), Bad("claims_json"));
    }

    #[test]
    fn the_cap_is_the_earliest_of_the_limits() {
        assert_eq!(cap_secs(None, None), 3600);
        assert_eq!(cap_secs(Some(600), None), 600);
        assert_eq!(cap_secs(Some(600), Some(300)), 300);
        assert_eq!(
            cap_secs(Some(7200), Some(10_000)),
            3600,
            "a limit above the maximum is not a limit"
        );
        assert_eq!(cap_secs(Some(0), Some(-5)), 3600, "zero is no value");
    }

    #[test]
    fn the_lifetime_stays_inside_the_cap_and_the_window_stays_at_now() {
        let c = |iat, exp| Shaped {
            iat,
            exp,
            ..shape(Typ::Id, &id(json!({}))).unwrap()
        };
        assert!(check_time(&c(1000, 1600), 1000, 600).is_ok());
        assert_eq!(
            check_time(&c(1000, 1601), 1000, 600),
            Err(Bad("claims.exp"))
        );
        assert_eq!(
            check_time(&c(1000, 1000), 1000, 600),
            Err(Bad("claims.exp"))
        );
        assert_eq!(
            check_time(&c(1000, 1500), 2000, 600),
            Err(Bad("claims.iat")),
            "iat far in the past"
        );
        assert_eq!(
            check_time(&c(2000, 2500), 1000, 600),
            Err(Bad("claims.iat")),
            "iat far ahead"
        );
        assert!(check_time(&c(1060, 1600), 1000, 600).is_ok());
        assert_eq!(
            check_time(&c(940, 990), 1000, 600),
            Err(Bad("claims.exp")),
            "already over"
        );
    }

    #[test]
    fn the_issuer_must_be_the_boundarys() {
        let c = shape(Typ::Id, &id(json!({}))).unwrap();
        assert!(check_issuer(&c, "https://sluis.dev.local.test").is_ok());
        assert_eq!(
            check_issuer(&c, "https://sluis.prod.local.test"),
            Err(Bad("claims.iss"))
        );
        assert_eq!(
            check_issuer(&c, "https://sluis.dev.local.test/"),
            Err(Bad("claims.iss"))
        );
    }

    #[test]
    fn only_two_types_are_issued() {
        assert_eq!(Typ::parse("JWT"), Some(Typ::Id));
        assert_eq!(Typ::parse("at+jwt"), Some(Typ::Access));
        for t in ["", "jwt", "AT+JWT", "JWS", "secevent+jwt", "at+JWT"] {
            assert_eq!(Typ::parse(t), None, "{t}");
        }
    }
}
