//! The closed parameter lists of the routes, one per contract message (contracts.md "Surfaces":
//! "validates each request against closed parameter lists generated from these contracts and from
//! the standards"). A test reads the `.proto` files and fails when a list and its message differ,
//! so a field added to a contract cannot be forgotten here.

/// Which set of routes an instance serves (0028 "The audit front": the same executable, with the
/// route table of the audit contracts and an instance name of its own).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Front {
    /// The identity front: sign-in, token, exchange, discovery and the key set.
    Identity,
    /// The audit front. It routes nothing until the audit contracts exist.
    Audit,
}

/// `grant_type` of RFC 8693 section 2.1.
pub(crate) const GRANT_EXCHANGE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";

/// `AuthorizeRequest`: RFC 6749 section 4.1.1, RFC 7636 section 4.3, OpenID Connect Core 3.1.2.1.
pub(crate) const AUTHORIZE: &[&str] = &[
    "response_type",
    "client_id",
    "redirect_uri",
    "scope",
    "state",
    "nonce",
    "code_challenge",
    "code_challenge_method",
    "response_mode",
    "prompt",
    "max_age",
    "acr_values",
];

/// `CallbackRequest` without `cookie`, which is a header, not a parameter.
pub(crate) const CALLBACK: &[&str] = &["code", "state", "error", "error_description", "iss"];

/// `TokenRequest` for `authorization_code`: RFC 6749 section 4.1.3 and RFC 7636 section 4.5.
/// `authorization` is a header.
pub(crate) const TOKEN_CODE: &[&str] = &[
    "grant_type",
    "code",
    "redirect_uri",
    "code_verifier",
    "client_id",
    "client_secret",
];

/// `TokenRequest` for `refresh_token`: RFC 6749 section 6.
pub(crate) const TOKEN_REFRESH: &[&str] = &[
    "grant_type",
    "refresh_token",
    "scope",
    "client_id",
    "client_secret",
];

/// `TokenExchangeRequest`: RFC 8693 section 2.1.
pub(crate) const TOKEN_EXCHANGE: &[&str] = &[
    "grant_type",
    "subject_token",
    "subject_token_type",
    "audience",
    "resource",
    "scope",
    "requested_token_type",
    "client_id",
    "actor_token",
    "actor_token_type",
];

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    const SESSION: &str = include_str!("../../../proto/sluis/session/v2alpha1/session.proto");
    const EXCHANGE: &str = include_str!("../../../proto/sluis/exchange/v2alpha1/exchange.proto");

    /// The field names of `message <name> { ... }`: the identifier before ` = <number>;`.
    fn fields(proto: &str, name: &str) -> BTreeSet<String> {
        let start = proto
            .find(&format!("message {name} {{"))
            .unwrap_or_else(|| panic!("no message {name}"));
        let body = &proto[start..];
        let body = &body[..body.find("\n}").expect("an unclosed message")];
        body.lines()
            .filter_map(|l| {
                let l = l.split("//").next()?.trim();
                let (decl, _) = l.split_once(" = ")?;
                decl.split_whitespace().last().map(str::to_owned)
            })
            .collect()
    }

    fn set(list: &[&str], extra: &[&str]) -> BTreeSet<String> {
        list.iter().chain(extra).map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn the_lists_are_the_fields_of_the_contracts() {
        assert_eq!(fields(SESSION, "AuthorizeRequest"), set(AUTHORIZE, &[]));
        // `cookie` and `authorization` are headers; every other field is a parameter.
        assert_eq!(
            fields(SESSION, "CallbackRequest"),
            set(CALLBACK, &["cookie"])
        );
        let token: Vec<&str> = TOKEN_CODE.iter().chain(TOKEN_REFRESH).copied().collect();
        assert_eq!(
            fields(SESSION, "TokenRequest"),
            set(&token, &["authorization"])
        );
        assert_eq!(
            fields(EXCHANGE, "TokenExchangeRequest"),
            set(TOKEN_EXCHANGE, &[])
        );
    }

    #[test]
    fn the_field_reader_reads_a_message() {
        let f = fields(SESSION, "CallbackRequest");
        assert!(
            f.contains("cookie") && f.contains("iss") && f.len() == 6,
            "{f:?}"
        );
    }
}
