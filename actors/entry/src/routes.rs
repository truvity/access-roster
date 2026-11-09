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
    /// The audit front: the reader's Search.
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
    // Defined by OpenID Connect Core sections 6 and 7.2.1 and not served: `session` answers each with its error
    // (3.1.2.6), once it knows the client and the redirect_uri, so the answer can go to the client.
    "request",
    "request_uri",
    "registration",
    // A hint about who the person is (OpenID Connect Core 3.1.2.1): `session` holds the sign-in to its subject.
    "id_token_hint",
];

/// The names that `/authorize` refuses. Every other name that is not on [`AUTHORIZE`] is ignored and counted, as RFC 6749
/// section 3.1 asks ("The authorization server MUST ignore unrecognized request parameters"): `display`, `ui_locales`,
/// `claims_locales`, `login_hint` and `claims` (`claims_parameter_supported` is false in discovery) among them. A name
/// is refused here when it narrows or binds what is issued, so that ignoring it would hand the client something other
/// than what it asked for and it might not notice. The names of the IANA OAuth Parameters registry (read 2026-11-07)
/// that are used in an authorization request and are of this kind:
///
/// - `resource` (RFC 8707) and `audience` (what Keycloak and Auth0 call it) set the audience of a token (REQ-ISO-029);
/// - `authorization_details` (RFC 9396) asks for fine-grained permissions in the token;
/// - `dpop_jkt` (RFC 9449 section 10) binds the code, and so the token, to a key: ignoring it gives a bearer token.
///
/// The rest of the registry is a hint (`display`, `login_hint`, ...), a request for something `session` answers itself
/// (`request`, `request_uri`, `registration`, `acr_values`, `max_age`), a claim of a request object, or belongs to a
/// protocol sluis does not speak (OpenID for Verifiable Presentations, OpenID Federation); the OpenID Foundation's
/// OIDCC modules send none of the four names above. `vtr` (RFC 8485) is a request for an assurance level like
/// `acr_values`, and the ID token shows whether it was met. POST and GET share this list.
pub(crate) const AUTHORIZE_REFUSED: &[&str] =
    &["resource", "audience", "authorization_details", "dpop_jkt"];

/// The names `/callback` recognises: the fields of `CallbackRequest` without `cookie`, which is a
/// header, and `error_uri` (RFC 6749 section 4.1.2.1), which no contract field carries. They keep
/// their checks (a repeat is refused). `/callback` is the route where the upstream answers sluis
/// as a client, and a client MUST ignore any other response parameter (RFC 6749 section 4.1.2):
/// `session_state` of Keycloak, and what Entra and Google add, are dropped. Every other route is
/// a request to sluis and keeps its closed list.
pub(crate) const CALLBACK: &[&str] = &[
    "code",
    "state",
    "error",
    "error_description",
    "error_uri",
    "iss",
];

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

/// `TokenExchangeRequest`: RFC 8693 section 2.1, and `client_secret` of RFC 6749 section 2.3.1.
/// `authorization` is a header.
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
    "client_secret",
];

/// `UserInfoRequest`: the UserInfo endpoint takes no parameter. The access token is the bearer token of the `Authorization`
/// header (RFC 6750 section 2.1), the only field of the contract and a header; it is never in the query (section 2.3 allows it
/// and says it SHOULD NOT be used, because a URL ends up in logs), and the route takes no body (section 2.2).
pub(crate) const USERINFO: &[&str] = &[];

/// `RevokeRequest`: RFC 7009 section 2.1 and `client_secret` of RFC 6749 section 2.3.1. `authorization` is a header.
pub(crate) const REVOKE: &[&str] = &["token", "token_type_hint", "client_id", "client_secret"];

/// `PasskeyAddRequest` has no field: the client whose admission a registration is decided on is the one `SignInMethods` names
/// (owner decision 10 of 2026-11-08), so the route takes nothing from the request, and `client_id`, like any name, is refused as
/// unknown. The route is a GET: the person is sent to the upstream again.
pub(crate) const PASSKEYS_ADD: &[&str] = &[];

/// `PasskeyRegisterRequest` without `cookie`, which is a header: the browser's answer to the registration page. The route reads
/// no `Authorization` and no other credential (REQ-REG-051).
pub(crate) const PASSKEYS_REGISTER: &[&str] = &["response"];

/// The longest `response` of `/passkeys/register`, in bytes after decoding: the answer of a registration page is the JSON of a
/// credential, and the attestation statement of a TPM or a security key carries a certificate chain, which can pass the
/// [`crate::params`] bound of one value. It is `session`'s `maxPasskeyResponse` (a test reads that file), and it fits the form
/// bound of 32 KiB with room for the percent-encoding of the JSON's punctuation. Every other value keeps its bound.
pub(crate) const PASSKEY_RESPONSE_MAX: usize = 24 * 1024;

/// `SearchRequest` of the reader (0028 "The audit front"): the body of the call, by the proto names.
pub(crate) const SEARCH: &[&str] = &[
    "tenants",
    "project",
    "q",
    "action",
    "status_code",
    "status_id",
    "actor_uid",
    "trace_id",
    "record_id",
    "from_ms",
    "to_ms",
    "page_size",
    "page_token",
];

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    const SESSION: &str = include_str!("../../../proto/sluis/session/v2alpha1/session.proto");
    const EXCHANGE: &str = include_str!("../../../proto/sluis/exchange/v2alpha1/exchange.proto");
    const READER: &str = include_str!("../../../proto/sluis/reader/v2alpha1/reader.proto");

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
        // `error_uri` is recognised and dropped: no contract field carries it.
        assert_eq!(
            &fields(SESSION, "CallbackRequest") | &set(&["error_uri"], &[]),
            set(CALLBACK, &["cookie"])
        );
        let token: Vec<&str> = TOKEN_CODE.iter().chain(TOKEN_REFRESH).copied().collect();
        assert_eq!(
            fields(SESSION, "TokenRequest"),
            set(&token, &["authorization"])
        );
        assert_eq!(
            fields(EXCHANGE, "TokenExchangeRequest"),
            set(TOKEN_EXCHANGE, &["authorization"])
        );
        assert_eq!(
            fields(SESSION, "UserInfoRequest"),
            set(USERINFO, &["authorization"])
        );
        assert_eq!(
            fields(SESSION, "RevokeRequest"),
            set(REVOKE, &["authorization"])
        );
        assert_eq!(fields(SESSION, "PasskeyAddRequest"), set(PASSKEYS_ADD, &[]));
        assert_eq!(
            fields(SESSION, "PasskeyRegisterRequest"),
            set(PASSKEYS_REGISTER, &["cookie"])
        );
        assert_eq!(fields(READER, "SearchRequest"), set(SEARCH, &[]));
    }

    /// The bound of the answer is the bound `session` applies to it: a value entry lets through is not refused for its size by
    /// `session`, and one it refuses is not one `session` would take.
    #[test]
    fn the_bound_of_the_registration_answer_is_the_one_session_applies() {
        const PASSKEY: &str = include_str!("../../session/internal/sessiond/passkey.go");
        let line = PASSKEY
            .lines()
            .find(|l| l.trim_start().starts_with("maxPasskeyResponse"))
            .expect("session's bound");
        let kib: usize = line
            .split('=')
            .nth(1)
            .and_then(|r| r.split("//").next())
            .and_then(|r| r.split('*').next())
            .and_then(|n| n.trim().parse().ok())
            .expect("a number of KiB");
        assert_eq!(PASSKEY_RESPONSE_MAX, kib * 1024);
        const { assert!(PASSKEY_RESPONSE_MAX < crate::params::FORM_MAX) };
    }

    #[test]
    fn a_refused_name_is_not_a_field_of_the_authorize_contract() {
        for n in AUTHORIZE_REFUSED {
            assert!(!AUTHORIZE.contains(n), "{n} is read and refused");
        }
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
