//! Headers of every response of `entry`, and the correlation id.
//!
//! The values are those of v1 (docs/reference/sluis/endpoints.md "Hardening"), which the sign-in
//! pages of session are built for. No actor behind `entry` can set one of them: `HttpReply`
//! relays only `Location`, `Set-Cookie`, `Content-Type`, `Cache-Control`, `Pragma` and
//! `WWW-Authenticate`. `entry` sets no cookie of its own.

use http::header::{
    CACHE_CONTROL, CONTENT_SECURITY_POLICY, HeaderName, HeaderValue, REFERRER_POLICY,
    STRICT_TRANSPORT_SECURITY, X_CONTENT_TYPE_OPTIONS, X_FRAME_OPTIONS,
};
use sluis_kit::HEADER_CORRELATION;

use crate::handler::Reply;

const CSP: &str = "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; \
frame-ancestors 'none'; base-uri 'none'; object-src 'none'; form-action 'self'";

/// The one inline script of the form_post page, byte for byte: the text between `<script>` and
/// `</script>`. The policy below allows exactly this text by its hash, and nothing else inline. The page
/// is built by `session`: its script element holds this text and no other script, or the browser refuses it. A Go
/// test of `session` reads the hash below from this file and compares it with the hash of the script the page serves.
/// A change of the text changes the hash: the test `the_form_post_policy_holds_the_hash_of_the_script` fails until both
/// agree.
#[cfg(test)]
const FORM_POST_SCRIPT: &str = "document.forms[0].submit();";

/// The policy of the one page that needs more: the form_post response of OpenID Connect Form Post
/// Response Mode 1.0, an HTML form that posts the answer to the client's `redirect_uri` and submits
/// itself. Everything is denied (`default-src 'none'`: the page loads no style, image or font, and the
/// form needs none) except the page's one inline script, which is allowed by its SHA-256 hash (CSP
/// Level 3, `script-src` hash-source), never by `'unsafe-inline'`.
///
/// `form-action` is not here: it is the web origin of the redirect URI of that response (REQ-AUTHN-079), which a
/// fixed string cannot hold. [`form_post_policy`] adds it, from the origin that `session` states for the response.
const CSP_FORM_POST: &str = "default-src 'none'; script-src 'sha256-8lDeP0UDwCO6/RhblgeH/ctdBzjVpJxrXizsnIk3cEQ='; \
frame-ancestors 'none'; base-uri 'none'";

/// The policy of one form_post page: [`CSP_FORM_POST`] and a `form-action` of the web origin the page posts to, so the
/// browser refuses to post the code to any other address. `None` when `origin` is not an origin: the scheme `http` or
/// `https`, a host (a name, an IPv4 address or a bracketed IPv6 address) and an optional port, and nothing else. A
/// character that could end the directive or start another (a space, `;`, `,`, a quote, a path) is refused, not escaped.
pub(crate) fn form_post_policy(origin: &str) -> Option<String> {
    let (scheme, rest) = origin.split_once("://")?;
    if !matches!(scheme, "http" | "https") {
        return None;
    }
    // The host, and what follows it: nothing, or ":" and a port.
    let (host_ok, port) = if let Some(v6) = rest.strip_prefix('[') {
        let (addr, after) = v6.split_once(']')?;
        let ok = addr.contains(':')
            && addr
                .bytes()
                .all(|c| c.is_ascii_hexdigit() || c == b':' || c == b'.');
        (
            ok,
            after
                .strip_prefix(':')
                .or_else(|| after.is_empty().then_some("")),
        )
    } else {
        let (host, port) = rest
            .split_once(':')
            .map_or((rest, None), |(h, p)| (h, Some(p)));
        let ok = !host.is_empty()
            && host.len() <= 253
            && host
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'.');
        (ok, port.or(Some("")))
    };
    let port = port?;
    let port_ok = port.is_empty() || (port.len() <= 5 && port.bytes().all(|c| c.is_ascii_digit()));
    // A trailing ":" with no port is not an origin either.
    let bare_colon = rest.ends_with(':');
    (host_ok && port_ok && !bare_colon).then(|| format!("{CSP_FORM_POST}; form-action {origin}"))
}

/// Whether a response is a form_post page: an HTML 200 of `/authorize` or `/callback`, which are the
/// routes that end in the client's `redirect_uri`.
fn is_form_post(resp: &Reply, route: &str) -> bool {
    matches!(route, "authorize" | "callback")
        && resp.status() == http::StatusCode::OK
        && resp
            .headers()
            .get(http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.to_ascii_lowercase().starts_with("text/html"))
}

/// The policy a reply asks for beyond the strict one (see [`crate::handler`] `finish`): none, the form_post page of a client's
/// redirect, or the registration page of a passkey.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Relax {
    None,
    /// The web origin that `session` names for a form_post page.
    FormPost(String),
    /// The policy of a page word of [`crate::pages`].
    Page(&'static str),
}

/// Puts the security headers and the correlation id on a response. A header the response already
/// carries is replaced, except `Cache-Control`, which is kept when an actor set one; without one a
/// response is `no-store`.
///
/// The page gets a policy of its own only with one asked for in `relax`, and only on the route that serves it: a form_post
/// page on an HTML 200 of `/authorize` or `/callback`, the registration page on `/callback`. Any other response, and a request
/// for a policy on another route, gets the strict policy, under which the page's script does not run and nothing is posted.
pub(crate) fn secure(mut resp: Reply, correlation: &str, route: &str, relax: &Relax) -> Reply {
    let relaxed = match relax {
        Relax::None => None,
        Relax::FormPost(origin) => is_form_post(&resp, route)
            .then_some(origin.as_str())
            .and_then(form_post_policy),
        Relax::Page(policy) => {
            (route == "callback" && crate::pages::is_html_ok(&resp)).then(|| (*policy).to_owned())
        }
    }
    .and_then(|p| HeaderValue::from_str(&p).ok());
    let h = resp.headers_mut();
    h.insert(
        CONTENT_SECURITY_POLICY,
        relaxed.unwrap_or(HeaderValue::from_static(CSP)),
    );
    h.insert(X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    h.insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    // The edge ends TLS and every host of sluis is https only (REQ-SEC-004: one year, with
    // includeSubDomains). `preload` is the operator's decision and is not sent.
    h.insert(
        STRICT_TRANSPORT_SECURITY,
        HeaderValue::from_static("max-age=31536000; includeSubDomains"),
    );
    if !h.contains_key(CACHE_CONTROL) {
        h.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
    // The id was made by `new_correlation_id` and is hex and hyphens.
    if let Ok(v) = HeaderValue::from_str(correlation) {
        h.insert(HeaderName::from_static(HEADER_CORRELATION), v);
    }
    resp
}

#[cfg(test)]
mod tests {
    use aws_lc_rs::digest::{SHA256, digest};
    use base64::Engine as _;

    use super::{CSP, CSP_FORM_POST, FORM_POST_SCRIPT, form_post_policy};

    /// The form-action directive is the origin of the response and nothing else: the policy is the fixed part, then the
    /// directive, and every other directive is the fixed part's.
    ///
    /// verifies: REQ-AUTHN-079
    #[test]
    fn the_form_post_policy_limits_form_action_to_the_origin_it_is_given() {
        for origin in [
            "https://app.example.test",
            "https://app.example.test:8443",
            "http://127.0.0.1:43210",
            "http://[::1]:9000",
            "https://[2001:db8::7]",
            "https://a-b.c.example.test:443",
        ] {
            let p = form_post_policy(origin).unwrap_or_else(|| panic!("{origin}"));
            assert_eq!(p, format!("{CSP_FORM_POST}; form-action {origin}"));
            let dirs: Vec<&str> = p.split(';').map(str::trim).collect();
            assert_eq!(
                dirs.iter().filter(|d| d.starts_with("form-action")).count(),
                1
            );
            assert!(!p.contains("'self'") && !p.contains("unsafe-inline"), "{p}");
        }
    }

    /// Whatever could end the directive, start another or widen the source is refused, not repaired.
    ///
    /// verifies: REQ-AUTHN-079
    #[test]
    fn the_form_post_policy_refuses_what_is_not_an_origin() {
        for bad in [
            "",
            "app.example.test",
            "https://",
            "https://app.example.test/",
            "https://app.example.test/cb",
            "https://app.example.test?x=1",
            "https://app.example.test#f",
            "https://user@app.example.test",
            "https://app.example.test:",
            "https://app.example.test:80a",
            "https://app.example.test:123456",
            "https://app.example.test; script-src *",
            "https://app.example.test, https://evil.example.test",
            "https://app.example.test https://evil.example.test",
            "https://app.example.test'",
            "https://*.example.test",
            "https://[::1",
            "https://[]",
            "https://[zz::1]",
            "http://[::1]x",
            "ftp://app.example.test",
            "javascript://app.example.test",
            "data:text/html,x",
            "'self'",
            "*",
            "https://app.example.test\r\nX: y",
            "https://ap\u{e9}.example.test",
        ] {
            assert_eq!(form_post_policy(bad), None, "{bad:?}");
        }
    }

    /// verifies: REQ-AUTHN-059
    #[test]
    fn the_form_post_policy_holds_the_hash_of_the_script() {
        let hash = base64::engine::general_purpose::STANDARD
            .encode(digest(&SHA256, FORM_POST_SCRIPT.as_bytes()).as_ref());
        let want = format!("script-src 'sha256-{hash}';");
        assert!(
            CSP_FORM_POST.contains(&want),
            "the script changed: put script-src 'sha256-{hash}' in CSP_FORM_POST"
        );
    }

    /// verifies: REQ-AUTHN-059
    #[test]
    fn the_form_post_policy_allows_nothing_inline() {
        assert!(!CSP_FORM_POST.contains("unsafe-inline"), "{CSP_FORM_POST}");
        assert!(!CSP_FORM_POST.contains("unsafe-eval"), "{CSP_FORM_POST}");
        assert!(
            CSP_FORM_POST.contains("default-src 'none'"),
            "{CSP_FORM_POST}"
        );
        // Only the policy of the other pages keeps inline style, and neither allows an inline script.
        let script = |p: &str| {
            p.split(';')
                .find(|d| d.trim_start().starts_with("script-src"))
                .map(str::to_owned)
        };
        assert_eq!(
            script(CSP),
            None,
            "the strict policy relies on default-src 'self'"
        );
    }
}
