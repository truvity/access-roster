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
/// is built by `session` (it builds none today and refuses `response_mode=form_post`); when it does, its
/// script element holds this text and no other script, or the browser refuses it. A change of the text
/// changes the hash: the test `the_form_post_policy_holds_the_hash_of_the_script` fails until both agree.
#[cfg(test)]
const FORM_POST_SCRIPT: &str = "document.forms[0].submit();";

/// The policy of the one page that needs more: the form_post response of OpenID Connect Form Post
/// Response Mode 1.0, an HTML form that posts the answer to the client's `redirect_uri` and submits
/// itself. Everything is denied (`default-src 'none'`: the page loads no style, image or font, and the
/// form needs none) except the page's one inline script, which is allowed by its SHA-256 hash (CSP
/// Level 3, `script-src` hash-source), never by `'unsafe-inline'`.
///
/// `form-action` is not set yet: it must be the web origin of the redirect URI of that response
/// (REQ-AUTHN-079), which a fixed string cannot hold. The page that ships it sets it per response; until
/// then no page exists to carry it.
const CSP_FORM_POST: &str = "default-src 'none'; script-src 'sha256-8lDeP0UDwCO6/RhblgeH/ctdBzjVpJxrXizsnIk3cEQ='; \
frame-ancestors 'none'; base-uri 'none'";

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

/// Puts the security headers and the correlation id on a response. A header the response already
/// carries is replaced, except `Cache-Control`, which is kept when an actor set one; without one a
/// response is `no-store`.
pub(crate) fn secure(mut resp: Reply, correlation: &str, route: &str) -> Reply {
    let csp = if is_form_post(&resp, route) {
        CSP_FORM_POST
    } else {
        CSP
    };
    let h = resp.headers_mut();
    h.insert(CONTENT_SECURITY_POLICY, HeaderValue::from_static(csp));
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

    use super::{CSP, CSP_FORM_POST, FORM_POST_SCRIPT};

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
