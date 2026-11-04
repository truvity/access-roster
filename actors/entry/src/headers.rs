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

/// Puts the security headers and the correlation id on a response. A header the response already
/// carries is replaced, except `Cache-Control`, which is kept when an actor set one; without one a
/// response is `no-store`.
pub(crate) fn secure(mut resp: Reply, correlation: &str) -> Reply {
    let h = resp.headers_mut();
    h.insert(CONTENT_SECURITY_POLICY, HeaderValue::from_static(CSP));
    h.insert(X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    h.insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    // The edge ends TLS and every host of sluis is https only; the header is one-way, so it is
    // sent without includeSubDomains and without preload.
    h.insert(
        STRICT_TRANSPORT_SECURITY,
        HeaderValue::from_static("max-age=31536000"),
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
