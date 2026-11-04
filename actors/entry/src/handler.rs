//! The routes. Each handler parses against the closed list of its contract, calls the actor that
//! owns the step through the generated client, and turns the typed answer into HTTP. It decides
//! nothing about sign-in, tokens or sessions.

use std::time::Duration;

use bytes::Bytes;
use connectrpc::client::CallOptions;
use http::header::{
    ALLOW, AUTHORIZATION, CACHE_CONTROL, CONTENT_LENGTH, CONTENT_TYPE, COOKIE, HeaderName,
    HeaderValue, LOCATION, PRAGMA, SET_COOKIE, WWW_AUTHENTICATE,
};
use http::{HeaderMap, Method, Response, StatusCode};
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::{Body, Incoming};
use sluis_kit::{Client, correlation, dial};
use sluis_proto::sluis::exchange::v2alpha1::{ExchangeServiceClient, TokenExchangeRequest};
use sluis_proto::sluis::session::v2alpha1::{
    AuthorizeRequest, CallbackRequest, SessionServiceClient, TokenRequest,
};
use sluis_proto::sluis::r#type::v2alpha1::HttpReply;

use crate::Sockets;
use crate::audit::{Auditor, Request};
use crate::discovery::Source;
use crate::params::{Bad, FORM_MAX, Params, QUERY_MAX};
use crate::refuse::{self, Refuse};
use crate::routes::{self, Front};

/// The whole request, from the first byte read to the last written.
const REQUEST: Duration = Duration::from_secs(30);
/// The deadline of a call to session or exchange: a little less, so the actor answers first.
const CALL: Duration = Duration::from_secs(25);
/// The largest `HttpReply` body entry will relay.
const REPLY_MAX: usize = 1 << 20;
/// The name of the sign-in cookie whose value goes to session in `CallbackRequest.cookie`.
/// `CallbackRequest` says "the sluis sign-in cookie" and no record names it: session sets it
/// through `Set-Cookie` of its reply, so session must use this name (a `__Host-` cookie).
const SIGNIN_COOKIE: &str = "__Host-sluis_signin";
/// The longest `Authorization` or sign-in cookie value.
const HEADER_VALUE_MAX: usize = 4096;

/// Headers of an `HttpReply` that `entry` relays (`type.proto`); any other is a refused reply.
const RELAYED: [HeaderName; 6] = [
    LOCATION,
    SET_COOKIE,
    CONTENT_TYPE,
    CACHE_CONTROL,
    PRAGMA,
    WWW_AUTHENTICATE,
];

pub(crate) type Reply = Response<Full<Bytes>>;

pub(crate) struct State {
    front: Front,
    session: SessionServiceClient<sluis_kit::Transport>,
    exchange: ExchangeServiceClient<sluis_kit::Transport>,
    docs: Source,
    audit: Auditor,
}

impl State {
    pub(crate) fn new(front: Front, s: &Sockets, audit: Auditor) -> Self {
        let session: Client = dial(&s.session);
        let exchange: Client = dial(&s.exchange);
        Self {
            front,
            session: SessionServiceClient::new(session.transport(), session.config()),
            exchange: ExchangeServiceClient::new(exchange.transport(), exchange.config()),
            docs: Source::new(&s.store),
            audit,
        }
    }
}

/// What a handler learned that the audit record carries.
#[derive(Default)]
struct Trace {
    route: &'static str,
    grant: &'static str,
}

/// An answer, relayed or made here.
enum Done {
    Relay(HttpReply),
    Json {
        body: Bytes,
        /// `Cache-Control` of a public document.
        public: bool,
    },
}

/// Handles one request: the correlation id, the route, the audit record, the security headers.
pub(crate) async fn handle(state: &State, req: http::Request<Incoming>) -> Reply {
    // contracts.md "Every call": entry makes the id and a client cannot choose it.
    let id = crate::ids::new_correlation_id();
    let method = req.method().clone();
    let reply = correlation::scope(Some(id.clone()), async {
        let mut trace = Trace::default();
        let outcome = tokio::time::timeout(REQUEST, route(state, req, &mut trace))
            .await
            .unwrap_or(Err(Refuse::new(504, "request_timeout")));
        let (reply, status, reason) = match outcome.and_then(finish) {
            Ok(r) => {
                let s = r.status().as_u16();
                (r, s, "")
            }
            Err(r) => (refused(r), refuse::status_of(r.status), r.reason),
        };
        let route = if trace.route.is_empty() {
            "unrouted"
        } else {
            trace.route
        };
        state
            .audit
            .request(Request {
                route,
                method: &method,
                status,
                reason,
                grant: trace.grant,
                correlation: &id,
            })
            .await;
        reply
    })
    .await;
    crate::headers::secure(reply, &id)
}

fn refused(r: Refuse) -> Reply {
    let status = refuse::status_of(r.status);
    let mut resp = Response::new(Full::new(Bytes::from_static(
        refuse::body(status).as_bytes(),
    )));
    *resp.status_mut() = StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let h = resp.headers_mut();
    h.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/problem+json"),
    );
    if let Some(a) = r.allow {
        h.insert(ALLOW, HeaderValue::from_static(a));
    }
    if status == 429 {
        h.insert(http::header::RETRY_AFTER, HeaderValue::from_static("5"));
    }
    resp
}

/// Builds the HTTP answer of a finished call.
fn finish(done: Done) -> Result<Reply, Refuse> {
    match done {
        Done::Json { body, public } => {
            let mut resp = Response::new(Full::new(body));
            let h = resp.headers_mut();
            h.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
            if public {
                // The same policy as v1 (docs/reference/sluis/endpoints.md "Hardening"): five
                // minutes, so a removed key leaves every cache that honours the header.
                h.insert(
                    CACHE_CONTROL,
                    HeaderValue::from_static("public, max-age=300"),
                );
                // Public read-only documents: a browser verifier may fetch them (CORS, no credentials).
                h.insert(
                    http::header::ACCESS_CONTROL_ALLOW_ORIGIN,
                    HeaderValue::from_static("*"),
                );
            }
            Ok(resp)
        }
        Done::Relay(r) => relay(r),
    }
}

/// An `HttpReply` as HTTP. A reply entry cannot relay exactly is a server error, never a repair:
/// a status outside 200 to 599, a header off the list or with an unusable value, a body over 1 MiB.
fn relay(r: HttpReply) -> Result<Reply, Refuse> {
    let bad = Refuse::new(500, "reply");
    let status = u16::try_from(r.status)
        .ok()
        .filter(|s| (200..=599).contains(s))
        .and_then(|s| StatusCode::from_u16(s).ok())
        .ok_or(bad)?;
    if r.body.len() > REPLY_MAX {
        return Err(bad);
    }
    let mut resp = Response::new(Full::new(Bytes::from(r.body)));
    *resp.status_mut() = status;
    for h in &r.headers {
        let name =
            HeaderName::from_bytes(h.name.to_ascii_lowercase().as_bytes()).map_err(|_| bad)?;
        if !RELAYED.contains(&name) {
            return Err(bad);
        }
        let value = HeaderValue::from_bytes(h.value.as_bytes()).map_err(|_| bad)?;
        if name == SET_COOKIE {
            resp.headers_mut().append(name, value);
        } else if resp.headers_mut().insert(name, value).is_some() {
            return Err(bad);
        }
    }
    Ok(resp)
}

fn bad(b: Bad) -> Refuse {
    Refuse::new(400, b.reason())
}

fn opts() -> CallOptions {
    CallOptions::default().with_timeout(CALL)
}

fn rpc(e: &connectrpc::ConnectError) -> Refuse {
    // The reason of the Refusal detail would be a value from another actor's list; the audit
    // record keeps the code only, which is enough to find the actor's own record by correlation id.
    Refuse::rpc(e.code)
}

/// The methods a route serves, and `Allow` for the 405.
fn method_ok(m: &Method, allowed: &[Method], allow: &'static str) -> Result<(), Refuse> {
    if allowed.contains(m) {
        Ok(())
    } else {
        Err(Refuse::method(allow))
    }
}

/// A request with a body where the route takes none.
fn no_body(body: &Incoming) -> Result<(), Refuse> {
    if body.is_end_stream() {
        Ok(())
    } else {
        Err(Refuse::new(400, "body"))
    }
}

async fn route(
    state: &State,
    req: http::Request<Incoming>,
    trace: &mut Trace,
) -> Result<Done, Refuse> {
    let (parts, body) = req.into_parts();
    let query = parts.uri.query().unwrap_or("");
    match (state.front, parts.uri.path()) {
        (Front::Identity, "/authorize") => {
            trace.route = "authorize";
            method_ok(&parts.method, &[Method::GET], "GET")?;
            no_body(&body)?;
            let p = Params::parse(query, QUERY_MAX)
                .and_then(|p| p.only(routes::AUTHORIZE))
                .map_err(bad)?;
            let r = AuthorizeRequest {
                response_type: p.get("response_type"),
                client_id: p.get("client_id"),
                redirect_uri: p.get("redirect_uri"),
                scope: p.get("scope"),
                state: p.get("state"),
                nonce: p.get("nonce"),
                code_challenge: p.get("code_challenge"),
                code_challenge_method: p.get("code_challenge_method"),
                response_mode: p.get("response_mode"),
                prompt: p.get("prompt"),
                max_age: p.get("max_age"),
                acr_values: p.get("acr_values"),
                ..AuthorizeRequest::default()
            };
            let reply = state
                .session
                .authorize_with_options(r, opts())
                .await
                .map_err(|e| rpc(&e))?;
            Ok(Done::Relay(reply.into_owned()))
        }
        (Front::Identity, "/callback") => {
            trace.route = "callback";
            method_ok(&parts.method, &[Method::GET], "GET")?;
            no_body(&body)?;
            let p = Params::parse(query, QUERY_MAX)
                .and_then(|p| p.only(routes::CALLBACK))
                .map_err(bad)?;
            let r = CallbackRequest {
                code: p.get("code"),
                state: p.get("state"),
                error: p.get("error"),
                error_description: p.get("error_description"),
                iss: p.get("iss"),
                cookie: signin_cookie(&parts.headers)?,
                ..CallbackRequest::default()
            };
            let reply = state
                .session
                .callback_with_options(r, opts())
                .await
                .map_err(|e| rpc(&e))?;
            Ok(Done::Relay(reply.into_owned()))
        }
        (Front::Identity, "/token") => {
            trace.route = "token";
            method_ok(&parts.method, &[Method::POST], "POST")?;
            token(state, &parts.headers, query, body, trace).await
        }
        (Front::Identity, "/.well-known/openid-configuration") => {
            trace.route = "discovery";
            public_document(state, &parts.method, query, &body, false).await
        }
        (Front::Identity, "/jwks") => {
            trace.route = "jwks";
            public_document(state, &parts.method, query, &body, true).await
        }
        // The audit front's routes arrive with the reader's contract; until then it routes nothing.
        // planned: the audit contracts of 0028 "The audit front"
        _ => Err(Refuse::new(404, "route")),
    }
}

async fn public_document(
    state: &State,
    method: &Method,
    query: &str,
    body: &Incoming,
    jwks: bool,
) -> Result<Done, Refuse> {
    method_ok(method, &[Method::GET, Method::HEAD], "GET, HEAD")?;
    no_body(body)?;
    // The closed list is empty: these documents take no parameter.
    Params::parse(query, QUERY_MAX)
        .and_then(|p| p.only(&[]))
        .map_err(bad)?;
    let docs = state.docs.get().await?;
    Ok(Done::Json {
        body: if jwks { docs.jwks } else { docs.discovery },
        public: true,
    })
}

/// The value of the sluis sign-in cookie, if the browser sent it. Other cookies are not ours.
fn signin_cookie(h: &HeaderMap) -> Result<String, Refuse> {
    let mut found: Option<String> = None;
    for v in h.get_all(COOKIE) {
        let v = v.to_str().map_err(|_| Refuse::new(400, "cookie"))?;
        for pair in v.split(';') {
            let Some((n, val)) = pair.trim().split_once('=') else {
                continue;
            };
            if n != SIGNIN_COOKIE {
                continue;
            }
            let ok = val.len() <= HEADER_VALUE_MAX && val.bytes().all(|b| b.is_ascii_graphic());
            if !ok || found.replace(val.to_owned()).is_some() {
                return Err(Refuse::new(400, "cookie"));
            }
        }
    }
    Ok(found.unwrap_or_default())
}

/// `application/x-www-form-urlencoded`, optionally with `charset=utf-8` (RFC 6749 section 3.2).
fn is_form(h: &HeaderMap) -> bool {
    let mut it = h.get_all(CONTENT_TYPE).iter();
    let (Some(v), None) = (it.next(), it.next()) else {
        return false;
    };
    let Ok(v) = v.to_str() else { return false };
    let v = v.to_ascii_lowercase();
    let mut parts = v.split(';').map(str::trim);
    parts.next() == Some("application/x-www-form-urlencoded") && parts.all(|p| p == "charset=utf-8")
}

/// The `Authorization` header, which RFC 6749 section 2.3.1 uses for `client_secret_basic`.
fn authorization(h: &HeaderMap) -> Result<String, Refuse> {
    let mut it = h.get_all(AUTHORIZATION).iter();
    let Some(v) = it.next() else {
        return Ok(String::new());
    };
    let v = v
        .to_str()
        .ok()
        .filter(|v| v.len() <= HEADER_VALUE_MAX && it.next().is_none());
    v.map(str::to_owned)
        .ok_or(Refuse::new(400, "authorization"))
}

async fn token(
    state: &State,
    headers: &HeaderMap,
    query: &str,
    body: Incoming,
    trace: &mut Trace,
) -> Result<Done, Refuse> {
    // The parameters of the token endpoint are in the body (RFC 6749 section 3.2), never the query.
    if !query.is_empty() {
        return Err(Refuse::new(400, "unknown_parameter"));
    }
    if !is_form(headers) {
        return Err(Refuse::new(415, "content_type"));
    }
    let declared = headers
        .get(CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<usize>().ok());
    if declared.is_some_and(|n| n > FORM_MAX) {
        return Err(Refuse::new(413, "body_size"));
    }
    let raw = Limited::new(body, FORM_MAX)
        .collect()
        .await
        .map_err(|e| {
            if e.downcast_ref::<http_body_util::LengthLimitError>()
                .is_some()
            {
                Refuse::new(413, "body_size")
            } else {
                Refuse::new(400, "body")
            }
        })?
        .to_bytes();
    let raw = std::str::from_utf8(&raw).map_err(|_| Refuse::new(400, "parameter_syntax"))?;
    let p = Params::parse(raw, FORM_MAX).map_err(bad)?;
    // One grant type, sent once, from the closed list; each grant has a closed list of its own.
    match p.get("grant_type").as_str() {
        "authorization_code" => {
            trace.grant = "authorization_code";
            let p = p.only(routes::TOKEN_CODE).map_err(bad)?;
            let r = TokenRequest {
                grant_type: p.get("grant_type"),
                code: p.get("code"),
                redirect_uri: p.get("redirect_uri"),
                code_verifier: p.get("code_verifier"),
                client_id: p.get("client_id"),
                client_secret: p.get("client_secret"),
                authorization: authorization(headers)?,
                ..TokenRequest::default()
            };
            let reply = state
                .session
                .token_with_options(r, opts())
                .await
                .map_err(|e| rpc(&e))?;
            Ok(Done::Relay(reply.into_owned()))
        }
        "refresh_token" => {
            trace.grant = "refresh_token";
            let p = p.only(routes::TOKEN_REFRESH).map_err(bad)?;
            let r = TokenRequest {
                grant_type: p.get("grant_type"),
                refresh_token: p.get("refresh_token"),
                scope: p.get("scope"),
                client_id: p.get("client_id"),
                client_secret: p.get("client_secret"),
                authorization: authorization(headers)?,
                ..TokenRequest::default()
            };
            let reply = state
                .session
                .token_with_options(r, opts())
                .await
                .map_err(|e| rpc(&e))?;
            Ok(Done::Relay(reply.into_owned()))
        }
        routes::GRANT_EXCHANGE => {
            trace.grant = "token_exchange";
            let p = p.only(routes::TOKEN_EXCHANGE).map_err(bad)?;
            // TokenExchangeRequest has no field for client authentication (a contract gap), so a
            // request that authenticates with a header is refused rather than run unauthenticated.
            if headers.contains_key(AUTHORIZATION) {
                return Err(Refuse::new(400, "authorization"));
            }
            let r = TokenExchangeRequest {
                grant_type: p.get("grant_type"),
                subject_token: p.get("subject_token"),
                subject_token_type: p.get("subject_token_type"),
                audience: p.get("audience"),
                resource: p.get("resource"),
                scope: p.get("scope"),
                requested_token_type: p.get("requested_token_type"),
                client_id: p.get("client_id"),
                actor_token: p.get("actor_token"),
                actor_token_type: p.get("actor_token_type"),
                ..TokenExchangeRequest::default()
            };
            let reply = state
                .exchange
                .token_with_options(r, opts())
                .await
                .map_err(|e| rpc(&e))?;
            Ok(Done::Relay(reply.into_owned()))
        }
        // Absent, repeated (refused above), or a grant this boundary does not serve.
        _ => Err(Refuse::new(400, "grant_type")),
    }
}
