//! `entry`: the only actor that speaks HTTP to the outside (ADR 0002 "Work actors", ADR 0003
//! "Listeners").
//!
//! A forwarder (the edge connector, or the harness's reverse proxy) ends TLS and passes each
//! request to `entry`'s Unix socket. `entry` parses it against the closed parameter lists of the
//! contracts, refuses anything unknown with one fixed answer per status, and calls the actor that
//! owns the step through its typed client: `session` for `/authorize`, `/callback` and the code and
//! refresh grants of `/token`, `exchange` for the token-exchange grant (PLAN.md D-10). It serves the
//! discovery document and the key set from the kinds `Boundary` and `SigningRing` (D-7).
//!
//! `entry` holds no key, no secret and no state beyond a few seconds of public documents, makes no
//! outbound connection but to the sockets of the actors the call graph allows, and sets no cookie.

mod audit;
mod discovery;
mod handler;
mod headers;
mod ids;
mod params;
mod refuse;
mod routes;
mod serve;

pub use routes::Front;
#[cfg(feature = "test-identities")]
pub use serve::serve_with;
pub use serve::{Config, Sockets, serve};
