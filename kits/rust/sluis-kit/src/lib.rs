//! The Rust kit of sluis: the same surface as the Go kit (`kits/go/rpc`, `cli`, `refusal`).
//!
//! - [`serve`] listens on a Unix socket, reads the caller's uid with `SO_PEERCRED` once per
//!   connection and refuses a caller outside the call graph before the message is decoded.
//! - [`dial`] returns a Connect client over a Unix socket (h2c). The deadline left and the
//!   correlation id of the call being served travel on every call made from its handler.
//! - [`refusal`] builds an error with the `sluis.type.v2alpha1.Refusal` detail.
//! - [`cli::main`] is the one command shape: `serve | check | version | conformance`.
//!
//! The Protobuf runtime is buffa, the one `connectrpc` 0.9 generates for (PLAN.md D-23).

mod client;
mod correlation_impl;
mod identity;
mod peercred;
mod refusal_impl;
mod server;

pub mod cli;

pub use client::{Client, Transport, dial};
pub use identity::Peer;
pub use refusal_impl::{refusal, refusal_reason};
pub use server::{Allow, ServerConfig, serve};

#[cfg(feature = "test-identities")]
pub use identity::Identities;
#[cfg(feature = "test-identities")]
pub use server::serve_with;

/// The header that carries the correlation id (contracts.md "Every call").
pub const HEADER_CORRELATION: &str = "sluis-correlation-id";

/// The caller of the call being served, set by the guard once the call passed it. `None` outside a
/// handler of a server built by [`serve`].
#[must_use]
pub fn peer(ext: &http::Extensions) -> Option<&Peer> {
    ext.get::<Peer>()
}

/// The correlation id of a call (contracts.md "Every call").
pub mod correlation {
    pub use crate::correlation_impl::{get, scope};

    /// The correlation id of the call being served, from any code that runs inside its handler
    /// (the kit sets it around the handler, and the client passes it on). `None` outside a handler,
    /// or when the caller sent none or an invalid one. The audit emitter reads it for
    /// `metadata.correlation_uid`.
    #[must_use]
    pub fn current() -> Option<String> {
        crate::correlation_impl::current().correlation
    }
}
