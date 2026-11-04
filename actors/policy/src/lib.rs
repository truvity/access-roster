//! policy: the decision point (ADR 0007).
//!
//! It evaluates the reviewed Cedar policy against the schema of sluis, and for an allow has key@
//! seal a grant for the asker. It holds no key and no data of its own, writes no kind and has no
//! network. The caller is known from the transport only.
//!
//! - [`engine`] compiles the four layers into one checked Cedar set and evaluates a request.
//! - [`decide`] turns the facts of an asker into a Cedar request and finds a person's grant names.
//! - [`grant`] and [`service`] make the grant, have it sealed, audit the decision and answer.
//! - [`source`] reads the config kinds through store@ and reloads them; [`run`] is the command line.
pub mod audit;
pub mod decide;
pub mod engine;
pub mod grant;
pub mod run;
pub mod schema;
pub mod service;
pub mod source;
pub mod vocab;
pub mod yaml;
