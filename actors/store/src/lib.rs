//! store@: the only holder of storage credentials (ADR 0005).
//!
//! It serves the generic store service to the actors with a data port, enforces the generated
//! rules and the kind registry on every call, and reaches its engines only through the item-port
//! drivers on their sockets. It never seals or opens a value.

pub mod address;
pub mod audit;
pub mod bootstrap;
pub mod config;
pub mod engine;
pub mod grant;
pub mod messages;
pub mod run;
pub mod service;
pub mod yaml;
