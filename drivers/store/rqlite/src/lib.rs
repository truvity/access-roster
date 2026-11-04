//! The rqlite driver of store@: the item contract over rqlite's HTTP API.
//!
//! - [`config`]: the command-line flags.
//! - [`client`]: rqlite's HTTP API (statements, transactions, `RETURNING`, read levels).
//! - [`sql`]: every statement the driver runs.
//! - [`service`]: `sluis.port.item.v2alpha1.ItemService` over them.
//! - [`sweeper`]: expired items and the change log, on rqlite's leader.

pub mod client;
pub mod config;
pub mod service;
pub mod sql;
pub mod sweeper;

pub use service::Driver;
