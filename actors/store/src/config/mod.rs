//! The seam between the store service and the signed config snapshot (WP-11 fills it in).
//!
//! A config kind is read-only to sluis: it comes from the snapshot, never from an engine
//! (ADR 0005, "Configuration loading").

/// The snapshot of the config kinds, as the store service reads it.
pub trait ConfigSnapshot: Send + Sync {
    /// The item of a config kind (segment, id), or None. Config kinds are read-only to sluis.
    fn get(&self, segment: &str, id: &str) -> Option<Vec<u8>>; // the kind's Protobuf bytes
    /// The items of a config kind as (id, bytes), sorted by id.
    fn list(&self, segment: &str) -> Vec<(String, Vec<u8>)>;
    /// The document's seq. None: no document of this kind is loaded, which the store service
    /// answers as `unavailable`/`engine` (fail closed), never as an empty kind.
    fn version(&self, segment: &str) -> Option<u64>;
}

/// No snapshot: every config read is unavailable until WP-11 loads one.
pub struct NoConfig;

impl ConfigSnapshot for NoConfig {
    fn get(&self, _segment: &str, _id: &str) -> Option<Vec<u8>> {
        None
    }
    fn list(&self, _segment: &str) -> Vec<(String, Vec<u8>)> {
        Vec::new()
    }
    fn version(&self, _segment: &str) -> Option<u64> {
        None
    }
}
