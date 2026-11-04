//! Who a uid is. The names come from the registry; a test may bring its own table.

use std::sync::Arc;

/// The caller of a call: the uid the kernel reported for the connection, and what the registry
/// says that uid is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Peer {
    /// The uid of the peer process.
    pub uid: u32,
    /// The gid of the peer process.
    pub gid: u32,
    /// The pid of the peer process (0 when the platform does not say).
    pub pid: i32,
    /// The registry name of the uid (`policy`, `sluis-node`, a driver, ...).
    pub name: &'static str,
    /// The uid block of the boundary the caller belongs to (REQ-ISO-072).
    pub uid_block: u32,
}

type Resolver = dyn Fn(u32) -> Option<(&'static str, u32)> + Send + Sync;

/// The table that turns a uid into a registry name and uid block, and the uid block of the
/// server's own boundary.
#[derive(Clone)]
pub struct Identities {
    resolve: Arc<Resolver>,
    own_block: u32,
}

impl Identities {
    /// The registry's table, with the uid block of this process's own uid. A server that does
    /// not run as a uid of the registry cannot tell its own boundary and refuses to start.
    pub(crate) fn registry() -> anyhow::Result<Self> {
        let uid = rustix::process::geteuid().as_raw();
        let (_, own_block) = sluis_registry::name_for_uid(uid)
            .ok_or_else(|| anyhow::anyhow!("own uid {uid} is not a uid of the registry"))?;
        Ok(Self {
            resolve: Arc::new(sluis_registry::name_for_uid),
            own_block,
        })
    }

    /// A table of a test's own. This exists only in test and example builds, through the
    /// `test-identities` feature, and no flag or environment variable reaches it.
    #[cfg(feature = "test-identities")]
    pub fn with(
        own_block: u32,
        resolve: impl Fn(u32) -> Option<(&'static str, u32)> + Send + Sync + 'static,
    ) -> Self {
        Self {
            resolve: Arc::new(resolve),
            own_block,
        }
    }

    pub(crate) fn name(&self, uid: u32) -> Option<(&'static str, u32)> {
        (self.resolve)(uid)
    }

    pub(crate) fn own_block(&self) -> u32 {
        self.own_block
    }
}
