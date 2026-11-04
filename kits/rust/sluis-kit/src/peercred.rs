//! The kernel's word about who is on the other end of a Unix socket connection.
//!
//! The safe `peer_cred` of `tokio::net::UnixStream` reads `SO_PEERCRED`; the kit needs no
//! `unsafe` of its own (BRIEF-WP-05).

use tokio::net::UnixStream;

/// What `SO_PEERCRED` said about one connection, before the registry names it.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ConnPeer {
    pub uid: u32,
    pub gid: u32,
    pub pid: i32,
}

/// Reads the credentials of the connection's peer.
pub(crate) fn read(stream: &UnixStream) -> std::io::Result<ConnPeer> {
    let c = stream.peer_cred()?;
    Ok(ConnPeer {
        uid: c.uid(),
        gid: c.gid(),
        pid: c.pid().unwrap_or(0),
    })
}
