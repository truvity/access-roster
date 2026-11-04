//! The client half of the kit: Connect over a Unix socket, h2c.

use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::Instant;

use connectrpc::client::{
    ClientBody, ClientConfig, ClientTransport, Http2Connection, SharedHttp2Connection,
};
use futures::future::BoxFuture;
use http::{HeaderValue, Request, Response};

use crate::HEADER_CORRELATION;
use crate::correlation_impl::current;

/// The `Connect-Timeout-Ms` header (Connect protocol, "Timeouts").
const TIMEOUT_MS: &str = "connect-timeout-ms";
/// The most Connect allows in that header: ten digits.
const TIMEOUT_MAX_MS: u128 = 9_999_999_999;
/// The base URI of every call: the authority is a name only, the socket is the address.
const BASE_URI: &str = "http://unix";

/// A Connect client over one Unix socket. Hand it to a generated client:
/// `StoreServiceClient::new(client.transport(), client.config())`.
///
/// While a handler of a server built by [`serve`](crate::serve) runs, every call made through a
/// client carries what is left of the caller's deadline and the caller's correlation id
/// (contracts.md "Every call").
#[derive(Clone)]
pub struct Client {
    transport: Transport,
}

impl Client {
    /// The transport, to build a generated client.
    #[must_use]
    pub fn transport(&self) -> Transport {
        self.transport.clone()
    }

    /// The configuration for a generated client: Connect, Protobuf, no compression.
    #[must_use]
    pub fn config(&self) -> ClientConfig {
        ClientConfig::new(http::Uri::from_static(BASE_URI))
    }

    /// The socket this client dials.
    #[must_use]
    pub fn socket(&self) -> &Path {
        &self.transport.socket
    }
}

/// A Connect client over the Unix socket. The connection is made at the first call, so `dial`
/// does not need a running server, and is remade when the server restarts.
#[must_use]
pub fn dial(socket: &Path) -> Client {
    Client {
        transport: Transport {
            socket: Arc::new(socket.to_path_buf()),
            conn: Arc::new(OnceLock::new()),
        },
    }
}

/// The client transport of the kit: one h2c connection to a Unix socket, shared by clones.
#[derive(Clone)]
pub struct Transport {
    socket: Arc<PathBuf>,
    conn: Arc<OnceLock<SharedHttp2Connection>>,
}

impl ClientTransport for Transport {
    type ResponseBody = <SharedHttp2Connection as ClientTransport>::ResponseBody;
    type Error = <SharedHttp2Connection as ClientTransport>::Error;

    fn send(
        &self,
        mut request: Request<ClientBody>,
    ) -> BoxFuture<'static, Result<Response<Self::ResponseBody>, Self::Error>> {
        pass_on(&mut request);
        // `shared` starts a worker task, so the connection is made here, inside the runtime.
        let conn = self
            .conn
            .get_or_init(|| {
                Http2Connection::lazy_unix(self.socket.as_path(), http::Uri::from_static(BASE_URI))
                    .shared(1024)
            })
            .clone();
        Box::pin(async move { conn.send(request).await })
    }
}

/// Puts the correlation id and the deadline left of the call being served on an outgoing call.
/// A callee never extends its caller's deadline: a shorter timeout the caller chose stays.
fn pass_on(request: &mut Request<ClientBody>) {
    let inherited = current();
    if let Some(id) = inherited.correlation.as_deref()
        && let Ok(v) = HeaderValue::from_str(id)
    {
        request.headers_mut().insert(HEADER_CORRELATION, v);
    }
    if let Some(deadline) = inherited.deadline {
        let left = deadline
            .saturating_duration_since(Instant::now())
            .as_millis();
        let left = left.min(TIMEOUT_MAX_MS);
        let own: Option<u128> = request
            .headers()
            .get(TIMEOUT_MS)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse().ok());
        let ms = own.map_or(left, |o| o.min(left));
        request.headers_mut().insert(
            TIMEOUT_MS,
            HeaderValue::from(u64::try_from(ms).unwrap_or(u64::MAX)),
        );
    }
}
