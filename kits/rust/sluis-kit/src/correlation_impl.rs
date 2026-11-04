//! The correlation id and the deadline of the call being served, passed on to the calls its
//! handler makes (contracts.md "Every call"). They live in a task-local that the guard sets around
//! the handler, so a handler needs no plumbing: the client reads them when it sends.

use std::future::Future;
use std::time::Instant;

use crate::HEADER_CORRELATION;

#[derive(Clone, Debug, Default)]
pub(crate) struct Inherited {
    pub correlation: Option<String>,
    pub deadline: Option<Instant>,
}

tokio::task_local! {
    pub(crate) static INHERITED: Inherited;
}

pub(crate) fn current() -> Inherited {
    INHERITED.try_with(Clone::clone).unwrap_or_default()
}

/// The correlation id in a handler's request extensions, set by the guard from the header the
/// caller sent. `None` when the caller sent none.
#[must_use]
pub fn get(ext: &http::Extensions) -> Option<String> {
    ext.get::<CorrelationId>().map(|c| c.0.clone())
}

/// The extension the guard sets.
#[derive(Clone, Debug)]
pub(crate) struct CorrelationId(pub String);

/// The id in the headers of a request, if the value is plain text.
pub(crate) fn from_headers(headers: &http::HeaderMap) -> Option<String> {
    headers
        .get(HEADER_CORRELATION)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
}

/// Runs `fut` as if it were the handler of a call with this correlation id. A test uses it to
/// show that an id reaches the calls a handler makes; the guard does the same for each call.
pub async fn scope<F: Future>(correlation: Option<String>, fut: F) -> F::Output {
    INHERITED
        .scope(
            Inherited {
                correlation,
                deadline: None,
            },
            fut,
        )
        .await
}
