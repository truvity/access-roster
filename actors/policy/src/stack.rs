//! Cedar on a thread with a stack of its own.
//!
//! Cedar parses and evaluates by recursion. When the stack is small it stops with `RecursionLimit`
//! and a policy that is good is refused (on a static musl build it did so at the start of `serve`,
//! and `check` as well). The size of the stack of a thread must not depend on where the thread comes
//! from: the main thread of a static musl binary, a runtime worker or a blocking thread of the
//! runtime each have their own default. So the build of a set, and each evaluation, run on a thread
//! started here with an explicit size.
//!
//! The size is [`STACK_BYTES`]. It is address space that the kernel maps and commits only as the
//! thread touches it, so a thread that does not recurse deeply costs a few pages.

use std::fmt;

/// The stack of a Cedar thread: 16 MiB.
///
/// MEASURED 2026-11-04 on a debug build, the worst case for stack use: `Engine::build` of the
/// local installation's policy needs between 256 KiB (it fails there) and 512 KiB (it passes); a
/// release build needs less. 16 MiB is more than 30 times the measure, so a reviewed set many times
/// larger than the local one still builds. It is a constant and not a setting: a smaller stack is not
/// a configuration, it is the fault this module fixes.
pub const STACK_BYTES: usize = 16 * 1024 * 1024;

/// The thread did not hand back a result: it could not be started, or it panicked.
#[derive(Debug)]
pub struct Lost;

impl fmt::Display for Lost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the policy thread ended without a result")
    }
}

impl std::error::Error for Lost {}

/// Runs `work` on a new thread whose stack is [`STACK_BYTES`], and waits for its result without
/// blocking the runtime.
///
/// # Errors
///
/// [`Lost`] when the thread cannot be started or panics.
pub async fn run<T, F>(work: F) -> Result<T, Lost>
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    let (tx, rx) = tokio::sync::oneshot::channel();
    std::thread::Builder::new()
        .name("policy-cedar".into())
        .stack_size(STACK_BYTES)
        .spawn(move || {
            // The receiver is gone only when the caller was cancelled: nobody wants the result.
            let _ = tx.send(work());
        })
        .map_err(|e| {
            tracing::error!(why = %e, "a thread for the policy could not be started");
            Lost
        })?;
    rx.await.map_err(|_| Lost)
}
