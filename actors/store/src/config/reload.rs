//! The reload loop (ADR 0005, "A failed reload"): it watches the config source, reads the whole
//! set again when a document changes, and hands the outcome to the caller to audit.
//!
//! Only a source whose capability is `notify` is watched. A source that is `none` cannot change
//! under a running store, and `poll` has no driver in this build (the `appconfig` driver arrives
//! with the serverless installation).

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use sluis_proto::sluis::port::source::v2alpha1::{SourceWatchRequest, Watch};
use tokio::sync::mpsc::{self, Sender};
use tokio::task::JoinSet;

use super::snapshot::{Loader, Reloaded};

/// Changes that arrive together are one reload.
const DEBOUNCE: Duration = Duration::from_millis(100);
/// The first pause before a watch is dialled again or an unreachable source is read again.
const BACKOFF_FIRST: Duration = Duration::from_secs(1);
/// The longest pause.
const BACKOFF_MAX: Duration = Duration::from_secs(30);

/// Runs until the task is dropped. `on` is called with the outcome of every reload.
pub async fn run<F, Fut>(loader: Arc<Loader>, on: F)
where
    F: Fn(Reloaded) -> Fut,
    Fut: Future<Output = ()>,
{
    if loader.watch() != Watch::NOTIFY {
        tracing::info!("the config source gives no change signal: config is read at start");
        return;
    }
    let (tx, mut rx) = mpsc::channel::<()>(1);
    let mut names = loader.snapshot().segments();
    // Dropping a JoinSet aborts its tasks, so the watchers end with this loop.
    let mut _watchers = spawn_watchers(&loader, &names, &tx);
    let mut retry = Duration::ZERO;
    loop {
        let retry_timer = async {
            if retry.is_zero() {
                std::future::pending::<()>().await;
            } else {
                tokio::time::sleep(retry).await;
            }
        };
        tokio::select! {
            _ = rx.recv() => {}
            () = retry_timer => {}
        }
        tokio::time::sleep(DEBOUNCE).await;
        while rx.try_recv().is_ok() {}

        let outcome = loader.reload().await;
        retry = match &outcome {
            // The source is retried with a back-off; a bad document is read again when it changes.
            Reloaded::Refused { error, .. } if error.unreachable => {
                (retry * 2).clamp(BACKOFF_FIRST, BACKOFF_MAX)
            }
            _ => Duration::ZERO,
        };
        on(outcome).await;

        // A reload can change which kinds are declared, and so which names are watched.
        let now = loader.snapshot().segments();
        if now != names {
            names = now;
            _watchers = spawn_watchers(&loader, &names, &tx);
        }
    }
}

fn spawn_watchers(loader: &Arc<Loader>, names: &[&'static str], tx: &Sender<()>) -> JoinSet<()> {
    let mut set = JoinSet::new();
    for name in names {
        set.spawn(watcher(Arc::clone(loader), (*name).to_owned(), tx.clone()));
    }
    set
}

async fn watcher(loader: Arc<Loader>, name: String, tx: Sender<()>) {
    let mut backoff = BACKOFF_FIRST;
    loop {
        match loader
            .source()
            .watch(SourceWatchRequest {
                name: name.clone(),
                ..SourceWatchRequest::default()
            })
            .await
        {
            Ok(mut stream) => {
                backoff = BACKOFF_FIRST;
                // A change can have come while nobody was watching.
                let _ = tx.try_send(());
                while let Ok(Some(_)) = stream.message().await {
                    let _ = tx.try_send(());
                }
            }
            Err(e) => tracing::warn!(code = e.code.as_str(), "config watch failed"),
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(BACKOFF_MAX);
    }
}
