//! The restart back-off of the executables of sluis, kept in the program and not in the unit (owner decision 24 A,
//! 2026-11-09); the same as `kits/go/backoff`.
//!
//! A generated unit has `Restart=on-failure` and `RestartSec=2s` and no start limit (REQ-DEPLOY-044), and the systemd of Amazon
//! Linux 2023 (252) does not know `RestartSteps=` and `RestartMaxDelaySec=` (254), so a unit that fails would restart every
//! 2 s for ever there. So a program that is about to exit with a failure under systemd first sleeps 2, 4, 8, 16, 30, 30 ...
//! seconds, by the count of failures in a row that it keeps in a small file, and the same unit then behaves the same on every
//! systemd.
//!
//! The file is the one the unit names in `SLUIS_RESTART_FILE`, in a directory the unit already writes (its run directory), per
//! instance and per unit. Outside systemd (neither `INVOCATION_ID` nor `NOTIFY_SOCKET` is set), or with no file named,
//! [`Guard::new`] returns `None` and the program exits at once, as it always did. The count is forgotten when the program has run
//! for [`HEALTHY`] without failing, or exits cleanly. The sleep ends at once when the stop future resolves (SIGTERM).
//!
//! During the sleep the process is "active (running)" to systemd and its restart count does not move, so a deploy that waits
//! for units to stand still would take a failing unit for a settled one. So the file says it: `N wait` while the process
//! sleeps before its exit, and plain `N` once a process has started ([`Guard::begin`]). A unit whose file says `wait` has not
//! settled (`deploy/boards/remote-lib.sh`, `settle_units`).

use std::fs;
use std::future::Future;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::task::JoinHandle;

/// The environment variable that names the file holding the count of failures in a row, as the unit sets it.
pub const ENV_FILE: &str = "SLUIS_RESTART_FILE";
/// The sleep after the first failure; each failure after it doubles the sleep, up to [`CAP`].
pub const BASE: Duration = Duration::from_secs(2);
/// The longest sleep. It is below the deploy's wait (60 s), so a unit that waited for an unlock comes up within [`CAP`] of it.
pub const CAP: Duration = Duration::from_secs(30);
/// How long a program must run without failing for the count to be forgotten.
pub const HEALTHY: Duration = Duration::from_secs(60);

/// Follows the count in the file while the process sleeps before its exit.
const WAIT_MARK: &str = "wait";

/// Bounds what is read from the file and written to it; the delay is [`CAP`] long before.
const MAX_COUNT: u32 = 1000;

/// The sleep after the `failures`-th failure in a row (the first is 1): 2, 4, 8, 16, 30, 30 ... seconds.
#[must_use]
pub fn delay(failures: u32) -> Duration {
    if failures == 0 {
        return Duration::ZERO;
    }
    let mut d = BASE;
    for _ in 1..failures {
        if d >= CAP {
            break;
        }
        d *= 2;
    }
    d.min(CAP)
}

/// Whether the environment says the process was started by systemd: `INVOCATION_ID` is set on every unit, and `NOTIFY_SOCKET`
/// on one that is notified.
#[must_use]
pub fn under_systemd(getenv: &impl Fn(&str) -> Option<String>) -> bool {
    ["INVOCATION_ID", "NOTIFY_SOCKET"]
        .iter()
        .any(|k| getenv(k).is_some_and(|v| !v.is_empty()))
}

/// The time the guard uses, so that a test needs no wall clock.
pub trait Clock: Send + Sync {
    /// The time since any fixed origin.
    fn now(&self) -> Duration;
    /// A future that resolves once `d` has passed.
    fn sleep(&self, d: Duration) -> Pin<Box<dyn Future<Output = ()> + Send>>;
}

/// The wall clock.
pub struct SystemClock(Instant);

impl SystemClock {
    /// A clock whose origin is now.
    #[must_use]
    pub fn new() -> Self {
        Self(Instant::now())
    }
}

impl Default for SystemClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for SystemClock {
    fn now(&self) -> Duration {
        self.0.elapsed()
    }
    fn sleep(&self, d: Duration) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        Box::pin(tokio::time::sleep(d))
    }
}

/// What [`Guard::failed`] did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The process had run for [`HEALTHY`]: the count was forgotten and nothing was waited.
    Healthy,
    /// The process waited this long.
    Waited(Duration),
    /// The stop future resolved (or had) before the wait of this length was over, or the wait was skipped for it.
    Interrupted(Duration),
}

/// The count of failures in a row of one unit instance.
pub struct Guard {
    file: PathBuf,
    clock: Arc<dyn Clock>,
    started: Option<Duration>,
    timer: Option<JoinHandle<()>>,
}

impl Guard {
    /// The guard of this process, from its environment; `None` outside systemd or when the unit names no file.
    #[must_use]
    pub fn from_env() -> Option<Self> {
        Self::new(|k| std::env::var(k).ok(), None)
    }

    /// The guard for an environment, or `None` outside systemd or when the unit names no file (nothing then waits).
    /// `None` for the clock is the wall clock.
    #[must_use]
    pub fn new(
        getenv: impl Fn(&str) -> Option<String>,
        clock: Option<Arc<dyn Clock>>,
    ) -> Option<Self> {
        let file = getenv(ENV_FILE).filter(|f| !f.is_empty())?;
        if !under_systemd(&getenv) {
            return None;
        }
        Some(Self {
            file: PathBuf::from(file),
            clock: clock.unwrap_or_else(|| Arc::new(SystemClock::new())),
            started: None,
            timer: None,
        })
    }

    /// Marks the start of the service. Once it has run for [`HEALTHY`] the count is forgotten, even if the process is later
    /// killed without a chance to call [`Guard::done`] or [`Guard::failed`]. Call it inside the runtime.
    pub fn begin(&mut self) {
        self.started = Some(self.clock.now());
        let (n, wait) = load(&self.file);
        if wait {
            store(&self.file, n, false); // the process before this one slept and exited; this one is running
        }
        if let Ok(h) = tokio::runtime::Handle::try_current() {
            let (file, clock) = (self.file.clone(), Arc::clone(&self.clock));
            self.timer = Some(h.spawn(async move {
                clock.sleep(HEALTHY).await;
                forget(&file);
            }));
        }
    }

    /// Records a clean exit: the count is forgotten.
    pub fn done(&mut self) {
        self.cancel_timer();
        forget(&self.file);
    }

    /// Called when the process is about to exit with a failure. A process that ran for [`HEALTHY`] has no start problem: the
    /// count is forgotten and it exits at once. Otherwise the failure is counted, and the process waits [`delay`] of the
    /// count unless `stop` resolves first (a stop must not wait).
    pub async fn failed(&mut self, stop: impl Future<Output = ()>) -> Outcome {
        self.cancel_timer();
        if let Some(s) = self.started
            && self.clock.now().saturating_sub(s) >= HEALTHY
        {
            forget(&self.file);
            return Outcome::Healthy;
        }
        let n = load(&self.file).0.saturating_add(1).min(MAX_COUNT);
        store(&self.file, n, true);
        let d = delay(n);
        tracing::warn!(
            failures_in_a_row = n,
            wait = ?d,
            "exiting with a failure; waiting before the restart"
        );
        tokio::select! {
            () = self.clock.sleep(d) => Outcome::Waited(d),
            () = stop => Outcome::Interrupted(d),
        }
    }

    fn cancel_timer(&mut self) {
        if let Some(t) = self.timer.take() {
            t.abort();
        }
    }
}

impl Drop for Guard {
    fn drop(&mut self) {
        self.cancel_timer();
    }
}

/// Reads the count and whether the file says `wait`; a missing, unreadable, odd or non-regular file is 0.
fn load(file: &std::path::Path) -> (u32, bool) {
    let Ok(m) = fs::symlink_metadata(file) else {
        return (0, false);
    };
    if !m.file_type().is_file() || m.len() > 16 {
        return (0, false);
    }
    let Ok(text) = fs::read_to_string(file) else {
        return (0, false);
    };
    let (count, mark) = text.trim().split_once(' ').unwrap_or((text.trim(), ""));
    match (count.parse::<u32>(), mark) {
        (Ok(n), "") => (n.min(MAX_COUNT), false),
        (Ok(n), WAIT_MARK) => (n.min(MAX_COUNT), true),
        _ => (0, false),
    }
}

/// Writes the count by a rename, so a reader never sees half a file. A failure is not an error: the back-off is a courtesy
/// to the journal, and a program that cannot write its count must still exit.
fn store(file: &std::path::Path, n: u32, wait: bool) {
    let mut tmp = file.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    let _ = fs::remove_file(&tmp); // a leftover, or a link put there: create_new below never follows one
    let written = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)
        .and_then(|mut f| {
            if wait {
                writeln!(f, "{n} {WAIT_MARK}")
            } else {
                writeln!(f, "{n}")
            }
        })
        .and_then(|()| fs::rename(&tmp, file));
    if let Err(e) = written {
        let _ = fs::remove_file(&tmp);
        tracing::debug!(err = %e, "restart count: not written");
    }
}

fn forget(file: &std::path::Path) {
    let _ = fs::remove_file(file);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use tokio::sync::watch;

    /// A clock that moves only when the test says so. `sleep` resolves once the time has passed its deadline, and is
    /// recorded; with `auto`, a sleep passes the time it asks for at once.
    struct Fake {
        now: watch::Sender<Duration>,
        sleeps: Mutex<Vec<Duration>>,
        auto: bool,
    }

    impl Fake {
        fn new(auto: bool) -> Arc<Self> {
            Arc::new(Self {
                now: watch::channel(Duration::from_secs(1000)).0,
                sleeps: Mutex::new(Vec::new()),
                auto,
            })
        }
        fn advance(&self, d: Duration) {
            self.now.send_modify(|t| *t += d);
        }
        fn slept(&self) -> Vec<Duration> {
            self.sleeps.lock().unwrap().clone()
        }
    }

    impl Clock for Fake {
        fn now(&self) -> Duration {
            *self.now.borrow()
        }
        fn sleep(&self, d: Duration) -> Pin<Box<dyn Future<Output = ()> + Send>> {
            // The timer of `begin` is a sleep too; only the waits of `failed` are recorded, which are not HEALTHY.
            if d != HEALTHY {
                self.sleeps.lock().unwrap().push(d);
                if self.auto {
                    self.advance(d);
                    return Box::pin(std::future::ready(()));
                }
            }
            let deadline = self.now() + d;
            let mut rx = self.now.subscribe();
            Box::pin(async move {
                let _ = rx.wait_for(|t| *t >= deadline).await;
            })
        }
    }

    fn env(file: &std::path::Path) -> impl Fn(&str) -> Option<String> {
        let file = file.to_string_lossy().into_owned();
        move |k| match k {
            "INVOCATION_ID" => Some("abc".into()),
            ENV_FILE => Some(file.clone()),
            _ => None,
        }
    }

    fn count(file: &std::path::Path) -> String {
        fs::read_to_string(file).unwrap_or_else(|_| "none".into())
    }

    fn secs(v: &[u64]) -> Vec<Duration> {
        v.iter().map(|s| Duration::from_secs(*s)).collect()
    }

    fn never() -> impl Future<Output = ()> {
        std::future::pending()
    }

    /// verifies: REQ-DEPLOY-051
    #[test]
    fn delay_is_two_four_eight_sixteen_then_thirty() {
        let got: Vec<_> = (1..=7).map(delay).collect();
        assert_eq!(got, secs(&[2, 4, 8, 16, 30, 30, 30]));
        assert_eq!(delay(0), Duration::ZERO);
        assert_eq!(delay(u32::MAX), CAP);
    }

    /// verifies: REQ-DEPLOY-051
    #[tokio::test]
    async fn failures_sleep_the_sequence_and_stay_at_the_cap() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("restarts");
        let clock = Fake::new(true);
        // Each loop is one process: it starts, fails soon, sleeps, and exits; the file carries the count to the next.
        for _ in 0..9 {
            let mut g = Guard::new(env(&file), Some(clock.clone())).unwrap();
            g.begin();
            clock.advance(Duration::from_millis(100));
            assert!(matches!(g.failed(never()).await, Outcome::Waited(_)));
        }
        assert_eq!(clock.slept(), secs(&[2, 4, 8, 16, 30, 30, 30, 30, 30]));
        assert_eq!(count(&file), "9 wait\n");
    }

    /// verifies: REQ-DEPLOY-051
    #[tokio::test]
    async fn running_healthy_for_a_while_resets_the_count() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("restarts");
        let clock = Fake::new(true);
        for _ in 0..3 {
            let mut g = Guard::new(env(&file), Some(clock.clone())).unwrap();
            g.begin();
            g.failed(never()).await;
        }
        assert_eq!(count(&file), "3 wait\n");
        // A process that runs for 60 s forgets the count, even if it is killed and so never calls failed or done.
        let mut g = Guard::new(env(&file), Some(clock.clone())).unwrap();
        g.begin();
        assert_eq!(count(&file), "3\n", "a running process still says wait");
        tokio::task::yield_now().await;
        clock.advance(HEALTHY - Duration::from_secs(1));
        tokio::task::yield_now().await;
        assert_eq!(count(&file), "3\n", "forgotten after 59 s");
        clock.advance(Duration::from_secs(1));
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
        assert_eq!(count(&file), "none", "not forgotten after 60 s");
        // So the next failure sleeps 2 s again.
        let before = clock.slept().len();
        let mut g = Guard::new(env(&file), Some(clock.clone())).unwrap();
        g.begin();
        g.failed(never()).await;
        assert_eq!(clock.slept()[before..], secs(&[2]));
    }

    #[tokio::test]
    async fn a_failure_after_a_healthy_run_exits_at_once() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("restarts");
        fs::write(&file, "4\n").unwrap();
        let clock = Fake::new(true);
        let mut g = Guard::new(env(&file), Some(clock.clone())).unwrap();
        g.begin();
        // No yield: the timer has not run, so it is the elapsed time that decides.
        clock.advance(HEALTHY + Duration::from_secs(1));
        assert_eq!(g.failed(never()).await, Outcome::Healthy);
        assert!(clock.slept().is_empty());
        assert_eq!(count(&file), "none");
    }

    #[tokio::test]
    async fn a_clean_exit_forgets_the_count_and_does_not_sleep() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("restarts");
        fs::write(&file, "3\n").unwrap();
        let clock = Fake::new(true);
        let mut g = Guard::new(env(&file), Some(clock.clone())).unwrap();
        g.begin();
        g.done();
        assert_eq!(count(&file), "none");
        assert!(clock.slept().is_empty());
    }

    /// verifies: REQ-DEPLOY-051
    #[tokio::test]
    async fn a_stop_ends_the_sleep_at_once() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("restarts");
        fs::write(&file, "5\n").unwrap();
        let clock = Fake::new(false); // the sleep of 30 s never ends by itself
        let mut g = Guard::new(env(&file), Some(clock.clone())).unwrap();
        g.begin();
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(async move {
            g.failed(async {
                let _ = rx.await;
            })
            .await
        });
        while clock.slept().is_empty() {
            tokio::task::yield_now().await;
        }
        // While it sleeps the file says so, for a deploy that watches the unit stand still (settle_units).
        assert_eq!(count(&file), "6 wait\n");
        tx.send(()).unwrap();
        let out = tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("the sleep did not end when the stop came")
            .unwrap();
        assert_eq!(out, Outcome::Interrupted(CAP));
        assert_eq!(clock.slept(), secs(&[30]));
    }

    /// verifies: REQ-DEPLOY-051
    #[tokio::test]
    async fn outside_systemd_there_is_no_guard() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("restarts");
        let f = file.to_string_lossy().into_owned();
        // Not under systemd: the file is named, but neither INVOCATION_ID nor NOTIFY_SOCKET is set.
        let outside = move |k: &str| (k == ENV_FILE).then(|| f.clone());
        assert!(Guard::new(outside, None).is_none());
        // Under systemd but the unit names no file (an older unit): nothing to count in.
        let nofile = |k: &str| (k == "INVOCATION_ID").then(|| "x".to_owned());
        assert!(Guard::new(nofile, None).is_none());
        // An empty value is not a value.
        let empty = |_: &str| Some(String::new());
        assert!(Guard::new(empty, None).is_none());
        assert!(!file.exists());
    }

    #[test]
    fn notify_socket_alone_means_systemd() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("r").to_string_lossy().into_owned();
        let e = move |k: &str| match k {
            "NOTIFY_SOCKET" => Some("/run/systemd/notify".to_owned()),
            ENV_FILE => Some(f.clone()),
            _ => None,
        };
        assert!(Guard::new(e, None).is_some());
    }

    #[tokio::test]
    async fn a_file_that_is_not_a_count_is_zero() {
        let dir = tempfile::tempdir().unwrap();
        for (name, content) in [
            ("empty", String::new()),
            ("text", "many\n".into()),
            ("negative", "-4\n".into()),
            ("huge", "99999999999999999999999\n".into()),
            ("long", format!("1\n{}", " ".repeat(100))),
        ] {
            let file = dir.path().join(name);
            fs::write(&file, content).unwrap();
            let clock = Fake::new(true);
            let mut g = Guard::new(env(&file), Some(clock.clone())).unwrap();
            g.begin();
            g.failed(never()).await;
            assert_eq!(clock.slept(), secs(&[2]), "{name}");
        }
        // A link is not followed, in either direction.
        let target = dir.path().join("target");
        fs::write(&target, "4\n").unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        std::os::unix::fs::symlink(&target, dir.path().join("link.tmp")).unwrap();
        let clock = Fake::new(true);
        let mut g = Guard::new(env(&link), Some(clock.clone())).unwrap();
        g.begin();
        g.failed(never()).await;
        assert_eq!(clock.slept(), secs(&[2]), "link");
        assert_eq!(fs::read_to_string(&target).unwrap(), "4\n");
    }

    #[tokio::test]
    async fn an_unwritable_directory_still_exits() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("no/such/dir/restarts");
        let clock = Fake::new(true);
        let mut g = Guard::new(env(&file), Some(clock.clone())).unwrap();
        g.begin();
        g.failed(never()).await;
        assert_eq!(clock.slept(), secs(&[2]));
    }
}
