#![allow(refining_impl_trait)] // the generated trait returns `impl Encodable`; a concrete type is fine
#![allow(clippy::unwrap_used, clippy::expect_used)] // a failed unwrap in a test is the failure
//! The watch helper of the typed client (`Store::watch`, ADR 0005 "Watch and the resume point") against a scripted
//! `StoreService` over a Unix socket: each `Watch` call takes the next session of a script (messages, a failure, a
//! silence, a clean end, or a refusal at the call), each listing takes the next listing of another, and the requests
//! are recorded, so a test says what the helper asked for as well as what it gave.

use std::collections::VecDeque;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use buffa::Message;
use connectrpc::error::ErrorCode;
use connectrpc::{RequestContext, Response, Router, ServiceRequest, ServiceResult, ServiceStream};
use sluis_kit::{Allow, Identities, ServerConfig, dial, refusal};
use sluis_proto::sluis::key::v2alpha1::KeyRevocation;
use sluis_proto::sluis::store::v2alpha1::{
    ChangeType, GetRequest, GetResponse, GetSignedConfigRequest, GetSignedConfigResponse,
    Item as WireItem, ListRequest, ListResponse, Provenance, StoreService, StoreServiceExt,
    WatchRequest, WatchResponse, WriteRequest, WriteResponse,
};
use sluis_proto::sluis::r#type::v2alpha1::Address;
use sluis_store::revocation::KeyRevocations;
use sluis_store::{Backoff, Error, Event, Kind, ResumePoint, ResyncCause, Store, Watch, WatchOpts};

/// The epoch of the change log in the scripts, unless a test says another.
const EPOCH: u64 = 5;

/// A resume point in the epoch of the scripts.
fn pt(sequence: u64) -> ResumePoint {
    ResumePoint {
        epoch: EPOCH,
        sequence,
    }
}

/// A kind with no tenant (`lease`), with any message as its value.
struct Lease;
impl Kind for Lease {
    type Id = String;
    type Value = Provenance;
    const NAME: &'static str = "Lease";
}

/// A kind with a tenant (`person`).
struct Person;
impl Kind for Person {
    type Id = String;
    type Value = Provenance;
    const NAME: &'static str = "Person";
}

/// A config kind: it has no change log.
struct KeyPlan;
impl Kind for KeyPlan {
    type Id = String;
    type Value = Provenance;
    const NAME: &'static str = "KeyPlan";
}

#[allow(clippy::large_enum_variant)] // a script of a few steps
enum Step {
    Msg(WatchResponse),
    Fail(ErrorCode, &'static str),
    Hang,
    End,
    /// Says nothing for this long, then goes on.
    Pause(Duration),
}

enum Session {
    /// The call itself is refused.
    Refuse(ErrorCode, &'static str),
    Stream(Vec<Step>),
}

/// The items of a listing (id, version) and its resume point.
type Items = (Vec<(&'static str, u64)>, u64, u64);

enum Listing {
    Items(Vec<(&'static str, u64)>, u64),
    /// As `Items`, in another epoch of the log.
    In(u64, Vec<(&'static str, u64)>, u64),
    Fail(ErrorCode),
}

#[derive(Default)]
struct Script {
    sessions: Mutex<VecDeque<Session>>,
    listings: Mutex<VecDeque<Listing>>,
    current: Mutex<Option<Items>>,
    /// What every `Watch` call asked for: kind, tenant, resume point.
    opens: Mutex<Vec<(String, String, u64)>>,
    /// The epoch that each `Watch` call named, in the order of the calls.
    open_epochs: Mutex<Vec<u64>>,
    lists: AtomicUsize,
    /// A listing fails once at this page (counted from 0), as a store that goes down in the middle of it.
    fail_at_page: Mutex<Option<usize>>,
    /// How long a page of a listing takes.
    page_delay: Mutex<Duration>,
    /// Streams that are open: counted up at the call, down when the stream is dropped.
    live: Arc<AtomicUsize>,
}

struct Live(Arc<AtomicUsize>);
impl Drop for Live {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

fn address(kind: &str, tenant: &str, id: &str) -> Address {
    Address {
        kind: kind.into(),
        tenant: tenant.into(),
        id: id.into(),
        ..Address::default()
    }
}

fn prov(path: &str) -> Provenance {
    Provenance {
        field_path: path.into(),
        version: 3,
        ..Provenance::default()
    }
}

fn wire(kind: &str, id: &str, version: u64, value: &[u8]) -> WireItem {
    wire_in(kind, "", id, version, value)
}

fn wire_in(kind: &str, tenant: &str, id: &str, version: u64, value: &[u8]) -> WireItem {
    WireItem {
        address: address(kind, tenant, id).into(),
        version,
        value: value.to_vec(),
        ..WireItem::default()
    }
}

fn put(seq: u64, id: &str, version: u64, path: &str) -> WatchResponse {
    put_in(EPOCH, seq, id, version, path)
}

/// A put that names the epoch of the log it comes from.
fn put_in(epoch: u64, seq: u64, id: &str, version: u64, path: &str) -> WatchResponse {
    WatchResponse {
        resume_point: seq,
        log_epoch: epoch,
        r#type: ChangeType::CHANGE_TYPE_PUT.into(),
        item: wire("lease", id, version, &prov(path).encode_to_vec()).into(),
        ..WatchResponse::default()
    }
}

fn delete(seq: u64, id: &str, version: u64) -> WatchResponse {
    WatchResponse {
        resume_point: seq,
        log_epoch: EPOCH,
        r#type: ChangeType::CHANGE_TYPE_DELETE.into(),
        item: wire("lease", id, version, b"").into(),
        ..WatchResponse::default()
    }
}

fn bookmark(seq: u64) -> WatchResponse {
    bookmark_in(EPOCH, seq)
}

/// The bookmark that says the stream is caught up, at the head `seq` that store@ read when it opened.
fn caught(seq: u64) -> WatchResponse {
    WatchResponse {
        caught_up: true,
        ..bookmark(seq)
    }
}

fn bookmark_in(epoch: u64, seq: u64) -> WatchResponse {
    WatchResponse {
        resume_point: seq,
        log_epoch: epoch,
        r#type: ChangeType::CHANGE_TYPE_BOOKMARK.into(),
        ..WatchResponse::default()
    }
}

impl StoreService for Script {
    async fn get(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, GetRequest>,
    ) -> ServiceResult<GetResponse> {
        Err(refusal(ErrorCode::Unimplemented, "unsupported", ""))
    }

    async fn list(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, ListRequest>,
    ) -> ServiceResult<ListResponse> {
        let r = request.to_owned_message();
        // A listing is read in pages of one item; the first page takes the next listing of the script.
        if r.page_token.is_empty() {
            self.lists.fetch_add(1, Ordering::SeqCst);
            match self.listings.lock().unwrap().pop_front() {
                Some(Listing::Items(items, point)) => {
                    *self.current.lock().unwrap() = Some((items, point, EPOCH));
                }
                Some(Listing::In(epoch, items, point)) => {
                    *self.current.lock().unwrap() = Some((items, point, epoch));
                }
                Some(Listing::Fail(c)) => return Err(refusal(c, "engine", "")),
                None => return Err(refusal(ErrorCode::Unavailable, "engine", "")),
            }
        }
        let cur = self.current.lock().unwrap().clone().unwrap();
        let from: usize = r.page_token.parse().unwrap_or(0);
        let delay = *self.page_delay.lock().unwrap();
        if !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }
        if *self.fail_at_page.lock().unwrap() == Some(from) {
            *self.fail_at_page.lock().unwrap() = None;
            return Err(refusal(ErrorCode::Unavailable, "engine", ""));
        }
        let items = cur
            .0
            .iter()
            .skip(from)
            .take(1)
            .map(|(id, v)| {
                // An id that starts with "bad" has a value that is not the kind's message.
                let value = if id.starts_with("bad") {
                    vec![0xff, 0xff, 0xff]
                } else {
                    prov(id).encode_to_vec()
                };
                wire_in(&r.kind, &r.tenant, id, *v, &value)
            })
            .collect();
        let next = if from + 1 < cur.0.len() {
            (from + 1).to_string()
        } else {
            String::new()
        };
        Response::ok(ListResponse {
            items,
            next_page_token: next,
            resume_point: cur.1,
            log_epoch: cur.2,
            ..ListResponse::default()
        })
    }

    async fn write(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, WriteRequest>,
    ) -> ServiceResult<WriteResponse> {
        Err(refusal(ErrorCode::Unimplemented, "unsupported", ""))
    }

    async fn get_signed_config(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, GetSignedConfigRequest>,
    ) -> ServiceResult<GetSignedConfigResponse> {
        Err(refusal(ErrorCode::Unimplemented, "unsupported", ""))
    }

    async fn watch(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, WatchRequest>,
    ) -> ServiceResult<ServiceStream<WatchResponse>> {
        let r = request.to_owned_message();
        self.opens
            .lock()
            .unwrap()
            .push((r.kind.clone(), r.tenant.clone(), r.resume_point));
        self.open_epochs.lock().unwrap().push(r.log_epoch);
        let steps = match self.sessions.lock().unwrap().pop_front() {
            Some(Session::Stream(s)) => s,
            Some(Session::Refuse(c, reason)) => return Err(refusal(c, reason, "resume_point")),
            None => return Err(refusal(ErrorCode::Unavailable, "engine", "")),
        };
        self.live.fetch_add(1, Ordering::SeqCst);
        let guard = Live(Arc::clone(&self.live));
        let stream = futures::stream::unfold(
            (VecDeque::from(steps), guard),
            |(mut steps, guard)| async move {
                loop {
                    match steps.pop_front()? {
                        Step::Msg(m) => return Some((Ok(m), (steps, guard))),
                        Step::Fail(c, reason) => {
                            steps.clear();
                            return Some((Err(refusal(c, reason, "resume_point")), (steps, guard)));
                        }
                        Step::Hang => std::future::pending().await,
                        Step::End => return None,
                        Step::Pause(d) => tokio::time::sleep(d).await,
                    }
                }
            },
        );
        Response::stream_ok(Box::pin(stream))
    }
}

struct Up {
    script: Arc<Script>,
    client: sluis_kit::Client,
    _dir: tempfile::TempDir,
}

async fn up(sessions: Vec<Session>, listings: Vec<Listing>) -> Up {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("store.sock");
    let script = Arc::new(Script::default());
    script.sessions.lock().unwrap().extend(sessions);
    script.listings.lock().unwrap().extend(listings);
    let router = Arc::clone(&script).register(Router::new());
    let me = rustix::process::geteuid().as_raw();
    let ids = Identities::with(0, move |u| (u == me).then_some(("session", 0)));
    tokio::spawn(sluis_kit::serve_with(
        ServerConfig {
            actor: "store",
            boundary: "dev".into(),
            socket: socket.clone(),
            mode: 0o660,
            socket_gid: None,
            allow: Allow::Exact("session"),
            default_deadline: Duration::from_secs(5),
        },
        router,
        std::future::pending(),
        ids,
    ));
    wait_for(&socket).await;
    Up {
        script,
        client: dial(&socket),
        _dir: dir,
    }
}

async fn wait_for(path: &Path) {
    for _ in 0..300 {
        if path.exists() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("{} did not appear", path.display());
}

const FAST: Backoff = Backoff {
    initial: Duration::from_millis(30),
    max: Duration::from_millis(200),
};

fn opts(from: Option<ResumePoint>) -> WatchOpts {
    WatchOpts {
        from,
        backoff: FAST,
        ..WatchOpts::default()
    }
}

fn lease_watch(up: &Up, from: Option<ResumePoint>) -> Watch<Lease> {
    Store::<Lease>::new(up.client.clone())
        .unwrap()
        .watch_with("", opts(from))
        .unwrap()
}

/// The next event, which must come within five seconds.
async fn ev<K: Kind>(w: &mut Watch<K>) -> Event<K> {
    tokio::time::timeout(Duration::from_secs(5), w.next())
        .await
        .expect("the watch said nothing in five seconds")
        .expect("the watch ended in an error")
}

/// The error the watch ends with, within five seconds.
async fn end<K: Kind>(w: &mut Watch<K>) -> Error {
    tokio::time::timeout(Duration::from_secs(5), w.next())
        .await
        .expect("the watch said nothing in five seconds")
        .err()
        .expect("the watch said an event, not an error")
}

/// The watch has nothing to say for a moment (its stream is open and quiet).
async fn quiet<K: Kind>(w: &mut Watch<K>) {
    assert!(
        tokio::time::timeout(Duration::from_millis(200), w.next())
            .await
            .is_err()
    );
}

fn ids(items: &[sluis_store::Item<Lease>]) -> Vec<&str> {
    items.iter().map(|i| i.id.as_str()).collect()
}

fn opens(up: &Up) -> Vec<u64> {
    up.script
        .opens
        .lock()
        .unwrap()
        .iter()
        .map(|o| o.2)
        .collect()
}

/// The event is a put of the item `id` at `seq`, with the value `path`.
fn is_put(e: &Event<Lease>, id: &str, version: u64, path: &str, seq: u64) {
    is_put_in(e, EPOCH, id, version, path, seq);
}

/// The same, in the epoch `epoch` of the log.
fn is_put_in(e: &Event<Lease>, epoch: u64, id: &str, version: u64, path: &str, seq: u64) {
    match e {
        Event::Put { item, resume_point } => {
            assert_eq!(
                (
                    item.id.as_str(),
                    item.version,
                    item.value.field_path.as_str(),
                    *resume_point
                ),
                (
                    id,
                    version,
                    path,
                    ResumePoint {
                        epoch,
                        sequence: seq
                    }
                ),
                "{e:?}"
            );
        }
        _ => panic!("not a put: {e:?}"),
    }
}

// ---- the order of the events ----

/// verifies: REQ-DATA-108
/// A watch lists the kind over all its pages and then follows it from the listing's position: the listing is the
/// first event, then creates, updates and deletes in the order of the log, then the bookmark of an idle stream.
#[tokio::test]
async fn a_watch_lists_then_delivers_puts_deletes_and_bookmarks_in_order() {
    let up = up(
        vec![Session::Stream(vec![
            Step::Msg(put(11, "a/one", 1, "created")),
            Step::Msg(put(12, "a/one", 2, "updated")),
            Step::Msg(delete(13, "a/one", 2)),
            Step::Msg(bookmark(13)),
            Step::Hang,
        ])],
        vec![Listing::Items(
            vec![("a/zero", 4), ("a/zero2", 1), ("a/zero3", 1)],
            10,
        )],
    )
    .await;
    let mut w = lease_watch(&up, None);
    assert_eq!(w.resume_point(), ResumePoint::default());

    match ev(&mut w).await {
        Event::Resync {
            cause,
            items,
            resume_point,
        } => {
            assert_eq!((cause, resume_point), (ResyncCause::Start, pt(10)));
            assert_eq!(
                ids(&items),
                ["a/zero", "a/zero2", "a/zero3"],
                "three pages of one"
            );
            assert_eq!(items[0].version, 4);
            assert_eq!(items[0].value.field_path, "a/zero");
        }
        e => panic!("not a resync: {e:?}"),
    }
    assert_eq!(w.resume_point(), pt(10));
    is_put(&ev(&mut w).await, "a/one", 1, "created", 11);
    is_put(&ev(&mut w).await, "a/one", 2, "updated", 12);
    match ev(&mut w).await {
        Event::Delete {
            tenant,
            id,
            version,
            resume_point,
        } => assert_eq!(
            (tenant.as_str(), id.as_str(), version, resume_point),
            ("", "a/one", 2, pt(13))
        ),
        e => panic!("not a delete: {e:?}"),
    }
    assert!(matches!(ev(&mut w).await, Event::Bookmark { resume_point } if resume_point == pt(13)));
    assert_eq!(w.resume_point(), pt(13));
    // The listing was read once, and the watch started from its position, for this kind and no tenant.
    assert_eq!(up.script.lists.load(Ordering::SeqCst), 1);
    assert_eq!(
        *up.script.opens.lock().unwrap(),
        [("lease".to_owned(), String::new(), 10)]
    );
}

/// verifies: REQ-DATA-108
/// A caller that kept a resume point starts from it, with no listing; a change at or below a point already applied
/// is a repeat and is not delivered again, and the bookmark never takes the point back.
#[tokio::test]
async fn a_watch_given_a_resume_point_lists_nothing_and_drops_repeats() {
    let up = up(
        vec![Session::Stream(vec![
            Step::Msg(put(40, "a/old", 1, "again")),
            Step::Msg(put(41, "a/new", 1, "new")),
            Step::Msg(put(41, "a/new", 1, "new")),
            Step::Msg(bookmark(30)),
            Step::Hang,
        ])],
        vec![],
    )
    .await;
    let mut w = lease_watch(&up, Some(pt(40)));
    assert_eq!(w.resume_point(), pt(40));
    is_put(&ev(&mut w).await, "a/new", 1, "new", 41);
    // The second 41 and nothing else came between: the next event is the bookmark, at the point and not before it.
    assert!(matches!(ev(&mut w).await, Event::Bookmark { resume_point } if resume_point == pt(41)));
    assert_eq!(opens(&up), [40]);
    assert_eq!(up.script.lists.load(Ordering::SeqCst), 0);
}

/// 0 would start a watch "from now" and lose what changed since: it is taken as no point.
#[tokio::test]
async fn a_zero_resume_point_is_a_request_for_a_listing() {
    let up = up(
        vec![Session::Stream(vec![Step::Hang])],
        vec![Listing::Items(vec![], 7)],
    )
    .await;
    let mut w = lease_watch(&up, Some(pt(0)));
    assert!(matches!(
        ev(&mut w).await,
        Event::Resync { cause: ResyncCause::Start, resume_point, .. } if resume_point == pt(7)
    ));
    quiet(&mut w).await;
    assert_eq!(opens(&up), [7]);
}

// ---- reconnects ----

/// verifies: REQ-DATA-108
/// A stream that fails, and one that ends, are said as an interruption; the watch reconnects from the last point it
/// gave, not from the start, and a change it was given before the break does not come twice.
#[tokio::test]
async fn a_watch_resumes_from_its_last_point_after_a_break_and_an_end() {
    let up = up(
        vec![
            Session::Stream(vec![
                Step::Msg(put(11, "a/one", 1, "one")),
                Step::Fail(ErrorCode::Unavailable, "engine"),
            ]),
            Session::Stream(vec![
                Step::Msg(put(11, "a/one", 1, "one")),
                Step::Msg(put(12, "a/two", 1, "two")),
                Step::End,
            ]),
            Session::Stream(vec![Step::Msg(put(13, "a/three", 1, "three")), Step::Hang]),
        ],
        vec![Listing::Items(vec![], 10)],
    )
    .await;
    let mut w = lease_watch(&up, None);
    assert!(matches!(ev(&mut w).await, Event::Resync { .. }));
    is_put(&ev(&mut w).await, "a/one", 1, "one", 11);
    match ev(&mut w).await {
        Event::Interrupted { reason, attempt } => {
            assert_eq!(attempt, 1);
            assert!(reason.contains("unavailable"), "{reason}");
        }
        e => panic!("not an interruption: {e:?}"),
    }
    is_put(&ev(&mut w).await, "a/two", 1, "two", 12);
    assert!(matches!(
        ev(&mut w).await,
        Event::Interrupted { attempt: 1, .. }
    ));
    is_put(&ev(&mut w).await, "a/three", 1, "three", 13);
    // The listing at the start, and the points of the two reconnects: the last one given, each time.
    assert_eq!(opens(&up), [10, 11, 12]);
    assert_eq!(
        up.script.lists.load(Ordering::SeqCst),
        1,
        "a break is not a resync"
    );
}

/// verifies: REQ-DATA-108
/// The retries wait: the first by the initial backoff, the next by twice that; the count restarts when a message
/// arrives. A store that is down at the start is retried the same way, before any listing.
#[tokio::test]
async fn a_watch_backs_off_between_retries_and_counts_the_failures() {
    let up = up(
        vec![
            Session::Refuse(ErrorCode::Unavailable, "engine"),
            Session::Refuse(ErrorCode::Unavailable, "engine"),
            Session::Stream(vec![Step::Msg(put(11, "a/one", 1, "one")), Step::Hang]),
        ],
        vec![
            Listing::Fail(ErrorCode::Unavailable),
            Listing::Items(vec![], 10),
        ],
    )
    .await;
    let mut w = lease_watch(&up, None);
    let t0 = Instant::now();
    assert!(
        matches!(ev(&mut w).await, Event::Interrupted { attempt: 1, .. }),
        "the listing failed"
    );
    assert!(matches!(ev(&mut w).await, Event::Resync { .. }));
    assert!(
        matches!(ev(&mut w).await, Event::Interrupted { attempt: 1, .. }),
        "the call was refused"
    );
    assert!(matches!(
        ev(&mut w).await,
        Event::Interrupted { attempt: 2, .. }
    ));
    is_put(&ev(&mut w).await, "a/one", 1, "one", 11);
    // Waits of 30 ms, 30 ms and 60 ms.
    assert!(
        t0.elapsed() >= Duration::from_millis(110),
        "{:?}",
        t0.elapsed()
    );
    assert_eq!(opens(&up), [10, 10, 10]);
}

// ---- resync ----

/// verifies: REQ-DATA-109
/// A resume point that store@ no longer holds, refused at the call, is an explicit resync: the kind is listed again
/// and the event carries the whole state and says why; the watch goes on from the new position. No change between
/// the old point and the new one is delivered or skipped silently.
#[tokio::test]
async fn an_expired_resume_point_at_the_call_is_a_resync_with_the_whole_state() {
    let up = up(
        vec![
            Session::Stream(vec![Step::Msg(put(11, "a/one", 1, "one")), Step::End]),
            Session::Refuse(ErrorCode::FailedPrecondition, "resume_point_expired"),
            Session::Stream(vec![Step::Msg(put(51, "a/two", 1, "two")), Step::Hang]),
        ],
        vec![
            Listing::Items(vec![("a/one", 1)], 10),
            Listing::Items(vec![("a/one", 1), ("a/nine", 2)], 50),
        ],
    )
    .await;
    let mut w = lease_watch(&up, None);
    assert!(matches!(
        ev(&mut w).await,
        Event::Resync {
            cause: ResyncCause::Start,
            ..
        }
    ));
    is_put(&ev(&mut w).await, "a/one", 1, "one", 11);
    assert!(matches!(ev(&mut w).await, Event::Interrupted { .. }));
    match ev(&mut w).await {
        Event::Resync {
            cause,
            items,
            resume_point,
        } => {
            assert_eq!((cause, resume_point), (ResyncCause::Expired, pt(50)));
            assert_eq!(ids(&items), ["a/one", "a/nine"]);
        }
        e => panic!("not a resync: {e:?}"),
    }
    assert_eq!(w.resume_point(), pt(50));
    is_put(&ev(&mut w).await, "a/two", 1, "two", 51);
    assert_eq!(opens(&up), [10, 11, 50]);
}

/// verifies: REQ-DATA-109
/// The same refusal as the first thing the stream says is a resync too, with no interruption before it.
#[tokio::test]
async fn an_expired_resume_point_in_the_stream_is_a_resync() {
    let up = up(
        vec![
            Session::Stream(vec![
                Step::Msg(put(11, "a/one", 1, "one")),
                Step::Fail(ErrorCode::FailedPrecondition, "resume_point_expired"),
            ]),
            Session::Stream(vec![Step::Hang]),
        ],
        vec![
            Listing::Items(vec![], 10),
            Listing::Items(vec![("a/seven", 3)], 60),
        ],
    )
    .await;
    let mut w = lease_watch(&up, None);
    assert!(matches!(ev(&mut w).await, Event::Resync { .. }));
    is_put(&ev(&mut w).await, "a/one", 1, "one", 11);
    match ev(&mut w).await {
        Event::Resync {
            cause: ResyncCause::Expired,
            items,
            resume_point,
        } => {
            assert_eq!(resume_point, pt(60));
            assert_eq!(ids(&items), ["a/seven"]);
        }
        e => panic!("not a resync: {e:?}"),
    }
    quiet(&mut w).await;
    assert_eq!(opens(&up), [10, 60]);
}

/// verifies: REQ-DATA-109
/// A caller's saved point that the store no longer holds ends in a listing: the watch starts with a resync whose
/// cause is the expiry, not the start.
#[tokio::test]
async fn a_saved_resume_point_that_is_gone_starts_with_a_resync() {
    let up = up(
        vec![
            Session::Refuse(ErrorCode::FailedPrecondition, "resume_point_expired"),
            Session::Stream(vec![Step::Hang]),
        ],
        vec![Listing::Items(vec![("a/one", 1)], 90)],
    )
    .await;
    let mut w = lease_watch(&up, Some(pt(5)));
    match ev(&mut w).await {
        Event::Resync {
            cause,
            resume_point,
            items,
        } => {
            assert_eq!(
                (cause, resume_point, items.len()),
                (ResyncCause::Expired, pt(90), 1)
            );
        }
        e => panic!("not a resync: {e:?}"),
    }
    quiet(&mut w).await;
    assert_eq!(opens(&up), [5, 90]);
}

/// verifies: REQ-DATA-118
/// A saved point of another log (the epoch differs: the log was made again by a restore or a reset, and its numbers
/// began again) and one with no epoch (saved before epochs) are handed to store@ as they are, refused there, and end in
/// a listing that replaces the state; the watch then follows the new log under its epoch, and the change that has a
/// sequence below the old point is applied.
#[tokio::test]
async fn a_saved_point_of_another_epoch_or_of_none_starts_with_a_resync_and_follows_the_new_log() {
    for saved in [
        ResumePoint {
            epoch: 4,
            sequence: 500,
        },
        ResumePoint {
            epoch: 0,
            sequence: 500,
        },
    ] {
        let up = up(
            vec![
                Session::Refuse(ErrorCode::FailedPrecondition, "resume_point_expired"),
                Session::Stream(vec![Step::Msg(put_in(6, 4, "a/new", 1, "new")), Step::Hang]),
            ],
            vec![Listing::In(6, vec![("a/one", 1)], 3)],
        )
        .await;
        let mut w = lease_watch(&up, Some(saved));
        let want = ResumePoint {
            epoch: 6,
            sequence: 3,
        };
        match ev(&mut w).await {
            Event::Resync {
                cause,
                resume_point,
                items,
            } => assert_eq!(
                (cause, resume_point, items.len()),
                (ResyncCause::Expired, want, 1),
                "{saved:?}"
            ),
            e => panic!("not a resync: {e:?}"),
        }
        // Sequence 4 is far below the saved 500: the epoch is what tells it from a repeat.
        let put = ev(&mut w).await;
        is_put_in(&put, 6, "a/new", 1, "new", 4);
        assert_eq!(
            *up.script.open_epochs.lock().unwrap(),
            [saved.epoch, 6],
            "{saved:?}: the point is handed to store@ whole, and the new one under the new epoch"
        );
        assert_eq!(opens(&up), [500, 3]);
    }
}

/// verifies: REQ-DATA-118
/// The dedupe of applied points is inside one epoch. A stream that goes on after the log was made again names another
/// epoch with sequences below the applied one; none of it is dropped as a repeat or applied: the stream ends and the kind
/// is listed again, and the changes of the new log after that listing are applied, whatever the old numbers were.
#[tokio::test]
async fn a_message_of_another_epoch_is_never_a_repeat_and_lists_the_kind_again() {
    let up = up(
        vec![
            Session::Stream(vec![
                Step::Msg(put(501, "a/old", 2, "old")),
                // The log was made again under the open stream: its sequence begins again, below 501.
                Step::Msg(put_in(6, 2, "a/lost", 1, "lost")),
                Step::Hang,
            ]),
            Session::Stream(vec![
                Step::Msg(put_in(6, 4, "a/new", 1, "new")),
                Step::Msg(bookmark_in(6, 5)),
                Step::Hang,
            ]),
        ],
        vec![
            Listing::Items(vec![], 500),
            Listing::In(6, vec![("a/lost", 1)], 3),
        ],
    )
    .await;
    let mut w = lease_watch(&up, None);
    assert!(matches!(ev(&mut w).await, Event::Resync { .. }));
    is_put(&ev(&mut w).await, "a/old", 2, "old", 501);
    // The put of epoch 6 is not delivered: the next thing is the listing of the new log.
    match ev(&mut w).await {
        Event::Resync {
            cause,
            resume_point,
            items,
        } => {
            assert_eq!(
                (cause, resume_point, ids(&items)),
                (
                    ResyncCause::Expired,
                    ResumePoint {
                        epoch: 6,
                        sequence: 3
                    },
                    vec!["a/lost"]
                )
            );
        }
        e => panic!("not a resync: {e:?}"),
    }
    is_put_in(&ev(&mut w).await, 6, "a/new", 1, "new", 4);
    match ev(&mut w).await {
        Event::Bookmark { resume_point } => assert_eq!(
            resume_point,
            ResumePoint {
                epoch: 6,
                sequence: 5
            }
        ),
        e => panic!("not a bookmark: {e:?}"),
    }
    assert_eq!(*up.script.open_epochs.lock().unwrap(), [5, 6]);
    assert_eq!(opens(&up), [500, 3]);
}

/// verifies: REQ-DATA-118
/// A bookmark or a delete of another epoch moves nothing either: the point stays where it was and the kind is listed again.
#[tokio::test]
async fn a_bookmark_of_another_epoch_does_not_move_the_point() {
    let up = up(
        vec![
            Session::Stream(vec![Step::Msg(bookmark_in(6, 900)), Step::Hang]),
            Session::Stream(vec![Step::Hang]),
        ],
        vec![Listing::Items(vec![], 10), Listing::In(6, vec![], 3)],
    )
    .await;
    let mut w = lease_watch(&up, None);
    assert!(matches!(ev(&mut w).await, Event::Resync { .. }));
    // Not a bookmark at 900: the stream is of another log, and the next thing said is the listing of it.
    match ev(&mut w).await {
        Event::Resync {
            cause,
            resume_point,
            ..
        } => assert_eq!(
            (cause, resume_point),
            (
                ResyncCause::Expired,
                ResumePoint {
                    epoch: 6,
                    sequence: 3
                }
            )
        ),
        e => panic!("not a resync: {e:?}"),
    }
    assert_eq!(
        w.resume_point(),
        ResumePoint {
            epoch: 6,
            sequence: 3
        }
    );
}

/// verifies: REQ-DATA-118
/// A listing that names a position with no epoch is a store out of its contract: the watch ends with an error and
/// builds nothing on a number that could be the same in another log.
#[tokio::test]
async fn a_listing_with_a_position_and_no_epoch_ends_the_watch() {
    let up = up(vec![], vec![Listing::In(0, vec![("a/one", 1)], 10)]).await;
    let mut w = lease_watch(&up, None);
    assert!(matches!(end(&mut w).await, Error::Protocol(_)));
    assert_eq!(up.script.opens.lock().unwrap().len(), 0);
}

/// A store that keeps expiring the point does not make the watch list in a tight loop: each listing after the first
/// waits, by the backoff.
#[tokio::test]
async fn repeated_expiry_is_backed_off() {
    let up = up(
        vec![
            Session::Refuse(ErrorCode::FailedPrecondition, "resume_point_expired"),
            Session::Refuse(ErrorCode::FailedPrecondition, "resume_point_expired"),
            Session::Stream(vec![Step::Hang]),
        ],
        vec![
            Listing::Items(vec![], 10),
            Listing::Items(vec![], 20),
            Listing::Items(vec![], 30),
        ],
    )
    .await;
    let mut w = lease_watch(&up, None);
    let t0 = Instant::now();
    for _ in 0..3 {
        assert!(matches!(ev(&mut w).await, Event::Resync { .. }));
    }
    // The first resync of the start waits for nothing, the second for 0 (the first expiry), the third for 30 ms.
    assert!(
        t0.elapsed() >= Duration::from_millis(30),
        "{:?}",
        t0.elapsed()
    );
    quiet(&mut w).await;
    assert_eq!(opens(&up), [10, 20, 30]);
}

// ---- failing closed ----

/// verifies: REQ-DATA-109
/// A value that does not decode as the kind's message ends the watch with `Decode`: it is neither skipped nor
/// delivered, and every later call says the watch has ended. The same for an item of the listing.
#[tokio::test]
async fn a_value_that_does_not_decode_ends_the_watch() {
    let broken = WatchResponse {
        resume_point: 12,
        log_epoch: EPOCH,
        r#type: ChangeType::CHANGE_TYPE_PUT.into(),
        item: wire("lease", "a/bad", 1, &[0xff, 0xff, 0xff]).into(),
        ..WatchResponse::default()
    };
    let up = up(
        vec![Session::Stream(vec![
            Step::Msg(put(11, "a/one", 1, "one")),
            Step::Msg(broken),
            Step::Msg(put(13, "a/after", 1, "after")),
            Step::Hang,
        ])],
        vec![Listing::Items(vec![], 10)],
    )
    .await;
    let mut w = lease_watch(&up, None);
    assert!(matches!(ev(&mut w).await, Event::Resync { .. }));
    is_put(&ev(&mut w).await, "a/one", 1, "one", 11);
    assert!(matches!(end(&mut w).await, Error::Decode));
    assert_eq!(
        w.resume_point(),
        pt(11),
        "the point did not move past the item"
    );
    assert!(matches!(end(&mut w).await, Error::Closed));
    assert!(matches!(end(&mut w).await, Error::Closed));

    // An item of the listing that does not decode ends the watch before any stream is opened.
    let up2 = self::up(
        vec![],
        vec![Listing::Items(vec![("a/ok", 1), ("bad", 1)], 10)],
    )
    .await;
    let mut w2 = lease_watch(&up2, None);
    assert!(matches!(end(&mut w2).await, Error::Decode));
    assert!(matches!(end(&mut w2).await, Error::Closed));
    assert_eq!(up2.script.opens.lock().unwrap().len(), 0);
}

/// verifies: REQ-DATA-109
/// A change the protocol does not allow ends the watch: no sequence, no item, an unknown type, or an item of another
/// kind. The store is not trusted to be well formed when the reader's answer is "not revoked".
#[tokio::test]
async fn a_malformed_change_ends_the_watch() {
    let mut no_seq = put(11, "a/x", 1, "x");
    no_seq.resume_point = 0;
    let mut no_item = put(11, "a/x", 1, "x");
    no_item.item = Default::default();
    let mut unknown = put(11, "a/x", 1, "x");
    unknown.r#type = ChangeType::CHANGE_TYPE_UNSPECIFIED.into();
    let mut other_kind = put(11, "a/x", 1, "x");
    other_kind.item = wire("person", "a/x", 1, &prov("x").encode_to_vec()).into();
    for (name, m) in [
        ("no sequence", no_seq),
        ("no item", no_item),
        ("unknown type", unknown),
        ("another kind", other_kind),
    ] {
        let up = up(
            vec![Session::Stream(vec![Step::Msg(m), Step::Hang])],
            vec![Listing::Items(vec![], 10)],
        )
        .await;
        let mut w = lease_watch(&up, None);
        assert!(matches!(ev(&mut w).await, Event::Resync { .. }));
        let e = end(&mut w).await;
        assert!(matches!(e, Error::Protocol(_)), "{name}: {e:?}");
        assert!(matches!(end(&mut w).await, Error::Closed), "{name}");
    }
}

/// verifies: REQ-DATA-109
/// A refusal that a retry cannot cure ends the watch at once, at the call and in the stream; one that a retry may
/// cure does not.
#[tokio::test]
async fn a_refusal_of_a_rule_ends_the_watch_and_a_busy_store_does_not() {
    for code in [
        ErrorCode::PermissionDenied,
        ErrorCode::InvalidArgument,
        ErrorCode::FailedPrecondition,
    ] {
        let up = up(
            vec![Session::Refuse(code, "rule")],
            vec![Listing::Items(vec![], 10)],
        )
        .await;
        let mut w = lease_watch(&up, None);
        assert!(matches!(ev(&mut w).await, Event::Resync { .. }));
        assert!(
            matches!(end(&mut w).await, Error::Rpc(c, _) if c.code == code),
            "{code:?}"
        );
        assert!(matches!(end(&mut w).await, Error::Closed));
    }
    // The limit of 16 watches a caller holds: the old stream may not be given back yet.
    let up = up(
        vec![
            Session::Refuse(ErrorCode::ResourceExhausted, "watch_limit"),
            Session::Stream(vec![Step::Msg(put(11, "a/one", 1, "one")), Step::Hang]),
        ],
        vec![Listing::Items(vec![], 10)],
    )
    .await;
    let mut w = lease_watch(&up, None);
    assert!(matches!(ev(&mut w).await, Event::Resync { .. }));
    assert!(matches!(ev(&mut w).await, Event::Interrupted { .. }));
    is_put(&ev(&mut w).await, "a/one", 1, "one", 11);
}

/// verifies: REQ-DATA-109
/// A kind with no change log is refused, not watched from a position that does not exist: a listing that names 0
/// ends the watch, and a config kind is refused when the watch is built.
#[tokio::test]
async fn a_kind_with_no_change_log_is_refused() {
    let up = up(vec![], vec![Listing::In(0, vec![("a/one", 1)], 0)]).await;
    let mut w = lease_watch(&up, None);
    assert!(matches!(end(&mut w).await, Error::NotWatchable));
    assert_eq!(
        up.script.opens.lock().unwrap().len(),
        0,
        "no watch was opened"
    );
    assert!(matches!(
        Store::<KeyPlan>::new(up.client.clone()).unwrap().watch(""),
        Err(Error::NotWatchable)
    ));
    // A tenant that does not fit the kind is refused before any call.
    assert!(matches!(
        Store::<Lease>::new(up.client.clone()).unwrap().watch("acme"),
        Err(Error::Address(f)) if f == "tenant"
    ));
}

/// verifies: REQ-DATA-109
/// A listing that names an epoch and position 0 is an engine out of its contract (a log starts with a marker row, so its
/// head is never 0): it is not taken for a kind with no log, and the loop says what is wrong rather than start a watch
/// from "now" that would lose what changed since the listing.
#[tokio::test]
async fn a_listing_with_an_epoch_and_no_position_is_a_broken_contract_not_a_kind_without_a_log() {
    let up = up(vec![], vec![Listing::Items(vec![], 0)]).await;
    let mut w = lease_watch(&up, None);
    assert!(matches!(end(&mut w).await, Error::Protocol(m) if m.contains("no marker row")));
    assert_eq!(up.script.opens.lock().unwrap().len(), 0);
}

// ---- cancellation ----

/// verifies: REQ-DATA-108
/// Dropping the watch ends its stream at the store, which gives the place back; dropping the future of `next` does
/// too, and the next call reconnects from the last point without losing or repeating an event.
#[tokio::test]
async fn a_cancelled_watch_closes_its_stream_and_a_cancelled_call_resumes() {
    let up = up(
        vec![
            Session::Stream(vec![Step::Msg(put(11, "a/one", 1, "one")), Step::Hang]),
            Session::Stream(vec![Step::Msg(put(12, "a/two", 1, "two")), Step::Hang]),
        ],
        vec![Listing::Items(vec![], 10)],
    )
    .await;
    let mut w = lease_watch(&up, None);
    assert!(matches!(ev(&mut w).await, Event::Resync { .. }));
    is_put(&ev(&mut w).await, "a/one", 1, "one", 11);
    assert_eq!(up.script.live.load(Ordering::SeqCst), 1);

    // The stream is quiet: a call that is given up drops the stream.
    assert!(
        tokio::time::timeout(Duration::from_millis(200), w.next())
            .await
            .is_err()
    );
    is_put(&ev(&mut w).await, "a/two", 1, "two", 12);
    assert_eq!(opens(&up), [10, 11]);

    drop(w);
    for _ in 0..200 {
        if up.script.live.load(Ordering::SeqCst) == 0 {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("the store still holds a stream of a watch that was dropped");
}

// ---- KeyRevocation ----

/// The reader of `KeyRevocation` follows the kind at no tenant, as the Go client's `OptionalTenant` and the rule of
/// store-api.md say: the wire tenant is empty and the segment is `key-revocation`.
#[tokio::test]
async fn the_revocation_reader_watches_at_no_tenant() {
    let up = up(
        vec![Session::Stream(vec![
            Step::Msg(WatchResponse {
                resume_point: 11,
                log_epoch: EPOCH,
                r#type: ChangeType::CHANGE_TYPE_PUT.into(),
                item: wire(
                    "key-revocation",
                    "kid/abc",
                    1,
                    &KeyRevocation {
                        target_kind: "kid".into(),
                        target: "abc".into(),
                        ..KeyRevocation::default()
                    }
                    .encode_to_vec(),
                )
                .into(),
                ..WatchResponse::default()
            }),
            Step::Hang,
        ])],
        vec![Listing::Items(vec![], 10)],
    )
    .await;
    let mut w = KeyRevocations::new(&up.client)
        .unwrap()
        .watch_with(opts(None))
        .unwrap();
    assert!(matches!(ev(&mut w).await, Event::Resync { .. }));
    match ev(&mut w).await {
        Event::Put { item, resume_point } => {
            assert_eq!(
                (item.tenant.as_str(), item.id.as_str(), resume_point),
                ("", "kid/abc", pt(11))
            );
            assert_eq!(item.value.target, "abc");
        }
        e => panic!("not a put: {e:?}"),
    }
    assert_eq!(
        *up.script.opens.lock().unwrap(),
        [("key-revocation".to_owned(), String::new(), 10)]
    );
}

// ---- the idle timeout ----

/// verifies: REQ-DATA-108
/// A stream that says nothing for the idle timeout is taken for dead (a store@ that is half open sends nothing, not
/// even an error): it is dropped, the watch says so and reconnects from the last point.
#[tokio::test]
async fn a_silent_stream_is_interrupted_after_the_idle_timeout() {
    let up = up(
        vec![
            Session::Stream(vec![Step::Msg(put(11, "a/one", 1, "one")), Step::Hang]),
            Session::Stream(vec![Step::Msg(put(12, "a/two", 1, "two")), Step::Hang]),
        ],
        vec![Listing::Items(vec![], 10)],
    )
    .await;
    let mut w = Store::<Lease>::new(up.client.clone())
        .unwrap()
        .watch_with(
            "",
            WatchOpts {
                idle_timeout: Duration::from_millis(150),
                ..opts(None)
            },
        )
        .unwrap();
    assert!(matches!(ev(&mut w).await, Event::Resync { .. }));
    is_put(&ev(&mut w).await, "a/one", 1, "one", 11);
    let t0 = Instant::now();
    match ev(&mut w).await {
        Event::Interrupted { reason, attempt } => {
            assert_eq!((reason.as_str(), attempt), ("no bookmark", 1));
        }
        e => panic!("not an interruption: {e:?}"),
    }
    assert!(
        t0.elapsed() >= Duration::from_millis(140),
        "{:?}",
        t0.elapsed()
    );
    is_put(&ev(&mut w).await, "a/two", 1, "two", 12);
    assert_eq!(opens(&up), [10, 11]);
    // The dead stream was dropped at the store.
    assert_eq!(up.script.live.load(Ordering::SeqCst), 1);
}

// ---- cancel safety ----

/// verifies: REQ-DATA-108
/// A call of `next` that is given up while the watch waits to retry does not shorten the wait: the deadline is kept, so
/// a loop of `select!` does not become a storm of reconnects.
#[tokio::test]
async fn a_cancelled_call_during_the_backoff_keeps_the_wait() {
    let up = up(
        vec![
            Session::Refuse(ErrorCode::Unavailable, "engine"),
            Session::Stream(vec![Step::Msg(put(11, "a/one", 1, "one")), Step::Hang]),
        ],
        vec![Listing::Items(vec![], 10)],
    )
    .await;
    let mut w = Store::<Lease>::new(up.client.clone())
        .unwrap()
        .watch_with(
            "",
            WatchOpts {
                backoff: Backoff {
                    initial: Duration::from_millis(400),
                    max: Duration::from_secs(1),
                },
                ..opts(None)
            },
        )
        .unwrap();
    assert!(matches!(ev(&mut w).await, Event::Resync { .. }));
    assert!(matches!(
        ev(&mut w).await,
        Event::Interrupted { attempt: 1, .. }
    ));
    let t0 = Instant::now();
    for _ in 0..3 {
        assert!(
            tokio::time::timeout(Duration::from_millis(50), w.next())
                .await
                .is_err(),
            "still waiting"
        );
    }
    assert_eq!(opens(&up), [10], "no reconnect while the wait lasts");
    is_put(&ev(&mut w).await, "a/one", 1, "one", 11);
    assert!(
        t0.elapsed() >= Duration::from_millis(380),
        "{:?}",
        t0.elapsed()
    );
    assert_eq!(opens(&up), [10, 10]);
}

/// verifies: REQ-DATA-108
/// A call of `next` that is given up in the middle of the listing leaves the watch as it was: the next call reads
/// the listing again from its first page and gives the whole state once.
#[tokio::test]
async fn a_cancelled_call_during_the_listing_reads_the_listing_again() {
    let up = up(
        vec![Session::Stream(vec![Step::Hang])],
        vec![
            Listing::Items(vec![("a/one", 1), ("a/two", 1), ("a/three", 1)], 10),
            Listing::Items(vec![("a/one", 1), ("a/two", 1), ("a/three", 1)], 10),
        ],
    )
    .await;
    *up.script.page_delay.lock().unwrap() = Duration::from_millis(200);
    let mut w = lease_watch(&up, None);
    assert!(
        tokio::time::timeout(Duration::from_millis(250), w.next())
            .await
            .is_err(),
        "the listing takes 600 ms"
    );
    *up.script.page_delay.lock().unwrap() = Duration::ZERO;
    match ev(&mut w).await {
        Event::Resync {
            cause,
            items,
            resume_point,
        } => {
            assert_eq!((cause, resume_point), (ResyncCause::Start, pt(10)));
            assert_eq!(ids(&items), ["a/one", "a/two", "a/three"]);
        }
        e => panic!("not a resync: {e:?}"),
    }
    assert_eq!(up.script.lists.load(Ordering::SeqCst), 2);
    quiet(&mut w).await;
    assert_eq!(
        opens(&up),
        [10],
        "one stream, for the one listing that was given"
    );
}

// ---- listing, bookmarks, tenants, giving up ----

/// verifies: REQ-DATA-108
/// A listing that fails on its second page is reported and read again from its first page; the state given is one
/// listing and never the halves of two.
#[tokio::test]
async fn a_listing_that_fails_on_a_later_page_restarts_whole() {
    let up = up(
        vec![Session::Stream(vec![Step::Hang])],
        vec![
            Listing::Items(vec![("a/one", 1), ("a/two", 1), ("a/three", 1)], 10),
            Listing::Items(vec![("a/one", 2), ("a/two", 2), ("a/three", 2)], 12),
        ],
    )
    .await;
    *up.script.fail_at_page.lock().unwrap() = Some(1);
    let mut w = lease_watch(&up, None);
    assert!(matches!(
        ev(&mut w).await,
        Event::Interrupted { attempt: 1, .. }
    ));
    match ev(&mut w).await {
        Event::Resync {
            items,
            resume_point,
            ..
        } => {
            assert_eq!(resume_point, pt(12));
            assert_eq!(ids(&items), ["a/one", "a/two", "a/three"]);
            assert!(items.iter().all(|i| i.version == 2));
        }
        e => panic!("not a resync: {e:?}"),
    }
    quiet(&mut w).await;
    assert_eq!(opens(&up), [12]);
}

/// verifies: REQ-DATA-108
/// The point of a bookmark is the point a reconnect resumes from, though no change moved it.
#[tokio::test]
async fn a_bookmark_moves_the_point_a_reconnect_starts_from() {
    let up = up(
        vec![
            Session::Stream(vec![
                Step::Msg(put(11, "a/one", 1, "one")),
                Step::Msg(bookmark(20)),
                Step::End,
            ]),
            Session::Stream(vec![Step::Hang]),
        ],
        vec![Listing::Items(vec![], 10)],
    )
    .await;
    let mut w = lease_watch(&up, None);
    assert!(matches!(ev(&mut w).await, Event::Resync { .. }));
    is_put(&ev(&mut w).await, "a/one", 1, "one", 11);
    assert!(matches!(ev(&mut w).await, Event::Bookmark { resume_point } if resume_point == pt(20)));
    assert!(matches!(ev(&mut w).await, Event::Interrupted { .. }));
    quiet(&mut w).await;
    assert_eq!(opens(&up), [10, 20]);
}

/// verifies: REQ-DATA-108
/// A store that alternates a bookmark and an expired point is still backed off: a bookmark shows that the stream is
/// up, not that the log is being read, so it does not reset the count of listings the expiry forced.
#[tokio::test]
async fn a_bookmark_does_not_end_the_backoff_of_repeated_expiry() {
    let expiry = || {
        Session::Stream(vec![
            Step::Msg(bookmark(0)),
            Step::Fail(ErrorCode::FailedPrecondition, "resume_point_expired"),
        ])
    };
    let up = up(
        vec![expiry(), expiry(), Session::Stream(vec![Step::Hang])],
        vec![
            Listing::Items(vec![], 10),
            Listing::Items(vec![], 20),
            Listing::Items(vec![], 30),
        ],
    )
    .await;
    let mut w = lease_watch(&up, None);
    assert!(matches!(ev(&mut w).await, Event::Resync { .. }));
    assert!(matches!(ev(&mut w).await, Event::Bookmark { .. }));
    assert!(
        matches!(ev(&mut w).await, Event::Resync { .. }),
        "the first expiry waits for nothing"
    );
    assert!(matches!(ev(&mut w).await, Event::Bookmark { .. }));
    let t0 = Instant::now();
    assert!(matches!(ev(&mut w).await, Event::Resync { .. }));
    assert!(
        t0.elapsed() >= Duration::from_millis(25),
        "{:?}",
        t0.elapsed()
    );
}

/// verifies: REQ-DATA-108
/// A kind with a tenant is followed under a tenant: the tenant is on the listing and on the watch, the items carry
/// it, and a change of another tenant ends the watch.
#[tokio::test]
async fn a_tenant_scoped_watch_asks_for_its_tenant_and_refuses_another() {
    let person = |tenant: &str, seq| WatchResponse {
        resume_point: seq,
        log_epoch: EPOCH,
        r#type: ChangeType::CHANGE_TYPE_PUT.into(),
        item: wire_in("person", tenant, "p1", 1, &prov("p").encode_to_vec()).into(),
        ..WatchResponse::default()
    };
    let up = up(
        vec![Session::Stream(vec![
            Step::Msg(person("acme", 11)),
            Step::Msg(person("other", 12)),
            Step::Hang,
        ])],
        vec![Listing::Items(vec![("p0", 1)], 10)],
    )
    .await;
    let store = Store::<Person>::new(up.client.clone()).unwrap();
    assert!(matches!(store.watch(""), Err(Error::Address(f)) if f == "tenant"));
    assert!(matches!(store.watch("-"), Err(Error::Address(f)) if f == "tenant"));
    let mut w = store.watch_with("acme", opts(None)).unwrap();
    match ev(&mut w).await {
        Event::Resync { items, .. } => assert_eq!(items[0].tenant, "acme"),
        e => panic!("not a resync: {e:?}"),
    }
    match ev(&mut w).await {
        Event::Put { item, .. } => {
            assert_eq!((item.tenant.as_str(), item.id.as_str()), ("acme", "p1"))
        }
        e => panic!("not a put: {e:?}"),
    }
    assert!(matches!(end(&mut w).await, Error::Protocol(_)));
    assert_eq!(
        *up.script.opens.lock().unwrap(),
        [("person".to_owned(), "acme".to_owned(), 10)]
    );
}

/// verifies: REQ-DATA-108
/// With a limit to give up, a store that stays down ends the watch with `GaveUp` after reporting each failure;
/// without one the watch goes on.
#[tokio::test]
async fn a_watch_with_a_limit_gives_up_when_the_store_stays_down() {
    let up = up(vec![], vec![Listing::Items(vec![], 10)]).await;
    let mut w = Store::<Lease>::new(up.client.clone())
        .unwrap()
        .watch_with(
            "",
            WatchOpts {
                give_up_after: Some(Duration::from_millis(150)),
                ..opts(None)
            },
        )
        .unwrap();
    assert!(matches!(ev(&mut w).await, Event::Resync { .. }));
    let mut last = 0;
    let err = loop {
        match tokio::time::timeout(Duration::from_secs(5), w.next())
            .await
            .unwrap()
        {
            Ok(Event::Interrupted { attempt, .. }) => {
                assert_eq!(attempt, last + 1, "attempts count up");
                last = attempt;
            }
            Ok(e) => panic!("{e:?}"),
            Err(e) => break e,
        }
    };
    assert!(matches!(err, Error::GaveUp), "{err:?}");
    assert!(last >= 2, "{last}");
    assert!(matches!(end(&mut w).await, Error::Closed));
}

// ---- caught up ----

/// verifies: REQ-DATA-121
/// The state is unconfirmed after a listing and until the stream says it is caught up; the change before it does not
/// confirm it, an idle bookmark after it does not take it back, and a break does.
#[tokio::test]
async fn a_watch_is_unconfirmed_until_the_stream_says_it_is_caught_up() {
    let up = up(
        vec![Session::Stream(vec![
            Step::Msg(put(11, "a/one", 1, "one")),
            Step::Msg(caught(12)),
            Step::Msg(bookmark(13)),
            Step::Msg(put(14, "a/two", 1, "two")),
            Step::Hang,
        ])],
        vec![Listing::Items(vec![], 10)],
    )
    .await;
    let mut w = lease_watch(&up, None);
    assert!(
        !w.caught_up(),
        "nothing is confirmed before the first event"
    );
    assert!(matches!(ev(&mut w).await, Event::Resync { .. }));
    assert!(!w.caught_up(), "a listing is not confirmed by itself");
    is_put(&ev(&mut w).await, "a/one", 1, "one", 11);
    assert!(
        !w.caught_up(),
        "the first change of a reconnect may be the first of many rows still to come"
    );
    match ev(&mut w).await {
        Event::CaughtUp { resume_point } => assert_eq!(resume_point, pt(12)),
        e => panic!("not caught up: {e:?}"),
    }
    assert!(w.caught_up());
    assert_eq!(
        w.resume_point(),
        pt(12),
        "the point is at the head the stream was caught up to"
    );
    assert!(matches!(ev(&mut w).await, Event::Bookmark { resume_point } if resume_point == pt(13)));
    assert!(
        w.caught_up(),
        "an idle bookmark does not take the confirmation back"
    );
    is_put(&ev(&mut w).await, "a/two", 1, "two", 14);
    assert!(w.caught_up(), "a later change keeps it");
}

/// verifies: REQ-DATA-121
/// An idle bookmark is no claim: a stream that has only said idle bookmarks has not said it is caught up.
#[tokio::test]
async fn an_idle_bookmark_does_not_confirm_the_state() {
    let up = up(
        vec![Session::Stream(vec![Step::Msg(bookmark(10)), Step::Hang])],
        vec![Listing::Items(vec![], 10)],
    )
    .await;
    let mut w = lease_watch(&up, None);
    assert!(matches!(ev(&mut w).await, Event::Resync { .. }));
    assert!(matches!(ev(&mut w).await, Event::Bookmark { .. }));
    assert!(!w.caught_up());
}

/// verifies: REQ-DATA-121
/// A break takes the confirmation away, the reconnect starts from the last point, and the new stream's bookmark gives it
/// back: after a store@ restart the reader waits for that bookmark and not for an idle one, and with nothing to deliver
/// it is the first message.
#[tokio::test]
async fn a_reconnect_is_confirmed_again_by_the_new_stream() {
    let up = up(
        vec![
            Session::Stream(vec![
                Step::Msg(caught(10)),
                Step::Msg(put(11, "a/one", 1, "one")),
                Step::End,
            ]),
            // The restart: rows behind the head, then the claim.
            Session::Stream(vec![
                Step::Msg(put(12, "a/two", 1, "two")),
                Step::Msg(caught(12)),
                Step::End,
            ]),
            // And again with nothing new: the claim is the first message.
            Session::Stream(vec![Step::Msg(caught(12)), Step::Hang]),
        ],
        vec![Listing::Items(vec![], 10)],
    )
    .await;
    let mut w = lease_watch(&up, None);
    assert!(matches!(ev(&mut w).await, Event::Resync { .. }));
    assert!(matches!(ev(&mut w).await, Event::CaughtUp { .. }));
    assert!(w.caught_up());
    is_put(&ev(&mut w).await, "a/one", 1, "one", 11);
    assert!(matches!(ev(&mut w).await, Event::Interrupted { .. }));
    assert!(!w.caught_up(), "a break takes it away");
    is_put(&ev(&mut w).await, "a/two", 1, "two", 12);
    assert!(
        !w.caught_up(),
        "the reconnect is not confirmed by its first change"
    );
    assert!(matches!(ev(&mut w).await, Event::CaughtUp { .. }));
    assert!(w.caught_up());
    assert!(matches!(ev(&mut w).await, Event::Interrupted { .. }));
    assert!(!w.caught_up());
    match ev(&mut w).await {
        Event::CaughtUp { resume_point } => assert_eq!(resume_point, pt(12)),
        e => panic!("not caught up at once: {e:?}"),
    }
    assert!(w.caught_up());
    assert_eq!(opens(&up), [10, 11, 12]);
}

/// verifies: REQ-DATA-121
/// A resync (store@ no longer holds the point, so the kind is listed again) takes the confirmation away too, until the
/// stream that follows the new listing says it is caught up.
#[tokio::test]
async fn a_resync_takes_the_confirmation_away() {
    let up = up(
        vec![
            Session::Stream(vec![
                Step::Msg(caught(10)),
                Step::Fail(ErrorCode::FailedPrecondition, "resume_point_expired"),
            ]),
            Session::Stream(vec![Step::Hang]),
        ],
        vec![
            Listing::Items(vec![], 10),
            Listing::Items(vec![("a/one", 1)], 50),
        ],
    )
    .await;
    let mut w = lease_watch(&up, None);
    assert!(matches!(ev(&mut w).await, Event::Resync { .. }));
    assert!(matches!(ev(&mut w).await, Event::CaughtUp { .. }));
    assert!(w.caught_up());
    assert!(matches!(
        ev(&mut w).await,
        Event::Resync {
            cause: ResyncCause::Expired,
            ..
        }
    ));
    assert!(
        !w.caught_up(),
        "the new state is not confirmed until its stream says so"
    );
}

/// verifies: REQ-DATA-121
/// A claim made about something else fails closed: a caught-up point below the applied one, and a change that says it.
#[tokio::test]
async fn a_claim_that_does_not_fit_the_stream_ends_the_watch() {
    let up1 = up(
        vec![Session::Stream(vec![
            Step::Msg(put(15, "a/one", 1, "one")),
            Step::Msg(caught(12)),
        ])],
        vec![Listing::Items(vec![], 10)],
    )
    .await;
    let mut w = lease_watch(&up1, None);
    assert!(matches!(ev(&mut w).await, Event::Resync { .. }));
    is_put(&ev(&mut w).await, "a/one", 1, "one", 15);
    assert!(matches!(end(&mut w).await, Error::Protocol(_)));
    assert!(!w.caught_up(), "an ended watch confirms nothing");

    let mut says = put(11, "a/one", 1, "one");
    says.caught_up = true;
    let up2 = up(
        vec![Session::Stream(vec![Step::Msg(says)])],
        vec![Listing::Items(vec![], 10)],
    )
    .await;
    let mut w = lease_watch(&up2, None);
    assert!(matches!(ev(&mut w).await, Event::Resync { .. }));
    assert!(matches!(end(&mut w).await, Error::Protocol(_)));
}

/// verifies: REQ-DATA-123
/// A stream that says it is caught up and then dies is a failure, not progress: the count of failures grows to the
/// cap and the wait with it, and `give_up_after` is reached. Without that a store@ whose open works and whose tail
/// does not would be asked again every first wait, for ever, and each time audited.
#[tokio::test]
async fn a_stream_that_is_caught_up_and_dies_does_not_end_the_failures() {
    let cycle = || Session::Stream(vec![Step::Msg(caught(10)), Step::End]);
    let up = up(
        (0..8).map(|_| cycle()).collect(),
        vec![Listing::Items(vec![], 10)],
    )
    .await;
    let mut w = lease_watch(&up, None);
    assert!(matches!(ev(&mut w).await, Event::Resync { .. }));
    let mut attempts = Vec::new();
    let t0 = Instant::now();
    for _ in 0..6 {
        assert!(matches!(ev(&mut w).await, Event::CaughtUp { .. }));
        assert!(w.caught_up());
        match ev(&mut w).await {
            Event::Interrupted { attempt, .. } => attempts.push(attempt),
            e => panic!("not an interruption: {e:?}"),
        }
        assert!(!w.caught_up());
    }
    assert_eq!(attempts, [1, 2, 3, 4, 5, 6], "the count grows every cycle");
    // Waits of 30, 60, 120, 200, 200 ms (the cap) before the cycles after the first.
    assert!(
        t0.elapsed() >= Duration::from_millis(30 + 60 + 120 + 200 + 200),
        "{:?}",
        t0.elapsed()
    );

    // And a limit on the failures is reached by such a store.
    let up = up_again(8).await;
    let mut w = Store::<Lease>::new(up.client.clone())
        .unwrap()
        .watch_with(
            "",
            WatchOpts {
                give_up_after: Some(Duration::from_millis(250)),
                ..opts(None)
            },
        )
        .unwrap();
    let mut gave_up = false;
    for _ in 0..40 {
        match tokio::time::timeout(Duration::from_secs(5), w.next())
            .await
            .unwrap()
        {
            Ok(_) => {}
            Err(Error::GaveUp) => {
                gave_up = true;
                break;
            }
            Err(e) => panic!("{e:?}"),
        }
    }
    assert!(
        gave_up,
        "a store that never delivers a change is given up on"
    );
}

async fn up_again(n: usize) -> Up {
    up(
        (0..n)
            .map(|_| Session::Stream(vec![Step::Msg(caught(10)), Step::End]))
            .collect(),
        vec![Listing::Items(vec![], 10)],
    )
    .await
}

/// verifies: REQ-DATA-121
/// A call of `next` that is given up while it waits on the stream takes the stream and the confirmation with it: the
/// state is unconfirmed until the stream that replaces it says it is caught up, and the rows it replays do not confirm it.
#[tokio::test]
async fn a_cancelled_call_takes_the_confirmation_with_the_stream() {
    let up = up(
        vec![
            Session::Stream(vec![Step::Msg(caught(10)), Step::Hang]),
            Session::Stream(vec![
                Step::Msg(put(11, "a/one", 1, "one")),
                Step::Msg(caught(11)),
                Step::Hang,
            ]),
        ],
        vec![Listing::Items(vec![], 10)],
    )
    .await;
    let mut w = lease_watch(&up, None);
    assert!(matches!(ev(&mut w).await, Event::Resync { .. }));
    assert!(matches!(ev(&mut w).await, Event::CaughtUp { .. }));
    assert!(w.caught_up());
    // A `select!` takes another branch while the call waits on the quiet stream.
    quiet(&mut w).await;
    assert!(
        !w.caught_up(),
        "the stream is gone, and with it the claim: a backlog may be coming"
    );
    is_put(&ev(&mut w).await, "a/one", 1, "one", 11);
    assert!(!w.caught_up(), "a replayed row does not confirm");
    assert!(matches!(ev(&mut w).await, Event::CaughtUp { .. }));
    assert!(w.caught_up());
    assert_eq!(opens(&up), [10, 10]);
}

/// verifies: REQ-DATA-123
/// The age of the confirmation is the age of the newest claim, and only a claim moves it: idle bookmarks and changes show
/// that store@ is talking, not that its log is fresh, so a stream that keeps talking without renewing the claim ages out
/// for a reader that bounds it. The first claim is dated by the moment the stream was opened. A renewal moves it.
#[tokio::test]
async fn only_a_claim_moves_the_age_of_the_confirmation() {
    let gap = || Step::Pause(Duration::from_millis(120));
    let up = up(
        vec![Session::Stream(vec![
            Step::Msg(caught(10)),
            gap(),
            Step::Msg(bookmark(10)),
            gap(),
            Step::Msg(put(11, "a/one", 1, "one")),
            gap(),
            Step::Msg(caught(11)),
            Step::Hang,
        ])],
        vec![Listing::Items(vec![], 10)],
    )
    .await;
    let mut w = lease_watch(&up, None);
    assert!(w.last_claim().is_none());
    assert!(matches!(ev(&mut w).await, Event::Resync { .. }));
    assert!(matches!(ev(&mut w).await, Event::CaughtUp { .. }));
    let first = w.last_claim().expect("claimed");
    assert!(first <= Instant::now());
    assert!(w.caught_up_within(Duration::from_secs(5)));
    // Talk without a claim: confirmed, and the claim ages.
    assert!(matches!(ev(&mut w).await, Event::Bookmark { .. }));
    is_put(&ev(&mut w).await, "a/one", 1, "one", 11);
    assert!(w.caught_up());
    assert_eq!(
        w.last_claim(),
        Some(first),
        "a bookmark and a change do not renew"
    );
    assert!(
        !w.caught_up_within(Duration::from_millis(100)),
        "heard from, but not renewed within the bound: fails closed"
    );
    assert!(w.caught_up_within(Duration::from_secs(30)));
    // A renewal moves it.
    assert!(matches!(ev(&mut w).await, Event::CaughtUp { .. }));
    let second = w.last_claim().unwrap();
    assert!(second > first, "a renewal is newer");
    assert!(w.caught_up_within(Duration::from_secs(2)));
}

/// verifies: REQ-DATA-123
/// The first claim of a stream is dated by the moment the stream was opened, not by the moment it was read: it was made
/// after the opening and not before, and a stream that took its time to say it leaves a claim that is that old.
#[tokio::test]
async fn the_first_claim_is_dated_by_the_opening() {
    let up = up(
        vec![Session::Stream(vec![
            Step::Pause(Duration::from_millis(300)),
            Step::Msg(caught(10)),
            Step::Hang,
        ])],
        vec![Listing::Items(vec![], 10)],
    )
    .await;
    let mut w = lease_watch(&up, None);
    assert!(matches!(ev(&mut w).await, Event::Resync { .. }));
    assert!(matches!(ev(&mut w).await, Event::CaughtUp { .. }));
    assert!(
        !w.caught_up_within(Duration::from_millis(250)),
        "the claim is at least as old as the wait for it"
    );
    assert!(w.caught_up_within(Duration::from_secs(10)));
}

/// verifies: REQ-DATA-123
/// A renewal counts as new only if the read of it had to wait for it. A consumer that was away while renewals piled up
/// behind a change it has not read reads them back to back, each at once: none of them is new, however small the gap
/// between its calls, and a reader on another task that bounds the age of the claim is not told "fresh" while the change
/// is unread. A renewal that arrives while the consumer waits for it is new.
#[tokio::test]
async fn renewals_that_were_queued_are_not_dated_new_and_one_that_was_waited_for_is() {
    let up = up(
        vec![Session::Stream(vec![
            Step::Msg(caught(10)),
            // Queued while the consumer is away: three renewals, then the change they stand in front of.
            Step::Msg(caught(10)),
            Step::Msg(caught(10)),
            Step::Msg(caught(10)),
            Step::Msg(put(11, "a/one", 1, "one")),
            Step::Pause(Duration::from_millis(1200)),
            Step::Msg(caught(11)),
            Step::Hang,
        ])],
        vec![Listing::Items(vec![], 10)],
    )
    .await;
    let mut w = lease_watch(&up, None);
    let reader = w.confirmation();
    assert!(matches!(ev(&mut w).await, Event::Resync { .. }));
    assert!(matches!(ev(&mut w).await, Event::CaughtUp { .. }));
    let first = w.last_claim().unwrap();
    // The consumer is away; the renewals and the change are queued in the stream.
    tokio::time::sleep(Duration::from_millis(300)).await;
    for _ in 0..3 {
        assert!(matches!(ev(&mut w).await, Event::CaughtUp { .. }));
        assert_eq!(w.last_claim(), Some(first), "a queued renewal is not new");
        assert!(
            !reader.caught_up_within(Duration::from_millis(200)),
            "and the reader is not told fresh while the change behind them is unread"
        );
    }
    is_put(&ev(&mut w).await, "a/one", 1, "one", 11);
    // The next one is waited for.
    assert!(matches!(ev(&mut w).await, Event::CaughtUp { .. }));
    assert!(
        w.last_claim().unwrap() > first,
        "a renewal waited for is new"
    );
    assert!(reader.caught_up_within(Duration::from_secs(5)));
}

/// verifies: REQ-DATA-123
/// A stream that was caught up and goes on talking without a new claim (a tail that fell behind the log) is not kept: after
/// `claim_timeout` the watch says so, drops the stream and reconnects with a count of failures that grows, and the
/// reader on another task is unconfirmed at once.
#[tokio::test]
async fn a_confirmed_stream_that_is_not_renewed_is_interrupted_and_reconnected() {
    let up = up(
        vec![
            Session::Stream(vec![
                Step::Msg(caught(10)),
                Step::Pause(Duration::from_millis(150)),
                Step::Msg(bookmark(10)),
                Step::Pause(Duration::from_millis(150)),
                Step::Msg(bookmark(10)),
                Step::Pause(Duration::from_millis(150)),
                Step::Msg(bookmark(10)),
                Step::Hang,
            ]),
            Session::Stream(vec![Step::Msg(caught(10)), Step::Hang]),
        ],
        vec![Listing::Items(vec![], 10)],
    )
    .await;
    let mut w = Store::<Lease>::new(up.client.clone())
        .unwrap()
        .watch_with(
            "",
            WatchOpts {
                claim_timeout: Duration::from_millis(300),
                ..opts(None)
            },
        )
        .unwrap();
    let reader = w.confirmation();
    assert!(matches!(ev(&mut w).await, Event::Resync { .. }));
    assert!(matches!(ev(&mut w).await, Event::CaughtUp { .. }));
    let mut bookmarks = 0;
    let reason = loop {
        match ev(&mut w).await {
            Event::Bookmark { .. } => {
                bookmarks += 1;
                assert!(reader.caught_up(), "confirmed, and getting old");
            }
            Event::Interrupted { reason, attempt } => {
                assert_eq!(attempt, 1);
                break reason;
            }
            e => panic!("{e:?}"),
        }
    };
    assert_eq!(reason, "claim not renewed");
    assert!(bookmarks >= 1, "it kept talking");
    assert!(!reader.caught_up());
    assert!(matches!(ev(&mut w).await, Event::CaughtUp { .. }));
    assert_eq!(opens(&up), [10, 10]);
}

/// verifies: REQ-DATA-123
/// Renewals that were queued do not restart the clock of the claim either: a consumer that reads only queued renewals, one
/// at a time and slowly, is cut off when no new claim has been waited for within `claim_timeout`.
#[tokio::test]
async fn queued_renewals_do_not_keep_the_claim_clock_going() {
    let mut steps = vec![Step::Msg(caught(10))];
    steps.extend((0..8).map(|_| Step::Msg(caught(10))));
    steps.push(Step::Hang);
    let up = up(
        vec![Session::Stream(steps)],
        vec![Listing::Items(vec![], 10)],
    )
    .await;
    let mut w = Store::<Lease>::new(up.client.clone())
        .unwrap()
        .watch_with(
            "",
            WatchOpts {
                claim_timeout: Duration::from_millis(500),
                ..opts(None)
            },
        )
        .unwrap();
    assert!(matches!(ev(&mut w).await, Event::Resync { .. }));
    assert!(matches!(ev(&mut w).await, Event::CaughtUp { .. }));
    let mut reason = None;
    for _ in 0..8 {
        tokio::time::sleep(Duration::from_millis(200)).await;
        if let Event::Interrupted { reason: r, .. } = ev(&mut w).await {
            reason = Some(r);
            break;
        }
    }
    assert_eq!(reason.as_deref(), Some("claim not renewed"));
}

/// verifies: REQ-DATA-123
/// A store that inches the position forward for ever never claims and never stalls on progress: the clock of the claim
/// ends it, whatever the progress.
#[tokio::test]
async fn progress_that_never_ends_in_a_claim_is_cut_off_by_the_claim_clock() {
    let mut steps = Vec::new();
    for seq in 11..=60 {
        steps.push(Step::Msg(bookmark(seq)));
        steps.push(Step::Pause(Duration::from_millis(40)));
    }
    steps.push(Step::Hang);
    let up = up(
        vec![Session::Stream(steps)],
        vec![Listing::Items(vec![], 10)],
    )
    .await;
    let mut w = Store::<Lease>::new(up.client.clone())
        .unwrap()
        .watch_with(
            "",
            WatchOpts {
                catch_up_timeout: Duration::from_secs(30),
                claim_timeout: Duration::from_millis(500),
                ..opts(None)
            },
        )
        .unwrap();
    assert!(matches!(ev(&mut w).await, Event::Resync { .. }));
    loop {
        match ev(&mut w).await {
            Event::Bookmark { .. } => {}
            Event::Interrupted { reason, .. } => {
                assert_eq!(reason, "catch-up stalled");
                break;
            }
            e => panic!("{e:?}"),
        }
    }
}

/// verifies: REQ-DATA-123
/// Dropping the watch takes the confirmation away from a reader that holds the handle.
#[tokio::test]
async fn dropping_the_watch_unconfirms_the_handle() {
    let up = up(
        vec![Session::Stream(vec![Step::Msg(caught(10)), Step::Hang])],
        vec![Listing::Items(vec![], 10)],
    )
    .await;
    let mut w = lease_watch(&up, None);
    let reader = w.confirmation();
    assert!(matches!(ev(&mut w).await, Event::Resync { .. }));
    assert!(matches!(ev(&mut w).await, Event::CaughtUp { .. }));
    assert!(reader.caught_up_within(Duration::from_secs(5)));
    drop(w);
    assert!(!reader.caught_up());
    assert!(!reader.caught_up_within(Duration::from_secs(5)));
}

/// verifies: REQ-DATA-123
/// A reader on another task holds a handle that shows the confirmation while the watch task waits for the next message,
/// and takes it away when that wait is given up.
#[tokio::test]
async fn a_reader_on_another_task_sees_the_confirmation_while_the_call_waits_and_loses_it_with_the_stream()
 {
    let up = up(
        vec![Session::Stream(vec![Step::Msg(caught(10)), Step::Hang])],
        vec![Listing::Items(vec![], 10)],
    )
    .await;
    let mut w = lease_watch(&up, None);
    let reader = w.confirmation();
    assert!(!reader.caught_up());
    assert!(matches!(ev(&mut w).await, Event::Resync { .. }));
    assert!(matches!(ev(&mut w).await, Event::CaughtUp { .. }));
    let (given_up, seen) = tokio::join!(
        tokio::time::timeout(Duration::from_millis(300), w.next()),
        async {
            tokio::time::sleep(Duration::from_millis(100)).await;
            (
                reader.caught_up(),
                reader.caught_up_within(Duration::from_secs(5)),
            )
        }
    );
    assert!(given_up.is_err(), "the call waited");
    assert_eq!(
        seen,
        (true, true),
        "confirmed while the stream is waited on"
    );
    assert!(
        !reader.caught_up(),
        "the call was given up, and the stream with it"
    );
    assert!(reader.last_claim().is_none());
}

/// verifies: REQ-DATA-123
/// A bookmark that moves the position is progress toward the claim: a catch-up through the rows of other kinds is slow, not
/// stalled, though it says nothing else for longer than the timeout.
#[tokio::test]
async fn a_catch_up_that_makes_progress_is_not_a_stall() {
    let gap = || Step::Pause(Duration::from_millis(80));
    let mut steps = Vec::new();
    for seq in 11..=17 {
        steps.push(Step::Msg(bookmark(seq)));
        steps.push(gap());
    }
    steps.push(Step::Msg(caught(17)));
    steps.push(Step::Hang);
    let up = up(
        vec![Session::Stream(steps)],
        vec![Listing::Items(vec![], 10)],
    )
    .await;
    let mut w = Store::<Lease>::new(up.client.clone())
        .unwrap()
        .watch_with(
            "",
            WatchOpts {
                catch_up_timeout: Duration::from_millis(400),
                ..opts(None)
            },
        )
        .unwrap();
    assert!(matches!(ev(&mut w).await, Event::Resync { .. }));
    let t0 = Instant::now();
    let mut n = 0;
    loop {
        match ev(&mut w).await {
            Event::Bookmark { .. } => n += 1,
            Event::CaughtUp { resume_point } => {
                assert_eq!(resume_point, pt(17));
                break;
            }
            e => panic!("a catch-up with progress was interrupted: {e:?}"),
        }
    }
    assert_eq!(n, 7);
    assert!(
        t0.elapsed() > Duration::from_millis(400),
        "it took longer than the timeout in all: {:?}",
        t0.elapsed()
    );
}

/// verifies: REQ-DATA-123
/// A stream that is not caught up within the catch-up timeout is interrupted with a reason that says so, though its idle
/// bookmarks keep coming, and the reconnect after it waits longer each time.
#[tokio::test]
async fn a_stream_that_does_not_catch_up_in_time_is_interrupted_and_backed_off() {
    let up = up(
        vec![
            Session::Stream(vec![Step::Msg(bookmark(10)), Step::Hang]),
            Session::Stream(vec![Step::Msg(bookmark(10)), Step::Hang]),
            Session::Stream(vec![Step::Msg(caught(10)), Step::Hang]),
        ],
        vec![Listing::Items(vec![], 10)],
    )
    .await;
    let mut w = Store::<Lease>::new(up.client.clone())
        .unwrap()
        .watch_with(
            "",
            WatchOpts {
                catch_up_timeout: Duration::from_millis(150),
                ..opts(None)
            },
        )
        .unwrap();
    assert!(matches!(ev(&mut w).await, Event::Resync { .. }));
    let mut reasons = Vec::new();
    let mut t = Instant::now();
    let mut stalls = Vec::new();
    loop {
        match ev(&mut w).await {
            Event::Bookmark { .. } => assert!(!w.caught_up()),
            Event::Interrupted { reason, attempt } => {
                reasons.push((reason, attempt));
                stalls.push(t.elapsed());
                t = Instant::now();
            }
            Event::CaughtUp { .. } => break,
            e => panic!("{e:?}"),
        }
    }
    assert_eq!(
        reasons,
        [
            ("catch-up stalled".to_owned(), 1),
            ("catch-up stalled".to_owned(), 2)
        ]
    );
    assert!(
        stalls.iter().all(|d| *d >= Duration::from_millis(100)),
        "{stalls:?}"
    );
    assert!(w.caught_up());
    assert_eq!(opens(&up), [10, 10, 10]);
}

/// verifies: REQ-DATA-123
/// The failures end when a caught-up stream has stayed up, and not for a stream that was never caught up: the idle
/// bookmarks of a stream that cannot catch up say it is alive, not that the log is being read.
#[tokio::test]
async fn a_caught_up_stream_that_stays_up_ends_the_failures_and_one_that_is_not_does_not() {
    let stable = |ms| WatchOpts {
        stable_after: Duration::from_millis(ms),
        ..opts(None)
    };
    let pause = Step::Pause(Duration::from_millis(150));
    // Caught up and up for longer than the stable time: the next failure is the first again.
    let up1 = up(
        vec![
            Session::Refuse(ErrorCode::Unavailable, "engine"),
            Session::Stream(vec![
                Step::Msg(caught(10)),
                pause,
                Step::Msg(bookmark(10)),
                Step::End,
            ]),
        ],
        vec![Listing::Items(vec![], 10)],
    )
    .await;
    let mut w = Store::<Lease>::new(up1.client.clone())
        .unwrap()
        .watch_with("", stable(100))
        .unwrap();
    assert!(matches!(ev(&mut w).await, Event::Resync { .. }));
    assert!(matches!(
        ev(&mut w).await,
        Event::Interrupted { attempt: 1, .. }
    ));
    assert!(matches!(ev(&mut w).await, Event::CaughtUp { .. }));
    assert!(matches!(ev(&mut w).await, Event::Bookmark { .. }));
    assert!(
        matches!(ev(&mut w).await, Event::Interrupted { attempt: 1, .. }),
        "a stream that stayed up and caught up is not a failure in the count"
    );

    // Up as long, and never caught up: the count goes on.
    let up2 = up(
        vec![
            Session::Refuse(ErrorCode::Unavailable, "engine"),
            Session::Stream(vec![
                Step::Msg(bookmark(10)),
                Step::Pause(Duration::from_millis(150)),
                Step::Msg(bookmark(10)),
                Step::End,
            ]),
        ],
        vec![Listing::Items(vec![], 10)],
    )
    .await;
    let mut w = Store::<Lease>::new(up2.client.clone())
        .unwrap()
        .watch_with("", stable(100))
        .unwrap();
    assert!(matches!(ev(&mut w).await, Event::Resync { .. }));
    assert!(matches!(
        ev(&mut w).await,
        Event::Interrupted { attempt: 1, .. }
    ));
    assert!(matches!(ev(&mut w).await, Event::Bookmark { .. }));
    assert!(matches!(ev(&mut w).await, Event::Bookmark { .. }));
    assert!(
        matches!(ev(&mut w).await, Event::Interrupted { attempt: 2, .. }),
        "a stream that was never caught up does not end the failures"
    );
}

/// verifies: REQ-DATA-123
/// The idle bookmarks of a stream that cannot catch up do not put off the stall deadline: it counts the time waited over
/// the whole stream, so a stream that keeps saying it is alive is still interrupted.
#[tokio::test]
async fn idle_bookmarks_do_not_postpone_the_stall_deadline() {
    let gap = || Step::Pause(Duration::from_millis(150));
    let up = up(
        vec![Session::Stream(vec![
            Step::Msg(bookmark(10)),
            gap(),
            Step::Msg(bookmark(10)),
            gap(),
            Step::Msg(bookmark(10)),
            gap(),
            Step::Msg(bookmark(10)),
            Step::Hang,
        ])],
        vec![Listing::Items(vec![], 10)],
    )
    .await;
    let mut w = Store::<Lease>::new(up.client.clone())
        .unwrap()
        .watch_with(
            "",
            WatchOpts {
                catch_up_timeout: Duration::from_millis(200),
                ..opts(None)
            },
        )
        .unwrap();
    assert!(matches!(ev(&mut w).await, Event::Resync { .. }));
    let mut n = 0;
    loop {
        match ev(&mut w).await {
            Event::Bookmark { .. } => n += 1,
            Event::Interrupted { reason, .. } => {
                assert_eq!(reason, "catch-up stalled");
                break;
            }
            e => panic!("{e:?}"),
        }
    }
    assert!(
        n < 4,
        "the deadline came before the last bookmark, which only a stream that kept talking would have reached: {n}"
    );
}
