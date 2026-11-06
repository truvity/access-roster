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
use sluis_store::{Backoff, Error, Event, Kind, ResyncCause, Store, Watch, WatchOpts};

/// A kind with no tenant (`lease`), with any message as its value.
struct Lease;
impl Kind for Lease {
    type Id = String;
    type Value = Provenance;
    const NAME: &'static str = "Lease";
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
}

enum Session {
    /// The call itself is refused.
    Refuse(ErrorCode, &'static str),
    Stream(Vec<Step>),
}

/// The items of a listing (id, version) and its resume point.
type Items = (Vec<(&'static str, u64)>, u64);

enum Listing {
    Items(Vec<(&'static str, u64)>, u64),
    Fail(ErrorCode),
}

#[derive(Default)]
struct Script {
    sessions: Mutex<VecDeque<Session>>,
    listings: Mutex<VecDeque<Listing>>,
    current: Mutex<Option<Items>>,
    /// What every `Watch` call asked for: kind, tenant, resume point.
    opens: Mutex<Vec<(String, String, u64)>>,
    lists: AtomicUsize,
    /// Streams that are open: counted up at the call, down when the stream is dropped.
    live: Arc<AtomicUsize>,
}

struct Live(Arc<AtomicUsize>);
impl Drop for Live {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

fn address(kind: &str, id: &str) -> Address {
    Address {
        kind: kind.into(),
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
    WireItem {
        address: address(kind, id).into(),
        version,
        value: value.to_vec(),
        ..WireItem::default()
    }
}

fn put(seq: u64, id: &str, version: u64, path: &str) -> WatchResponse {
    WatchResponse {
        resume_point: seq,
        r#type: ChangeType::CHANGE_TYPE_PUT.into(),
        item: wire("lease", id, version, &prov(path).encode_to_vec()).into(),
        ..WatchResponse::default()
    }
}

fn delete(seq: u64, id: &str, version: u64) -> WatchResponse {
    WatchResponse {
        resume_point: seq,
        r#type: ChangeType::CHANGE_TYPE_DELETE.into(),
        item: wire("lease", id, version, b"").into(),
        ..WatchResponse::default()
    }
}

fn bookmark(seq: u64) -> WatchResponse {
    WatchResponse {
        resume_point: seq,
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
                    *self.current.lock().unwrap() = Some((items, point))
                }
                Some(Listing::Fail(c)) => return Err(refusal(c, "engine", "")),
                None => return Err(refusal(ErrorCode::Unavailable, "engine", "")),
            }
        }
        let cur = self.current.lock().unwrap().clone().unwrap();
        let from: usize = r.page_token.parse().unwrap_or(0);
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
                wire(&r.kind, id, *v, &value)
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
                match steps.pop_front()? {
                    Step::Msg(m) => Some((Ok(m), (steps, guard))),
                    Step::Fail(c, reason) => {
                        steps.clear();
                        Some((Err(refusal(c, reason, "resume_point")), (steps, guard)))
                    }
                    Step::Hang => std::future::pending().await,
                    Step::End => None,
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

fn opts(from: Option<u64>) -> WatchOpts {
    WatchOpts {
        from,
        backoff: FAST,
    }
}

fn lease_watch(up: &Up, from: Option<u64>) -> Watch<Lease> {
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
    match e {
        Event::Put { item, resume_point } => {
            assert_eq!(
                (
                    item.id.as_str(),
                    item.version,
                    item.value.field_path.as_str(),
                    *resume_point
                ),
                (id, version, path, seq),
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
    assert_eq!(w.resume_point(), 0);

    match ev(&mut w).await {
        Event::Resync {
            cause,
            items,
            resume_point,
        } => {
            assert_eq!((cause, resume_point), (ResyncCause::Start, 10));
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
    assert_eq!(w.resume_point(), 10);
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
            ("", "a/one", 2, 13)
        ),
        e => panic!("not a delete: {e:?}"),
    }
    assert!(matches!(
        ev(&mut w).await,
        Event::Bookmark { resume_point: 13 }
    ));
    assert_eq!(w.resume_point(), 13);
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
    let mut w = lease_watch(&up, Some(40));
    assert_eq!(w.resume_point(), 40);
    is_put(&ev(&mut w).await, "a/new", 1, "new", 41);
    // The second 41 and nothing else came between: the next event is the bookmark, at the point and not before it.
    assert!(matches!(
        ev(&mut w).await,
        Event::Bookmark { resume_point: 41 }
    ));
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
    let mut w = lease_watch(&up, Some(0));
    assert!(matches!(
        ev(&mut w).await,
        Event::Resync {
            cause: ResyncCause::Start,
            resume_point: 7,
            ..
        }
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
            assert_eq!((cause, resume_point), (ResyncCause::Expired, 50));
            assert_eq!(ids(&items), ["a/one", "a/nine"]);
        }
        e => panic!("not a resync: {e:?}"),
    }
    assert_eq!(w.resume_point(), 50);
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
            resume_point: 60,
        } => assert_eq!(ids(&items), ["a/seven"]),
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
    let mut w = lease_watch(&up, Some(5));
    match ev(&mut w).await {
        Event::Resync {
            cause,
            resume_point,
            items,
        } => {
            assert_eq!(
                (cause, resume_point, items.len()),
                (ResyncCause::Expired, 90, 1)
            );
        }
        e => panic!("not a resync: {e:?}"),
    }
    quiet(&mut w).await;
    assert_eq!(opens(&up), [5, 90]);
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
    assert_eq!(w.resume_point(), 11, "the point did not move past the item");
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
    let up = up(vec![], vec![Listing::Items(vec![("a/one", 1)], 0)]).await;
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
                ("", "kid/abc", 11)
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
