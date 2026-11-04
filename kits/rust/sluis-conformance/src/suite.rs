//! The item-port suite: the cases every engine behind `sluis.port.item.v2alpha1.ItemService` must
//! pass (store-api.md "The item contract" and "The command line and the suite").
//!
//! The suite speaks the contract and nothing else, over a client the caller dials. It writes under
//! a prefix of its own, `conformance-<run>/`, and removes what it wrote at the end, so it can run
//! against a driver that serves a real namespace.

use std::future::Future;
use std::time::Duration;

use anyhow::{Context, bail, ensure};
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use buffa::Message as _;
use connectrpc::ConnectError;
use connectrpc::error::ErrorCode;
use sluis_kit::Client;
use sluis_proto::sluis::port::item::v2alpha1::__buffa::oneof::condition::Expect;
use sluis_proto::sluis::port::item::v2alpha1::{
    Condition, Delete, DriverItem, ItemGetRequest, ItemServiceClient, Put, QueryRequest,
    TailLogRequest, TailLogResponse, TransactRequest,
};
use sluis_proto::sluis::r#type::v2alpha1::{IndexEntry, Refusal};

use crate::rules::{MAX_PAGE, ms_to_ts, now_ms};
use crate::{Case, run_case};

type Rpc = ItemServiceClient<sluis_kit::Transport>;

/// How long the suite waits for a message that must arrive, and for one that must not.
const ARRIVES: Duration = Duration::from_secs(10);
const SILENT: Duration = Duration::from_millis(700);

/// Runs every case against the engine behind `client` and returns their results. The caller
/// decides what a failure means ([`crate::report`] fails on any failed case and on none run).
pub async fn item_suite(client: Client) -> Vec<Case> {
    let s = Suite::new(client);
    let mut cases = vec![
        run_case("item_round_trip", s.item_round_trip()).await,
        run_case("create_if_absent_twice", s.create_if_absent_twice()).await,
        run_case("update_at_version_and_stale", s.update_versions()).await,
        run_case("delete_at_version", s.delete_at_version()).await,
        run_case("transact_all_or_none", s.transact_all_or_none()).await,
        run_case("one_put_one_condition", s.one_put_one_condition()).await,
        run_case("expiry", s.expiry()).await,
        run_case("prefix_query_order_and_paging", s.prefix_paging()).await,
        run_case("index_query", s.index_query()).await,
        run_case("log_order_and_from_sequence", s.log_order()).await,
        run_case("sequence_expired", s.sequence_expired()).await,
    ];
    // What the cases wrote is removed; a failure to do so is a failed case of its own, so a driver
    // that cannot delete does not pass.
    cases.push(run_case("cleanup", s.cleanup()).await);
    cases
}

struct Suite {
    client: Client,
    /// `conformance-<run>`: the one prefix of every key of this run.
    base: String,
}

impl Suite {
    fn new(client: Client) -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        Self {
            client,
            base: format!("conformance-{:x}{:x}", nanos, std::process::id()),
        }
    }

    fn rpc(&self) -> Rpc {
        ItemServiceClient::new(self.client.transport(), self.client.config())
    }

    /// A key of this run: `conformance-<run>/<case>/<name>`.
    fn key(&self, case: &str, name: &str) -> Vec<u8> {
        format!("{}/{case}/{name}", self.base).into_bytes()
    }

    async fn get(&self, key: &[u8], linearizable: bool) -> Result<DriverItem, ConnectError> {
        let r = self
            .rpc()
            .get(ItemGetRequest {
                key: key.to_vec(),
                linearizable,
                ..ItemGetRequest::default()
            })
            .await?
            .into_owned();
        Ok(r.item.as_option().cloned().unwrap_or_default())
    }

    async fn transact(
        &self,
        conditions: Vec<Condition>,
        puts: Vec<Put>,
        deletes: Vec<Delete>,
    ) -> Result<Vec<DriverItem>, ConnectError> {
        let r = self
            .rpc()
            .transact(TransactRequest {
                conditions,
                puts,
                deletes,
                ..TransactRequest::default()
            })
            .await?
            .into_owned();
        Ok(r.items)
    }

    async fn query(
        &self,
        prefix: &[u8],
        index: Option<(&str, &[u8])>,
        page_size: i32,
        token: Vec<u8>,
    ) -> Result<(Vec<DriverItem>, Vec<u8>), ConnectError> {
        let r = self
            .rpc()
            .query(QueryRequest {
                prefix: prefix.to_vec(),
                index: index.map(|i| i.0.to_owned()).unwrap_or_default(),
                index_value: index.map(|i| i.1.to_vec()).unwrap_or_default(),
                page_size,
                page_token: token,
                ..QueryRequest::default()
            })
            .await?
            .into_owned();
        Ok((r.items, r.next_page_token))
    }

    /// Every item under `prefix`, page by page.
    async fn query_all(&self, prefix: &[u8], page_size: i32) -> anyhow::Result<Vec<DriverItem>> {
        let (mut all, mut token) = (Vec::new(), Vec::new());
        for _ in 0..1000 {
            let (items, next) = self.query(prefix, None, page_size, token).await?;
            all.extend(items);
            if next.is_empty() {
                return Ok(all);
            }
            token = next;
        }
        bail!("a listing that never ends")
    }

    // ---- cases ------------------------------------------------------------------------------

    async fn item_round_trip(&self) -> anyhow::Result<()> {
        let k = self.key("round-trip", "a");
        // Every byte value, and a value large enough to cross a small buffer.
        let mut value: Vec<u8> = (0..=255u8).collect();
        value.extend(std::iter::repeat_n(0xa5, 70_000));
        let expires = ms_to_ts((now_ms() / 1000 + 3600) * 1000);
        let wrote = self
            .transact(
                vec![absent(&k)],
                vec![Put {
                    key: k.clone(),
                    value: value.clone(),
                    expires_at: expires.clone().into(),
                    indexes: vec![index("owner", b"\x00\xff"), index("kind", b"x")],
                    ..Put::default()
                }],
                vec![],
            )
            .await?;
        ensure!(
            wrote.len() == 1,
            "the reply holds {} items, want 1",
            wrote.len()
        );
        ensure!(
            wrote[0].key == k && wrote[0].version == 1,
            "the reply names key/version {:?}/{}",
            String::from_utf8_lossy(&wrote[0].key),
            wrote[0].version
        );
        for lin in [true, false] {
            let got = self.get(&k, lin).await?;
            ensure!(
                got.key == k,
                "key came back as another (linearizable={lin})"
            );
            ensure!(
                got.version == 1,
                "version {} (linearizable={lin})",
                got.version
            );
            ensure!(got.value == value, "value differs (linearizable={lin})");
            ensure!(
                got.expires_at.as_option().map(|t| (t.seconds, t.nanos))
                    == Some((expires.seconds, 0)),
                "expires_at differs (linearizable={lin})"
            );
            // By name, then value: the order a read gives.
            let want = [("kind", b"x".to_vec()), ("owner", b"\x00\xff".to_vec())];
            let have: Vec<_> = got
                .indexes
                .iter()
                .map(|e| (e.name.as_str(), e.value.clone()))
                .collect();
            ensure!(have == want, "indexes differ (linearizable={lin})");
        }
        // An empty value is a value.
        let e = self.key("round-trip", "empty");
        self.transact(vec![absent(&e)], vec![put(&e, b"")], vec![])
            .await?;
        let got = self.get(&e, true).await?;
        ensure!(
            got.value.is_empty() && got.version == 1,
            "the empty value came back as another"
        );
        Ok(())
    }

    async fn create_if_absent_twice(&self) -> anyhow::Result<()> {
        let k = self.key("create", "a");
        let first = self
            .transact(vec![absent(&k)], vec![put(&k, b"one")], vec![])
            .await?;
        ensure!(
            first.first().map(|i| i.version) == Some(1),
            "a create is version 1"
        );
        let second = self
            .transact(vec![absent(&k)], vec![put(&k, b"two")], vec![])
            .await;
        expect_refusal(second, ErrorCode::Aborted, "version", Some("conditions[0]"))?;
        let got = self.get(&k, true).await?;
        ensure!(
            got.value == b"one" && got.version == 1,
            "the second create changed the item"
        );
        Ok(())
    }

    async fn update_versions(&self) -> anyhow::Result<()> {
        let k = self.key("update", "a");
        self.transact(vec![absent(&k)], vec![put(&k, b"v1")], vec![])
            .await?;
        let up = self
            .transact(vec![at_version(&k, 1)], vec![put(&k, b"v2")], vec![])
            .await?;
        ensure!(
            up.first().map(|i| i.version) == Some(2),
            "an update at version 1 gives version 2"
        );
        let stale = self
            .transact(vec![at_version(&k, 1)], vec![put(&k, b"v3")], vec![])
            .await;
        expect_refusal(stale, ErrorCode::Aborted, "version", Some("conditions[0]"))?;
        let got = self.get(&k, true).await?;
        ensure!(
            got.value == b"v2" && got.version == 2,
            "a stale update changed the item"
        );
        // A version condition on a key that is not there fails too.
        let missing = self.key("update", "missing");
        let r = self
            .transact(
                vec![at_version(&missing, 1)],
                vec![put(&missing, b"x")],
                vec![],
            )
            .await;
        expect_refusal(r, ErrorCode::Aborted, "version", Some("conditions[0]"))?;
        ensure!(
            is_absent(self.get(&missing, true).await),
            "a failed update created the item"
        );
        // A put without a condition writes the next version (the APPLY of store@).
        let applied = self.transact(vec![], vec![put(&k, b"v3")], vec![]).await?;
        ensure!(
            applied.first().map(|i| i.version) == Some(3),
            "an unconditional put is the next version"
        );
        Ok(())
    }

    async fn delete_at_version(&self) -> anyhow::Result<()> {
        let k = self.key("delete", "a");
        self.transact(vec![absent(&k)], vec![put(&k, b"v1")], vec![])
            .await?;
        let stale = self
            .transact(vec![at_version(&k, 5)], vec![], vec![del(&k)])
            .await;
        expect_refusal(stale, ErrorCode::Aborted, "version", Some("conditions[0]"))?;
        ensure!(
            self.get(&k, true).await?.version == 1,
            "a stale delete removed the item"
        );
        let reply = self
            .transact(vec![at_version(&k, 1)], vec![], vec![del(&k)])
            .await?;
        ensure!(reply.is_empty(), "a delete has no item in the reply");
        ensure!(
            is_absent(self.get(&k, true).await),
            "the deleted item is still there"
        );
        let again = self
            .transact(vec![absent(&k)], vec![put(&k, b"fresh")], vec![])
            .await?;
        ensure!(
            again.first().map(|i| i.version) == Some(1),
            "a key created again starts at version 1"
        );
        Ok(())
    }

    async fn transact_all_or_none(&self) -> anyhow::Result<()> {
        let (a, b, x) = (
            self.key("tx", "a"),
            self.key("tx", "b"),
            self.key("tx", "x"),
        );
        self.transact(vec![absent(&x)], vec![put(&x, b"x1")], vec![])
            .await?;
        // The second condition fails: the first put must not be there, and x must not move.
        let r = self
            .transact(
                vec![absent(&a), at_version(&x, 5)],
                vec![put(&a, b"a1"), put(&x, b"x2")],
                vec![],
            )
            .await;
        expect_refusal(r, ErrorCode::Aborted, "version", Some("conditions[1]"))?;
        ensure!(
            is_absent(self.get(&a, true).await),
            "a put of a refused transaction was written"
        );
        let got = self.get(&x, true).await?;
        ensure!(
            got.value == b"x1" && got.version == 1,
            "an item of a refused transaction changed"
        );
        // Two conditions fail: the first one is named.
        let r = self
            .transact(
                vec![at_version(&x, 9), at_version(&x, 8)],
                vec![put(&a, b"a1")],
                vec![],
            )
            .await;
        expect_refusal(r, ErrorCode::Aborted, "version", Some("conditions[0]"))?;
        // A delete in a refused transaction removes nothing.
        let r = self
            .transact(vec![absent(&x)], vec![put(&a, b"a1")], vec![del(&x)])
            .await;
        expect_refusal(r, ErrorCode::Aborted, "version", Some("conditions[0]"))?;
        ensure!(
            self.get(&x, true).await?.version == 1,
            "a delete of a refused transaction ran"
        );
        // Everything holds: puts and a delete land together.
        let reply = self
            .transact(
                vec![absent(&a), absent(&b), at_version(&x, 1)],
                vec![put(&a, b"a1"), put(&b, b"b1")],
                vec![del(&x)],
            )
            .await?;
        ensure!(
            reply.len() == 2,
            "the reply holds {} items, want the 2 puts",
            reply.len()
        );
        ensure!(
            reply.iter().all(|i| i.version == 1),
            "the puts of the reply are version 1"
        );
        ensure!(
            is_absent(self.get(&x, true).await),
            "the delete of a transaction did not apply"
        );
        ensure!(
            self.get(&b, true).await?.value == b"b1",
            "the puts of a transaction did not apply"
        );
        Ok(())
    }

    async fn one_put_one_condition(&self) -> anyhow::Result<()> {
        // A counter, the way an allowance is kept: each step is one conditional update.
        let k = self.key("counter", "c");
        self.transact(vec![absent(&k)], vec![put(&k, b"1")], vec![])
            .await?;
        for v in 1..=10u64 {
            let r = self
                .transact(
                    vec![at_version(&k, v)],
                    vec![put(&k, format!("{}", v + 1).as_bytes())],
                    vec![],
                )
                .await?;
            ensure!(
                r.first().map(|i| i.version) == Some(v + 1),
                "step {v} gave another version"
            );
        }
        // Many callers at once: exactly one wins each race.
        let r = self.key("counter", "race");
        let results = futures::future::join_all((0..8).map(|i| {
            let r = r.clone();
            async move {
                self.transact(
                    vec![absent(&r)],
                    vec![put(&r, format!("{i}").as_bytes())],
                    vec![],
                )
                .await
            }
        }))
        .await;
        let won = results.iter().filter(|x| x.is_ok()).count();
        ensure!(won == 1, "{won} of 8 concurrent creates won, want 1");
        for res in results.into_iter().filter(Result::is_err) {
            expect_refusal(res, ErrorCode::Aborted, "version", Some("conditions[0]"))?;
        }
        let results = futures::future::join_all((0..8).map(|i| {
            let r = r.clone();
            async move {
                self.transact(
                    vec![at_version(&r, 1)],
                    vec![put(&r, format!("u{i}").as_bytes())],
                    vec![],
                )
                .await
            }
        }))
        .await;
        let won = results.iter().filter(|x| x.is_ok()).count();
        ensure!(
            won == 1,
            "{won} of 8 concurrent updates at one version won, want 1"
        );
        ensure!(
            self.get(&r, true).await?.version == 2,
            "the race left another version"
        );
        Ok(())
    }

    async fn expiry(&self) -> anyhow::Result<()> {
        let past = ms_to_ts(now_ms() - 10_000);
        let future = ms_to_ts((now_ms() / 1000 + 3600) * 1000);
        let (gone, live, plain) = (
            self.key("expiry", "a-gone"),
            self.key("expiry", "b-live"),
            self.key("expiry", "c-plain"),
        );
        let expiring = |k: &[u8], t: &buffa_types::google::protobuf::Timestamp| Put {
            expires_at: t.clone().into(),
            ..put(k, b"v")
        };
        self.transact(
            vec![absent(&gone), absent(&live), absent(&plain)],
            vec![
                expiring(&gone, &past),
                expiring(&live, &future),
                put(&plain, b"v"),
            ],
            vec![],
        )
        .await?;
        for lin in [true, false] {
            ensure!(
                is_absent(self.get(&gone, lin).await),
                "an item past its expiry is readable (linearizable={lin})"
            );
        }
        ensure!(
            self.get(&live, true).await?.version == 1,
            "an item before its expiry is not readable"
        );
        let listed = self.query_all(&self.key("expiry", ""), 0).await?;
        let keys: Vec<_> = listed.iter().map(|i| i.key.clone()).collect();
        ensure!(
            keys == vec![live.clone(), plain.clone()],
            "a listing shows {} items, want the 2 live ones",
            keys.len()
        );
        // An expired item does not satisfy a version condition, and a create may write it again.
        let r = self
            .transact(vec![at_version(&gone, 1)], vec![put(&gone, b"x")], vec![])
            .await;
        expect_refusal(r, ErrorCode::Aborted, "version", Some("conditions[0]"))?;
        let again = self
            .transact(vec![absent(&gone)], vec![expiring(&gone, &future)], vec![])
            .await?;
        ensure!(
            again.first().map(|i| i.version) == Some(1),
            "a create over an expired item starts at version 1"
        );
        ensure!(
            self.get(&gone, true).await?.version == 1,
            "the item created over an expired one is not readable"
        );
        Ok(())
    }

    async fn prefix_paging(&self) -> anyhow::Result<()> {
        const N: usize = 1200;
        let prefix = self.key("page", "");
        let name = |i: usize| format!("{i:04}");
        // 1,200 items in batches of 100, and decoys on both sides of the prefix's range.
        for chunk in (0..N).collect::<Vec<_>>().chunks(100) {
            let puts = chunk
                .iter()
                .map(|i| put(&self.key("page", &name(*i)), name(*i).as_bytes()))
                .collect();
            self.transact(vec![], puts, vec![]).await?;
        }
        let before = format!("{}/page.x/1", self.base).into_bytes();
        let after = format!("{}/page0/1", self.base).into_bytes();
        self.transact(vec![], vec![put(&before, b"d"), put(&after, b"d")], vec![])
            .await?;

        let want: Vec<Vec<u8>> = (0..N).map(|i| self.key("page", &name(i))).collect();
        let (mut have, mut token, mut sizes) = (Vec::new(), Vec::new(), Vec::new());
        loop {
            let (items, next) = self.query(&prefix, None, 500, token).await?;
            sizes.push(items.len());
            have.extend(items.into_iter().map(|i| i.key));
            if next.is_empty() {
                break;
            }
            token = next;
            ensure!(sizes.len() < 10, "a listing that never ends");
        }
        ensure!(
            sizes == [500, 500, 200],
            "pages of {sizes:?}, want [500, 500, 200]"
        );
        ensure!(
            have == want,
            "the 1,200 keys do not come back once each in key order"
        );
        // A page size above the bound is the bound; a size of 7 is 7.
        let (items, next) = self.query(&prefix, None, 100_000, vec![]).await?;
        ensure!(
            items.len() == MAX_PAGE && !next.is_empty(),
            "a page size above {MAX_PAGE} gave {} items",
            items.len()
        );
        let (items, _) = self.query(&prefix, None, 7, vec![]).await?;
        ensure!(
            items.len() == 7,
            "a page size of 7 gave {} items",
            items.len()
        );
        // A token that is not a key under the prefix is refused.
        let r = self
            .query(&prefix, None, 10, b"not/under/the/prefix".to_vec())
            .await;
        expect_refusal(
            r.map(|_| ()),
            ErrorCode::InvalidArgument,
            "address",
            Some("page_token"),
        )?;
        // The values came back with the keys.
        let (items, _) = self.query(&prefix, None, 3, vec![]).await?;
        ensure!(
            items
                .iter()
                .all(|i| i.value == i.key.rsplit(|b| *b == b'/').next().unwrap_or_default()),
            "a listed item holds another item's value"
        );
        Ok(())
    }

    async fn index_query(&self) -> anyhow::Result<()> {
        let prefix = self.key("index", "");
        let (i1, i2, i3) = (
            self.key("index", "1"),
            self.key("index", "2"),
            self.key("index", "3"),
        );
        let with = |k: &[u8], ix: Vec<IndexEntry>| Put {
            indexes: ix,
            ..put(k, b"v")
        };
        self.transact(
            vec![],
            vec![
                with(
                    &i1,
                    vec![index("by-owner", b"alice"), index("by-state", b"open")],
                ),
                with(&i2, vec![index("by-owner", b"alice")]),
                with(&i3, vec![index("by-owner", b"bob")]),
            ],
            vec![],
        )
        .await?;
        let keys = |items: Vec<DriverItem>| items.into_iter().map(|i| i.key).collect::<Vec<_>>();
        let by = |name: &'static str, v: &'static [u8]| (name, v);
        let (alice, _) = self
            .query(&prefix, Some(by("by-owner", b"alice")), 0, vec![])
            .await?;
        let first = alice.first().cloned().unwrap_or_default();
        ensure!(
            first
                .indexes
                .iter()
                .any(|e| e.name == "by-state" && e.value == b"open"),
            "an item found by one index does not show its other index entries"
        );
        ensure!(
            keys(alice) == vec![i1.clone(), i2.clone()],
            "alice does not find items 1 and 2 in key order"
        );
        let (bob, _) = self
            .query(&prefix, Some(by("by-owner", b"bob")), 0, vec![])
            .await?;
        ensure!(keys(bob) == vec![i3.clone()], "bob does not find item 3");
        let (none, _) = self
            .query(&prefix, Some(by("by-owner", b"nobody")), 0, vec![])
            .await?;
        ensure!(none.is_empty(), "a value nobody has finds items");
        let (other, _) = self
            .query(&prefix, Some(by("by-state", b"alice")), 0, vec![])
            .await?;
        ensure!(
            other.is_empty(),
            "an index entry is found under another index name"
        );
        // The index entries of an item are rewritten by a put, and removed by a delete.
        self.transact(
            vec![at_version(&i1, 1)],
            vec![with(&i1, vec![index("by-owner", b"bob")])],
            vec![],
        )
        .await?;
        let (alice, _) = self
            .query(&prefix, Some(by("by-owner", b"alice")), 0, vec![])
            .await?;
        ensure!(
            keys(alice) == vec![i2.clone()],
            "a rewritten item is still found under its old entry"
        );
        let (bob, next) = self
            .query(&prefix, Some(by("by-owner", b"bob")), 1, vec![])
            .await?;
        ensure!(
            keys(bob) == vec![i1.clone()] && !next.is_empty(),
            "the first page of bob is item 1 and a token"
        );
        let (bob, next) = self
            .query(&prefix, Some(by("by-owner", b"bob")), 1, next)
            .await?;
        ensure!(
            keys(bob) == vec![i3.clone()] && next.is_empty(),
            "the second page of bob is item 3, the last"
        );
        self.transact(vec![], vec![], vec![del(&i3)]).await?;
        let (bob, _) = self
            .query(&prefix, Some(by("by-owner", b"bob")), 0, vec![])
            .await?;
        ensure!(
            keys(bob) == vec![i1.clone()],
            "a deleted item is still found by its index entry"
        );
        // A re-created key does not inherit the entries of the item it replaces.
        self.transact(vec![at_version(&i2, 1)], vec![], vec![del(&i2)])
            .await?;
        self.transact(vec![absent(&i2)], vec![put(&i2, b"v")], vec![])
            .await?;
        let (alice, _) = self
            .query(&prefix, Some(by("by-owner", b"alice")), 0, vec![])
            .await?;
        ensure!(
            alice.is_empty(),
            "a key created again is found under its old index entry"
        );
        Ok(())
    }

    async fn log_order(&self) -> anyhow::Result<()> {
        let (a, b, c) = (
            self.key("log", "a"),
            self.key("log", "b"),
            self.key("log", "c"),
        );
        let mine = self.key("log", "");
        // A tail from now sees what is written after the call returned.
        let mut live = self.open_tail(0).await?;
        let logged = |k: &[u8]| Put {
            log: true,
            ..put(k, b"v")
        };
        self.transact(vec![absent(&a)], vec![logged(&a)], vec![])
            .await?;
        self.transact(vec![at_version(&a, 1)], vec![logged(&a)], vec![])
            .await?;
        // No row for a write that did not ask for one.
        self.transact(vec![absent(&b)], vec![put(&b, b"v")], vec![])
            .await?;
        let delete = Delete {
            key: a.clone(),
            log: true,
            ..Delete::default()
        };
        self.transact(vec![at_version(&a, 2)], vec![], vec![delete])
            .await?;
        self.transact(vec![absent(&c)], vec![logged(&c)], vec![])
            .await?;

        let mut rows = Vec::new();
        while rows.len() < 4 {
            rows.push(live.row(&mine, ARRIVES).await?);
        }
        // A delete's row carries the version the item had when it was removed.
        let shape: Vec<_> = rows
            .iter()
            .map(|r| (r.key.clone(), r.version, r.deleted))
            .collect();
        let want = vec![
            (a.clone(), 1, false),
            (a.clone(), 2, false),
            (a.clone(), 2, true),
            (c.clone(), 1, false),
        ];
        ensure!(
            shape == want,
            "the log rows are not the 3 logged writes and the logged delete, in order"
        );
        ensure!(
            rows.windows(2).all(|w| w[0].sequence < w[1].sequence),
            "the sequences do not grow"
        );
        // From a sequence: the rows after it, in order, and then what is written later.
        let after = rows[1].sequence;
        let mut tail = self.open_tail(after).await?;
        let mut again = Vec::new();
        while again.len() < 2 {
            let m = tail.row(&mine, ARRIVES).await?;
            again.push((m.sequence, m.key));
        }
        ensure!(
            again == vec![(rows[2].sequence, a.clone()), (rows[3].sequence, c.clone())],
            "a tail from sequence {after} does not give the rows after it"
        );
        ensure!(
            matches!(tail.tick(&mine, SILENT).await, Tick::Silent),
            "a tail delivers a row nobody wrote"
        );
        self.transact(vec![at_version(&c, 1)], vec![logged(&c)], vec![])
            .await?;
        let m = tail.row(&mine, ARRIVES).await?;
        ensure!(
            m.key == c && m.version == 2,
            "the later write came as another row"
        );
        Ok(())
    }

    async fn sequence_expired(&self) -> anyhow::Result<()> {
        // A sequence the log does not hold: one it has not reached is as unusable to a watcher as
        // one it dropped, because a change could be missed. (A dropped one is the rqlite
        // driver's own test: the suite cannot make an engine drop rows.)
        let err = match self.open_tail(u64::MAX).await {
            Err(e) => e,
            Ok(mut t) => match t.tick(b"", ARRIVES).await {
                Tick::Failed(e) => e,
                _ => bail!("a tail from a sequence the log does not hold delivered or waits"),
            },
        };
        expect_refusal(
            Err::<(), _>(err),
            ErrorCode::FailedPrecondition,
            "sequence_expired",
            None,
        )
    }

    /// A tail of the change log from `from`, read by a task so that waiting for a row with a
    /// bound never cancels a read half way.
    async fn open_tail(&self, from: u64) -> Result<Tail, ConnectError> {
        let mut stream = self
            .rpc()
            .tail_log(TailLogRequest {
                from_sequence: from,
                ..TailLogRequest::default()
            })
            .await?;
        let (tx, rx) = tokio::sync::mpsc::channel(1024);
        let task = tokio::spawn(async move {
            loop {
                let next = match stream.message().await {
                    Ok(Some(m)) => Ok(m.to_owned_message()),
                    Ok(None) => return,
                    Err(e) => Err(e),
                };
                let failed = next.is_err();
                if tx.send(next).await.is_err() || failed {
                    return;
                }
            }
        });
        Ok(Tail { rx, task })
    }

    /// Removes every key of this run.
    async fn cleanup(&self) -> anyhow::Result<()> {
        let prefix = format!("{}/", self.base).into_bytes();
        let items = self.query_all(&prefix, 0).await?;
        for chunk in items.chunks(100) {
            let deletes = chunk.iter().map(|i| del(&i.key)).collect();
            self.transact(vec![], vec![], deletes).await?;
        }
        ensure!(
            self.query_all(&prefix, 0).await?.is_empty(),
            "the suite's keys are still there"
        );
        Ok(())
    }
}

/// What a tail gave within a bound.
enum Tick {
    Row(TailLogResponse),
    Silent,
    Ended,
    Failed(ConnectError),
}

struct Tail {
    rx: tokio::sync::mpsc::Receiver<Result<TailLogResponse, ConnectError>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Tail {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Tail {
    /// The next row whose key starts with `mine` (rows of other writers are skipped), or why not.
    async fn tick(&mut self, mine: &[u8], within: Duration) -> Tick {
        let deadline = tokio::time::Instant::now() + within;
        loop {
            match tokio::time::timeout_at(deadline, self.rx.recv()).await {
                Err(_) => return Tick::Silent,
                Ok(None) => return Tick::Ended,
                Ok(Some(Err(e))) => return Tick::Failed(e),
                Ok(Some(Ok(row))) if row.key.starts_with(mine) => return Tick::Row(row),
                Ok(Some(Ok(_))) => {}
            }
        }
    }

    async fn row(&mut self, mine: &[u8], within: Duration) -> anyhow::Result<TailLogResponse> {
        match self.tick(mine, within).await {
            Tick::Row(r) => Ok(r),
            Tick::Silent => bail!("the change log did not deliver a row in {within:?}"),
            Tick::Ended => bail!("the change log ended"),
            Tick::Failed(e) => bail!("the change log failed: {:?}", e.code),
        }
    }
}

// ---- builders and checks ---------------------------------------------------------------------

fn put(key: &[u8], value: &[u8]) -> Put {
    Put {
        key: key.to_vec(),
        value: value.to_vec(),
        ..Put::default()
    }
}

fn del(key: &[u8]) -> Delete {
    Delete {
        key: key.to_vec(),
        ..Delete::default()
    }
}

fn absent(key: &[u8]) -> Condition {
    Condition {
        key: key.to_vec(),
        expect: Some(Expect::Absent(true)),
        ..Condition::default()
    }
}

fn at_version(key: &[u8], v: u64) -> Condition {
    Condition {
        key: key.to_vec(),
        expect: Some(Expect::Version(v)),
        ..Condition::default()
    }
}

fn index(name: &str, value: &[u8]) -> IndexEntry {
    IndexEntry {
        name: name.to_owned(),
        value: value.to_vec(),
        ..IndexEntry::default()
    }
}

/// The `Refusal` detail of an error.
fn refusal_of(err: &ConnectError) -> Option<Refusal> {
    err.details.iter().find_map(|d| {
        if d.type_url.rsplit('/').next()? != "sluis.type.v2alpha1.Refusal" {
            return None;
        }
        let raw = d.value.as_deref()?;
        let bytes = STANDARD_NO_PAD
            .decode(raw)
            .or_else(|_| STANDARD.decode(raw))
            .ok()?;
        Refusal::decode_from_slice(&bytes).ok()
    })
}

/// Checks that `res` is the refusal `code` with `reason` and, when given, `field_path`.
fn expect_refusal<T>(
    res: Result<T, ConnectError>,
    code: ErrorCode,
    reason: &str,
    field_path: Option<&str>,
) -> anyhow::Result<()> {
    let Err(err) = res else {
        bail!("want the refusal {code:?}/{reason}, got success");
    };
    let r = refusal_of(&err);
    ensure!(
        err.code == code && r.as_ref().is_some_and(|r| r.reason == reason),
        "want {code:?}/{reason}, got {:?}/{:?}",
        err.code,
        r.as_ref().map(|r| r.reason.as_str())
    );
    if let Some(path) = field_path {
        let have = r.map(|r| r.field_path).unwrap_or_default();
        ensure!(have == path, "want the field path {path:?}, got {have:?}");
    }
    Ok(())
}

/// Whether a read said `not_found` with the reason `absent`.
fn is_absent(res: Result<DriverItem, ConnectError>) -> bool {
    res.err().is_some_and(|e| {
        e.code == ErrorCode::NotFound && refusal_of(&e).is_some_and(|r| r.reason == "absent")
    })
}

/// Awaits a case under the suite's bound.
pub(crate) async fn bounded(fut: impl Future<Output = anyhow::Result<()>>) -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(180), fut)
        .await
        .context("the case ran past its bound")?
}
