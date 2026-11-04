#![allow(refining_impl_trait)] // the generated traits return `impl Encodable`; a concrete type is fine
#![allow(clippy::unwrap_used, clippy::expect_used)] // a failed unwrap in a test is the failure
//! The reload: a set that fails leaves the set in force in force; a good one replaces it.

mod common;

use common::{Rig, fresh_mfa, local_inputs, token};
use policy::engine::PolicyDoc;
use policy::source::{Reloaded, Reloader, StoreSource};
use sluis_kit::dial;
use sluis_proto::sluis::policy::v2alpha1::Decision;

async fn rig_with_reloader() -> (Rig, Reloader) {
    let rig = Rig::new("session").await;
    rig.around.store.set(&local_inputs());
    let source = StoreSource::new(&dial(&rig.around.store_socket), "dev").unwrap();
    let reloader = Reloader::new(source, rig.service.clone(), &local_inputs());
    (rig, reloader)
}

async fn analyst_allowed(rig: &Rig) -> bool {
    rig.client
        .decide(token(
            "token.issue",
            &["workforce/u-1001"],
            "live",
            fresh_mfa(),
        ))
        .await
        .unwrap()
        .into_owned()
        .decision
        == Decision::ALLOW
}

#[tokio::test]
async fn the_source_reads_what_store_serves() {
    let rig = Rig::new("session").await;
    rig.around.store.set(&local_inputs());
    let source = StoreSource::new(&dial(&rig.around.store_socket), "dev").unwrap();
    let got = source.fetch().await.unwrap();
    assert_eq!(got.boundary, "dev");
    assert_eq!(got.vocabulary, local_inputs().vocabulary);
    assert_eq!(got.policies, local_inputs().policies);
    assert_eq!(got.fingerprint(), local_inputs().fingerprint());
}

#[tokio::test]
async fn nothing_changed_nothing_happens() {
    let (rig, r) = rig_with_reloader().await;
    assert!(matches!(r.once().await, Reloaded::Unchanged));
    assert!(
        rig.around.spool.records().is_empty(),
        "no fact for a reload that did nothing"
    );
}

#[tokio::test]
async fn a_set_that_fails_is_refused_once_and_the_last_good_one_stays_in_force() {
    let (rig, r) = rig_with_reloader().await;
    let digest = rig.service.engine().digest().to_owned();

    let mut bad = local_inputs();
    bad.policies.push(PolicyDoc {
        file: "oops".into(),
        cedar: "@id(\"oops\")\npermit (principal is Person, action == Action::\"token.issue\", resource is Client) when { principal.shoe_size == 9 };".into(),
    });
    rig.around.store.set(&bad);
    let Reloaded::Refused(why) = r.once().await else {
        panic!("not refused")
    };
    assert!(why.to_string().contains("oops"), "{why}");
    assert_eq!(
        rig.service.engine().digest(),
        digest,
        "the set in force did not change"
    );
    assert!(analyst_allowed(&rig).await, "and it still decides");

    let refused = rig.around.spool.of("policy.reload.refused");
    assert_eq!(refused.len(), 1);
    assert_eq!(refused[0].0["status_id"], 2);
    assert_eq!(
        refused[0].0["unmapped"]["sluis"]["in_force_digest"],
        digest.as_str()
    );
    assert!(
        refused[0].0["unmapped"]["sluis"]["faults"][0]
            .as_str()
            .unwrap()
            .contains("oops")
    );

    // The same bad set again is not reported again.
    assert!(matches!(r.once().await, Reloaded::Unchanged));
    assert_eq!(rig.around.spool.of("policy.reload.refused").len(), 1);

    // A good set replaces it, and the decisions follow at once.
    let mut good = local_inputs();
    good.policies.push(PolicyDoc {
        file: "freeze".into(),
        cedar: "@id(\"freeze\")\nforbid (principal is Person, action == Action::\"token.issue\", resource is Client);".into(),
    });
    rig.around.store.set(&good);
    let Reloaded::Applied(new) = r.once().await else {
        panic!("not applied")
    };
    assert_ne!(new, digest);
    assert_eq!(rig.service.engine().digest(), new);
    assert!(
        !analyst_allowed(&rig).await,
        "a tightening takes effect on the next decision"
    );
    assert_eq!(rig.around.spool.of("policy.reload").len(), 1);
}

#[tokio::test]
async fn when_store_cannot_serve_the_set_in_force_stays() {
    let (rig, r) = rig_with_reloader().await;
    let digest = rig.service.engine().digest().to_owned();
    *rig.around.store.down.lock().unwrap() = true;
    assert!(matches!(r.once().await, Reloaded::Unavailable(_)));
    assert_eq!(rig.service.engine().digest(), digest);
    assert!(analyst_allowed(&rig).await);
    *rig.around.store.down.lock().unwrap() = false;
    assert!(matches!(r.once().await, Reloaded::Unchanged));
}
