#![allow(refining_impl_trait)] // the generated traits return `impl Encodable`; a concrete type is fine
#![allow(clippy::unwrap_used, clippy::expect_used)] // a failed unwrap in a test is the failure
//! The decision over the kit's transport: the sealed grant, the audit fact, and the denials.

mod common;

use common::{Rig, accounts, audit, auth_age, fresh_mfa, open_sealed, requires, subject, token};
use connectrpc::error::ErrorCode;
use sluis_kit::refusal_reason;
use sluis_proto::sluis::policy::v2alpha1::{Authentication, Decision};

fn allowed(d: Decision) -> bool {
    d == Decision::ALLOW
}

#[tokio::test]
async fn an_allow_has_the_grant_names_and_a_grant_sealed_for_the_asker_that_ends_in_60_seconds() {
    let rig = Rig::new("session").await;
    let req = token("token.issue", &["workforce/u-1001"], "live", fresh_mfa());
    let r = rig.client.decide(req).await.unwrap().into_owned();

    assert!(allowed(r.decision.as_known().unwrap()));
    assert_eq!(r.grant_names, ["dev:example-app:user"]);
    assert_eq!(
        r.reasons
            .iter()
            .map(|x| x.policy_id.as_str())
            .collect::<Vec<_>>(),
        ["token-requires"]
    );
    assert_eq!(r.reasons[0].layer, "config");
    assert_eq!(r.digest.len(), 96, "a SHA-384 in hex");
    assert!(!r.sealed_grant.is_empty());

    // What key@ was asked to seal (the fake keeps it; the wire form is key@'s).
    let g = open_sealed(&r.sealed_grant);
    assert_eq!(g.boundary, "dev");
    assert_eq!(
        g.holder, "session",
        "the grant is made for the asker the transport named"
    );
    assert_eq!(g.tenants, ["acme"]);
    assert_eq!(g.action, "token.issue");
    assert_eq!(g.decision_id, r.decision_id);
    let (i, e) = (
        g.issued_at.as_option().unwrap(),
        g.expires_at.as_option().unwrap(),
    );
    assert_eq!(
        e.seconds - i.seconds,
        60,
        "at most 60 s, which key@ enforces too"
    );
    assert_eq!(i.seconds, 1_793_750_400);
    assert_eq!(g.store_verbs, ["create", "get"]);
    assert_eq!(g.key_ops, ["open", "seal"]);
}

#[tokio::test]
async fn every_decision_is_audited_once_and_an_allow_is_audited_before_it_is_handed_out() {
    let rig = Rig::new("session").await;
    let r = rig
        .client
        .decide(token(
            "token.issue",
            &["workforce/u-1001"],
            "live",
            fresh_mfa(),
        ))
        .await
        .unwrap()
        .into_owned();
    let d = rig.around.spool.of("policy.decide");
    assert_eq!(d.len(), 1, "one record for one decision");
    let (rec, blocking) = &d[0];
    assert!(blocking, "a grant is a power: its fact is durable first");
    assert_eq!(rec["policy"]["uid"], r.decision_id.as_str());
    assert_eq!(rec["policy"]["version"], r.digest.as_str());
    assert_eq!(rec["action_id"], 1);
    assert_eq!(rec["authorizations"][0]["policy"]["uid"], "token-requires");
    assert_eq!(rec["metadata"]["tenant_uid"], "acme");
    assert_eq!(rec["status_id"], 1);
    assert!(
        rec["user"]["uid"].as_str().unwrap().starts_with("p1."),
        "a person is a pseudonym"
    );
    let text = serde_json::to_string(rec).unwrap();
    assert!(
        !text.contains("p-1") && !text.contains("u-1001"),
        "no subject, no account: {text}"
    );
    assert_eq!(rec["unmapped"]["sluis"]["asker"], "session");
    assert_eq!(rec["unmapped"]["sluis"]["grant_count"], 1);
}

#[tokio::test]
async fn a_denial_by_a_policy_has_no_grant_names_the_forbid_and_its_step_up() {
    let rig = Rig::new("session").await;
    let pwd = Authentication {
        acr: Some("urn:example:acr:pwd".into()),
        amr: vec!["pwd".into()],
        amr_present: true,
        auth_age: Some(300),
        ..Authentication::default()
    };
    let r = rig
        .client
        .decide(token("token.issue", &["workforce/u-1001"], "live", pwd))
        .await
        .unwrap()
        .into_owned();
    assert!(!allowed(r.decision.as_known().unwrap()));
    assert!(r.sealed_grant.is_empty());
    assert_eq!(r.reasons.len(), 1);
    assert_eq!(r.reasons[0].policy_id, "example-app-fresh-mfa");
    assert_eq!(
        r.reasons[0].annotations.get("step_up").map(String::as_str),
        Some("acr_values=urn:example:acr:mfa max_age=900"),
        "session reads the step-up from the reason"
    );
    let d = rig.around.spool.of("policy.decide");
    assert_eq!(d.len(), 1);
    assert!(
        !d[0].1,
        "a denial hands out nothing, so it need not hold the answer"
    );
    assert_eq!(d[0].0["action_id"], 2);
    assert_eq!(d[0].0["unmapped"]["sluis"]["step_up"], true);
    assert!(
        rig.around.keys.sealed.lock().unwrap().is_empty(),
        "nothing was sealed"
    );
}

#[tokio::test]
async fn an_upstream_that_sends_nothing_is_asked_to_step_up() {
    let rig = Rig::new("session").await;
    let r = rig
        .client
        .decide(token(
            "token.issue",
            &["workforce/u-1001"],
            "live",
            Authentication::default(),
        ))
        .await
        .unwrap()
        .into_owned();
    assert!(!allowed(r.decision.as_known().unwrap()));
    assert_eq!(r.reasons[0].policy_id, "example-app-fresh-mfa");
}

#[tokio::test]
async fn a_held_person_gets_nothing_and_holds_no_grant_name() {
    let rig = Rig::new("session").await;
    let r = rig
        .client
        .decide(token(
            "token.issue",
            &["workforce/u-1001"],
            "held",
            fresh_mfa(),
        ))
        .await
        .unwrap()
        .into_owned();
    assert!(!allowed(r.decision.as_known().unwrap()));
    assert_eq!(r.reasons[0].policy_id, "person-not-live");
    assert!(r.grant_names.is_empty());
}

#[tokio::test]
async fn the_ladder_is_expanded_and_the_answer_carries_the_full_set() {
    let rig = Rig::new("exchange").await;
    // u-2001 holds dev admin by a wildcard in the thing position; the client wants the operator role.
    let req = requires(
        token("token.exchange", &["workforce/u-2001"], "live", fresh_mfa()),
        &["dev:example-app:operator"],
    );
    let r = rig.client.decide(req).await.unwrap().into_owned();
    assert!(allowed(r.decision.as_known().unwrap()));
    assert_eq!(
        r.grant_names,
        [
            "dev:example-app:admin",
            "dev:example-app:operator",
            "dev:example-app:user"
        ]
    );
}

#[tokio::test]
async fn a_wildcard_never_reaches_a_sensitive_scope_but_a_grant_named_in_full_does() {
    let rig = Rig::new("session").await;
    // u-4001: "any admin" by a condition on the role. Cedar would give prod too; policy does not.
    let req = requires(
        token("token.issue", &["workforce/u-4001"], "live", fresh_mfa()),
        &["prod:example-app:user"],
    );
    let r = rig.client.decide(req).await.unwrap().into_owned();
    assert!(
        !allowed(r.decision.as_known().unwrap()),
        "row 6: allowed by Cedar, not counted here"
    );
    let req = requires(
        token("token.issue", &["workforce/u-4001"], "live", fresh_mfa()),
        &["dev:example-app:user"],
    );
    let r = rig.client.decide(req).await.unwrap().into_owned();
    assert!(
        allowed(r.decision.as_known().unwrap()),
        "the same wildcard gives the dev admin ladder"
    );
    assert!(
        r.grant_names.iter().all(|g| !g.starts_with("prod:")),
        "{:?}",
        r.grant_names
    );
    assert!(r.grant_names.iter().any(|g| g == "acme:example-app:admin"));

    // u-3001 is bound to prod:example-app:admin in full; the ladder then gives the rest of prod.
    let req = requires(
        token("token.issue", &["workforce/u-3001"], "live", fresh_mfa()),
        &["prod:example-app:user"],
    );
    let r = rig.client.decide(req).await.unwrap().into_owned();
    assert!(allowed(r.decision.as_known().unwrap()));
    assert_eq!(
        r.grant_names,
        [
            "prod:example-app:admin",
            "prod:example-app:operator",
            "prod:example-app:user"
        ]
    );
}

#[tokio::test]
async fn an_unknown_action_or_entity_or_a_misfit_is_a_denial_that_is_audited() {
    let rig = Rig::new("session").await;
    let mut cases = Vec::new();
    let mut r = token("token.issue", &["workforce/u-1001"], "live", fresh_mfa());
    r.action = "grant.hold".into(); // asked by policy for itself, never by an asker
    cases.push(("action", r));
    let mut r = token("token.issue", &["workforce/u-1001"], "live", fresh_mfa());
    r.action = "nonsense".into();
    cases.push(("action", r));
    let mut r = token("token.issue", &["workforce/u-1001"], "live", fresh_mfa());
    r.principal = common::entity("Spaceship", "p-1").into();
    cases.push(("principal", r));
    let mut r = token("token.issue", &["workforce/u-1001"], "live", fresh_mfa());
    r.resource = common::entity("Hangar", "example-app").into();
    cases.push(("resource", r));
    let r = subject(
        token("token.issue", &["workforce/u-1001"], "live", fresh_mfa()),
        "someone-else",
    ); // not the principal
    cases.push(("facts", r));
    let r = accounts(
        token("token.issue", &["workforce/u-1001"], "live", fresh_mfa()),
        &["no-slash"],
    );
    cases.push(("facts", r));
    let r = auth_age(
        token("token.issue", &["workforce/u-1001"], "live", fresh_mfa()),
        -1,
    );
    cases.push(("schema", r));
    let mut r = token("token.issue", &["workforce/u-1001"], "live", fresh_mfa());
    r.tenant = "*".into(); // every tenant is for audit actions
    cases.push(("tenant", r));
    let mut r = token("token.issue", &["workforce/u-1001"], "live", fresh_mfa());
    r.tenant = String::new();
    cases.push(("tenant", r));
    let mut r = token("token.issue", &["workforce/u-1001"], "live", fresh_mfa());
    r.grant_store_verbs = vec!["root".into()];
    cases.push(("grant", r));

    let n = cases.len();
    for (why, req) in cases {
        let r = rig.client.decide(req).await.unwrap().into_owned();
        assert!(!allowed(r.decision.as_known().unwrap()), "{why}");
        assert!(
            r.sealed_grant.is_empty() && r.reasons.is_empty() && r.grant_names.is_empty(),
            "{why}"
        );
    }
    let d = rig.around.spool.of("policy.decide");
    assert_eq!(d.len(), n, "each one audited once");
    assert!(
        d.iter()
            .all(|(r, _)| r["status_id"] == 2 && r["action_id"] == 2)
    );
    let codes: Vec<&str> = d
        .iter()
        .map(|(r, _)| r["status_code"].as_str().unwrap())
        .collect();
    assert_eq!(
        codes,
        [
            "action",
            "action",
            "principal",
            "resource",
            "facts",
            "facts",
            "schema",
            "tenant",
            "tenant",
            "grant"
        ]
    );
    // The text of an unknown action is the asker's, so the record says only that it was unknown.
    assert_eq!(d[1].0["unmapped"]["sluis"]["cedar_action"], "unknown");
    assert!(rig.around.keys.sealed.lock().unwrap().is_empty());
}

#[tokio::test]
async fn an_asker_asks_only_its_own_actions() {
    // exchange asks token.exchange, not token.issue; session the other way round.
    let rig = Rig::new("exchange").await;
    let r = rig
        .client
        .decide(token(
            "token.issue",
            &["workforce/u-1001"],
            "live",
            fresh_mfa(),
        ))
        .await
        .unwrap()
        .into_owned();
    assert!(!allowed(r.decision.as_known().unwrap()));
    assert_eq!(
        rig.around.spool.of("policy.decide")[0].0["status_code"],
        "asker"
    );
    let r = rig
        .client
        .decide(token(
            "token.exchange",
            &["workforce/u-1001"],
            "live",
            fresh_mfa(),
        ))
        .await
        .unwrap()
        .into_owned();
    assert!(allowed(r.decision.as_known().unwrap()));
    assert_eq!(open_sealed(&r.sealed_grant).holder, "exchange");
}

#[tokio::test]
async fn the_audit_pieces_get_the_built_in_grants_for_themselves_only() {
    let rig = Rig::new("writer").await;
    let r = rig
        .client
        .decide(audit("audit.seal", "writer", "acme"))
        .await
        .unwrap()
        .into_owned();
    assert!(allowed(r.decision.as_known().unwrap()));
    assert_eq!(r.reasons[0].policy_id, "builtin-audit-seal-writer");
    assert_eq!(r.reasons[0].layer, "built-in");
    let g = open_sealed(&r.sealed_grant);
    assert_eq!(
        (g.holder.as_str(), g.tenants.as_slice()),
        ("writer", ["acme".to_owned()].as_slice())
    );
    // It asked for seal and open; the registry gives the writer seal under `evidence` alone, so the
    // grant is narrowed to seal.
    assert_eq!(g.key_ops, ["seal"]);

    // The writer cannot ask as another actor, or for another actor's action, or for every tenant.
    for req in [
        audit("audit.seal", "indexer", "acme"),
        audit("audit.index", "writer", "acme"),
        audit("audit.seal", "writer", "*"),
    ] {
        let r = rig.client.decide(req).await.unwrap().into_owned();
        assert!(!allowed(r.decision.as_known().unwrap()));
    }
    // The reader has no built-in permit: audit.read comes from the bindings of the configuration.
    let rig = Rig::new("reader").await;
    let r = rig
        .client
        .decide(audit("audit.read", "reader", "acme"))
        .await
        .unwrap()
        .into_owned();
    assert!(!allowed(r.decision.as_known().unwrap()));
}

#[tokio::test]
async fn the_indexer_may_index_every_tenant_of_the_boundary() {
    let rig = Rig::new("indexer").await;
    let r = rig
        .client
        .decide(audit("audit.index", "indexer", "*"))
        .await
        .unwrap()
        .into_owned();
    assert!(allowed(r.decision.as_known().unwrap()));
    assert_eq!(open_sealed(&r.sealed_grant).tenants, ["*"]);
    let d = rig.around.spool.of("policy.decide");
    assert!(
        d[0].0["metadata"].get("tenant_uid").is_none(),
        "every tenant is the operator's own record"
    );
}

#[tokio::test]
async fn when_key_cannot_seal_policy_cannot_decide_and_denies() {
    let rig = Rig::new("session").await;
    *rig.around.keys.fail.lock().unwrap() = true;
    let r = rig
        .client
        .decide(token(
            "token.issue",
            &["workforce/u-1001"],
            "live",
            fresh_mfa(),
        ))
        .await
        .unwrap()
        .into_owned();
    assert!(!allowed(r.decision.as_known().unwrap()));
    assert!(r.sealed_grant.is_empty());
    let d = rig.around.spool.of("policy.decide");
    assert_eq!(d.len(), 1);
    assert_eq!(d[0].0["status_code"], "keys");
    assert_eq!(
        d[0].0["action_id"], 2,
        "the record says denied, as the answer does"
    );
}

#[tokio::test]
async fn an_allow_whose_audit_fact_is_not_durable_is_withdrawn() {
    let rig = Rig::new("session").await;
    *rig.around.spool.fail.lock().unwrap() = Some(ErrorCode::Unavailable);
    let r = rig
        .client
        .decide(token(
            "token.issue",
            &["workforce/u-1001"],
            "live",
            fresh_mfa(),
        ))
        .await
        .unwrap()
        .into_owned();
    assert!(!allowed(r.decision.as_known().unwrap()));
    assert!(
        r.sealed_grant.is_empty(),
        "a grant nobody can account for is never handed out"
    );
    assert!(r.grant_names.is_empty());
}

#[tokio::test]
async fn an_actor_the_registry_does_not_let_call_policy_is_refused_before_the_message() {
    // signer is an actor of the registry with no call to policy.
    let rig = Rig::new("signer").await;
    let err = rig
        .client
        .decide(token(
            "token.issue",
            &["workforce/u-1001"],
            "live",
            fresh_mfa(),
        ))
        .await
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::PermissionDenied);
    assert_eq!(refusal_reason(&err).as_deref(), Some("call_graph"));
    assert!(rig.around.spool.records().is_empty());
}

#[tokio::test]
async fn an_allow_reached_past_a_policy_that_errored_is_a_denial() {
    // A forbid that errors is skipped by Cedar, which would let the permit through. The overflow
    // happens only at run time, so the schema accepts the policy.
    let mut inputs = common::local_inputs();
    inputs.policies.push(policy::engine::PolicyDoc {
        file: "overflow".into(),
        cedar: "@id(\"overflow\")\nforbid (principal is Person, action == Action::\"token.issue\", resource is Client)\nwhen { context has auth_age && context.auth_age * 9223372036854775807 > 0 };".into(),
    });
    let rig = Rig::with("session", &inputs).await;
    let r = rig
        .client
        .decide(token(
            "token.issue",
            &["workforce/u-1001"],
            "live",
            fresh_mfa(),
        ))
        .await
        .unwrap()
        .into_owned();
    assert!(!allowed(r.decision.as_known().unwrap()));
    assert!(r.sealed_grant.is_empty() && r.reasons.is_empty());
    let d = rig.around.spool.of("policy.decide");
    assert_eq!(d[0].0["status_code"], "evaluation");
    assert_eq!(d[0].0["unmapped"]["sluis"]["policy_errors"], 1);
}

#[tokio::test]
async fn an_id_is_taken_verbatim_whatever_characters_it_has() {
    let rig = Rig::new("session").await;
    let r = rig
        .client
        .decide(subject_and_principal(
            token("token.issue", &["workforce/u-1001"], "live", fresh_mfa()),
            "p\"x\\y é",
        ))
        .await
        .unwrap()
        .into_owned();
    assert!(allowed(r.decision.as_known().unwrap()));
}

fn subject_and_principal(
    mut r: sluis_proto::sluis::policy::v2alpha1::DecideRequest,
    s: &str,
) -> sluis_proto::sluis::policy::v2alpha1::DecideRequest {
    r.principal = common::entity("Person", s).into();
    subject(r, s)
}
