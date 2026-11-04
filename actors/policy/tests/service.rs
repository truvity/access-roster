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
    // The built-in floor and the example's own rule both forbid.
    let ids: Vec<&str> = r.reasons.iter().map(|x| x.policy_id.as_str()).collect();
    assert_eq!(ids, ["builtin-person-not-live", "person-not-live"]);
    assert!(r.grant_names.is_empty());
}

#[tokio::test]
async fn the_held_person_floor_does_not_depend_on_the_example_policy() {
    // A boundary whose config says nothing about holds still refuses a held person.
    let mut inputs = common::local_inputs();
    inputs.policies[0].cedar = common::local("local.cedar")
        .replace("@id(\"person-not-live\")", "@id(\"person-state\")")
        .replace(
            "principal.state != \"live\"",
            "principal.state == \"never\"",
        );
    let rig = Rig::with("session", &inputs).await;
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
    assert_eq!(r.reasons[0].policy_id, "builtin-person-not-live");
    assert_eq!(r.reasons[0].layer, "built-in");
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
async fn a_question_that_is_not_one_is_refused_with_the_code_that_says_why_and_audited() {
    use ErrorCode::{InvalidArgument as Bad, PermissionDenied as Denied};
    let rig = Rig::new("session").await;
    let ok = || token("token.issue", &["workforce/u-1001"], "live", fresh_mfa());
    let mut cases: Vec<(
        ErrorCode,
        &str,
        &str,
        sluis_proto::sluis::policy::v2alpha1::DecideRequest,
    )> = Vec::new();
    let mut r = ok();
    r.action = "grant.hold".into(); // asked by policy for itself, never by an asker
    cases.push((Bad, "schema", "action", r));
    let mut r = ok();
    r.action = "nonsense".into();
    cases.push((Bad, "schema", "action", r));
    let mut r = ok();
    r.principal = common::entity("Spaceship", "p-1").into();
    cases.push((Bad, "schema", "principal.type", r));
    let mut r = ok();
    r.resource = common::entity("Hangar", "example-app").into();
    cases.push((Bad, "schema", "resource.type", r));
    cases.push((
        Bad,
        "schema",
        "person.subject",
        subject(ok(), "someone-else"),
    ));
    cases.push((
        Bad,
        "schema",
        "person.accounts",
        accounts(ok(), &["no-slash"]),
    ));
    cases.push((Bad, "schema", "person.org", common::org(ok(), "")));
    cases.push((Bad, "schema", "client.kind", common::kind(ok(), "")));
    cases.push((Bad, "schema", "client.kind", common::kind(ok(), "secret")));
    cases.push((Bad, "schema", "context", auth_age(ok(), -1)));
    let mut r = ok();
    r.tenant = "*".into(); // every tenant is for audit actions
    cases.push((Bad, "schema", "tenant", r));
    let mut r = ok();
    r.tenant = String::new();
    cases.push((Bad, "schema", "tenant", r));
    let mut r = ok();
    r.grant_store_verbs = vec!["root".into()];
    cases.push((Bad, "schema", "grant_store_verbs", r));
    let mut r = ok();
    r.grant_key_ops = vec!["root".into()];
    cases.push((Bad, "schema", "grant_key_ops", r));
    let mut r = ok();
    r.action = "token.exchange".into(); // session asks token.issue only
    cases.push((Denied, "rule", "action", r));

    let n = cases.len();
    for (code, reason, path, req) in cases {
        let e = rig.client.decide(req).await.unwrap_err();
        assert_eq!(
            (e.code, refusal_reason(&e).as_deref()),
            (code, Some(reason)),
            "{path}"
        );
    }
    let d = rig.around.spool.of("policy.decide");
    assert_eq!(d.len(), n, "each one audited once");
    for (r, _) in &d {
        assert_eq!(r["status_id"], 2);
        assert!(
            r.get("action_id").is_none(),
            "nothing was decided, so no decision is recorded"
        );
    }
    let paths: Vec<&str> = d
        .iter()
        .map(|(r, _)| r["unmapped"]["sluis"]["path"].as_str().unwrap())
        .collect();
    assert_eq!(paths[2], "principal.type");
    assert_eq!(paths[n - 1], "action");
    // The text of an unknown action is the asker's, so the record says only that it was unknown.
    assert_eq!(d[1].0["unmapped"]["sluis"]["cedar_action"], "unknown");
    assert!(rig.around.keys.sealed.lock().unwrap().is_empty());
}

#[tokio::test]
async fn a_forbid_that_reads_the_kind_or_the_org_sees_what_the_asker_sent() {
    let mut inputs = common::local_inputs();
    inputs.policies.push(policy::engine::PolicyDoc {
        file: "kinds".into(),
        cedar: "@id(\"no-public\")\nforbid (principal is Person, action == Action::\"token.issue\", resource is Client) when { resource.kind == \"public\" };\n@id(\"no-globex\")\nforbid (principal is Person, action == Action::\"token.issue\", resource is Client) when { principal.org == \"globex\" };".into(),
    });
    let rig = Rig::with("session", &inputs).await;
    let ask = |req| async { rig.client.decide(req).await.unwrap().into_owned() };
    let ok = || token("token.issue", &["workforce/u-1001"], "live", fresh_mfa());

    assert!(allowed(ask(ok()).await.decision.as_known().unwrap()));
    let r = ask(common::kind(ok(), "public")).await;
    assert_eq!(r.reasons[0].policy_id, "no-public");
    // The org is the person's, not the tenant of the question: tenant acme, person of globex.
    let r = ask(common::org(ok(), "globex")).await;
    assert!(!allowed(r.decision.as_known().unwrap()));
    assert_eq!(r.reasons[0].policy_id, "no-globex");
    let r = ask(common::org(ok(), "acme")).await;
    assert!(allowed(r.decision.as_known().unwrap()));
}

#[tokio::test]
async fn an_asker_asks_only_its_own_actions() {
    // exchange asks token.exchange, not token.issue.
    let rig = Rig::new("exchange").await;
    let e = rig
        .client
        .decide(token(
            "token.issue",
            &["workforce/u-1001"],
            "live",
            fresh_mfa(),
        ))
        .await
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::PermissionDenied);
    assert_eq!(refusal_reason(&e).as_deref(), Some("rule"));
    assert_eq!(
        rig.around.spool.of("policy.decide")[0].0["status_code"],
        "rule"
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
async fn an_action_cannot_widen_its_own_grant() {
    // token.exchange may allow get, list, create, update and seal, open; whatever the asker asks.
    let rig = Rig::new("exchange").await;
    let mut req = token("token.exchange", &["workforce/u-1001"], "live", fresh_mfa());
    req.grant_store_verbs = ["get", "create", "delete", "apply"]
        .map(String::from)
        .to_vec();
    req.grant_key_ops = ["seal", "open", "mac", "sign"].map(String::from).to_vec();
    let g = open_sealed(
        &rig.client
            .decide(req)
            .await
            .unwrap()
            .into_owned()
            .sealed_grant,
    );
    assert_eq!(g.store_verbs, ["create", "get"]);
    assert_eq!(g.key_ops, ["open", "seal"]);

    // An audit grant allows no store verb at all.
    let rig = Rig::new("writer").await;
    let mut req = audit("audit.seal", "writer", "acme");
    req.grant_store_verbs = vec!["create".into(), "get".into()];
    let g = open_sealed(
        &rig.client
            .decide(req)
            .await
            .unwrap()
            .into_owned()
            .sealed_grant,
    );
    assert!(g.store_verbs.is_empty());
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
    for (req, code) in [
        (
            audit("audit.seal", "indexer", "acme"),
            ErrorCode::PermissionDenied,
        ),
        (
            audit("audit.index", "writer", "acme"),
            ErrorCode::PermissionDenied,
        ),
        (
            audit("audit.seal", "writer", "*"),
            ErrorCode::InvalidArgument,
        ),
    ] {
        assert_eq!(rig.client.decide(req).await.unwrap_err().code, code);
    }
    // The reader has no built-in permit: audit.read comes from the bindings of the configuration. The
    // local policy binds the reader; a configuration without that binding denies it.
    let rig = Rig::new("reader").await;
    let r = rig
        .client
        .decide(audit("audit.read", "reader", "acme"))
        .await
        .unwrap()
        .into_owned();
    assert!(allowed(r.decision.as_known().unwrap()));
    assert_eq!(r.reasons[0].policy_id, "bind-reader-audit-read");
    assert_eq!(r.reasons[0].layer, "config");
    let g = open_sealed(&r.sealed_grant);
    assert_eq!(
        (
            g.holder.as_str(),
            g.tenants.as_slice(),
            g.key_ops.as_slice()
        ),
        (
            "reader",
            ["acme".to_owned()].as_slice(),
            ["open".to_owned()].as_slice()
        )
    );
    assert!(g.store_verbs.is_empty());
    let mut inputs = common::local_inputs();
    let binding = "@id(\"bind-reader-audit-read\")\npermit (principal == Actor::\"reader\", action == Action::\"audit.read\", resource is Boundary);\n";
    assert!(inputs.policies[0].cedar.contains(binding));
    inputs.policies[0].cedar = inputs.policies[0].cedar.replace(binding, "");
    let rig = Rig::with("reader", &inputs).await;
    let r = rig
        .client
        .decide(audit("audit.read", "reader", "acme"))
        .await
        .unwrap()
        .into_owned();
    assert!(!allowed(r.decision.as_known().unwrap()));
    assert!(r.sealed_grant.is_empty());
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
async fn when_key_cannot_seal_the_caller_is_told_it_is_unavailable_and_gets_no_grant() {
    let rig = Rig::new("session").await;
    *rig.around.keys.fail.lock().unwrap() = true;
    let e = rig
        .client
        .decide(token(
            "token.issue",
            &["workforce/u-1001"],
            "live",
            fresh_mfa(),
        ))
        .await
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::Unavailable);
    assert_eq!(refusal_reason(&e).as_deref(), Some("keys"));
    // Audit first, one record: the decision was made and is on record; nothing else is added.
    let d = rig.around.spool.of("policy.decide");
    assert_eq!(d.len(), 1);
    assert!(d[0].1, "blocking");
    assert_eq!(d[0].0["action_id"], 1);
}

#[tokio::test]
async fn an_allow_whose_audit_fact_is_not_durable_is_unavailable_and_no_grant_was_ever_sealed() {
    let rig = Rig::new("session").await;
    *rig.around.spool.fail.lock().unwrap() = Some(ErrorCode::Unavailable);
    let e = rig
        .client
        .decide(token(
            "token.issue",
            &["workforce/u-1001"],
            "live",
            fresh_mfa(),
        ))
        .await
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::Unavailable);
    assert_eq!(refusal_reason(&e).as_deref(), Some("audit"));
    assert!(
        rig.around.keys.sealed.lock().unwrap().is_empty(),
        "audit comes first: a grant nobody can account for is never made"
    );
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
    assert_eq!(d[0].0["action_id"], 2);
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
