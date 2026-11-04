#![allow(clippy::unwrap_used, clippy::expect_used)] // a failed unwrap in a test is the failure
//! A set that does not fit is refused at load, naming the policy and never a value; and the load
//! checks of policy.md "What `sluis config check` checks".

mod common;

use common::{local, local_inputs};
use policy::engine::{Engine, Inputs, Link, PolicyDoc};

fn with(extra: &str) -> Inputs {
    let mut i = local_inputs();
    i.policies.push(PolicyDoc {
        file: "extra".into(),
        cedar: extra.into(),
    });
    i
}

fn refused(i: &Inputs) -> String {
    Engine::build(i).unwrap_err().to_string()
}

#[test]
fn the_local_installation_loads_and_has_a_digest() {
    let a = Engine::build(&local_inputs()).unwrap();
    let b = Engine::build(&local_inputs()).unwrap();
    assert_eq!(a.digest(), b.digest(), "the same set is the same digest");
    assert_eq!(a.digest().len(), 96);
    let mut other = local_inputs();
    other.policies[0]
        .cedar
        .push_str("\n// a comment is a change of the reviewed file\n");
    assert_ne!(Engine::build(&other).unwrap().digest(), a.digest());
    let mut other = local_inputs();
    other.vocabulary.extend_from_slice(b"\n# a comment\n");
    assert_ne!(
        Engine::build(&other).unwrap().digest(),
        a.digest(),
        "the vocabulary is in the digest"
    );
}

#[test]
fn a_policy_that_does_not_fit_the_schema_is_refused_naming_the_policy() {
    // an attribute the schema does not have
    let e = refused(&with(
        "@id(\"bad-attr\")\npermit (principal is Person, action == Action::\"token.issue\", resource is Client)\nwhen { principal.shoe_size == 9 };",
    ));
    assert!(
        e.contains("bad-attr") && e.contains("does not fit the schema"),
        "{e}"
    );
    // an action the schema does not have
    let e = refused(&with(
        "@id(\"bad-action\")\npermit (principal, action == Action::\"coffee.make\", resource);",
    ));
    assert!(e.contains("bad-action"), "{e}");
    // a type error
    let e = refused(&with(
        "@id(\"bad-type\")\nforbid (principal is Person, action == Action::\"token.issue\", resource is Client)\nwhen { context.auth_age == \"soon\" };",
    ));
    assert!(e.contains("bad-type"), "{e}");
}

#[test]
fn a_file_that_does_not_parse_is_refused_without_showing_it() {
    let e = refused(&with(
        "permit (principal, action, resource) when {{{ secret-looking-text",
    ));
    assert!(e.contains("extra: does not parse"), "{e}");
    assert!(!e.contains("secret-looking-text"), "{e}");
}

#[test]
fn every_policy_has_one_unique_id() {
    let e = refused(&with(
        "permit (principal, action == Action::\"audit.seal\", resource);",
    ));
    assert!(e.contains("a policy has no @id"), "{e}");
    let e = refused(&with(
        "@id(\"token-requires\")\nforbid (principal, action == Action::\"audit.seal\", resource);",
    ));
    assert!(e.contains("token-requires is used twice"), "{e}");
    // within one file, too
    let e = refused(&with(
        "@id(\"x\")\nforbid (principal, action == Action::\"audit.seal\", resource);\n@id(\"x\")\nforbid (principal, action == Action::\"audit.index\", resource);",
    ));
    assert!(e.contains("used twice"), "{e}");
    // and a file may not use an id of the built-in layer
    let e = refused(&with(
        "@id(\"builtin-audit-seal-writer\")\nforbid (principal, action == Action::\"audit.seal\", resource);",
    ));
    assert!(e.contains("used twice"), "{e}");
}

#[test]
fn step_up_is_for_a_forbid_and_holds_acr_values_and_max_age() {
    let step = |attr: &str, effect: &str| {
        with(&format!(
            "@id(\"s\")\n@step_up(\"{attr}\")\n{effect} (principal is Person, action == Action::\"token.issue\", resource is Client);"
        ))
    };
    assert!(Engine::build(&step("acr_values=urn:x max_age=60", "forbid")).is_ok());
    assert!(Engine::build(&step("max_age=60", "forbid")).is_ok());
    assert!(refused(&step("acr_values=urn:x max_age=60", "permit")).contains("only for a forbid"));
    for bad in [
        "",
        "max_age=soon",
        "acr_values=a acr_values=b",
        "other=1",
        "max_age=60;x",
    ] {
        assert!(
            refused(&step(bad, "forbid")).contains("@step_up is not"),
            "{bad}"
        );
    }
}

#[test]
fn a_grant_name_the_vocabulary_does_not_declare_is_refused_with_the_policy() {
    let e = refused(&with(
        "@id(\"typo\")\npermit (principal in Account::\"workforce/u-1\", action == Action::\"grant.hold\", resource == Grant::\"dev:example-app:root\");",
    ));
    assert!(
        e.contains("typo") && e.contains("the vocabulary does not declare"),
        "{e}"
    );
    // in a template, too
    let e = refused(&with(
        "@id(\"t\")\npermit (principal in ?principal, action == Action::\"grant.hold\", resource == Grant::\"nope:x:y\");",
    ));
    assert!(e.contains("t:") && e.contains("does not declare"), "{e}");
}

#[test]
fn a_wildcard_that_expands_to_nothing_is_refused() {
    // REQ-POLICY-012: no grant name of the vocabulary has the role `owner`.
    let e = refused(&with(
        "@id(\"empty\")\npermit (principal in Account::\"workforce/u-77\", action == Action::\"grant.hold\", resource)\nwhen { resource.role == \"owner\" };",
    ));
    assert!(
        e.contains("empty") && e.contains("expands to no grant name"),
        "{e}"
    );
}

#[test]
fn a_wildcard_in_the_role_position_is_refused_because_it_gives_several_roles_at_once() {
    let e = refused(&with(
        "@id(\"all-roles\")\npermit (principal in Account::\"workforce/u-78\", action == Action::\"grant.hold\", resource)\nwhen { resource.scope == \"dev\" };",
    ));
    assert!(
        e.contains("all-roles") && e.contains("several roles"),
        "{e}"
    );
}

#[test]
fn a_link_that_cannot_be_applied_is_a_refusal_of_the_set() {
    let link = |template: &str, id: &str, principal: &str, resource: &str| Link {
        template_id: template.into(),
        link_id: id.into(),
        args: [
            ("?principal".to_owned(), principal.to_owned()),
            ("?resource".to_owned(), resource.to_owned()),
        ]
        .into(),
        layer: "tenant".into(),
    };
    let ok = link(
        "bind-account-to-grant",
        "l1",
        "Account::\"acme/s-9\"",
        "Grant::\"acme:example-app:user\"",
    );
    let mut i = local_inputs();
    i.links = vec![ok.clone()];
    assert!(Engine::build(&i).is_ok());
    for (bad, what) in [
        (
            link(
                "no-such-template",
                "l2",
                "Account::\"a/b\"",
                "Grant::\"acme:example-app:user\"",
            ),
            "does not apply",
        ),
        (
            link(
                "token-requires",
                "l3",
                "Account::\"a/b\"",
                "Grant::\"acme:example-app:user\"",
            ),
            "does not apply",
        ), // a policy, not a template
        (
            link(
                "bind-account-to-grant",
                "l4",
                "Account::\"a/b\"",
                "Grant::\"acme:example-app:root\"",
            ),
            "does not declare",
        ),
        (
            link(
                "bind-account-to-grant",
                "l1",
                "Account::\"a/b\"",
                "Grant::\"acme:example-app:user\"",
            ),
            "used or not valid",
        ),
        (
            link(
                "bind-account-to-grant",
                "l5",
                "Account::\"a/b\"",
                "Person::\"p\"",
            ),
            "wrong type",
        ), // a slot of the wrong type
        (
            link(
                "bind-account-to-grant",
                "l6",
                "not an entity",
                "Grant::\"acme:example-app:user\"",
            ),
            "not an entity",
        ),
    ] {
        let mut i = local_inputs();
        i.links = vec![ok.clone(), bad];
        let e = refused(&i);
        assert!(e.contains(what), "{what}: {e}");
    }
}

#[test]
fn a_vocabulary_that_does_not_fit_is_refused_with_its_path() {
    let mut i = local_inputs();
    i.vocabulary = b"scopes: {dev: {}}\nthings: {t: {roles: {a: [b]}}}\n".to_vec();
    let e = refused(&i);
    assert!(
        e.contains("GrantVocabulary: things.t.roles.a.implies[0]"),
        "{e}"
    );
    // and the policies are then not read against it
    assert!(!e.contains("example-app"), "{e}");
    let _ = local("vocabulary.yaml");
}
