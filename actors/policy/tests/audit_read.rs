#![allow(refining_impl_trait)] // the generated traits return `impl Encodable`; a concrete type is fine
#![allow(clippy::unwrap_used, clippy::expect_used)] // a failed unwrap in a test is the failure
//! A read of the audit log is decided on the log it names: its project and its log kind, with the tenant of the
//! question (ADR 0028 "Access", REQ-AUDIT-073).

mod common;

use common::{Rig, audit, entity};
use connectrpc::error::ErrorCode;
use sluis_kit::refusal_reason;
use sluis_proto::sluis::policy::v2alpha1::{DecideRequest, Decision};

fn read_of(log: &str, tenant: &str) -> DecideRequest {
    let mut r = audit("audit.read", "reader", tenant);
    r.resource = entity("AuditLog", log).into();
    r
}

async fn verdict(rig: &Rig, log: &str, tenant: &str) -> Decision {
    rig.client
        .decide(read_of(log, tenant))
        .await
        .unwrap()
        .into_owned()
        .decision
        .as_known()
        .unwrap()
}

/// The binding of the local installation reads any log. A binding that names a project and a kind allows exactly
/// that log, and the others are denied by it: the project and the kind are Cedar's, not the reader's. A question about
/// the boundary at large, or about a log whose name is not `<project>/<kind>`, is not a question.
///
/// verifies: REQ-AUDIT-073
#[tokio::test]
async fn a_read_is_decided_on_the_project_and_the_log_kind_it_names() {
    let rig = Rig::new("reader").await;
    for log in ["sluis/audit", "sluis/usage", "billing/audit"] {
        assert_eq!(verdict(&rig, log, "acme").await, Decision::ALLOW, "{log}");
    }

    let mut inputs = common::local_inputs();
    let wide = "permit (principal == Actor::\"reader\", action == Action::\"audit.read\", resource is AuditLog);\n";
    let narrow = "permit (principal == Actor::\"reader\", action == Action::\"audit.read\", resource is AuditLog)\nwhen { resource.project == \"sluis\" && resource.kind == \"audit\" };\n";
    assert!(inputs.policies[0].cedar.contains(wide));
    inputs.policies[0].cedar = inputs.policies[0].cedar.replace(wide, narrow);
    let rig = Rig::with("reader", &inputs).await;
    assert_eq!(verdict(&rig, "sluis/audit", "acme").await, Decision::ALLOW);
    for log in ["sluis/usage", "billing/audit", "billing/usage"] {
        let r = rig
            .client
            .decide(read_of(log, "acme"))
            .await
            .unwrap()
            .into_owned();
        assert_eq!(r.decision.as_known().unwrap(), Decision::DENY, "{log}");
        assert!(r.sealed_grant.is_empty(), "{log}");
    }

    for (what, mut req) in [
        ("the boundary", read_of("sluis/audit", "acme")),
        ("no kind", read_of("sluis", "acme")),
        ("a kind that is none", read_of("sluis/metrics", "acme")),
        ("a slash too many", read_of("a/b/audit", "acme")),
        ("no project", read_of("/audit", "acme")),
    ] {
        if what == "the boundary" {
            req.resource = entity("Boundary", "dev").into();
        }
        let e = rig.client.decide(req).await.unwrap_err();
        assert_eq!(e.code, ErrorCode::InvalidArgument, "{what}");
        assert_eq!(refusal_reason(&e).as_deref(), Some("schema"), "{what}");
    }
}
