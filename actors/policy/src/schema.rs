//! The Cedar schema `policy` is written against, and its built-in layer.
//!
//! The schema is fixed by sluis and embedded here (policy.md "The schema is sluis's, the policy is
//! the operator's"). The file `docs/reference/policy-schema.cedarschema` is the schema of the
//! reference page; the additions below it are decision D-6 of the build plan: the entity `Actor`
//! and the audit actions, which the page does not have yet.

use std::str::FromStr as _;

use cedar_policy::Schema;

/// The schema of the reference page, schema version 1.
const PAGE: &str = include_str!("../../../docs/reference/policy-schema.cedarschema");

/// The additions of this build to the page's schema (decision D-6): the audit pieces are
/// principals, and their actions get a decision and a grant like any other.
const AUDIT: &str = r#"
// An actor of sluis that asks for a grant for itself (decision D-6): `writer`, `indexer`,
// `reader`. Named by its registry name, which the asker cannot choose: `policy` takes it from the
// transport.
entity Actor;

// The audit writer asks for a grant to seal a batch of a tenant's evidence.
action "audit.seal" appliesTo {
  principal: Actor,
  resource: Boundary,
  context: {},
};

// The indexer asks for a grant to index a tenant's evidence, or every tenant's.
action "audit.index" appliesTo {
  principal: Actor,
  resource: Boundary,
  context: {},
};

// One log of a project of the boundary, named `<project>/<kind>` such as `sluis/audit` (ADR 0028 "Access":
// every call is decided on project x log kind x tenant). The project is the `AuditLog` document's, the kind
// is `audit` or `usage`.
entity AuditLog in [Boundary] = {
  project: String,
  kind: String,
};

// A reader asks for a grant to open a tenant's evidence in one log, for itself or for a person. Which
// readers may read what is a binding of the configuration.
action "audit.read" appliesTo {
  principal: [Actor, Person],
  resource: AuditLog,
  context: Authentication,
};
"#;

/// The version of the schema, which the digest of a policy set names.
pub const VERSION: &str = "1";

/// The built-in layer (ADR 0007 "Four layers"): the predefined permits of the audit pieces
/// (decision D-6). They hold for every tenant of the boundary, because a tenant is not a Cedar
/// entity: the grant of a decision names the tenant the asker said, and `key@` and `store@` check
/// the tenant again.
pub const BUILTIN: &str = r#"
@id("builtin-audit-seal-writer")
permit (principal == Actor::"writer", action == Action::"audit.seal", resource is Boundary);

@id("builtin-audit-index-indexer")
permit (principal == Actor::"indexer", action == Action::"audit.index", resource is Boundary);

// The floor (ADR 0007 "Four layers": a forbid of a lower layer holds whatever a higher one adds):
// an operator's hold takes effect at once and outlasts every binding (ADR 0019). The example
// policy has the same rule as a config policy; this one does not depend on it.
@id("builtin-person-not-live")
forbid (principal is Person, action, resource)
when { principal.state != "live" };

// A pull request runs the files it proposes, so its author controls the workflow that asks for a
// signature, and a rule that names only the repository would let that author sign (REQ-WORKLOAD-007).
// So do the events that can run pull-request code (owner decision W1 A, 2026-11-06).
// No operator policy can undo this forbid. It refuses `artifact.sign` for a workload that:
//  - has a ref under `refs/pull/` (the merge ref of a pull request, whatever the event),
//  - has an event that begins `pull_request`: `pull_request`, `pull_request_review`,
//    `pull_request_review_comment` and `pull_request_target`. The last runs in the context of the
//    base repository, with its secrets, but it checks out and runs what the author influences and
//    its ref is the base branch, so the ref test alone would pass it; it is refused too, because
//    refusing is the safe default and a release signature has no use for it,
//  - has the event `issue_comment` or `workflow_run`, which run on the default branch and can
//    still run code that a pull request proposes (a comment, or a workflow that a pull request
//    triggered), or `merge_group`, whose run holds the changes of the pull requests in the queue
//    (exact matches: a release signs from a `push` to a tag),
//  - or comes from the `github-oidc` verifier with no event at all: GitHub sends `event_name` in
//    every token, so a token without it is not one to take for a push. A workload of another
//    verifier that carries neither a ref nor an event is not a pull request and is not caught.
@id("builtin-workload-pull-request-no-sign")
forbid (principal is Workload, action == Action::"artifact.sign", resource)
when {
  (principal has ref && principal.ref like "refs/pull/*") ||
  (principal has event && principal.event like "pull_request*") ||
  (principal has event && principal.event == "issue_comment") ||
  (principal has event && principal.event == "workflow_run") ||
  (principal has event && principal.event == "merge_group") ||
  (principal.verifier == "github-oidc" && !(principal has event))
};
"#;

/// The text of the schema that is embedded, for the digest.
#[must_use]
pub fn text() -> String {
    format!("{PAGE}\n{AUDIT}")
}

/// The embedded schema.
///
/// # Errors
///
/// A message when the embedded text does not parse, which is a bug of the build.
pub fn schema() -> Result<Schema, String> {
    Schema::from_str(&text()).map_err(|e| format!("the embedded schema: {e}"))
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_embedded_schema_parses_and_has_the_audit_actions() {
        let s = super::schema().unwrap();
        let actions: Vec<String> = s.actions().map(|a| a.to_string()).collect();
        for a in [
            "grant.hold",
            "token.issue",
            "token.exchange",
            "artifact.sign",
            "policy.link",
            "audit.seal",
            "audit.index",
            "audit.read",
        ] {
            assert!(
                actions.iter().any(|x| x == &format!("Action::\"{a}\"")),
                "{a} in {actions:?}"
            );
        }
    }
}
