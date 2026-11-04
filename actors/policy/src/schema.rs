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

// A reader asks for a grant to open a tenant's evidence, for itself or for a person. Which
// readers may read what is a binding of the configuration.
action "audit.read" appliesTo {
  principal: [Actor, Person],
  resource: Boundary,
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
