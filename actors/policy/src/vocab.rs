//! The grant vocabulary (docs/reference/policy.md "The grant vocabulary"): the grant names of a
//! boundary, their scopes, and the ladder of roles.
//!
//! The document is the config kind `GrantVocabulary`. This module reads it, checks what the schema
//! cannot state (policy.md "What the vocabulary checks"), and answers the two questions `policy`
//! asks of it: which grant names exist, and which roles a held role implies. An error names a path
//! of the document, never a value.

use std::collections::{BTreeMap, BTreeSet};

use crate::yaml::{self, Value};

/// The `$id` of the schema of schema v1 (policy.md "Format").
pub const SCHEMA_ID: &str = "https://sluis.id/schema/vocabulary/v1/vocabulary.schema.json";

/// A grant name, `<scope>:<thing>:<role>`, in parts.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GrantName {
    pub scope: String,
    pub thing: String,
    pub role: String,
}

impl GrantName {
    /// The grant name as text: the id of the Cedar entity `Grant`.
    #[must_use]
    pub fn id(&self) -> String {
        format!("{}:{}:{}", self.scope, self.thing, self.role)
    }
}

/// A document that is not a valid vocabulary: the path and the rule.
#[derive(Debug, PartialEq, Eq)]
pub struct VocabError(pub String);

impl std::fmt::Display for VocabError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for VocabError {}

fn err<T>(path: &str, rule: &str) -> Result<T, VocabError> {
    Err(VocabError(if path.is_empty() {
        rule.to_owned()
    } else {
        format!("{path}: {rule}")
    }))
}

#[derive(Debug)]
struct Role {
    implies: Vec<String>,
    scopes: BTreeSet<String>,
}

/// The vocabulary of one boundary.
#[derive(Debug)]
pub struct Vocabulary {
    /// Scope name to `sensitive`.
    scopes: BTreeMap<String, bool>,
    /// Thing name to role name to role.
    things: BTreeMap<String, BTreeMap<String, Role>>,
}

fn valid_name(s: &str) -> bool {
    (1..=64).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn map<'a>(v: &'a Value, path: &str) -> Result<&'a [(String, Value)], VocabError> {
    match v {
        Value::Map(m) => Ok(m),
        _ => err(path, "must be a mapping"),
    }
}

fn names(v: &Value, path: &str) -> Result<Vec<String>, VocabError> {
    let Value::Seq(items) = v else {
        return err(path, "must be a list of names");
    };
    items
        .iter()
        .enumerate()
        .map(|(i, item)| match item {
            Value::String(s) if valid_name(s) => Ok(s.clone()),
            _ => err(&format!("{path}[{i}]"), "not a valid name"),
        })
        .collect()
}

impl Vocabulary {
    /// Reads and checks the document.
    ///
    /// # Errors
    ///
    /// [`VocabError`] naming the path at fault.
    pub fn parse(document: &[u8]) -> Result<Self, VocabError> {
        let Ok(text) = std::str::from_utf8(document) else {
            return err("", "not UTF-8");
        };
        let root = yaml::parse(text).map_err(|e| VocabError(e.to_string()))?;
        let top = map(&root, "")?;
        let (mut scopes_v, mut things_v) = (None, None);
        for (k, v) in top {
            match k.as_str() {
                "$schema" => match v {
                    Value::String(s) if s == SCHEMA_ID => {}
                    _ => return err("$schema", "must name the schema of this version"),
                },
                "scopes" => scopes_v = Some(v),
                "things" => things_v = Some(v),
                _ => return err(k, "unknown key"),
            }
        }
        let Some(scopes_v) = scopes_v else {
            return err("scopes", "is required");
        };
        let Some(things_v) = things_v else {
            return err("things", "is required");
        };

        let mut scopes = BTreeMap::new();
        for (name, decl) in map(scopes_v, "scopes")? {
            let path = format!("scopes.{name}");
            if !valid_name(name) {
                return err(&path, "not a valid name");
            }
            let mut sensitive = false;
            for (k, v) in map(decl, &path)? {
                match (k.as_str(), v) {
                    ("sensitive", Value::Bool(b)) => sensitive = *b,
                    ("sensitive", _) => {
                        return err(&format!("{path}.sensitive"), "must be a boolean");
                    }
                    _ => return err(&format!("{path}.{k}"), "unknown key"),
                }
            }
            scopes.insert(name.clone(), sensitive);
        }
        if scopes.is_empty() {
            return err("scopes", "needs at least one scope");
        }

        let mut things = BTreeMap::new();
        for (name, decl) in map(things_v, "things")? {
            let path = format!("things.{name}");
            if !valid_name(name) {
                return err(&path, "not a valid name");
            }
            let mut roles_v = None;
            for (k, v) in map(decl, &path)? {
                match k.as_str() {
                    "roles" => roles_v = Some(v),
                    _ => return err(&format!("{path}.{k}"), "unknown key"),
                }
            }
            let Some(roles_v) = roles_v else {
                return err(&format!("{path}.roles"), "is required");
            };
            let roles = Self::roles(roles_v, &format!("{path}.roles"), &scopes)?;
            things.insert(name.clone(), roles);
        }
        if things.is_empty() {
            return err("things", "needs at least one thing");
        }
        let v = Self { scopes, things };
        v.check_ladders()?;
        Ok(v)
    }

    fn roles(
        v: &Value,
        path: &str,
        scopes: &BTreeMap<String, bool>,
    ) -> Result<BTreeMap<String, Role>, VocabError> {
        let mut roles = BTreeMap::new();
        for (name, decl) in map(v, path)? {
            let rpath = format!("{path}.{name}");
            if !valid_name(name) {
                return err(&rpath, "not a valid name");
            }
            let mut role = Role {
                implies: Vec::new(),
                scopes: scopes.keys().cloned().collect(),
            };
            match decl {
                // The short form: the roles it implies.
                Value::Seq(_) => role.implies = names(decl, &rpath)?,
                // The long form.
                Value::Map(m) => {
                    for (k, v) in m {
                        let kpath = format!("{rpath}.{k}");
                        match k.as_str() {
                            "implies" => role.implies = names(v, &kpath)?,
                            "scopes" => {
                                let listed = names(v, &kpath)?;
                                if listed.is_empty() {
                                    return err(&kpath, "needs at least one scope");
                                }
                                let mut set = BTreeSet::new();
                                for (i, s) in listed.into_iter().enumerate() {
                                    if !scopes.contains_key(&s) {
                                        return err(
                                            &format!("{kpath}[{i}]"),
                                            "not a declared scope",
                                        );
                                    }
                                    if !set.insert(s) {
                                        return err(&format!("{kpath}[{i}]"), "repeated");
                                    }
                                }
                                role.scopes = set;
                            }
                            _ => return err(&kpath, "unknown key"),
                        }
                    }
                }
                _ => return err(&rpath, "must be a list of roles or a mapping"),
            }
            roles.insert(name.clone(), role);
        }
        if roles.is_empty() {
            return err(path, "needs at least one role");
        }
        Ok(roles)
    }

    /// policy.md "What the vocabulary checks": implied roles exist and are not the role itself,
    /// the ladder has no cycle, and a role exists in no scope an implied role lacks.
    fn check_ladders(&self) -> Result<(), VocabError> {
        for (thing, roles) in &self.things {
            for (name, role) in roles {
                let path = format!("things.{thing}.roles.{name}");
                for (i, implied) in role.implies.iter().enumerate() {
                    let ipath = format!("{path}.implies[{i}]");
                    if implied == name {
                        return err(&ipath, "a role cannot imply itself");
                    }
                    let Some(other) = roles.get(implied) else {
                        return err(&ipath, "not a role of this thing");
                    };
                    if !role.scopes.is_subset(&other.scopes) {
                        return err(&ipath, "the role exists in a scope the implied role lacks");
                    }
                }
                // A cycle: the role is reachable from itself.
                let mut seen = BTreeSet::new();
                let mut todo: Vec<&str> = role.implies.iter().map(String::as_str).collect();
                while let Some(r) = todo.pop() {
                    if r == name {
                        return err(&path, "the ladder has a cycle");
                    }
                    if seen.insert(r)
                        && let Some(next) = roles.get(r)
                    {
                        todo.extend(next.implies.iter().map(String::as_str));
                    }
                }
            }
        }
        Ok(())
    }

    /// Every grant name the document declares, with whether its scope is sensitive.
    #[must_use]
    pub fn grants(&self) -> Vec<(GrantName, bool)> {
        let mut out = Vec::new();
        for (thing, roles) in &self.things {
            for (role, r) in roles {
                for scope in &r.scopes {
                    out.push((
                        GrantName {
                            scope: scope.clone(),
                            thing: thing.clone(),
                            role: role.clone(),
                        },
                        self.scopes.get(scope).copied().unwrap_or(false),
                    ));
                }
            }
        }
        out
    }

    /// Whether the grant name is declared.
    #[must_use]
    pub fn declares(&self, g: &GrantName) -> bool {
        self.things
            .get(&g.thing)
            .and_then(|roles| roles.get(&g.role))
            .is_some_and(|r| r.scopes.contains(&g.scope))
    }

    /// Whether a scope is sensitive; an unknown scope is.
    #[must_use]
    pub fn sensitive(&self, scope: &str) -> bool {
        self.scopes.get(scope).copied().unwrap_or(true)
    }

    /// The grant names text (`dev:example-app:user`) as a name of the vocabulary, or `None` when it is
    /// not a declared grant name.
    #[must_use]
    pub fn parse_name(&self, text: &str) -> Option<GrantName> {
        let mut it = text.split(':');
        let (scope, thing, role) = (it.next()?, it.next()?, it.next()?);
        if it.next().is_some() {
            return None;
        }
        let g = GrantName {
            scope: scope.to_owned(),
            thing: thing.to_owned(),
            role: role.to_owned(),
        };
        self.declares(&g).then_some(g)
    }

    /// The held grant names with every role they imply added, by the ladder, on the same scope and
    /// thing (policy.md "How a person's grants are found", step 1).
    #[must_use]
    pub fn expand(&self, held: &BTreeSet<GrantName>) -> BTreeSet<GrantName> {
        let mut out = held.clone();
        let mut todo: Vec<GrantName> = held.iter().cloned().collect();
        while let Some(g) = todo.pop() {
            let Some(role) = self.things.get(&g.thing).and_then(|r| r.get(&g.role)) else {
                continue;
            };
            for implied in &role.implies {
                let next = GrantName {
                    scope: g.scope.clone(),
                    thing: g.thing.clone(),
                    role: implied.clone(),
                };
                if out.insert(next.clone()) {
                    todo.push(next);
                }
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOCAL: &str = include_str!("../../../tests/installations/local/policy/vocabulary.yaml");

    fn g(s: &str) -> GrantName {
        Vocabulary::parse(LOCAL.as_bytes())
            .unwrap()
            .parse_name(s)
            .unwrap()
    }

    #[test]
    fn the_local_vocabulary_declares_nine_grant_names() {
        let v = Vocabulary::parse(LOCAL.as_bytes()).unwrap();
        let all = v.grants();
        assert_eq!(all.len(), 9);
        assert!(
            all.iter()
                .filter(|(_, s)| *s)
                .all(|(g, _)| g.scope == "prod")
        );
        assert_eq!(all.iter().filter(|(_, s)| *s).count(), 3);
        assert!(v.parse_name("dev:example-app:user").is_some());
        assert!(v.parse_name("dev:example-app:root").is_none());
        assert!(v.parse_name("dev:example-app").is_none());
        assert!(v.parse_name("a:b:c:d").is_none());
    }

    #[test]
    fn the_ladder_is_expanded_on_the_same_scope_and_thing() {
        let v = Vocabulary::parse(LOCAL.as_bytes()).unwrap();
        let held = BTreeSet::from([g("acme:example-app:admin")]);
        let full: Vec<String> = v.expand(&held).iter().map(GrantName::id).collect();
        assert_eq!(
            full,
            [
                "acme:example-app:admin",
                "acme:example-app:operator",
                "acme:example-app:user"
            ]
        );
    }

    #[test]
    fn a_role_that_exists_in_some_scopes_only() {
        let v = Vocabulary::parse(
            b"scopes:\n  dev: {}\n  prod: { sensitive: true }\nthings:\n  deploy:\n    roles:\n      viewer: []\n      releaser: { implies: [viewer], scopes: [dev, prod] }\n      debugger: { implies: [viewer], scopes: [dev] }\n",
        )
        .unwrap();
        assert_eq!(v.grants().len(), 2 + 2 + 1);
        assert!(v.parse_name("prod:deploy:debugger").is_none());
        assert!(v.sensitive("prod") && !v.sensitive("dev"));
    }

    fn refused(doc: &str) -> String {
        Vocabulary::parse(doc.as_bytes()).unwrap_err().0
    }

    #[test]
    fn what_the_vocabulary_checks_beyond_the_schema() {
        let head = "scopes: {dev: {}, prod: {sensitive: true}}\nthings:\n  t:\n    roles:\n";
        assert_eq!(
            refused(&format!("{head}      a: [a]\n")),
            "things.t.roles.a.implies[0]: a role cannot imply itself"
        );
        assert_eq!(
            refused(&format!("{head}      a: [nope]\n")),
            "things.t.roles.a.implies[0]: not a role of this thing"
        );
        assert_eq!(
            refused(&format!("{head}      a: [b]\n      b: [a]\n")),
            "things.t.roles.a: the ladder has a cycle"
        );
        assert_eq!(
            refused(&format!(
                "{head}      a: {{implies: [b]}}\n      b: {{scopes: [dev]}}\n"
            )),
            "things.t.roles.a.implies[0]: the role exists in a scope the implied role lacks"
        );
        assert_eq!(
            refused(&format!("{head}      a: {{scopes: [dev, dev]}}\n")),
            "things.t.roles.a.scopes[1]: repeated"
        );
        assert_eq!(
            refused(&format!("{head}      a: {{scopes: [qa]}}\n")),
            "things.t.roles.a.scopes[0]: not a declared scope"
        );
    }

    #[test]
    fn shape_errors_name_a_path_and_never_a_value() {
        assert_eq!(refused("things: {}\n"), "scopes: is required");
        assert_eq!(
            refused("scopes: {}\nthings: {}\n"),
            "scopes: needs at least one scope"
        );
        assert_eq!(
            refused("scopes: {a b: {}}\nthings: {}\n"),
            "scopes.a b: not a valid name"
        );
        assert_eq!(
            refused("scopes: {dev: {}}\nthings: {}\nextra: 1\n"),
            "extra: unknown key"
        );
        assert_eq!(
            refused("scopes: {dev: {sensitive: yes-please}}\nthings: {}\n"),
            "scopes.dev.sensitive: must be a boolean"
        );
        assert_eq!(
            refused("$schema: https://example.com/other.json\nscopes: {}\nthings: {}\n"),
            "$schema: must name the schema of this version"
        );
    }
}
