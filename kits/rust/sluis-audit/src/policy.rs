//! The policy of the schema documents of an `AuditCatalogue` (see `kits/go/audit/policy.go`, which holds the same).
//!
//! A catalogue is signed by the release pipeline and read by store@, the writer and the indexer, and a schema engine is a
//! program that a document drives: a `$ref` can name a file or a URL, a pattern can need a backtracking engine, and nested
//! combinators multiply the work of one record (MEASURED 2026-11-07: 1.4 KB of nested `anyOf` took 2.9 s for one record in the
//! Go writer, which is sequential). So the documents are held to what `tools/gen/audit` makes: a closed list of keywords,
//! references only to the shared definitions, patterns that RE2 and the regex crate read alike, and bounded depth, branching
//! and size. `kits/conformance/audit/schema-policy-vectors.json` keeps the two implementations in step.

use std::collections::HashMap;

use serde_json::Value;

use crate::DEFS_NAME;

const DRAFT: &str = "https://json-schema.org/draft/2020-12/schema";
const MAX_SCHEMA_DEPTH: usize = 24;
const MAX_COMBINATOR_DEEP: usize = 2;
const MAX_BRANCHES: usize = 8;
const MAX_SCHEMA_NODES: usize = 4000;
const MAX_PATTERN_LEN: usize = 256;
const MAX_REF_CHAIN: usize = 4;

const ALLOWED: [&str; 26] = [
    "$schema",
    "$comment",
    "title",
    "description",
    "$defs",
    "$ref",
    "type",
    "const",
    "enum",
    "properties",
    "required",
    "additionalProperties",
    "propertyNames",
    "maxProperties",
    "items",
    "minItems",
    "maxItems",
    "minLength",
    "maxLength",
    "minimum",
    "maximum",
    "pattern",
    "allOf",
    "anyOf",
    "if",
    "then",
];

fn allowed(k: &str) -> bool {
    ALLOWED.contains(&k)
}

fn fail<T>(name: &str, why: &str) -> Result<T, String> {
    Err(format!("schema policy: {name}: {why}"))
}

/// Checks the documents (file name to JSON text) against the policy. It does not compile them.
///
/// # Errors
///
/// A message that names the document and the rule, never a value of a record.
pub fn check_policy(files: &[(String, String)]) -> Result<(), String> {
    let mut docs: HashMap<&str, Value> = HashMap::new();
    for (name, text) in files {
        let v: Value =
            serde_json::from_str(text).map_err(|_| format!("schema policy: {name}: not JSON"))?;
        if !v.is_object() {
            return fail(name, "not a JSON Schema object");
        }
        docs.insert(name, v);
    }
    let Some(defs_doc) = docs.get(DEFS_NAME) else {
        return fail(DEFS_NAME, "missing");
    };
    let empty = serde_json::Map::new();
    let defs = defs_doc
        .get("$defs")
        .and_then(Value::as_object)
        .unwrap_or(&empty);
    let mut graph: HashMap<&str, Vec<String>> = HashMap::new();
    for (name, d) in &docs {
        let mut w = Walker::new(name, defs);
        w.schema(d, 0, 0)?;
        if *name != DEFS_NAME {
            continue;
        }
        for (dn, dv) in defs {
            let mut dw = Walker::new(name, defs);
            dw.schema(dv, 0, 0)?;
            graph.insert(dn, dw.refs);
        }
    }
    for dn in graph.keys() {
        match ref_chain(&graph, dn, &mut Vec::new()) {
            Some(n) if n <= MAX_REF_CHAIN => {}
            _ => {
                return fail(
                    DEFS_NAME,
                    "definitions refer to one another too deep, or in a circle",
                );
            }
        }
    }
    Ok(())
}

/// The longest chain of definitions below `dn`, or None for a circle.
fn ref_chain(g: &HashMap<&str, Vec<String>>, dn: &str, on: &mut Vec<String>) -> Option<usize> {
    if on.iter().any(|x| x == dn) {
        return None;
    }
    on.push(dn.to_owned());
    let mut longest = 0;
    if let Some(next) = g.get(dn) {
        for n in next {
            longest = longest.max(ref_chain(g, n, on)? + 1);
        }
    }
    on.pop();
    Some(longest)
}

struct Walker<'a> {
    name: &'a str,
    defs: &'a serde_json::Map<String, Value>,
    nodes: usize,
    refs: Vec<String>,
}

impl<'a> Walker<'a> {
    fn new(name: &'a str, defs: &'a serde_json::Map<String, Value>) -> Self {
        Self {
            name,
            defs,
            nodes: 0,
            refs: Vec::new(),
        }
    }

    fn schema(&mut self, v: &Value, depth: usize, comb: usize) -> Result<(), String> {
        let Some(m) = v.as_object() else {
            return fail(self.name, "a schema is not an object");
        };
        if depth > MAX_SCHEMA_DEPTH {
            return fail(self.name, "nested too deep");
        }
        self.nodes += 1;
        if self.nodes > MAX_SCHEMA_NODES {
            return fail(self.name, "too many schemas");
        }
        for (k, e) in m {
            if !allowed(k) {
                return fail(self.name, "a keyword is not one the generator makes");
            }
            match k.as_str() {
                "properties" | "$defs" => {
                    let Some(sub) = e.as_object() else {
                        return fail(self.name, "properties or $defs is not an object");
                    };
                    for s in sub.values() {
                        self.schema(s, depth + 1, comb)?;
                    }
                }
                "additionalProperties" => {
                    if !e.is_boolean() {
                        self.schema(e, depth + 1, comb)?;
                    }
                }
                "propertyNames" | "items" => self.schema(e, depth + 1, comb)?,
                "if" | "then" => {
                    if comb + 1 > MAX_COMBINATOR_DEEP {
                        return fail(self.name, "combinators nested too deep");
                    }
                    self.schema(e, depth + 1, comb + 1)?;
                }
                "allOf" | "anyOf" => {
                    let Some(list) = e.as_array().filter(|l| l.len() <= MAX_BRANCHES) else {
                        return fail(self.name, "allOf or anyOf is not a short list");
                    };
                    if comb + 1 > MAX_COMBINATOR_DEEP {
                        return fail(self.name, "combinators nested too deep");
                    }
                    for s in list {
                        self.schema(s, depth + 1, comb + 1)?;
                    }
                }
                "$schema" => {
                    if e.as_str() != Some(DRAFT) {
                        return fail(self.name, "$schema is not JSON Schema 2020-12");
                    }
                }
                "$ref" => {
                    let target = e
                        .as_str()
                        .and_then(|s| s.strip_prefix("defs.schema.json#/$defs/"))
                        .filter(|n| {
                            !n.is_empty()
                                && n.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_')
                        });
                    let Some(target) = target else {
                        return fail(self.name, "a $ref is not a shared definition");
                    };
                    if !self.defs.contains_key(target) {
                        return fail(self.name, "a $ref names no definition");
                    }
                    self.refs.push(target.to_owned());
                }
                "pattern" => {
                    let Some(p) = e.as_str() else {
                        return fail(self.name, "a pattern is not a string");
                    };
                    check_pattern(p).or_else(|why| fail(self.name, why))?;
                }
                _ => {}
            }
        }
        Ok(())
    }
}

/// A pattern RE2 and the regex crate read alike: no group with `(?` (look-around, atomic and named groups, flags), no
/// back-reference or class escape, and only an escaped punctuation character.
fn check_pattern(p: &str) -> Result<(), &'static str> {
    if p.len() > MAX_PATTERN_LEN {
        return Err("a pattern is too long");
    }
    if p.contains("(?") {
        return Err("a pattern has a group with a question mark");
    }
    let mut it = p.chars();
    while let Some(c) = it.next() {
        if c == '\\' && !it.next().is_some_and(|n| "\\^$.|?*+()[]{}/-".contains(n)) {
            return Err("a pattern has an escape other than of punctuation");
        }
    }
    if regex::Regex::new(p).is_err() {
        return Err("a pattern does not compile");
    }
    Ok(())
}

/// Whether `s` is a release: `MAJOR.MINOR.PATCH` with an optional prerelease and build, as semver.org writes it, and no `v`.
/// The same corpus, `kits/conformance/audit/semver-vectors.json`, runs through the Go package.
#[must_use]
pub fn valid_release(s: &str) -> bool {
    fn numeric(p: &str) -> bool {
        !p.is_empty() && p.bytes().all(|c| c.is_ascii_digit())
    }
    fn ident(p: &str) -> bool {
        !p.is_empty() && p.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
    }
    fn pre(p: &str) -> bool {
        if numeric(p) {
            p == "0" || !p.starts_with('0')
        } else {
            ident(p)
        }
    }
    let (rest, build) = match s.split_once('+') {
        Some((r, b)) => (r, Some(b)),
        None => (s, None),
    };
    let (core, prerelease) = match rest.split_once('-') {
        Some((c, p)) => (c, Some(p)),
        None => (rest, None),
    };
    let parts: Vec<&str> = core.split('.').collect();
    parts.len() == 3
        && parts
            .iter()
            .all(|p| numeric(p) && (*p == "0" || !p.starts_with('0')))
        && prerelease.is_none_or(|p| p.split('.').all(pre))
        && build.is_none_or(|b| b.split('.').all(ident))
}
