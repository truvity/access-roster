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

/// The version of this policy; see `kits/go/audit/policy.go` (`PolicyVersion`), which holds the same number and the reason.
pub const POLICY_VERSION: u32 = 1;

const DRAFT: &str = "https://json-schema.org/draft/2020-12/schema";
const MAX_SCHEMA_DEPTH: usize = 24;
const MAX_COMBINATOR_DEEP: usize = 3;
const MAX_BRANCHES: usize = 8;
const MAX_SCHEMA_NODES: usize = 4000;
const MAX_PATTERN_LEN: usize = 256;
const MAX_REF_CHAIN: usize = 4;
const MAX_REPEAT: usize = 256;
const MAX_PATTERN_DEPTH: usize = 4;
/// The most work one instance can make the engine do against a document or a definition, in schema objects visited in the
/// worst case; see `kits/go/audit/policy.go` for what it counts and how it was calibrated (the real maximum is 885).
const MAX_COST: usize = 4000;
const MAX_FANOUT: usize = 1024;

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

/// What is known of a schema once it is analysed: its cost, and how many definitions deep its references go.
#[derive(Clone, Copy, Default)]
struct Res {
    cost: usize,
    chain: usize,
}

fn add(x: usize, y: usize) -> usize {
    x.saturating_add(y).min(MAX_COST + 1)
}

fn mul(x: usize, n: usize) -> usize {
    x.saturating_mul(n).min(MAX_COST + 1)
}

/// Checks the documents (file name to JSON text) against the policy. It does not compile them. It is linear in the size of
/// the documents: a definition is analysed once, whatever refers to it how often.
///
/// # Errors
///
/// A message that names the document and the rule, never a value of a record.
pub fn check_policy(files: &[(String, String)]) -> Result<(), String> {
    analyse(files).map(|_| ())
}

/// The worst-case cost of one instance against any one document of the set, for tests that say what the real catalogue costs.
///
/// # Errors
///
/// As [`check_policy`].
pub fn max_cost(files: &[(String, String)]) -> Result<usize, String> {
    analyse(files)
}

fn analyse(files: &[(String, String)]) -> Result<usize, String> {
    let mut docs: Vec<(&str, Value)> = Vec::new();
    for (name, text) in files {
        let v: Value =
            serde_json::from_str(text).map_err(|_| format!("schema policy: {name}: not JSON"))?;
        if !v.is_object() {
            return fail(name, "not a JSON Schema object");
        }
        docs.push((name, v));
    }
    docs.sort_by(|a, b| a.0.cmp(b.0));
    let Some(defs_doc) = docs.iter().find(|(n, _)| *n == DEFS_NAME).map(|(_, v)| v) else {
        return fail(DEFS_NAME, "missing");
    };
    let empty = serde_json::Map::new();
    let defs = defs_doc
        .get("$defs")
        .and_then(Value::as_object)
        .unwrap_or(&empty);
    let mut a = Analyzer {
        defs,
        memo: HashMap::new(),
        on: Vec::new(),
        worst: 0,
        nodes: 0,
        doc: DEFS_NAME,
    };
    let mut names: Vec<&String> = defs.keys().collect();
    names.sort();
    for dn in names {
        a.def(dn)?;
    }
    for (name, d) in &docs {
        a.doc = name;
        a.nodes = 0;
        let r = if *name == DEFS_NAME {
            // Its $defs are analysed above; what else the document holds is held to the keywords and the form.
            let mut m = d.as_object().cloned().unwrap_or_default();
            m.remove("$defs");
            a.schema(&Value::Object(m), 0, 0)?
        } else {
            a.schema(d, 0, 0)?
        };
        a.worst = a.worst.max(r.cost);
    }
    Ok(a.worst)
}

struct Analyzer<'a> {
    defs: &'a serde_json::Map<String, Value>,
    memo: HashMap<String, Res>,
    on: Vec<String>,
    worst: usize,
    nodes: usize,
    doc: &'a str,
}

impl<'a> Analyzer<'a> {
    /// Analyses one definition, once.
    fn def(&mut self, name: &str) -> Result<Res, String> {
        if let Some(r) = self.memo.get(name) {
            return Ok(*r);
        }
        if self.on.iter().any(|x| x == name) {
            return fail(DEFS_NAME, "definitions refer to one another in a circle");
        }
        self.on.push(name.to_owned());
        let (saved_doc, saved_nodes) = (self.doc, self.nodes);
        self.doc = DEFS_NAME;
        self.nodes = 0;
        let v = self.defs.get(name).cloned().unwrap_or(Value::Null);
        let r = self.schema(&v, 0, 0);
        self.doc = saved_doc;
        self.nodes = saved_nodes;
        self.on.pop();
        let r = r?;
        if r.chain > MAX_REF_CHAIN {
            return fail(DEFS_NAME, "definitions refer to one another too deep");
        }
        self.memo.insert(name.to_owned(), r);
        self.worst = self.worst.max(r.cost);
        Ok(r)
    }

    fn schema(&mut self, v: &Value, depth: usize, comb: usize) -> Result<Res, String> {
        let Some(m) = v.as_object() else {
            return fail(self.doc, "a schema is not an object");
        };
        if depth > MAX_SCHEMA_DEPTH {
            return fail(self.doc, "nested too deep");
        }
        self.nodes += 1;
        if self.nodes > MAX_SCHEMA_NODES {
            return fail(self.doc, "too many schemas");
        }
        let mut out = Res { cost: 1, chain: 0 };
        let fan = |key: &str| -> usize {
            m.get(key)
                .and_then(Value::as_u64)
                .and_then(|n| usize::try_from(n).ok())
                .filter(|n| *n <= MAX_FANOUT)
                .unwrap_or(MAX_FANOUT)
        };
        let mut keys: Vec<&String> = m.keys().collect();
        keys.sort();
        for k in keys {
            let e = &m[k];
            if !allowed(k) {
                return fail(self.doc, "a keyword is not one the generator makes");
            }
            match k.as_str() {
                "properties" => {
                    let Some(props) = e.as_object() else {
                        return fail(self.doc, "properties is not an object");
                    };
                    let mut names: Vec<&String> = props.keys().collect();
                    names.sort();
                    for pn in names {
                        let r = self.schema(&props[pn], depth + 1, comb)?;
                        out.cost = add(out.cost, r.cost);
                        out.chain = out.chain.max(r.chain);
                    }
                }
                "$defs" => {
                    let Some(defs) = e.as_object() else {
                        return fail(self.doc, "$defs is not an object");
                    };
                    let mut names: Vec<&String> = defs.keys().collect();
                    names.sort();
                    for dn in names {
                        self.def(dn)?;
                    }
                }
                "additionalProperties" => {
                    if !e.is_boolean() {
                        let r = self.schema(e, depth + 1, comb)?;
                        out.cost = add(out.cost, mul(r.cost, fan("maxProperties")));
                        out.chain = out.chain.max(r.chain);
                    }
                }
                "propertyNames" => {
                    let r = self.schema(e, depth + 1, comb)?;
                    out.cost = add(out.cost, mul(r.cost, fan("maxProperties")));
                    out.chain = out.chain.max(r.chain);
                }
                "items" => {
                    let r = self.schema(e, depth + 1, comb)?;
                    out.cost = add(out.cost, mul(r.cost, fan("maxItems")));
                    out.chain = out.chain.max(r.chain);
                }
                "if" | "then" => {
                    if comb + 1 > MAX_COMBINATOR_DEEP {
                        return fail(self.doc, "combinators nested too deep");
                    }
                    let r = self.schema(e, depth + 1, comb + 1)?;
                    out.cost = add(out.cost, r.cost);
                    out.chain = out.chain.max(r.chain);
                }
                "allOf" | "anyOf" => {
                    let Some(list) = e.as_array().filter(|l| l.len() <= MAX_BRANCHES) else {
                        return fail(self.doc, "allOf or anyOf is not a short list");
                    };
                    if comb + 1 > MAX_COMBINATOR_DEEP {
                        return fail(self.doc, "combinators nested too deep");
                    }
                    for s in list {
                        let r = self.schema(s, depth + 1, comb + 1)?;
                        out.cost = add(out.cost, r.cost);
                        out.chain = out.chain.max(r.chain);
                    }
                }
                "$schema" => {
                    if e.as_str() != Some(DRAFT) {
                        return fail(self.doc, "$schema is not JSON Schema 2020-12");
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
                        return fail(self.doc, "a $ref is not a shared definition");
                    };
                    if !self.defs.contains_key(target) {
                        return fail(self.doc, "a $ref names no definition");
                    }
                    let r = self.def(target)?;
                    out.cost = add(out.cost, r.cost);
                    out.chain = out.chain.max(r.chain + 1);
                    if out.chain > MAX_REF_CHAIN {
                        return fail(self.doc, "definitions refer to one another too deep");
                    }
                }
                "pattern" => {
                    let Some(p) = e.as_str() else {
                        return fail(self.doc, "a pattern is not a string");
                    };
                    check_pattern(p).or_else(|why| fail(self.doc, why))?;
                }
                _ => {}
            }
        }
        if out.cost > MAX_COST {
            return fail(self.doc, "validating one record could take too long");
        }
        Ok(out)
    }
}

const ESCAPABLE: &str = "\\^$.|?*+()[]{}/-";

/// A pattern held to one grammar that RE2 and the regex crate read the same way, so the emitter and the writer cannot disagree
/// on what matches: anchored, an alternation only inside groups, a class of plain items, an atom quantified at most once and
/// never a group, counts up to `MAX_REPEAT`, only punctuation escaped. `kits/go/audit/policy.go` parses the same grammar.
fn check_pattern(p: &str) -> Result<(), &'static str> {
    if p.len() > MAX_PATTERN_LEN {
        return Err("a pattern is too long");
    }
    let b = p.as_bytes();
    if b.len() < 2 || b[0] != b'^' || b[b.len() - 1] != b'$' {
        return Err("a pattern is not anchored");
    }
    let body = &b[1..b.len() - 1];
    let (mut depth, mut can_quantify, mut quantified) = (0_usize, false, false);
    let mut i = 0;
    while i < body.len() {
        let c = body[i];
        match c {
            b'\\' => {
                i += 1;
                if i >= body.len() || !ESCAPABLE.as_bytes().contains(&body[i]) {
                    return Err("a pattern has an escape other than of punctuation");
                }
                (can_quantify, quantified) = (true, false);
            }
            b'[' => {
                i = scan_class(body, i)?;
                (can_quantify, quantified) = (true, false);
            }
            b'(' => {
                if body.get(i + 1) == Some(&b'?') {
                    return Err("a pattern has a group with a question mark");
                }
                depth += 1;
                if depth > MAX_PATTERN_DEPTH {
                    return Err("a pattern nests groups too deep");
                }
                (can_quantify, quantified) = (false, false);
            }
            b')' => {
                if depth == 0 {
                    return Err("a pattern closes a group it did not open");
                }
                depth -= 1;
                (can_quantify, quantified) = (false, false);
            }
            b'|' => {
                if depth == 0 {
                    return Err("a pattern alternates outside a group");
                }
                (can_quantify, quantified) = (false, false);
            }
            b'*' | b'+' | b'?' => {
                if !can_quantify || quantified {
                    return Err(
                        "a pattern has a quantifier with nothing to repeat, or a second one",
                    );
                }
                quantified = true;
            }
            b'{' => {
                let end = scan_repeat(body, i)?;
                if !can_quantify || quantified {
                    return Err(
                        "a pattern has a quantifier with nothing to repeat, or a second one",
                    );
                }
                i = end;
                quantified = true;
            }
            b'}' | b']' | b'^' | b'$' => {
                return Err(
                    "a pattern has a character that is a literal in one engine and not in the other",
                );
            }
            b'.' | 0x20..=0x7e => (can_quantify, quantified) = (true, false),
            _ => return Err("a pattern has a character outside printable ASCII"),
        }
        i += 1;
    }
    if depth != 0 {
        return Err("a pattern leaves a group open");
    }
    if regex::Regex::new(p).is_err() {
        return Err("a pattern does not compile");
    }
    Ok(())
}

/// The index of the `]` that closes the class opened at `body[i]`: plain items and escaped punctuation, no nested class, no set
/// operation (`&&`, `~~` and `--` mean something in Rust and nothing in RE2), not beginning with `]`.
fn scan_class(body: &[u8], i: usize) -> Result<usize, &'static str> {
    let mut j = i + 1;
    if body.get(j) == Some(&b'^') {
        j += 1;
    }
    let start = j;
    while j < body.len() {
        let c = body[j];
        match c {
            b']' => {
                if j == start {
                    return Err("a pattern has an empty class");
                }
                return Ok(j);
            }
            b'[' => return Err("a pattern nests a class"),
            b'\\' => {
                j += 1;
                if j >= body.len() || !ESCAPABLE.as_bytes().contains(&body[j]) {
                    return Err("a pattern has an escape other than of punctuation");
                }
            }
            0..=0x1f | 0x7f..=0xff => {
                return Err("a pattern has a character outside printable ASCII");
            }
            b'&' | b'~' | b'-' if body.get(j + 1) == Some(&c) => {
                return Err("a pattern has a set operation in a class");
            }
            _ => {}
        }
        j += 1;
    }
    Err("a pattern leaves a class open")
}

/// The index of the `}` that closes the repeat opened at `body[i]`: `{n}`, `{n,}` or `{n,m}`, counts up to `MAX_REPEAT`, n not
/// above m.
fn scan_repeat(body: &[u8], i: usize) -> Result<usize, &'static str> {
    let Some(end) = body[i..].iter().position(|c| *c == b'}') else {
        return Err("a pattern leaves a repeat open");
    };
    let inner = &body[i + 1..i + end];
    let (lo, hi, comma) = match inner.iter().position(|c| *c == b',') {
        Some(k) => (&inner[..k], &inner[k + 1..], true),
        None => (inner, &inner[..0], false),
    };
    let Some(n) = small_number(lo) else {
        return Err("a pattern has a repeat that is not a count");
    };
    if comma && !hi.is_empty() && small_number(hi).is_none_or(|m| m < n) {
        return Err("a pattern has a repeat that is not a count");
    }
    Ok(i + end)
}

/// Decimal digits, no sign and no leading zero, up to `MAX_REPEAT`.
fn small_number(s: &[u8]) -> Option<usize> {
    if s.is_empty()
        || s.len() > 3
        || (s.len() > 1 && s[0] == b'0')
        || !s.iter().all(u8::is_ascii_digit)
    {
        return None;
    }
    let n = s.iter().fold(0, |n, c| n * 10 + usize::from(c - b'0'));
    (n <= MAX_REPEAT).then_some(n)
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
