//! The strict YAML profile of docs/reference/bootstrap-file.md "Format", over `saphyr-parser`.
//!
//! The reader turns a document into plain JSON-like data or refuses it. An error names a kind and
//! a place (line and column, or a path), never a value, because the reader's own messages can
//! print the source line.

use std::borrow::Cow;

use saphyr_parser::{Event, Parser, ScalarStyle, Span};

/// Flow collections nest at most this deep (profile rule 7).
const FLOW_DEPTH_MAX: usize = 64;
/// A document larger than this is refused before it is parsed.
pub const DOCUMENT_MAX: usize = 256 * 1024;

/// A document as plain data. A number keeps its text, so a field that wants an integer decides.
#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    /// A plain scalar that matches the JSON number grammar.
    Number(String),
    String(String),
    Seq(Vec<Value>),
    /// Keys are strings, in document order, and unique.
    Map(Vec<(String, Value)>),
}

/// Why a document was refused, and where. Never the value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct YamlError {
    pub what: &'static str,
    /// 1-based line and column; 0 when the refusal has no place (the whole document).
    pub line: usize,
    pub col: usize,
}

impl std::fmt::Display for YamlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.line == 0 {
            write!(f, "{}", self.what)
        } else {
            write!(f, "line {}, column {}: {}", self.line, self.col, self.what)
        }
    }
}

impl std::error::Error for YamlError {}

fn refuse(what: &'static str, span: Span) -> YamlError {
    YamlError {
        what,
        line: span.start.line(),
        col: span.start.col() + 1,
    }
}

fn whole(what: &'static str) -> YamlError {
    YamlError {
        what,
        line: 0,
        col: 0,
    }
}

/// Reads one document under the strict profile.
///
/// # Errors
///
/// [`YamlError`] for every refusal of the profile, and for a syntax error (its kind only: the two
/// readers place a syntax error differently).
pub fn parse(source: &str) -> Result<Value, YamlError> {
    if source.len() > DOCUMENT_MAX {
        return Err(whole("document too large"));
    }
    // Rule 6: a tab anywhere.
    if let Some(i) = source.find('\t') {
        let before = &source[..i];
        let line = before.matches('\n').count() + 1;
        let col = before.rsplit('\n').next().map_or(0, |l| l.chars().count()) + 1;
        return Err(YamlError {
            what: "tab",
            line,
            col,
        });
    }
    // Rule 5: a directive before the content.
    for (n, line) in source.lines().enumerate() {
        let t = line.trim_start_matches([' ', '\u{feff}']);
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        if line.starts_with('%') {
            return Err(YamlError {
                what: "directive",
                line: n + 1,
                col: 1,
            });
        }
        break;
    }
    flow_depth(source)?;

    let mut parser = Parser::new_from_str(source);
    let mut documents = 0usize;
    let mut root = None;
    loop {
        match parser.next_event() {
            None => break,
            Some(Err(_)) => return Err(whole("syntax error")),
            Some(Ok((Event::StreamStart | Event::StreamEnd | Event::DocumentEnd, _))) => {}
            Some(Ok((Event::DocumentStart(_), span))) => {
                documents += 1;
                if documents > 1 {
                    return Err(refuse("more than one document", span));
                }
                root = Some(node(&mut parser)?);
            }
            Some(Ok((_, span))) => return Err(refuse("unexpected content", span)),
        }
    }
    root.ok_or_else(|| whole("no document"))
}

/// Rule 7, from the text: the deepest nesting of `[` and `{` outside quotes and comments. The
/// parser's own limit differs between readers, so the profile counts here.
fn flow_depth(source: &str) -> Result<(), YamlError> {
    let (mut depth, mut quote) = (0usize, None::<char>);
    for (n, line) in source.lines().enumerate() {
        let mut prev = ' ';
        let mut chars = line.chars().enumerate().peekable();
        while let Some((col, c)) = chars.next() {
            match quote {
                Some('"') if c == '\\' => {
                    chars.next();
                }
                Some(q) if c == q => quote = None,
                Some(_) => {}
                None => match c {
                    '#' if prev.is_whitespace() => break,
                    '"' | '\'' if prev.is_whitespace() || "[{,:".contains(prev) => quote = Some(c),
                    '[' | '{' => {
                        depth += 1;
                        if depth > FLOW_DEPTH_MAX {
                            return Err(YamlError {
                                what: "flow collections nested too deep",
                                line: n + 1,
                                col: col + 1,
                            });
                        }
                    }
                    ']' | '}' => depth = depth.saturating_sub(1),
                    _ => {}
                },
            }
            prev = c;
        }
        // A quoted scalar may run over lines; a flow collection too.
    }
    Ok(())
}

type P<'a> = Parser<'a, saphyr_parser::StrInput<'a>>;

fn next(p: &mut P<'_>) -> Result<(Event<'static>, Span), YamlError> {
    match p.next_event() {
        Some(Ok((ev, span))) => Ok((own(ev), span)),
        Some(Err(_)) => Err(whole("syntax error")),
        None => Err(whole("syntax error")),
    }
}

/// The events borrow the source; the profile keeps nothing of them past one step.
fn own(ev: Event<'_>) -> Event<'static> {
    match ev {
        Event::Scalar(v, style, anchor, tag) => Event::Scalar(
            Cow::Owned(v.into_owned()),
            style,
            anchor,
            tag.map(|t| Cow::Owned(t.into_owned())),
        ),
        Event::SequenceStart(a, t) => {
            Event::SequenceStart(a, t.map(|t| Cow::Owned(t.into_owned())))
        }
        Event::MappingStart(a, t) => Event::MappingStart(a, t.map(|t| Cow::Owned(t.into_owned()))),
        Event::Nothing => Event::Nothing,
        Event::StreamStart => Event::StreamStart,
        Event::StreamEnd => Event::StreamEnd,
        Event::DocumentStart(b) => Event::DocumentStart(b),
        Event::DocumentEnd => Event::DocumentEnd,
        Event::Alias(i) => Event::Alias(i),
        Event::SequenceEnd => Event::SequenceEnd,
        Event::MappingEnd => Event::MappingEnd,
    }
}

fn node(p: &mut P<'_>) -> Result<Value, YamlError> {
    let (ev, span) = next(p)?;
    value(p, ev, span)
}

fn value(p: &mut P<'_>, ev: Event<'static>, span: Span) -> Result<Value, YamlError> {
    match ev {
        Event::Alias(_) => Err(refuse("alias", span)),
        Event::Scalar(text, style, anchor, tag) => {
            if anchor != 0 {
                return Err(refuse("anchor", span));
            }
            if tag.is_some() {
                return Err(refuse("tag", span));
            }
            Ok(scalar(&text, style))
        }
        Event::SequenceStart(anchor, tag) => {
            if anchor != 0 {
                return Err(refuse("anchor", span));
            }
            if tag.is_some() {
                return Err(refuse("tag", span));
            }
            let mut items = Vec::new();
            loop {
                let (ev, span) = next(p)?;
                if matches!(ev, Event::SequenceEnd) {
                    return Ok(Value::Seq(items));
                }
                items.push(value(p, ev, span)?);
            }
        }
        Event::MappingStart(anchor, tag) => {
            if anchor != 0 {
                return Err(refuse("anchor", span));
            }
            if tag.is_some() {
                return Err(refuse("tag", span));
            }
            let mut entries: Vec<(String, Value)> = Vec::new();
            loop {
                let (ev, kspan) = next(p)?;
                let key = match ev {
                    Event::MappingEnd => return Ok(Value::Map(entries)),
                    Event::Scalar(text, style, anchor, tag) => {
                        if anchor != 0 {
                            return Err(refuse("anchor", kspan));
                        }
                        if tag.is_some() {
                            return Err(refuse("tag", kspan));
                        }
                        // Rule 3: an empty plain key.
                        if style == ScalarStyle::Plain && text.is_empty() {
                            return Err(refuse("empty key", kspan));
                        }
                        text.into_owned()
                    }
                    Event::Alias(_) => return Err(refuse("alias", kspan)),
                    _ => return Err(refuse("key is not a scalar", kspan)),
                };
                // Rule 2: the merge key.
                if key == "<<" {
                    return Err(refuse("merge key", kspan));
                }
                if entries.iter().any(|(k, _)| *k == key) {
                    return Err(refuse("duplicate key", kspan));
                }
                let (ev, vspan) = next(p)?;
                entries.push((key, value(p, ev, vspan)?));
            }
        }
        _ => Err(refuse("unexpected content", span)),
    }
}

/// Rule 4: a plain scalar is null, a boolean, a JSON number, or a string; any other style is a
/// string.
fn scalar(text: &str, style: ScalarStyle) -> Value {
    if style != ScalarStyle::Plain {
        return Value::String(text.to_owned());
    }
    match text {
        "" | "~" | "null" => Value::Null,
        "true" => Value::Bool(true),
        "false" => Value::Bool(false),
        t if is_json_number(t) => Value::Number(t.to_owned()),
        t => Value::String(t.to_owned()),
    }
}

/// `-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?` (RFC 8259, section 6).
fn is_json_number(t: &str) -> bool {
    let b = t.as_bytes();
    let mut i = 0;
    if b.get(i) == Some(&b'-') {
        i += 1;
    }
    match b.get(i) {
        Some(b'0') => i += 1,
        Some(b'1'..=b'9') => {
            while b.get(i).is_some_and(u8::is_ascii_digit) {
                i += 1;
            }
        }
        _ => return false,
    }
    if b.get(i) == Some(&b'.') {
        i += 1;
        let start = i;
        while b.get(i).is_some_and(u8::is_ascii_digit) {
            i += 1;
        }
        if i == start {
            return false;
        }
    }
    if matches!(b.get(i), Some(b'e' | b'E')) {
        i += 1;
        if matches!(b.get(i), Some(b'+' | b'-')) {
            i += 1;
        }
        let start = i;
        while b.get(i).is_some_and(u8::is_ascii_digit) {
            i += 1;
        }
        if i == start {
            return false;
        }
    }
    i == b.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &str) -> Value {
        Value::String(v.into())
    }
    fn n(v: &str) -> Value {
        Value::Number(v.into())
    }
    fn map(v: Vec<(&str, Value)>) -> Value {
        Value::Map(v.into_iter().map(|(k, v)| (k.to_owned(), v)).collect())
    }
    fn refused(src: &str, what: &str) {
        match parse(src) {
            Err(e) => assert_eq!(e.what, what, "{src:?}: {e}"),
            Ok(v) => panic!("{src:?} was read as {v:?}"),
        }
    }

    // The vectors of bootstrap-file.md "Format".
    #[test]
    fn the_profile_vectors_are_read() {
        assert_eq!(
            parse("a: 1\nb: [x, y]\nc: {d: true}\n").unwrap(),
            map(vec![
                ("a", n("1")),
                ("b", Value::Seq(vec![s("x"), s("y")])),
                ("c", map(vec![("d", Value::Bool(true))])),
            ])
        );
        assert_eq!(
            parse("a: yes\nb: 0o17\nc: 010\nd: y\n").unwrap(),
            map(vec![
                ("a", s("yes")),
                ("b", s("0o17")),
                ("c", s("010")),
                ("d", s("y"))
            ])
        );
        assert_eq!(
            parse("a: ~\nc: 0x1F\nd:\n").unwrap(),
            map(vec![
                ("a", Value::Null),
                ("c", s("0x1F")),
                ("d", Value::Null)
            ])
        );
        assert_eq!(
            parse("a: 1.5e3\nb: .inf\nc: +1\nd: -0\ne: 1_000\n").unwrap(),
            map(vec![
                ("a", n("1.5e3")),
                ("b", s(".inf")),
                ("c", s("+1")),
                ("d", n("-0")),
                ("e", s("1_000"))
            ])
        );
        assert_eq!(
            parse("a: \"12\"\nb: 'true'\nc: \"null\"\n").unwrap(),
            map(vec![("a", s("12")), ("b", s("true")), ("c", s("null"))])
        );
        assert_eq!(parse("1: a\n").unwrap(), map(vec![("1", s("a"))]));
        assert_eq!(
            parse("a: 2026-11-01\n").unwrap(),
            map(vec![("a", s("2026-11-01"))])
        );
    }

    #[test]
    fn the_profile_vectors_are_refused() {
        refused("a: 1\na: 2\n", "duplicate key");
        refused("a: &x [1,2]\nb: *x\n", "anchor");
        refused("<<: {a: 1}\n", "merge key");
        refused("a: !foo bar\n", "tag");
        refused("a: !!str 12\n", "tag");
        refused("a: ! 12\n", "tag");
        refused("a: 1\n---\nb: 2\n", "more than one document");
        refused("? [a, b]\n: 1\n", "key is not a scalar");
        refused("a: [1,\n", "syntax error");
        refused("%YAML 1.2\n---\na: 1\n", "directive");
        refused("a:\t1\n", "tab");
        refused(": 1\n", "empty key");
        refused(
            &format!("a: {}\n", "[".repeat(65)),
            "flow collections nested too deep",
        );
        refused("", "no document");
    }

    #[test]
    fn sixty_four_levels_are_read_and_an_error_never_shows_the_value() {
        let ok = format!("a: {}{}\n", "[".repeat(64), "]".repeat(64));
        assert!(parse(&ok).is_ok());
        let e = parse("secret-value: 1\nsecret-value: 2\n").unwrap_err();
        assert!(!e.to_string().contains("secret"), "{e}");
        assert_eq!((e.line, e.col), (2, 1));
    }

    #[test]
    fn a_bracket_in_a_quoted_string_or_a_comment_is_not_nesting() {
        let q = format!("a: \"{}\"\nb: x # {}\n", "[".repeat(100), "{".repeat(100));
        assert!(parse(&q).is_ok());
    }
}
