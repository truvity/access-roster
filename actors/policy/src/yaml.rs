//! A reader for the YAML of the grant vocabulary, over `saphyr-parser`.
//!
//! store@ has already read the document under the strict profile of
//! docs/reference/bootstrap-file.md "Format" before it served it. This reader repeats the rules
//! that matter to what `policy` does with the data (one document, no anchor, alias, tag, merge
//! key or duplicate key), so that a document that reaches `policy` another way is read the same.
//! An error names a place, never a value, because the parser's own messages can print the source.

use std::borrow::Cow;

use saphyr_parser::{Event, Parser, ScalarStyle, Span};

/// The largest document read.
const DOCUMENT_MAX: usize = 256 * 1024;
/// Collections nest at most this deep.
const DEPTH_MAX: usize = 32;

/// A document as plain data. The vocabulary has no number: a plain scalar that is not a boolean or
/// null is a string.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    Null,
    Bool(bool),
    String(String),
    Seq(Vec<Value>),
    /// Keys are strings, unique, in document order.
    Map(Vec<(String, Value)>),
}

/// Why a document was refused and where; never the value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct YamlError {
    pub what: &'static str,
    /// 1-based line; 0 for the whole document.
    pub line: usize,
}

impl std::fmt::Display for YamlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.line == 0 {
            f.write_str(self.what)
        } else {
            write!(f, "line {}: {}", self.line, self.what)
        }
    }
}

impl std::error::Error for YamlError {}

fn at(what: &'static str, span: Span) -> YamlError {
    YamlError {
        what,
        line: span.start.line(),
    }
}

fn whole(what: &'static str) -> YamlError {
    YamlError { what, line: 0 }
}

type P<'a> = Parser<'a, saphyr_parser::StrInput<'a>>;

/// Reads one document.
///
/// # Errors
///
/// [`YamlError`] for a syntax error and for each refusal above.
pub fn parse(source: &str) -> Result<Value, YamlError> {
    if source.len() > DOCUMENT_MAX {
        return Err(whole("document too large"));
    }
    let mut parser = Parser::new_from_str(source);
    let mut root = None;
    loop {
        match next(&mut parser)? {
            None => break,
            Some((Event::StreamStart | Event::StreamEnd | Event::DocumentEnd, _)) => {}
            Some((Event::DocumentStart(_), span)) => {
                if root.is_some() {
                    return Err(at("more than one document", span));
                }
                let (ev, span) = next(&mut parser)?.ok_or_else(|| whole("syntax error"))?;
                root = Some(value(&mut parser, ev, span, 0)?);
            }
            Some((_, span)) => return Err(at("unexpected content", span)),
        }
    }
    root.ok_or_else(|| whole("no document"))
}

fn next(p: &mut P<'_>) -> Result<Option<(Event<'static>, Span)>, YamlError> {
    match p.next_event() {
        None => Ok(None),
        Some(Err(_)) => Err(whole("syntax error")),
        Some(Ok((ev, span))) => Ok(Some((own(ev), span))),
    }
}

fn step(p: &mut P<'_>) -> Result<(Event<'static>, Span), YamlError> {
    next(p)?.ok_or_else(|| whole("syntax error"))
}

/// The events borrow the source; nothing of them is kept past one step.
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

fn value(p: &mut P<'_>, ev: Event<'static>, span: Span, depth: usize) -> Result<Value, YamlError> {
    if depth > DEPTH_MAX {
        return Err(at("nested too deep", span));
    }
    match ev {
        Event::Alias(_) => Err(at("alias", span)),
        Event::Scalar(text, style, anchor, tag) => {
            plain(anchor, tag.is_some(), span)?;
            Ok(scalar(&text, style))
        }
        Event::SequenceStart(anchor, tag) => {
            plain(anchor, tag.is_some(), span)?;
            let mut items = Vec::new();
            loop {
                let (ev, span) = step(p)?;
                if matches!(ev, Event::SequenceEnd) {
                    return Ok(Value::Seq(items));
                }
                items.push(value(p, ev, span, depth + 1)?);
            }
        }
        Event::MappingStart(anchor, tag) => {
            plain(anchor, tag.is_some(), span)?;
            let mut entries: Vec<(String, Value)> = Vec::new();
            loop {
                let (ev, kspan) = step(p)?;
                let key = match ev {
                    Event::MappingEnd => return Ok(Value::Map(entries)),
                    Event::Scalar(text, _, anchor, tag) => {
                        plain(anchor, tag.is_some(), kspan)?;
                        text.into_owned()
                    }
                    Event::Alias(_) => return Err(at("alias", kspan)),
                    _ => return Err(at("key is not a scalar", kspan)),
                };
                if key == "<<" {
                    return Err(at("merge key", kspan));
                }
                if entries.iter().any(|(k, _)| *k == key) {
                    return Err(at("duplicate key", kspan));
                }
                let (ev, vspan) = step(p)?;
                entries.push((key, value(p, ev, vspan, depth + 1)?));
            }
        }
        _ => Err(at("unexpected content", span)),
    }
}

fn plain(anchor: usize, tagged: bool, span: Span) -> Result<(), YamlError> {
    if anchor != 0 {
        return Err(at("anchor", span));
    }
    if tagged {
        return Err(at("tag", span));
    }
    Ok(())
}

fn scalar(text: &str, style: ScalarStyle) -> Value {
    if style != ScalarStyle::Plain {
        return Value::String(text.to_owned());
    }
    match text {
        "" | "~" | "null" => Value::Null,
        "true" => Value::Bool(true),
        "false" => Value::Bool(false),
        t => Value::String(t.to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_data_is_read() {
        let v = parse("a: {b: [x, \"y\"], c: true}\nd: ~\n").unwrap();
        assert_eq!(
            v,
            Value::Map(vec![
                (
                    "a".into(),
                    Value::Map(vec![
                        (
                            "b".into(),
                            Value::Seq(vec![Value::String("x".into()), Value::String("y".into())])
                        ),
                        ("c".into(), Value::Bool(true)),
                    ])
                ),
                ("d".into(), Value::Null),
            ])
        );
    }

    #[test]
    fn what_the_profile_refuses_is_refused_without_showing_the_value() {
        for (src, what) in [
            ("a: &x 1\nb: *x\n", "anchor"),
            ("a: !!str 1\n", "tag"),
            ("a: 1\na: 2\n", "duplicate key"),
            ("<<: {a: 1}\n", "merge key"),
            ("a: 1\n---\nb: 2\n", "more than one document"),
        ] {
            let e = parse(src).unwrap_err();
            assert_eq!(e.what, what, "{src}");
        }
        assert_eq!(parse("a: [").unwrap_err().what, "syntax error");
        assert!(
            !parse("secret: [")
                .unwrap_err()
                .to_string()
                .contains("secret")
        );
    }
}
