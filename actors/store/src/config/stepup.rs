//! The `acr_values` of the `@step_up` annotations in the text of a Policy document, for the one rule of the set that
//! needs them: a step-up rule asks a client for an acr that the Boundary lists in `acr_values_supported`, or the
//! challenge it sends back would not be enforced (policy.md "Step-up", REQ-AUTHN-009).
//!
//! store@ does not parse Cedar: `policy` does, and refuses a text that is not Cedar or an annotation that is not
//! `acr_values=<value> max_age=<seconds>`. This is a lexer for the three things that matter to find an annotation: a
//! comment (`//` to the end of the line), a string (with its escapes) and `@name("value")`. A `@step_up` in a comment or a
//! string is not one. What the lexer cannot read it skips, because the rule is a check of the set and `policy` is the
//! reader that decides; the enforcement in `session` does not depend on it.

/// The `acr_values` of every `@step_up("…")` annotation in `cedar`, in the order they are written. An annotation with no
/// `acr_values` (a `max_age` alone is well-formed) gives none.
pub fn acr_values(cedar: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut s = Lexer {
        b: cedar.char_indices().peekable(),
        text: cedar,
    };
    while let Some((_, c)) = s.b.next() {
        match c {
            '/' if s.b.peek().is_some_and(|&(_, n)| n == '/') => s.line(),
            '"' => {
                s.string();
            }
            '@' => {
                let name = s.ident();
                if name == "step_up"
                    && let Some(v) = s.annotation_value()
                {
                    out.extend(
                        v.split(' ')
                            .filter_map(|p| p.strip_prefix("acr_values="))
                            .filter(|a| !a.is_empty())
                            .map(str::to_owned),
                    );
                }
            }
            _ => {}
        }
    }
    out
}

struct Lexer<'a> {
    b: std::iter::Peekable<std::str::CharIndices<'a>>,
    text: &'a str,
}

impl Lexer<'_> {
    /// Skips the rest of a `//` comment.
    fn line(&mut self) {
        for (_, c) in self.b.by_ref() {
            if c == '\n' {
                return;
            }
        }
    }

    /// Skips white space and comments.
    fn space(&mut self) {
        while let Some(&(_, c)) = self.b.peek() {
            if c.is_whitespace() {
                self.b.next();
            } else if c == '/' {
                let mut ahead = self.b.clone();
                ahead.next();
                if ahead.peek().is_some_and(|&(_, n)| n == '/') {
                    self.line();
                } else {
                    return;
                }
            } else {
                return;
            }
        }
    }

    /// Reads an identifier at the cursor (possibly empty).
    fn ident(&mut self) -> &str {
        let start = self.b.peek().map_or(self.text.len(), |&(i, _)| i);
        let mut end = start;
        while let Some(&(i, c)) = self.b.peek() {
            if c.is_ascii_alphanumeric() || c == '_' {
                end = i + c.len_utf8();
                self.b.next();
            } else {
                break;
            }
        }
        &self.text[start..end]
    }

    /// Reads the rest of a string whose opening quote was read; `None` when it does not end or has an escape Cedar does
    /// not have.
    fn string(&mut self) -> Option<String> {
        let mut out = String::new();
        while let Some((_, c)) = self.b.next() {
            match c {
                '"' => return Some(out),
                '\\' => match self.b.next()?.1 {
                    '\\' => out.push('\\'),
                    '"' => out.push('"'),
                    '\'' => out.push('\''),
                    'n' => out.push('\n'),
                    'r' => out.push('\r'),
                    't' => out.push('\t'),
                    '0' => out.push('\0'),
                    'u' => {
                        if self.b.next()?.1 != '{' {
                            return None;
                        }
                        let mut hex = String::new();
                        loop {
                            match self.b.next()?.1 {
                                '}' => break,
                                h if h.is_ascii_hexdigit() && hex.len() < 6 => hex.push(h),
                                _ => return None,
                            }
                        }
                        out.push(char::from_u32(u32::from_str_radix(&hex, 16).ok()?)?);
                    }
                    _ => return None,
                },
                c => out.push(c),
            }
        }
        None
    }

    /// `("value")` after an annotation name: the value, or `None` for an annotation with no value or one that is not a
    /// string in parentheses.
    fn annotation_value(&mut self) -> Option<String> {
        self.space();
        if self.b.peek()?.1 != '(' {
            return None;
        }
        self.b.next();
        self.space();
        if self.b.next()?.1 != '"' {
            return None;
        }
        let v = self.string()?;
        self.space();
        (self.b.next()?.1 == ')').then_some(v)
    }
}

#[cfg(test)]
mod tests {
    use super::acr_values;

    #[test]
    fn the_annotation_of_the_local_policy_is_read() {
        let text = include_str!("../../../../tests/installations/local/config/policy.cedar");
        assert_eq!(acr_values(text), ["urn:example:acr:mfa"]);
    }

    #[test]
    fn every_way_to_write_an_annotation_is_read() {
        for (cedar, want) in [
            (
                r#"@step_up("acr_values=a max_age=900") forbid (principal, action, resource);"#,
                vec!["a"],
            ),
            (
                r#"@step_up("max_age=900 acr_values=a") forbid (principal, action, resource);"#,
                vec!["a"],
            ),
            (
                r#"@step_up ( "acr_values=a" ) forbid (principal, action, resource);"#,
                vec!["a"],
            ),
            (
                "@step_up\n(\n\"acr_values=a\"\n)\nforbid (principal, action, resource);",
                vec!["a"],
            ),
            (r#"@step_up("acr_values=\u{61}")"#, vec!["a"]),
            (r#"@step_up("acr_values=-x")"#, vec!["-x"]),
            (
                r#"@step_up("acr_values=a") @step_up("acr_values=b")"#,
                vec!["a", "b"],
            ),
            (
                r#"@id("x") @step_up("acr_values=urn:a:b")"#,
                vec!["urn:a:b"],
            ),
            // No acr: a max_age alone, no value, a value that is not a string.
            (r#"@step_up("max_age=900")"#, vec![]),
            (r"@step_up forbid (principal, action, resource);", vec![]),
            (r"@step_up(5)", vec![]),
            (r#"@step_up("acr_values=")"#, vec![]),
            // Other annotations and other names.
            (r#"@step_up2("acr_values=a")"#, vec![]),
            (r#"@other("acr_values=a")"#, vec![]),
        ] {
            assert_eq!(acr_values(cedar), want, "{cedar}");
        }
    }

    /// A `@step_up` in a comment or in a string is not an annotation, and the text after either is still read.
    #[test]
    fn a_comment_or_a_string_hides_what_it_holds_and_not_what_follows() {
        for (cedar, want) in [
            (
                "// @step_up(\"acr_values=a\")\n@step_up(\"acr_values=b\")",
                vec!["b"],
            ),
            (
                r#"@id("@step_up(\"acr_values=a\")") @step_up("acr_values=b")"#,
                vec!["b"],
            ),
            ("@step_up(// c\n\"acr_values=a\")", vec!["a"]),
            (
                r#"permit (principal, action, resource) when { context.x == "//" }; @step_up("acr_values=a")"#,
                vec!["a"],
            ),
            (r#"@id("a\\") @step_up("acr_values=a")"#, vec!["a"]),
            ("/ @step_up(\"acr_values=a\")", vec!["a"]),
            // A string that does not end hides the rest, and a bad escape ends the annotation: what is not read is `policy`'s to
            // refuse.
            (r#"@id("never ends @step_up("acr_values=a")"#, vec![]),
            (r#"@step_up("acr_values=a\q")"#, vec![]),
        ] {
            assert_eq!(acr_values(cedar), want, "{cedar}");
        }
    }

    #[test]
    fn text_that_is_not_cedar_does_not_panic() {
        for cedar in [
            "",
            "@",
            "@step_up(",
            "@step_up(\"",
            "\"",
            "\\",
            "é@step_up(\"acr_values=é\")",
            "@é",
            "//",
        ] {
            let _ = acr_values(cedar);
        }
        assert_eq!(acr_values("é@step_up(\"acr_values=é\")"), ["é"]);
    }
}
