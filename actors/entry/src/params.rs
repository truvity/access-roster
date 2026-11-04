//! Query strings and form bodies, parsed strictly (RFC 6749 section 3.1 and 4.1.3: the
//! `application/x-www-form-urlencoded` format of the WHATWG URL standard).
//!
//! The parser refuses what it cannot read exactly: an empty pair, a bad percent escape, bytes that
//! are not UTF-8, a control character, a parameter sent twice, a name outside the route's closed
//! list. It never reports a name or a value, only a reason from a closed list.

/// The most a query string may hold, in bytes.
pub(crate) const QUERY_MAX: usize = 8 * 1024;
/// The most a form body may hold, in bytes.
pub(crate) const FORM_MAX: usize = 32 * 1024;
/// The longest decoded value of one parameter, in bytes.
const VALUE_MAX: usize = 8 * 1024;
/// The longest parameter name.
const NAME_MAX: usize = 64;

/// Why a parameter list was refused. The text goes to the audit record, never to the caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Bad {
    /// An empty pair, a bad percent escape, bytes that are not UTF-8, or a control character.
    Syntax,
    /// The same name twice.
    Duplicate,
    /// A name that is not on the route's closed list.
    Unknown,
    /// A name or a value too long.
    Size,
}

impl Bad {
    pub(crate) fn reason(self) -> &'static str {
        match self {
            Bad::Syntax => "parameter_syntax",
            Bad::Duplicate => "duplicate_parameter",
            Bad::Unknown => "unknown_parameter",
            Bad::Size => "parameter_size",
        }
    }
}

/// The parameters of one request, each name at most once.
#[derive(Debug, Default)]
pub(crate) struct Params(Vec<(String, String)>);

impl Params {
    /// Parses `raw`, an undecoded query string or form body. The empty string holds no parameter.
    pub(crate) fn parse(raw: &str, limit: usize) -> Result<Self, Bad> {
        Self::read(raw, limit, None)
    }

    /// Like [`Params::parse`], but a name outside `known` is dropped and not kept: a client of the
    /// route ignores what it does not recognise (RFC 6749 section 4.1.2). It is for a response
    /// that reaches sluis as a client only. The dropped pair is still read and bounded, and it is
    /// not checked for a repeat; a known name is checked as in `parse`.
    pub(crate) fn parse_ignoring_unknown(
        raw: &str,
        limit: usize,
        known: &[&str],
    ) -> Result<Self, Bad> {
        Self::read(raw, limit, Some(known))
    }

    fn read(raw: &str, limit: usize, known: Option<&[&str]>) -> Result<Self, Bad> {
        if raw.len() > limit {
            return Err(Bad::Size);
        }
        let mut out: Vec<(String, String)> = Vec::new();
        if raw.is_empty() {
            return Ok(Self(out));
        }
        for pair in raw.split('&') {
            // An empty pair ("a=1&&b=2", a trailing "&") is not a parameter.
            if pair.is_empty() {
                return Err(Bad::Syntax);
            }
            let (n, v) = pair.split_once('=').unwrap_or((pair, ""));
            let name = decode(n)?;
            let value = decode(v)?;
            if name.is_empty() {
                return Err(Bad::Syntax);
            }
            if name.len() > NAME_MAX || value.len() > VALUE_MAX {
                return Err(Bad::Size);
            }
            if known.is_some_and(|k| !k.contains(&name.as_str())) {
                continue;
            }
            if out.iter().any(|(k, _)| *k == name) {
                return Err(Bad::Duplicate);
            }
            out.push((name, value));
        }
        Ok(Self(out))
    }

    /// Refuses a name outside `allowed`: the route's closed list.
    pub(crate) fn only(self, allowed: &[&str]) -> Result<Self, Bad> {
        if self.0.iter().all(|(k, _)| allowed.contains(&k.as_str())) {
            Ok(self)
        } else {
            Err(Bad::Unknown)
        }
    }

    /// The value of a parameter; the empty string when it was not sent (a proto3 field's default).
    pub(crate) fn get(&self, name: &str) -> String {
        self.0
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.clone())
            .unwrap_or_default()
    }

    pub(crate) fn has(&self, name: &str) -> bool {
        self.0.iter().any(|(k, _)| k == name)
    }
}

fn hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Percent-decodes one name or value; `+` is a space in this format.
fn decode(s: &str) -> Result<String, Bad> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' => {
                let hi = b.get(i + 1).copied().and_then(hex).ok_or(Bad::Syntax)?;
                let lo = b.get(i + 2).copied().and_then(hex).ok_or(Bad::Syntax)?;
                out.push(hi << 4 | lo);
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    let s = String::from_utf8(out).map_err(|_| Bad::Syntax)?;
    // NUL, line breaks and the other control characters have no place in a parameter.
    if s.chars().any(char::is_control) {
        return Err(Bad::Syntax);
    }
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> Result<Params, Bad> {
        Params::parse(s, QUERY_MAX)
    }

    #[test]
    fn a_plain_list_is_read_and_decoded() {
        let q = p("a=1&b=x%20y&c=p+q&d=&e").unwrap();
        assert_eq!(q.get("a"), "1");
        assert_eq!(q.get("b"), "x y");
        assert_eq!(q.get("c"), "p q");
        assert_eq!(q.get("d"), "");
        assert!(q.has("e") && !q.has("f"));
        assert_eq!(q.get("f"), "");
        assert!(p("").unwrap().0.is_empty());
    }

    #[test]
    fn a_duplicate_is_refused_even_when_the_values_agree_or_are_empty() {
        assert_eq!(p("a=1&a=1").unwrap_err(), Bad::Duplicate);
        assert_eq!(p("a&a").unwrap_err(), Bad::Duplicate);
        // The same name written two ways is the same name.
        assert_eq!(p("a=1&%61=2").unwrap_err(), Bad::Duplicate);
    }

    #[test]
    fn what_cannot_be_read_exactly_is_refused() {
        for bad in [
            "a=1&&b=2", "a=1&", "&a=1", "=x", "a=%", "a=%4", "a=%zz", "a=%ff", "a=%00", "a=%0a",
            "a=%0d%0a", "a=\u{7}",
        ] {
            assert_eq!(p(bad).unwrap_err(), Bad::Syntax, "{bad:?}");
        }
    }

    #[test]
    fn sizes_are_bounded() {
        assert_eq!(Params::parse("a=1", 2).unwrap_err(), Bad::Size);
        assert_eq!(
            p(&format!("{}=1", "n".repeat(NAME_MAX + 1))).unwrap_err(),
            Bad::Size
        );
        assert_eq!(
            Params::parse(&format!("a={}", "v".repeat(VALUE_MAX + 1)), FORM_MAX).unwrap_err(),
            Bad::Size
        );
        assert!(Params::parse(&format!("a={}", "v".repeat(VALUE_MAX)), FORM_MAX).is_ok());
    }

    #[test]
    fn a_name_off_the_closed_list_is_refused() {
        assert_eq!(
            p("a=1&z=2").unwrap().only(&["a"]).unwrap_err(),
            Bad::Unknown
        );
        assert!(p("a=1").unwrap().only(&["a", "b"]).is_ok());
        // Names are exact: no case folding, no trimming.
        assert_eq!(p("A=1").unwrap().only(&["a"]).unwrap_err(), Bad::Unknown);
        assert_eq!(p("a%20=1").unwrap().only(&["a"]).unwrap_err(), Bad::Unknown);
    }

    #[test]
    fn unknown_names_are_dropped_when_asked_and_known_names_keep_their_checks() {
        let k = ["code", "state"];
        let q = |s: &str| Params::parse_ignoring_unknown(s, QUERY_MAX, &k);
        let ok = q("code=c&session_state=s&x=1&x=2&state=st").unwrap();
        assert_eq!((ok.get("code"), ok.get("state")), ("c".into(), "st".into()));
        assert!(!ok.has("session_state") && !ok.has("x"));
        assert!(ok.only(&k).is_ok());
        assert_eq!(q("code=1&code=2").unwrap_err(), Bad::Duplicate);
        assert_eq!(q("state=1&x=2&state=3").unwrap_err(), Bad::Duplicate);
        // A dropped pair is still read and bounded.
        assert_eq!(q("code=c&x=%zz").unwrap_err(), Bad::Syntax);
        assert_eq!(q("code=c&&x=1").unwrap_err(), Bad::Syntax);
        let long = format!("code=c&x={}", "a".repeat(VALUE_MAX + 1));
        assert_eq!(q(&long).unwrap_err(), Bad::Size);
        assert_eq!(
            Params::parse_ignoring_unknown("code=c&x=1", 4, &k).unwrap_err(),
            Bad::Size
        );
    }

    #[test]
    fn no_input_makes_the_parser_panic() {
        // A cheap stand-in for a fuzzer (REQ-ISO-092 asks for a real one): every two-byte prefix
        // and a spread of pseudo-random strings are either read or refused.
        let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
        for _ in 0..20_000 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let len = (x % 24) as usize;
            let alphabet = b"%&=+0aF\x00\n z";
            let s: String = (0..len)
                .map(|i| alphabet[((x >> (i % 56)) as usize) % alphabet.len()] as char)
                .collect();
            let _ = p(&s);
        }
        for a in 0u8..=127 {
            for b in 0u8..=127 {
                let _ = p(&String::from_utf8_lossy(&[a, b]));
            }
        }
    }
}
