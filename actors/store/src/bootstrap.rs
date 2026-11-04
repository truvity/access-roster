//! The bootstrap file of store@ (docs/reference/bootstrap-file.md, schema v1).
//!
//! Read under the strict YAML profile, decoded with unknown keys refused, and checked: names,
//! durations, the four destinations, and the pin of every publisher key. An error names a path,
//! never a value.

use std::collections::HashSet;
use std::io::Read as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use aws_lc_rs::digest;
use aws_lc_rs::signature::{ECDSA_P384_SHA384_ASN1, ParsedPublicKey};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use sluis_registry::Class;

use crate::yaml::{self, Value};

/// The `$id` of the schema (bootstrap-file.md "Schema and validation").
pub const SCHEMA_ID: &str = "https://sluis.id/schema/bootstrap/v1/bootstrap.schema.json";
/// The default of `start_timeout`.
const START_TIMEOUT_DEFAULT: Duration = Duration::from_secs(30);

/// The DER prefix of a SubjectPublicKeyInfo of an EC P-384 key (RFC 5480, sections 2.1.1 and
/// 2.1.1.1: id-ecPublicKey, secp384r1, then the BIT STRING of an uncompressed point).
const SPKI_P384_PREFIX: [u8; 23] = [
    0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b,
    0x81, 0x04, 0x00, 0x22, 0x03, 0x62, 0x00,
];
const SPKI_P384_LEN: usize = 23 + 97;

/// A destination: the driver of a port and the socket where store@ reaches it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Destination {
    pub driver: String,
    pub socket: PathBuf,
}

/// A pinned public key that may sign config. WP-11 reads these; store@ only keeps them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Publisher {
    pub kid: String,
    /// The DER SubjectPublicKeyInfo of the key.
    pub spki_der: Vec<u8>,
    /// The pin: the SHA-384 of `spki_der`, lower-case hex.
    pub spki_sha384: String,
    pub co_signs: Vec<String>,
}

/// The bootstrap file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bootstrap {
    pub boundary: String,
    pub start_timeout: Duration,
    pub config_source: Destination,
    pub secret_source: Destination,
    pub durable: Destination,
    pub temp: Destination,
    pub publishers: Vec<Publisher>,
}

/// Why the file was refused: a path or a place and a rule, never a value.
#[derive(Debug, PartialEq, Eq)]
pub struct BootstrapError(pub String);

impl std::fmt::Display for BootstrapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for BootstrapError {}

fn err<T>(path: &str, rule: &str) -> Result<T, BootstrapError> {
    Err(BootstrapError(format!("{path}: {rule}")))
}

impl Bootstrap {
    /// The destinations with the name of their port, in the order of the file.
    #[must_use]
    pub fn destinations(&self) -> [(&'static str, &Destination); 4] {
        [
            ("config_source", &self.config_source),
            ("secret_source", &self.secret_source),
            ("durable", &self.durable),
            ("temp", &self.temp),
        ]
    }

    /// Reads the file at `path`. The file must belong to root or to `own_uid`, and no one but its
    /// owner may write it (bootstrap-file.md "Where it lives").
    ///
    /// # Errors
    ///
    /// [`BootstrapError`] for an unreadable or writable-by-others file and for every rule of
    /// [`Bootstrap::parse`].
    pub fn load(path: &Path, own_uid: u32) -> Result<Self, BootstrapError> {
        let mut file = std::fs::File::open(path).map_err(|e| {
            BootstrapError(format!("bootstrap: cannot open the file ({})", e.kind()))
        })?;
        // The checks are on the open file, so the file checked is the file read.
        let meta = file.metadata().map_err(|e| {
            BootstrapError(format!("bootstrap: cannot stat the file ({})", e.kind()))
        })?;
        if !meta.is_file() {
            return err("bootstrap", "not a regular file");
        }
        if meta.uid() != 0 && meta.uid() != own_uid {
            return err("bootstrap", "owner must be root or the uid of store@");
        }
        if meta.mode() & 0o022 != 0 {
            return err("bootstrap", "mode allows a write by group or others");
        }
        let mut text = String::new();
        file.by_ref()
            .take(yaml::DOCUMENT_MAX as u64 + 1)
            .read_to_string(&mut text)
            .map_err(|e| {
                BootstrapError(format!("bootstrap: cannot read the file ({})", e.kind()))
            })?;
        Self::parse(&text)
    }

    /// Parses and checks the text of a bootstrap file.
    ///
    /// # Errors
    ///
    /// [`BootstrapError`] naming the path of the field at fault.
    pub fn parse(text: &str) -> Result<Self, BootstrapError> {
        let doc = yaml::parse(text).map_err(|e| BootstrapError(format!("bootstrap: {e}")))?;
        let Value::Map(top) = doc else {
            return err("bootstrap", "must be a mapping");
        };
        let mut m = Fields::new(
            "",
            top,
            &[
                "$schema",
                "boundary",
                "start_timeout",
                "config_source",
                "secret_source",
                "durable",
                "temp",
                "publishers",
            ],
        )?;
        if let Some(v) = m.take("$schema") {
            match v {
                Value::String(s) if s == SCHEMA_ID => {}
                _ => return err("$schema", "must name the schema of bootstrap v1"),
            }
        }
        let boundary = name(m.require("boundary")?, "boundary")?;
        let start_timeout = match m.take("start_timeout") {
            Some(v) => duration(v, "start_timeout")?,
            None => START_TIMEOUT_DEFAULT,
        };
        let config_source = destination(m.require("config_source")?, "config_source", &["file"])?;
        let secret_source = destination(
            m.require("secret_source")?,
            "secret_source",
            &["credential"],
        )?;
        let durable = destination(m.require("durable")?, "durable", &["rqlite"])?;
        let temp = destination(m.require("temp")?, "temp", &["rqlite"])?;
        let publishers = publishers(m.require("publishers")?)?;

        let b = Bootstrap {
            boundary,
            start_timeout,
            config_source,
            secret_source,
            durable,
            temp,
            publishers,
        };
        let mut sockets = HashSet::new();
        for (port, d) in b.destinations() {
            if !sockets.insert(d.socket.clone()) {
                return err(port, "shares a socket path with another destination");
            }
        }
        Ok(b)
    }
}

/// A mapping with its keys checked against a closed list; each key is taken once.
struct Fields {
    path: String,
    entries: Vec<(String, Value)>,
}

impl Fields {
    fn new(
        path: &str,
        entries: Vec<(String, Value)>,
        allowed: &[&str],
    ) -> Result<Self, BootstrapError> {
        for (k, _) in &entries {
            if !allowed.contains(&k.as_str()) {
                // A key is a name of the schema's author, but an unknown one is the file's own
                // text: name its place, not the key.
                return err(&child(path, "<key>"), "unknown key");
            }
        }
        Ok(Self {
            path: path.to_owned(),
            entries,
        })
    }

    fn take(&mut self, key: &str) -> Option<Value> {
        let i = self.entries.iter().position(|(k, _)| k == key)?;
        Some(self.entries.remove(i).1)
    }

    fn require(&mut self, key: &str) -> Result<Value, BootstrapError> {
        self.take(key)
            .map_or_else(|| err(&child(&self.path, key), "required"), Ok)
    }
}

fn child(path: &str, key: &str) -> String {
    if path.is_empty() {
        key.to_owned()
    } else {
        format!("{path}.{key}")
    }
}

/// A boundary or `kid`: lower-case kebab-case, 1 to 32 characters, starting with a letter.
fn name(v: Value, path: &str) -> Result<String, BootstrapError> {
    let Value::String(s) = v else {
        return err(path, "must be a string");
    };
    let mut chars = s.chars();
    let ok = chars.next().is_some_and(|c| c.is_ascii_lowercase())
        && s.len() <= 32
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
    if ok {
        Ok(s)
    } else {
        err(
            path,
            "must be lower-case kebab-case, 1 to 32 characters, starting with a letter",
        )
    }
}

/// One whole number and one unit of `s`, `m`, `h` or `d` (bootstrap-file.md "Durations").
fn duration(v: Value, path: &str) -> Result<Duration, BootstrapError> {
    let Value::String(s) = v else {
        return err(path, "not a duration string");
    };
    let Some(unit) = s.chars().last() else {
        return err(path, "not a duration string");
    };
    let digits = &s[..s.len() - unit.len_utf8()];
    let per = match unit {
        's' => 1,
        'm' => 60,
        'h' => 3600,
        'd' => 86400,
        _ => return err(path, "not a duration string"),
    };
    if digits.is_empty() || digits.len() > 9 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return err(path, "not a duration string");
    }
    let n: u64 = digits
        .parse()
        .map_err(|_| BootstrapError(format!("{path}: not a duration string")))?;
    if n == 0 {
        return err(path, "must be above zero");
    }
    Ok(Duration::from_secs(n * per))
}

fn destination(v: Value, path: &str, drivers: &[&str]) -> Result<Destination, BootstrapError> {
    let Value::Map(entries) = v else {
        return err(path, "must be a mapping");
    };
    let mut m = Fields::new(path, entries, &["driver", "socket"])?;
    let driver = match m.require("driver")? {
        Value::String(s) if drivers.contains(&s.as_str()) => s,
        Value::String(_) => {
            return err(
                &child(path, "driver"),
                "not a driver of this port in schema v1",
            );
        }
        _ => return err(&child(path, "driver"), "must be a string"),
    };
    let socket = match m.require("socket")? {
        Value::String(s) if s.starts_with('/') && !s.contains('\0') => PathBuf::from(s),
        _ => return err(&child(path, "socket"), "must be an absolute path"),
    };
    Ok(Destination { driver, socket })
}

fn publishers(v: Value) -> Result<Vec<Publisher>, BootstrapError> {
    let Value::Seq(items) = v else {
        return err("publishers", "must be a list");
    };
    if items.is_empty() {
        // A list that verifies nothing: config could never load.
        return err("publishers", "must hold at least one publisher");
    }
    let mut out: Vec<Publisher> = Vec::new();
    for (i, item) in items.into_iter().enumerate() {
        let path = format!("publishers[{i}]");
        let Value::Map(entries) = item else {
            return err(&path, "must be a mapping");
        };
        let mut m = Fields::new(
            &path,
            entries,
            &["kid", "public_key", "spki_sha384", "co_signs"],
        )?;
        let kid = name(m.require("kid")?, &child(&path, "kid"))?;
        if out.iter().any(|p| p.kid == kid) {
            return err(&child(&path, "kid"), "not unique");
        }
        let pem_path = child(&path, "public_key");
        let Value::String(pem) = m.require("public_key")? else {
            return err(&pem_path, "must be a string");
        };
        let spki_der = spki_from_pem(&pem, &pem_path)?;
        let pin_path = child(&path, "spki_sha384");
        let Value::String(pin) = m.require("spki_sha384")? else {
            return err(&pin_path, "must be a string");
        };
        let actual = hex(digest::digest(&digest::SHA384, &spki_der).as_ref());
        if pin.len() != 96 || !constant_time_eq(pin.as_bytes(), actual.as_bytes()) {
            return err(&pin_path, "does not match the key");
        }
        let co_signs = match m.take("co_signs") {
            None => Vec::new(),
            Some(Value::Seq(kinds)) => {
                let mut out = Vec::new();
                for (j, k) in kinds.into_iter().enumerate() {
                    let kp = format!("{}[{j}]", child(&path, "co_signs"));
                    let Value::String(k) = k else {
                        return err(&kp, "must be a string");
                    };
                    if !sluis_registry::kind_by_name(&k).is_some_and(|k| k.class == Class::Config) {
                        return err(&kp, "not a config kind of the registry");
                    }
                    out.push(k);
                }
                out
            }
            Some(_) => return err(&child(&path, "co_signs"), "must be a list"),
        };
        out.push(Publisher {
            kid,
            spki_der,
            spki_sha384: pin,
            co_signs,
        });
    }
    Ok(out)
}

/// A PEM `PUBLIC KEY` (RFC 7468, section 13) that holds an EC P-384 key (RFC 5480): one block, the
/// prefix of a P-384 SubjectPublicKeyInfo, and a point on the curve.
fn spki_from_pem(pem: &str, path: &str) -> Result<Vec<u8>, BootstrapError> {
    const BEGIN: &str = "-----BEGIN PUBLIC KEY-----";
    const END: &str = "-----END PUBLIC KEY-----";
    let t = pem.trim();
    let Some(body) = t.strip_prefix(BEGIN).and_then(|r| r.strip_suffix(END)) else {
        return err(path, "must be one PEM PUBLIC KEY block");
    };
    let b64: String = body.split_whitespace().collect();
    let der = STANDARD
        .decode(b64.as_bytes())
        .map_err(|_| BootstrapError(format!("{path}: not valid base64")))?;
    if der.len() != SPKI_P384_LEN || der[..SPKI_P384_PREFIX.len()] != SPKI_P384_PREFIX {
        return err(path, "not an EC P-384 SubjectPublicKeyInfo");
    }
    if ParsedPublicKey::new(&ECDSA_P384_SHA384_ASN1, &der[SPKI_P384_PREFIX.len()..]).is_err() {
        return err(path, "not a point on P-384");
    }
    Ok(der)
}

fn hex(b: &[u8]) -> String {
    use std::fmt::Write as _;
    b.iter()
        .fold(String::with_capacity(b.len() * 2), |mut s, x| {
            let _ = write!(s, "{x:02x}");
            s
        })
}

/// The pin is public, but a comparison of a hash does not need to leak where it differs.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |d, (x, y)| d | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    /// tests/installations/local/bootstrap.yaml, the example of bootstrap-file.md.
    const LOCAL: &str = include_str!("../../../tests/installations/local/bootstrap.yaml");

    fn local(replace: &[(&str, &str)]) -> String {
        replace.iter().fold(LOCAL.to_owned(), |t, (a, b)| {
            assert!(t.contains(a), "the vector does not hold {a:?}");
            t.replacen(a, b, 1)
        })
    }

    fn refusal(text: &str) -> String {
        Bootstrap::parse(text).expect_err("must be refused").0
    }

    #[test]
    fn the_local_example_is_read() {
        let b = Bootstrap::parse(LOCAL).unwrap();
        assert_eq!(b.boundary, "dev");
        assert_eq!(b.start_timeout, Duration::from_secs(30));
        assert_eq!(b.durable.driver, "rqlite");
        assert_eq!(
            b.durable.socket,
            Path::new("/run/sluis/store/dev/durable.sock")
        );
        assert_eq!(b.publishers.len(), 1);
        assert_eq!(b.publishers[0].kid, "publisher-1");
        assert_eq!(b.publishers[0].spki_der.len(), SPKI_P384_LEN);
    }

    #[test]
    fn start_timeout_defaults_and_follows_the_duration_grammar() {
        let b = Bootstrap::parse(&local(&[("start_timeout: 30s\n", "")])).unwrap();
        assert_eq!(b.start_timeout, Duration::from_secs(30));
        for (v, secs) in [
            ("900s", 900),
            ("15m", 900),
            ("12h", 43200),
            ("30d", 2_592_000),
        ] {
            let b = Bootstrap::parse(&local(&[("30s", v)])).unwrap();
            assert_eq!(b.start_timeout, Duration::from_secs(secs), "{v}");
        }
        for v in [
            "30", "\"30 s\"", "30S", "15M", "PT30S", "P1D", "1.5s", "1h30m", "2w", "-1s", "0s",
        ] {
            let e = refusal(&local(&[("30s", v)]));
            assert!(e.starts_with("start_timeout:"), "{v}: {e}");
        }
    }

    #[test]
    fn an_unknown_key_is_refused_by_place_and_the_error_shows_no_value() {
        let e = refusal(&local(&[(
            "start_timeout: 30s",
            "start_timeout: 30s\nsecret-name: x",
        )]));
        assert_eq!(e, "<key>: unknown key");
        assert!(!e.contains("secret"));
        let e = refusal(&local(&[(
            "driver: rqlite, socket: /run/sluis/store/dev/durable.sock",
            "driver: rqlite, socket: /a.sock, extra: 1",
        )]));
        assert_eq!(e, "durable.<key>: unknown key");
    }

    #[test]
    fn required_keys_names_drivers_and_sockets_are_checked() {
        assert_eq!(
            refusal(&local(&[("boundary: dev\n", "")])),
            "boundary: required"
        );
        assert!(refusal(&local(&[("boundary: dev", "boundary: Dev")])).starts_with("boundary:"));
        assert!(refusal(&local(&[("boundary: dev", "boundary: 1dev")])).starts_with("boundary:"));
        let long = "a".repeat(33);
        assert!(
            refusal(&local(&[("boundary: dev", &format!("boundary: {long}"))]))
                .starts_with("boundary:")
        );
        assert_eq!(
            refusal(&local(&[("driver: file", "driver: appconfig")])),
            "config_source.driver: not a driver of this port in schema v1"
        );
        assert_eq!(
            refusal(&local(&[(
                "socket: /run/sluis/store/dev/temp.sock",
                "socket: temp.sock"
            )])),
            "temp.socket: must be an absolute path"
        );
        assert_eq!(
            refusal(&local(&[(
                "/run/sluis/store/dev/temp.sock",
                "/run/sluis/store/dev/durable.sock"
            )])),
            "temp: shares a socket path with another destination"
        );
        assert!(
            refusal(&local(&[(
                "$schema: https://sluis.id/schema/bootstrap/v1/bootstrap.schema.json",
                "$schema: https://example.com/other.json"
            )]))
            .starts_with("$schema:")
        );
    }

    #[test]
    fn a_publisher_pin_must_match_its_key() {
        let pin = "db0b54d40d09fffd2c296f8cadfa8454b7d4f2615a893a9b2f877621132c09e00fd8f33f199abc12b2bc1248246ece58";
        let wrong = pin.replacen("db0b", "db0c", 1);
        assert_eq!(
            refusal(&local(&[(pin, &wrong)])),
            "publishers[0].spki_sha384: does not match the key"
        );
        assert!(refusal(&local(&[(pin, "abc")])).starts_with("publishers[0].spki_sha384:"));
    }

    #[test]
    fn a_publisher_key_must_be_p384_and_a_kid_unique_and_co_signs_a_config_kind() {
        let e = refusal(&local(&[(
            "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE",
            "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAF",
        )]));
        assert_eq!(e, "publishers[0].public_key: not a point on P-384");
        let e = refusal(&local(&[(
            "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE",
            "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE",
        )]));
        assert_eq!(
            e,
            "publishers[0].public_key: not an EC P-384 SubjectPublicKeyInfo"
        );
        // Built at run time: a PEM private-key header is never written in a tracked file.
        let private = format!("-----BEGIN {} KEY-----", "PRIVATE");
        let e = refusal(&local(&[("-----BEGIN PUBLIC KEY-----", &private)]));
        assert_eq!(
            e,
            "publishers[0].public_key: must be one PEM PUBLIC KEY block"
        );

        let one = LOCAL.split("publishers:\n").nth(1).unwrap().to_owned();
        let two = format!("{LOCAL}{one}");
        assert_eq!(refusal(&two), "publishers[1].kid: not unique");

        let kinds = local(&[(
            "    spki_sha384:",
            "    co_signs: [Policy]\n    spki_sha384:",
        )]);
        assert_eq!(
            Bootstrap::parse(&kinds).unwrap().publishers[0].co_signs,
            ["Policy"]
        );
        let bad = local(&[(
            "    spki_sha384:",
            "    co_signs: [Person]\n    spki_sha384:",
        )]);
        assert_eq!(
            refusal(&bad),
            "publishers[0].co_signs[0]: not a config kind of the registry"
        );
    }

    #[test]
    fn a_file_that_another_uid_can_write_is_refused() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dev.yaml");
        std::fs::write(&path, LOCAL).unwrap();
        let me = rustix::process::geteuid().as_raw();
        let set =
            |mode| std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();

        set(0o640);
        assert!(Bootstrap::load(&path, me).is_ok());
        for mode in [0o660, 0o606, 0o666, 0o622] {
            set(mode);
            let e = Bootstrap::load(&path, me).unwrap_err().0;
            assert_eq!(
                e, "bootstrap: mode allows a write by group or others",
                "{mode:o}"
            );
        }
        set(0o640);
        // Owned by a uid that is neither root nor store@'s own.
        if me == 0 {
            eprintln!("SKIP: the owner check needs a test uid other than root");
        } else {
            let e = Bootstrap::load(&path, me.wrapping_add(1)).unwrap_err().0;
            assert_eq!(e, "bootstrap: owner must be root or the uid of store@");
        }
        let e = Bootstrap::load(&dir.path().join("missing.yaml"), me)
            .unwrap_err()
            .0;
        assert!(e.starts_with("bootstrap: cannot open"), "{e}");
    }
}
