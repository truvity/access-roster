#![allow(clippy::unwrap_used, clippy::expect_used)] // a failed unwrap in a test is the failure
//! The lock mode of an `AuditLog` is declared and is one of the three of ADR 0029 "Lock modes".

mod config_support;

use buffa::Message as _;
use config_support::LOCAL;
use sluis_proto::sluis::config::v2alpha1 as pb;
use store::config::payload;

fn audit_log() -> &'static str {
    LOCAL.iter().find(|(s, _)| *s == "audit-log").unwrap().1
}

fn decode(text: &str) -> Result<pb::AuditLog, String> {
    let k = sluis_registry::kind_by_name("AuditLog").unwrap();
    let items = payload::decode(k, text.as_bytes()).map_err(|e| e.0)?;
    Ok(pb::AuditLog::decode_from_slice(&items[0].1).unwrap())
}

/// The log store is a blob store with an explicit lock mode: each of the three is taken as written, and a document
/// with none, an empty one, another word or another case is no `AuditLog`.
///
/// verifies: REQ-AUDIT-008
#[test]
fn an_audit_log_declares_its_lock_mode_as_none_removable_or_compliance() {
    let doc = audit_log();
    assert!(
        doc.contains("lock_mode: none"),
        "the fixture changed: {doc}"
    );
    for mode in ["none", "removable", "compliance"] {
        let got = decode(&doc.replace("lock_mode: none", &format!("lock_mode: {mode}"))).unwrap();
        assert_eq!(got.lock_mode, mode);
    }
    for bad in [
        "lock_mode: \"\"",
        "lock_mode: governance",
        "lock_mode: Compliance",
        "lock_mode: true",
    ] {
        let e = decode(&doc.replace("lock_mode: none", bad)).unwrap_err();
        assert!(e.contains("lock_mode"), "{bad}: {e}");
    }
    let e = decode(&doc.replace("  lock_mode: none\n", "")).unwrap_err();
    assert!(e.contains("lock_mode"), "no lock mode: {e}");
}
