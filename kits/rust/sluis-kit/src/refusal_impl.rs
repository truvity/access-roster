//! Connect errors with the `sluis.type.v2alpha1.Refusal` detail (contracts.md "Errors").

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use buffa::Message as _;
use connectrpc::ConnectError;
use connectrpc::error::{ErrorCode, ErrorDetail};
use sluis_proto::sluis::r#type::v2alpha1::Refusal;

/// The fully-qualified name of the detail message.
const DETAIL: &str = "sluis.type.v2alpha1.Refusal";

/// A Connect error with the `Refusal` detail. The message is the reason; an error never shows a
/// value, only the path of the field at fault.
#[must_use]
pub fn refusal(code: ErrorCode, reason: &str, field_path: &str) -> ConnectError {
    let detail = Refusal {
        reason: reason.to_owned(),
        field_path: field_path.to_owned(),
        ..Refusal::default()
    };
    ConnectError::new(code, reason).with_detail(ErrorDetail::from_message(DETAIL, &detail))
}

/// The reason of the `Refusal` detail of an error, if it has one.
#[must_use]
pub fn refusal_reason(err: &ConnectError) -> Option<String> {
    err.details.iter().find_map(|d| {
        // The Connect protocol writes the bare name; a gRPC peer writes the Any type URL.
        let name = d.type_url.rsplit('/').next()?;
        if name != DETAIL {
            return None;
        }
        let raw = d.value.as_deref()?;
        let bytes = STANDARD_NO_PAD
            .decode(raw)
            .or_else(|_| STANDARD.decode(raw))
            .ok()?;
        Refusal::decode_from_slice(&bytes).ok().map(|r| r.reason)
    })
}
