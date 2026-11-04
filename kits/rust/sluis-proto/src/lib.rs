//! Generated Rust contracts of `proto/`: buffa messages and connectrpc services, one module per
//! package (`sluis::store::v2alpha1`, `sluis::r#type::v2alpha1`, ...). Nothing here is written
//! by hand; `build.rs` generates it into `OUT_DIR`.
#![allow(clippy::all, missing_docs, unreachable_pub, unused_qualifications)]
connectrpc::include_generated!();

#[cfg(test)]
mod tests {
    use buffa::Message;

    use crate::sluis::r#type::v2alpha1::{Address, Refusal};

    #[test]
    fn the_modules_follow_the_proto_packages_and_messages_round_trip() {
        let a = Address {
            kind: "lease".into(),
            tenant: String::new(),
            id: "a/b".into(),
            ..Address::default()
        };
        let back = Address::decode_from_slice(&a.encode_to_vec()).expect("decode");
        assert_eq!(a, back);
        let r = Refusal {
            reason: "bound".into(),
            field_path: "a.b".into(),
            ..Refusal::default()
        };
        assert_eq!(
            Refusal::decode_from_slice(&r.encode_to_vec()).expect("decode"),
            r
        );
    }

    #[test]
    fn every_service_of_the_skeleton_is_generated() {
        // One name per contract package that has a service: a missing one does not compile.
        let _ = crate::sluis::store::v2alpha1::STORE_SERVICE_SERVICE_NAME;
        let _ = crate::sluis::key::v2alpha1::KEY_SERVICE_SERVICE_NAME;
        let _ = crate::sluis::policy::v2alpha1::POLICY_SERVICE_SERVICE_NAME;
        let _ = crate::sluis::signer::v2alpha1::SIGNER_SERVICE_SERVICE_NAME;
    }
}
