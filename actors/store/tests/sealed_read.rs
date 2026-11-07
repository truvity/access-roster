#![allow(clippy::unwrap_used, clippy::expect_used)] // a failed unwrap in a test is the failure
//! What store@ hands to a reader of a sealed kind: the sealed bytes, to the actors whose rule allows the read and to
//! no one else. It holds no key, so the bytes stay ciphertext until key@ opens them under a grant (REQ-ISO-084).

mod common;

use common::*;
use connectrpc::error::ErrorCode;

/// A sealed value as store@ keeps it: the envelope header of the `data` purpose and bytes that only key@ can read.
fn envelope() -> Vec<u8> {
    let mut v = sealed();
    v[2..].iter_mut().enumerate().for_each(|(i, b)| {
        *b = u8::try_from((i * 7 + 3) % 251).unwrap();
    });
    v
}

/// verifies: REQ-ISO-084
/// The store's rule is one of the two checks that a sealed value passes before it is plain: an actor whose rule gives it
/// `get` on the sealed kind `Person` reads the item and gets exactly the envelope that was written (store@ has no key,
/// so there is no other form for it to give), with no grant; an actor without that rule is refused by the rule, the
/// engine is not asked, and the envelope does not come back in the refusal. The other check, key@'s grant, is
/// `TestASealedValueNeedsTheStoreRuleAndTheKeyGrant` in actors/key: a reader that has the bytes and no grant for the
/// tenant is refused there.
#[tokio::test]
async fn a_sealed_value_is_given_only_to_an_actor_with_the_rule_and_only_as_the_envelope() {
    let f = F::new().await;
    let env = envelope();
    f.as_("session");
    let grant = f.grant("session", &["acme"], &["create"], 60);
    f.write(
        vec![op(
            sluis_proto::sluis::store::v2alpha1::Verb::CREATE,
            "person",
            "acme",
            "p1",
            &env,
        )],
        &grant,
    )
    .await
    .unwrap();

    let callers = sluis_registry::callers_of("store");
    assert!(callers.len() > 8, "the callers of store@: {callers:?}");
    let (mut read, mut refused) = (0usize, 0usize);
    for &caller in callers {
        f.as_(caller);
        let got = f.get("person", "acme", "p1").await;
        if sluis_registry::store_allows(caller, "person", "get") {
            let item = got.unwrap_or_else(|e| panic!("{caller} has the rule and was refused: {e:?}")).item;
            assert_eq!(item.value, env, "{caller} was given something but the envelope");
            read += 1;
        } else {
            let e = got.expect_err(&format!("{caller} has no rule on person and read it"));
            assert_eq!(e.code, ErrorCode::PermissionDenied, "{caller}");
            assert_eq!(reason(&e), "rule", "{caller}");
            assert!(
                !format!("{e:?}").contains(&format!("{:?}", &env[8..24])),
                "{caller}: the refusal repeats the value"
            );
            refused += 1;
        }
    }
    // Every actor of the registry is either a reader or refused: the sweep saw both sides.
    assert!(read >= 3 && refused >= 5, "{read} readers, {refused} refused");
    assert_eq!(read + refused, callers.len());
}
