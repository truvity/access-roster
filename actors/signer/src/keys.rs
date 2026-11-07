//! key@, as `signer` uses it: the public key of the `token-signing` purpose (ES384) or of the `token-signing-rs256`
//! purpose (RS256, an audience that needs it), and a signature over a JWS signing input. `signer` reaches key@ on its own socket,
//! `/run/sluis/key/<boundary>/signer/key.sock`, that only `signer` may open (ADR 0006 "Exclusive
//! card access"; PLAN.md "Socket layout").

use std::path::Path;
use std::time::Duration;

use connectrpc::ConnectError;
use sluis_kit::{Client, Transport, dial};
use sluis_proto::sluis::key::v2alpha1::{KeyServiceClient, PublicKeyRequest, SignRequest};

use crate::jwks::{p384_point, rsa2048_modulus, thumbprint, verifies, verifies_rs256};

/// The key purpose of tokens (keys.yaml).
pub const PURPOSE: &str = "token-signing";
/// The algorithm of that purpose (ADR 0020: ES384 is the default).
pub const ALGORITHM: &str = "ES384";
/// The key purpose of the ID tokens of an audience that needs RS256 (keys.yaml, ADR 0006 "Named exceptions").
pub const RS256_PURPOSE: &str = "token-signing-rs256";
/// The algorithm of that purpose.
pub const RS256: &str = "RS256";

/// The two algorithms `signer` signs with. Each has a purpose and a key of its own at key@, and its own life in the ring.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Alg {
    /// ES384, the default and the only one for an access token.
    Es384,
    /// RS256, for the ID tokens of an audience whose `signing_alg` says so.
    Rs256,
}

impl Alg {
    /// The JOSE name (`alg`) and the `algorithm` of a ring key.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Es384 => ALGORITHM,
            Self::Rs256 => RS256,
        }
    }

    /// The purpose key@ holds the key under.
    #[must_use]
    pub const fn purpose(self) -> &'static str {
        match self {
            Self::Es384 => PURPOSE,
            Self::Rs256 => RS256_PURPOSE,
        }
    }

    /// The algorithm of a ring key, or `None` for one this version does not sign with.
    #[must_use]
    pub fn of(name: &str) -> Option<Self> {
        match name {
            ALGORITHM => Some(Self::Es384),
            RS256 => Some(Self::Rs256),
            _ => None,
        }
    }
}
/// How long one call to key@ may take.
const CALL: Duration = Duration::from_secs(10);

/// The public key key@ signs tokens with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Current {
    /// The algorithm of the key, and so the purpose it is held under.
    pub alg: Alg,
    /// The RFC 7638 thumbprint: the `kid` of the key.
    pub key_id: String,
    /// The public key, SubjectPublicKeyInfo in DER.
    pub spki_der: Vec<u8>,
    /// The certificate chain, DER, when key@ has one (none while the key is a software key, D-8).
    pub x5c: Vec<Vec<u8>>,
    /// key@ holds a certificate for the key and does not give it now: the ring drops the chain it has.
    pub x5c_withdrawn: bool,
}

/// Why key@ gave no answer `signer` can use.
#[derive(Debug)]
pub enum KeyError {
    /// key@ is down, refused, or timed out. The code and the reason of its refusal are logged.
    Unavailable,
    /// key@ refused the public key of the purpose as one its KeyPlan does not list (`purpose`): its plan is older than the
    /// signer's, or it has not been restarted onto it. key@ audits that refusal, so `signer` asks again only after a long while
    /// (REQ-AUDIT-180).
    NotPlanned,
    /// key@ answered something that is not what the contract promises: a key that is not a P-384
    /// key (an RSA-2048 key for RS256), a `kid` that is not the thumbprint of the key, or a signature that does not verify.
    Inconsistent,
}

fn unavailable(what: &str, e: &ConnectError) -> KeyError {
    // The code and the reason only: an error text may carry a path of key@'s, never a value.
    tracing::warn!(
        call = what,
        code = e.code.as_str(),
        reason = sluis_kit::refusal_reason(e).as_deref().unwrap_or("-"),
        "key@ did not answer"
    );
    KeyError::Unavailable
}

/// The client of key@.
pub struct KeyAt {
    client: KeyServiceClient<Transport>,
}

impl KeyAt {
    /// A client for the socket; nothing is dialled until the first call.
    #[must_use]
    pub fn new(socket: &Path) -> Self {
        let c: Client = dial(socket);
        Self {
            client: KeyServiceClient::new(c.transport(), c.config()),
        }
    }

    /// The key key@ signs tokens of an algorithm with now. It is checked before it is used: a P-384 key for ES384, an RSA-2048
    /// key with the exponent 65537 for RS256, the algorithm key@ names, and a `kid` that is the thumbprint of the key, so
    /// that a verifier that recomputes it agrees.
    ///
    /// # Errors
    ///
    /// [`KeyError`].
    pub async fn current(&self, alg: Alg) -> Result<Current, KeyError> {
        let req = PublicKeyRequest {
            purpose: alg.purpose().into(),
            ..PublicKeyRequest::default()
        };
        let resp = tokio::time::timeout(CALL, self.client.public_key(req))
            .await
            .map_err(|_| KeyError::Unavailable)?
            .map_err(|e| {
                if sluis_kit::refusal_reason(&e).as_deref() == Some("purpose") {
                    tracing::warn!(
                        alg = alg.name(),
                        "key@ does not list the purpose: asked again after a while"
                    );
                    return KeyError::NotPlanned;
                }
                unavailable("public_key", &e)
            })?
            .into_owned();
        let shaped = match alg {
            Alg::Es384 => p384_point(&resp.spki_der).is_some(),
            Alg::Rs256 => rsa2048_modulus(&resp.spki_der).is_some(),
        };
        let ok = resp.algorithm == alg.name()
            && shaped
            && thumbprint(&resp.spki_der).as_deref() == Some(resp.key_id.as_str());
        if !ok {
            tracing::error!(
                alg = alg.name(),
                "key@ answered a public key that is not a key of that algorithm with its own kid"
            );
            return Err(KeyError::Inconsistent);
        }
        Ok(Current {
            alg,
            key_id: resp.key_id,
            spki_der: resp.spki_der,
            // An RSA key has no chain: `ca` certifies the ES384 token key alone.
            x5c: if alg == Alg::Es384 { resp.x5c } else { vec![] },
            x5c_withdrawn: resp.x5c_withdrawn,
        })
    }

    /// The signature (ES384 raw r||s, RFC 7518 section 3.4; RS256 the 256 octets of section 3.3) of a JWS signing input
    /// under the key `key`. key@ checks the input before it signs and audits the signature durably first; the signature
    /// is checked here against the public key before it is returned.
    ///
    /// # Errors
    ///
    /// [`KeyError`].
    pub async fn sign(&self, input: &[u8], key: &Current) -> Result<Vec<u8>, KeyError> {
        let req = SignRequest {
            purpose: key.alg.purpose().into(),
            content: input.to_vec(),
            algorithm: key.alg.name().into(),
            ..SignRequest::default()
        };
        let resp = tokio::time::timeout(CALL, self.client.sign(req))
            .await
            .map_err(|_| KeyError::Unavailable)?
            .map_err(|e| unavailable("sign", &e))?
            .into_owned();
        let good = match key.alg {
            Alg::Es384 => verifies(&key.spki_der, input, &resp.signature_raw),
            Alg::Rs256 => verifies_rs256(&key.spki_der, input, &resp.signature_raw),
        };
        if resp.key_id != key.key_id || !good {
            tracing::error!("key@ returned a signature that does not verify under its own key");
            return Err(KeyError::Inconsistent);
        }
        Ok(resp.signature_raw)
    }
}
