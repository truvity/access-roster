//! key@, as `signer` uses it: the public key of the `token-signing` purpose, and a signature over a
//! JWS signing input. `signer` reaches key@ on its own socket,
//! `/run/sluis/key/<boundary>/signer/key.sock`, that only `signer` may open (ADR 0006 "Exclusive
//! card access"; PLAN.md "Socket layout").

use std::path::Path;
use std::time::Duration;

use connectrpc::ConnectError;
use sluis_kit::{Client, Transport, dial};
use sluis_proto::sluis::key::v2alpha1::{KeyServiceClient, PublicKeyRequest, SignRequest};

use crate::jwks::{p384_point, thumbprint, verifies};

/// The key purpose of tokens (keys.yaml).
pub const PURPOSE: &str = "token-signing";
/// The algorithm of that purpose (ADR 0020: ES384 is the default and the only one tonight).
pub const ALGORITHM: &str = "ES384";
/// How long one call to key@ may take.
const CALL: Duration = Duration::from_secs(10);

/// The public key key@ signs tokens with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Current {
    /// The RFC 7638 thumbprint: the `kid` of the key.
    pub key_id: String,
    /// The public key, SubjectPublicKeyInfo in DER.
    pub spki_der: Vec<u8>,
    /// The certificate chain, DER, when key@ has one (none while the key is a software key, D-8).
    pub x5c: Vec<Vec<u8>>,
}

/// Why key@ gave no answer `signer` can use.
#[derive(Debug)]
pub enum KeyError {
    /// key@ is down, refused, or timed out. The code and the reason of its refusal are logged.
    Unavailable,
    /// key@ answered something that is not what the contract promises: a key that is not a P-384
    /// key, a `kid` that is not the thumbprint of the key, or a signature that does not verify.
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

    /// The key key@ signs tokens with now. It is checked before it is used: a P-384 key, ES384, and
    /// a `kid` that is the thumbprint of the key, so that a verifier that recomputes it agrees.
    ///
    /// # Errors
    ///
    /// [`KeyError`].
    pub async fn current(&self) -> Result<Current, KeyError> {
        let req = PublicKeyRequest {
            purpose: PURPOSE.into(),
            ..PublicKeyRequest::default()
        };
        let resp = tokio::time::timeout(CALL, self.client.public_key(req))
            .await
            .map_err(|_| KeyError::Unavailable)?
            .map_err(|e| unavailable("public_key", &e))?
            .into_owned();
        let ok = resp.algorithm == ALGORITHM
            && p384_point(&resp.spki_der).is_some()
            && thumbprint(&resp.spki_der).as_deref() == Some(resp.key_id.as_str());
        if !ok {
            tracing::error!("key@ answered a public key that is not an ES384 key of its own kid");
            return Err(KeyError::Inconsistent);
        }
        Ok(Current {
            key_id: resp.key_id,
            spki_der: resp.spki_der,
            x5c: resp.x5c,
        })
    }

    /// The ES384 signature (raw r||s, RFC 7518 section 3.4) of a JWS signing input under the key
    /// `key`. key@ checks the input before it signs and audits the signature durably first; the
    /// signature is checked here against the public key before it is returned.
    ///
    /// # Errors
    ///
    /// [`KeyError`].
    pub async fn sign(&self, input: &[u8], key: &Current) -> Result<Vec<u8>, KeyError> {
        let req = SignRequest {
            purpose: PURPOSE.into(),
            content: input.to_vec(),
            algorithm: ALGORITHM.into(),
            ..SignRequest::default()
        };
        let resp = tokio::time::timeout(CALL, self.client.sign(req))
            .await
            .map_err(|_| KeyError::Unavailable)?
            .map_err(|e| unavailable("sign", &e))?
            .into_owned();
        if resp.key_id != key.key_id || !verifies(&key.spki_der, input, &resp.signature_raw) {
            tracing::error!("key@ returned a signature that does not verify under its own key");
            return Err(KeyError::Inconsistent);
        }
        Ok(resp.signature_raw)
    }
}
