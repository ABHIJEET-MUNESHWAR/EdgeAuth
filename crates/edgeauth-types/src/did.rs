//! `did:key` identifiers backed by Ed25519 verification keys.
//!
//! A `did:key` embeds the public key in the identifier itself (multibase
//! base58btc, `z` prefix, over the multicodec-tagged Ed25519 key), so the DID
//! *is* the key and no network resolution is required — ideal for an edge
//! verifier. This mirrors the format issued by the sibling TrustFabric service.

use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::error::{VerifyError, PUBLIC_KEY_LEN, SIGNATURE_LEN};

/// Multicodec varint prefix identifying an Ed25519 public key.
const ED25519_MULTICODEC: [u8; 2] = [0xed, 0x01];
/// Multibase base58btc discriminator.
const BASE58BTC: char = 'z';
/// The `did:key` method prefix.
const DID_KEY_PREFIX: &str = "did:key:";

/// A self-certifying decentralized identifier of the form `did:key:z…`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Did(String);

impl Did {
    /// Derives the `did:key` identifier for an Ed25519 verifying key.
    #[must_use]
    pub fn from_verifying_key(key: &VerifyingKey) -> Self {
        let mut tagged = Vec::with_capacity(2 + PUBLIC_KEY_LEN);
        tagged.extend_from_slice(&ED25519_MULTICODEC);
        tagged.extend_from_slice(key.as_bytes());
        let mut s = String::from(DID_KEY_PREFIX);
        s.push(BASE58BTC);
        s.push_str(&bs58::encode(tagged).into_string());
        Self(s)
    }

    /// Wraps a pre-formed identifier string after validating its structure.
    ///
    /// # Errors
    /// Returns [`VerifyError::MalformedDid`] (or a key error) if the string is
    /// not a valid `did:key` Ed25519 identifier.
    pub fn parse(s: impl Into<String>) -> Result<Self, VerifyError> {
        let did = Self(s.into());
        did.verifying_key()?; // validates method, multibase, multicodec, length
        Ok(did)
    }

    /// Recovers the Ed25519 verifying key encoded in the identifier.
    ///
    /// # Errors
    /// Returns an error if the DID is malformed or does not encode an Ed25519 key.
    pub fn verifying_key(&self) -> Result<VerifyingKey, VerifyError> {
        let rest = self
            .0
            .strip_prefix(DID_KEY_PREFIX)
            .ok_or_else(|| VerifyError::MalformedDid(self.0.clone()))?;
        let mut chars = rest.chars();
        if chars.next() != Some(BASE58BTC) {
            return Err(VerifyError::MalformedDid(self.0.clone()));
        }
        let decoded = bs58::decode(chars.as_str())
            .into_vec()
            .map_err(|e| VerifyError::MalformedDid(e.to_string()))?;
        let key_bytes = decoded
            .strip_prefix(&ED25519_MULTICODEC[..])
            .ok_or(VerifyError::UnsupportedKeyType)?;
        let arr: [u8; PUBLIC_KEY_LEN] =
            key_bytes
                .try_into()
                .map_err(|_| VerifyError::InvalidKeyLength {
                    expected: PUBLIC_KEY_LEN,
                    got: key_bytes.len(),
                })?;
        VerifyingKey::from_bytes(&arr).map_err(|_| VerifyError::UnsupportedKeyType)
    }

    /// Borrows the identifier string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for Did {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Signs `payload` with an Ed25519 signing key, returning the raw signature.
#[must_use]
pub fn sign_payload(signing_key: &SigningKey, payload: &[u8]) -> [u8; SIGNATURE_LEN] {
    signing_key.sign(payload).to_bytes()
}

/// Verifies a raw Ed25519 signature over `payload` against `key`.
///
/// # Errors
/// Returns [`VerifyError::SignatureInvalid`] if verification fails.
pub fn verify_payload(
    key: &VerifyingKey,
    payload: &[u8],
    signature: &[u8; SIGNATURE_LEN],
) -> Result<(), VerifyError> {
    let sig = Signature::from_bytes(signature);
    key.verify(payload, &sig)
        .map_err(|_| VerifyError::SignatureInvalid)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signing_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    #[test]
    fn did_round_trips_through_string() {
        let sk = signing_key(7);
        let did = Did::from_verifying_key(&sk.verifying_key());
        assert!(did.as_str().starts_with("did:key:z"));
        let recovered = did.verifying_key().unwrap();
        assert_eq!(recovered.as_bytes(), sk.verifying_key().as_bytes());
    }

    #[test]
    fn parse_accepts_valid_and_rejects_garbage() {
        let sk = signing_key(11);
        let did = Did::from_verifying_key(&sk.verifying_key());
        assert!(Did::parse(did.as_str()).is_ok());
        assert!(Did::parse("did:web:example.com").is_err());
        assert!(Did::parse("did:key:xNOTBASE58").is_err());
        assert!(Did::parse("did:key:zbadbase58!!").is_err());
    }

    #[test]
    fn sign_and_verify_payload_round_trip() {
        let sk = signing_key(3);
        let vk = sk.verifying_key();
        let payload = b"verifiable-credential-bytes";
        let sig = sign_payload(&sk, payload);
        assert!(verify_payload(&vk, payload, &sig).is_ok());
        assert!(verify_payload(&vk, b"tampered", &sig).is_err());
    }
}
