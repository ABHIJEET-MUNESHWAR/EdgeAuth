//! W3C-style Verifiable Credentials with detached Ed25519 proofs.
//!
//! A [`VerifiableCredential`] binds claims about a subject DID to an issuer DID
//! and carries a cryptographic [`Proof`] the verifier checks against the key
//! recovered directly from the issuer `did:key`. The canonical signing payload
//! is byte-compatible with the sibling TrustFabric issuer: the credential id is
//! a transparent string, `type` is renamed, and claims use a sorted `BTreeMap`.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::did::{sign_payload, verify_payload, Did};
use crate::error::{VerifyError, SIGNATURE_LEN};

/// The proof suite identifier EdgeAuth understands.
pub const PROOF_TYPE: &str = "Ed25519Signature2020";

/// The subject of a credential: who the claims are about.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialSubject {
    /// The subject's decentralized identifier.
    pub id: Did,
    /// Claims as a canonical (sorted) key/value map.
    pub claims: BTreeMap<String, String>,
}

/// A detached Ed25519 proof over the credential's canonical bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proof {
    /// Proof suite identifier.
    #[serde(rename = "type")]
    pub proof_type: String,
    /// The DID whose key produced the signature (must equal the issuer).
    pub verification_method: Did,
    /// Unix seconds at which the proof was created.
    pub created: i64,
    /// The 64-byte Ed25519 signature, hex-encoded.
    pub signature_hex: String,
}

impl Proof {
    /// Decodes the signature into raw bytes.
    ///
    /// # Errors
    /// Returns an error if the hex is malformed or not 64 bytes.
    pub fn signature_bytes(&self) -> Result<[u8; SIGNATURE_LEN], VerifyError> {
        let raw = hex::decode(&self.signature_hex)
            .map_err(|e| VerifyError::MalformedDid(e.to_string()))?;
        raw.try_into()
            .map_err(|v: Vec<u8>| VerifyError::InvalidSignatureLength(v.len()))
    }
}

/// A verifiable credential: signed claims about a subject issued by an issuer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiableCredential {
    /// Unique credential identifier (an opaque, transparent string).
    pub id: String,
    /// Credential type (e.g. `"ProofOfPersonhood"`, `"KycVerified"`).
    #[serde(rename = "type")]
    pub credential_type: String,
    /// The issuing authority's DID.
    pub issuer: Did,
    /// The subject and claims.
    pub subject: CredentialSubject,
    /// Unix seconds at which the credential becomes valid.
    pub issued_at: i64,
    /// Optional unix-seconds expiry; `None` means it never expires.
    pub expires_at: Option<i64>,
    /// The cryptographic proof; `None` until signed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<Proof>,
}

/// A borrowed, proof-free view used to produce deterministic signing bytes.
///
/// Field names and order are byte-identical to the issuer's canonical form.
#[derive(Serialize)]
struct UnsignedView<'a> {
    id: &'a str,
    #[serde(rename = "type")]
    credential_type: &'a str,
    issuer: &'a Did,
    subject: &'a CredentialSubject,
    issued_at: i64,
    expires_at: Option<i64>,
}

impl VerifiableCredential {
    /// Produces the canonical byte payload that the proof signs. The proof
    /// itself is excluded, and `BTreeMap` claims guarantee a stable key order.
    ///
    /// # Errors
    /// Returns an error if serialization fails.
    pub fn signing_payload(&self) -> Result<Vec<u8>, VerifyError> {
        let view = UnsignedView {
            id: &self.id,
            credential_type: &self.credential_type,
            issuer: &self.issuer,
            subject: &self.subject,
            issued_at: self.issued_at,
            expires_at: self.expires_at,
        };
        serde_json::to_vec(&view).map_err(|e| VerifyError::Json(e.to_string()))
    }

    /// Attaches an Ed25519 proof signed by `signing_key`. Primarily a test and
    /// tooling helper — edge deployments only ever verify.
    ///
    /// # Errors
    /// Returns an error if the canonical payload cannot be produced.
    pub fn sign_with(
        &mut self,
        signing_key: &ed25519_dalek::SigningKey,
        created: i64,
    ) -> Result<(), VerifyError> {
        let payload = self.signing_payload()?;
        let signature = sign_payload(signing_key, &payload);
        self.proof = Some(Proof {
            proof_type: PROOF_TYPE.to_string(),
            verification_method: self.issuer.clone(),
            created,
            signature_hex: hex::encode(signature),
        });
        Ok(())
    }

    /// Verifies the credential's proof against the issuer's `did:key`.
    ///
    /// Checks that a proof is present, its verification method equals the
    /// issuer, and the Ed25519 signature validates over the canonical payload.
    ///
    /// # Errors
    /// Returns the specific [`VerifyError`] describing the failure.
    pub fn verify_signature(&self) -> Result<(), VerifyError> {
        let proof = self.proof.as_ref().ok_or(VerifyError::MissingProof)?;
        if proof.verification_method != self.issuer {
            return Err(VerifyError::IssuerMismatch);
        }
        let key = self.issuer.verifying_key()?;
        let signature = proof.signature_bytes()?;
        let payload = self.signing_payload()?;
        verify_payload(&key, &payload, &signature)
    }

    /// Reports whether the credential is temporally valid at `now`, within a
    /// clock-skew `leeway` (seconds). Returns `(not_before_ok, not_expired_ok)`.
    #[must_use]
    pub fn validity_at(&self, now: i64, leeway: i64) -> (bool, bool) {
        let not_before_ok = now + leeway >= self.issued_at;
        let not_expired_ok = self.expires_at.is_none_or(|exp| now - leeway < exp);
        (not_before_ok, not_expired_ok)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn issuer_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn sample(issuer: &Did, subject: &Did) -> VerifiableCredential {
        let mut claims = BTreeMap::new();
        claims.insert("kyc".to_string(), "verified".to_string());
        VerifiableCredential {
            id: "cred-001".to_string(),
            credential_type: "KycVerified".to_string(),
            issuer: issuer.clone(),
            subject: CredentialSubject {
                id: subject.clone(),
                claims,
            },
            issued_at: 1_000,
            expires_at: Some(2_000),
            proof: None,
        }
    }

    #[test]
    fn sign_then_verify_succeeds() {
        let issuer_sk = issuer_key(1);
        let issuer = Did::from_verifying_key(&issuer_sk.verifying_key());
        let subject = Did::from_verifying_key(&issuer_key(2).verifying_key());
        let mut vc = sample(&issuer, &subject);
        vc.sign_with(&issuer_sk, 1_000).unwrap();
        assert!(vc.verify_signature().is_ok());
    }

    #[test]
    fn tampered_claims_break_verification() {
        let issuer_sk = issuer_key(1);
        let issuer = Did::from_verifying_key(&issuer_sk.verifying_key());
        let subject = Did::from_verifying_key(&issuer_key(2).verifying_key());
        let mut vc = sample(&issuer, &subject);
        vc.sign_with(&issuer_sk, 1_000).unwrap();
        vc.subject
            .claims
            .insert("kyc".to_string(), "forged".to_string());
        assert!(matches!(
            vc.verify_signature(),
            Err(VerifyError::SignatureInvalid)
        ));
    }

    #[test]
    fn issuer_mismatch_is_rejected() {
        let issuer_sk = issuer_key(1);
        let issuer = Did::from_verifying_key(&issuer_sk.verifying_key());
        let subject = Did::from_verifying_key(&issuer_key(2).verifying_key());
        let mut vc = sample(&issuer, &subject);
        vc.sign_with(&issuer_sk, 1_000).unwrap();
        // Point the proof at a different issuer than the credential claims.
        vc.issuer = Did::from_verifying_key(&issuer_key(9).verifying_key());
        assert!(matches!(
            vc.verify_signature(),
            Err(VerifyError::IssuerMismatch)
        ));
    }

    #[test]
    fn validity_window_respects_leeway() {
        let issuer = Did::from_verifying_key(&issuer_key(1).verifying_key());
        let subject = Did::from_verifying_key(&issuer_key(2).verifying_key());
        let vc = sample(&issuer, &subject);
        // Before the window, but within leeway.
        assert_eq!(vc.validity_at(995, 10), (true, true));
        // Well before the window.
        assert_eq!(vc.validity_at(900, 10), (false, true));
        // After expiry.
        assert_eq!(vc.validity_at(2_100, 10), (true, false));
    }
}
