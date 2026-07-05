//! Error types for parsing and cryptographically verifying identity artifacts.
//!
//! These describe *hard* failures (malformed input, bad signatures, unknown
//! keys). Soft policy outcomes — expiry, audience mismatch, missing scopes —
//! are represented as booleans on [`crate::VerificationChecks`], not errors, so
//! a verifier can report every failed check at once rather than short-circuit.

use thiserror::Error;

/// The length of a raw Ed25519 public key, in bytes.
pub const PUBLIC_KEY_LEN: usize = 32;
/// The length of a raw Ed25519 signature, in bytes.
pub const SIGNATURE_LEN: usize = 64;

/// A hard failure encountered while decoding or verifying an artifact.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum VerifyError {
    /// The compact JWS was not three `base64url` segments separated by dots.
    #[error("malformed JWT: {0}")]
    MalformedJwt(String),

    /// The JOSE header advertised an algorithm other than `EdDSA`.
    #[error("unsupported JWS algorithm: expected EdDSA, got {0}")]
    UnsupportedAlgorithm(String),

    /// The token's `kid` did not match any key in the trusted JWKS.
    #[error("unknown key id: {0}")]
    UnknownKeyId(String),

    /// A JWK could not be decoded into an Ed25519 verifying key.
    #[error("invalid verifying key: {0}")]
    InvalidKey(String),

    /// The Ed25519 signature failed to verify against the payload.
    #[error("signature verification failed")]
    SignatureInvalid,

    /// A `base64url` segment could not be decoded.
    #[error("base64 decode error: {0}")]
    Base64(String),

    /// A JSON body (header or claims) could not be parsed.
    #[error("json decode error: {0}")]
    Json(String),

    /// A `did:key` identifier was structurally invalid.
    #[error("malformed did:key: {0}")]
    MalformedDid(String),

    /// A DID encoded a key type other than Ed25519.
    #[error("unsupported DID key type (only Ed25519 is supported)")]
    UnsupportedKeyType,

    /// A decoded key had an unexpected length.
    #[error("invalid key length: expected {expected}, got {got}")]
    InvalidKeyLength {
        /// Expected byte length.
        expected: usize,
        /// Actual byte length.
        got: usize,
    },

    /// A decoded signature had an unexpected length.
    #[error("invalid signature length: {0} (expected 64)")]
    InvalidSignatureLength(usize),

    /// A verifiable credential carried no proof to check.
    #[error("credential has no proof")]
    MissingProof,

    /// A credential's proof `verificationMethod` did not equal its issuer.
    #[error("proof verification method does not match issuer")]
    IssuerMismatch,
}
