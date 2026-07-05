//! # `edgeauth-types`
//!
//! Pure, `wasm`-safe domain types for the EdgeAuth edge identity verifier.
//!
//! This crate contains **no** async runtime, **no** I/O and **no** randomness,
//! so it compiles unchanged to `wasm32-unknown-unknown` for serverless / edge
//! deployment. It models the two artifacts EdgeAuth verifies:
//!
//! * **EdDSA JSON Web Tokens** ([`jwt`]) against a [`Jwks`], and
//! * **`did:key` Verifiable Credentials** ([`credential`]),
//!
//! plus the [`TrustPolicy`] that constrains acceptance and the
//! [`VerificationOutcome`] that reports, check-by-check, why an artifact was
//! accepted or rejected.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod credential;
pub mod did;
pub mod error;
pub mod jwt;
pub mod outcome;
pub mod policy;

pub use credential::{CredentialSubject, Proof, VerifiableCredential, PROOF_TYPE};
pub use did::{sign_payload, verify_payload, Did};
pub use error::{VerifyError, PUBLIC_KEY_LEN, SIGNATURE_LEN};
pub use jwt::{
    b64url_decode, b64url_encode, encode_jwt, Audience, Jwk, Jwks, JwtClaims, JwtHeader, SignedJwt,
    JWK_CRV, JWK_KTY, JWK_USE_SIG, JWT_ALG,
};
pub use outcome::{TokenKind, VerificationChecks, VerificationOutcome};
pub use policy::TrustPolicy;
