//! The result of verifying an identity artifact.
//!
//! [`VerificationOutcome`] is deliberately *non-throwing*: every individual
//! check is recorded as a boolean on [`VerificationChecks`], so a caller sees
//! the full picture (e.g. "signature valid but expired and wrong audience")
//! rather than only the first failure. `valid` is the AND of every check.

use serde::{Deserialize, Serialize};

/// The kind of artifact that was verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenKind {
    /// A compact EdDSA JSON Web Token.
    Jwt,
    /// A `did:key` Verifiable Credential.
    VerifiableCredential,
}

impl TokenKind {
    /// A short, stable label for metrics and logs.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Jwt => "jwt",
            Self::VerifiableCredential => "vc",
        }
    }
}

/// Every individual check performed during verification.
///
/// Checks that do not apply to a given artifact or are disabled by policy are
/// reported as `true` (vacuously satisfied), so `valid` is a simple AND.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationChecks {
    /// The cryptographic signature verified against a trusted key.
    pub signature: bool,
    /// The artifact has not expired (`exp` / credential expiry).
    pub not_expired: bool,
    /// The artifact is already valid (`nbf` / credential `issued_at`).
    pub not_before: bool,
    /// The issuer is on the trusted list.
    pub issuer_trusted: bool,
    /// The audience matches the expected value (`aud`).
    pub audience: bool,
    /// All required scopes are present.
    pub scopes: bool,
    /// The token id is not on the revocation denylist.
    pub not_revoked: bool,
}

impl VerificationChecks {
    /// All checks satisfied.
    #[must_use]
    pub const fn all_passing() -> Self {
        Self {
            signature: true,
            not_expired: true,
            not_before: true,
            issuer_trusted: true,
            audience: true,
            scopes: true,
            not_revoked: true,
        }
    }

    /// A hard parse/crypto failure: nothing could be checked.
    #[must_use]
    pub const fn hard_failure() -> Self {
        Self {
            signature: false,
            not_expired: false,
            not_before: false,
            issuer_trusted: false,
            audience: false,
            scopes: false,
            not_revoked: false,
        }
    }

    /// `true` only when every check passed.
    #[must_use]
    pub const fn all(&self) -> bool {
        self.signature
            && self.not_expired
            && self.not_before
            && self.issuer_trusted
            && self.audience
            && self.scopes
            && self.not_revoked
    }
}

/// The full result of verifying a JWT or credential.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationOutcome {
    /// Whether the artifact is accepted (all checks passed).
    pub valid: bool,
    /// Which kind of artifact was inspected.
    pub kind: TokenKind,
    /// The authenticated subject, when available.
    pub subject: Option<String>,
    /// The issuer, when available.
    pub issuer: Option<String>,
    /// Scopes carried by the artifact.
    pub scopes: Vec<String>,
    /// Roles carried by the artifact.
    pub roles: Vec<String>,
    /// The per-check breakdown.
    pub checks: VerificationChecks,
    /// A human-readable reason for the first failure, if any.
    pub reason: Option<String>,
}

impl VerificationOutcome {
    /// Builds a hard-failure outcome (parse or signature error).
    #[must_use]
    pub fn rejected(kind: TokenKind, reason: impl Into<String>) -> Self {
        Self {
            valid: false,
            kind,
            subject: None,
            issuer: None,
            scopes: Vec::new(),
            roles: Vec::new(),
            checks: VerificationChecks::hard_failure(),
            reason: Some(reason.into()),
        }
    }
}
