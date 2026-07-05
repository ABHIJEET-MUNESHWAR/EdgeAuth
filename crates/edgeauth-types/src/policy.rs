//! The trust policy that constrains which identities an edge node accepts.
//!
//! A policy is pure configuration: a set of trusted issuers, an expected
//! audience, required scopes, a revocation denylist and a clock-skew leeway.
//! It carries no secrets and is safe to ship to every edge location.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

/// Constraints applied to a cryptographically valid artifact before it is
/// accepted. An empty `trusted_issuers` set means "any issuer" (signature and
/// temporal checks still apply); all other empty sets are simply not enforced.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct TrustPolicy {
    /// Issuers (JWT `iss` or credential issuer DID) that are trusted. Empty
    /// means any issuer is allowed.
    pub trusted_issuers: BTreeSet<String>,
    /// The audience an access token must be addressed to (`aud`). `None`
    /// disables the audience check.
    pub expected_audience: Option<String>,
    /// Scopes that must all be present on the token. Empty disables the check.
    pub required_scopes: BTreeSet<String>,
    /// Token identifiers (`jti`) that have been revoked.
    pub revoked_jti: BTreeSet<String>,
    /// Permitted clock skew, in seconds, applied to `exp`/`nbf`/validity checks.
    pub leeway_secs: i64,
}

impl TrustPolicy {
    /// Builds an empty, permissive policy (any issuer, no audience/scope checks).
    #[must_use]
    pub fn permissive() -> Self {
        Self::default()
    }

    /// Returns `true` if `issuer` is trusted (an empty trust set trusts all).
    #[must_use]
    pub fn issuer_trusted(&self, issuer: Option<&str>) -> bool {
        if self.trusted_issuers.is_empty() {
            return true;
        }
        issuer.is_some_and(|i| self.trusted_issuers.contains(i))
    }

    /// Adds a trusted issuer, returning `self` for chaining.
    #[must_use]
    pub fn with_trusted_issuer(mut self, issuer: impl Into<String>) -> Self {
        self.trusted_issuers.insert(issuer.into());
        self
    }

    /// Sets the expected audience, returning `self` for chaining.
    #[must_use]
    pub fn with_audience(mut self, audience: impl Into<String>) -> Self {
        self.expected_audience = Some(audience.into());
        self
    }

    /// Adds a required scope, returning `self` for chaining.
    #[must_use]
    pub fn requiring_scope(mut self, scope: impl Into<String>) -> Self {
        self.required_scopes.insert(scope.into());
        self
    }

    /// Marks a token id as revoked, returning `self` for chaining.
    #[must_use]
    pub fn revoking(mut self, jti: impl Into<String>) -> Self {
        self.revoked_jti.insert(jti.into());
        self
    }

    /// Sets the clock-skew leeway in seconds, returning `self` for chaining.
    #[must_use]
    pub fn with_leeway(mut self, leeway_secs: i64) -> Self {
        self.leeway_secs = leeway_secs;
        self
    }
}
