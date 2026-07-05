//! The `EdgeVerifier` application service.
//!
//! This is the thin orchestration layer that the native server exposes: it
//! resolves the current [`Jwks`] and time from its ports, delegates the actual
//! decision to the pure [`edgeauth_verifier`], then records metrics, emits an
//! audit event and updates aggregate stats. The verification logic itself lives
//! entirely in the (wasm-safe) verifier crate; nothing security-relevant is
//! duplicated here.

use std::borrow::Cow;
use std::collections::BTreeSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use edgeauth_types::{Jwks, TokenKind, TrustPolicy, VerificationOutcome, VerifyError};
use serde::Serialize;

use crate::audit::{AuditSink, VerificationEvent};
use crate::clock::UnixClock;
use crate::error::InfraError;
use crate::jwks::JwksProvider;

/// Per-request tightening of the base [`TrustPolicy`].
///
/// Overrides are *additive* for scopes (the union is required) and *replacing*
/// for the audience, so an endpoint can demand a stricter check than the node
/// default but never loosen it below the configured trusted-issuer set.
#[derive(Debug, Clone, Default)]
pub struct PolicyOverride {
    /// If set, the audience the token must be addressed to.
    pub audience: Option<String>,
    /// Extra scopes that must be present, on top of the base policy.
    pub required_scopes: BTreeSet<String>,
}

impl PolicyOverride {
    /// Returns `true` if this override changes nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.audience.is_none() && self.required_scopes.is_empty()
    }
}

/// Aggregate counters, cheap to read for the `stats` query.
#[derive(Debug, Default)]
struct Counters {
    jwt_accepted: AtomicU64,
    jwt_rejected: AtomicU64,
    vc_accepted: AtomicU64,
    vc_rejected: AtomicU64,
}

/// A point-in-time snapshot of the service counters.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub struct StatsSnapshot {
    /// JWTs accepted.
    pub jwt_accepted: u64,
    /// JWTs rejected.
    pub jwt_rejected: u64,
    /// Credentials accepted.
    pub vc_accepted: u64,
    /// Credentials rejected.
    pub vc_rejected: u64,
}

/// Orchestrates verification over the configured ports.
pub struct EdgeVerifier {
    jwks: Arc<dyn JwksProvider>,
    clock: Arc<dyn UnixClock>,
    audit: Arc<dyn AuditSink>,
    policy: TrustPolicy,
    counters: Counters,
}

impl EdgeVerifier {
    /// Wires the service from its ports and base policy.
    #[must_use]
    pub fn new(
        jwks: Arc<dyn JwksProvider>,
        clock: Arc<dyn UnixClock>,
        audit: Arc<dyn AuditSink>,
        policy: TrustPolicy,
    ) -> Self {
        Self {
            jwks,
            clock,
            audit,
            policy,
            counters: Counters::default(),
        }
    }

    /// The base trust policy.
    #[must_use]
    pub fn policy(&self) -> &TrustPolicy {
        &self.policy
    }

    /// A snapshot of the currently trusted key set.
    #[must_use]
    pub fn jwks(&self) -> Jwks {
        self.jwks.current()
    }

    /// The current time in Unix seconds, per the configured clock.
    #[must_use]
    pub fn now_unix(&self) -> i64 {
        self.clock.now_unix()
    }

    /// Forces a refresh of the trusted key set from its source.
    ///
    /// # Errors
    /// Returns [`InfraError`] if the refresh fails or is unsupported.
    pub async fn refresh_jwks(&self) -> Result<(), InfraError> {
        self.jwks.refresh().await
    }

    /// Computes the effective policy for a request, applying any override.
    fn effective_policy<'a>(&'a self, over: Option<&PolicyOverride>) -> Cow<'a, TrustPolicy> {
        match over {
            None => Cow::Borrowed(&self.policy),
            Some(o) if o.is_empty() => Cow::Borrowed(&self.policy),
            Some(o) => {
                let mut p = self.policy.clone();
                if let Some(aud) = &o.audience {
                    p.expected_audience = Some(aud.clone());
                }
                p.required_scopes.extend(o.required_scopes.iter().cloned());
                Cow::Owned(p)
            }
        }
    }

    /// Verifies a compact EdDSA JWT, recording metrics and an audit event.
    #[must_use]
    pub fn verify_jwt(&self, token: &str, over: Option<&PolicyOverride>) -> VerificationOutcome {
        let policy = self.effective_policy(over);
        let jwks = self.jwks.current();
        let now = self.clock.now_unix();
        let outcome = edgeauth_verifier::verify_jwt(token, &jwks, &policy, now);
        self.record(&outcome, now);
        outcome
    }

    /// Verifies a JSON-encoded Verifiable Credential.
    ///
    /// # Errors
    /// Returns [`VerifyError::Json`] if the document is not a valid credential.
    pub fn verify_credential_json(
        &self,
        json: &str,
        over: Option<&PolicyOverride>,
    ) -> Result<VerificationOutcome, VerifyError> {
        let policy = self.effective_policy(over);
        let now = self.clock.now_unix();
        let outcome = edgeauth_verifier::verify_credential_json(json, &policy, now)?;
        self.record(&outcome, now);
        Ok(outcome)
    }

    /// Returns a snapshot of the aggregate counters.
    #[must_use]
    pub fn stats(&self) -> StatsSnapshot {
        StatsSnapshot {
            jwt_accepted: self.counters.jwt_accepted.load(Ordering::Relaxed),
            jwt_rejected: self.counters.jwt_rejected.load(Ordering::Relaxed),
            vc_accepted: self.counters.vc_accepted.load(Ordering::Relaxed),
            vc_rejected: self.counters.vc_rejected.load(Ordering::Relaxed),
        }
    }

    /// Emits metrics, updates counters, and publishes an audit event.
    fn record(&self, outcome: &VerificationOutcome, now: i64) {
        let result = if outcome.valid {
            "accepted"
        } else {
            "rejected"
        };
        match (outcome.kind, outcome.valid) {
            (TokenKind::Jwt, true) => {
                self.counters.jwt_accepted.fetch_add(1, Ordering::Relaxed);
            }
            (TokenKind::Jwt, false) => {
                self.counters.jwt_rejected.fetch_add(1, Ordering::Relaxed);
            }
            (TokenKind::VerifiableCredential, true) => {
                self.counters.vc_accepted.fetch_add(1, Ordering::Relaxed);
            }
            (TokenKind::VerifiableCredential, false) => {
                self.counters.vc_rejected.fetch_add(1, Ordering::Relaxed);
            }
        }
        metrics::counter!(
            "edgeauth_verifications_total",
            "kind" => outcome.kind.as_str(),
            "result" => result,
        )
        .increment(1);
        self.audit
            .record(VerificationEvent::from_outcome(outcome, now));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::BroadcastAuditSink;
    use crate::clock::FixedClock;
    use crate::jwks::StaticJwksProvider;
    use ed25519_dalek::SigningKey;
    use edgeauth_types::{encode_jwt, Audience, Jwk, JwtClaims, JwtHeader, JWT_ALG};

    fn build(now: i64, policy: TrustPolicy) -> (EdgeVerifier, SigningKey) {
        let sk = SigningKey::from_bytes(&[1u8; 32]);
        let jwks = Jwks::from_keys([Jwk::from_verifying_key(&sk.verifying_key(), "k1")]);
        let service = EdgeVerifier::new(
            Arc::new(StaticJwksProvider::new(jwks)),
            Arc::new(FixedClock(now)),
            Arc::new(BroadcastAuditSink::new(16)),
            policy,
        );
        (service, sk)
    }

    fn token(sk: &SigningKey) -> String {
        let header = JwtHeader {
            alg: JWT_ALG.to_string(),
            typ: Some("JWT".to_string()),
            kid: Some("k1".to_string()),
        };
        let claims = JwtClaims {
            iss: Some("https://issuer.example".to_string()),
            sub: Some("user-1".to_string()),
            aud: Some(Audience::Single("edge-api".to_string())),
            exp: Some(2_000),
            nbf: Some(1_000),
            iat: Some(1_000),
            jti: Some("tok-1".to_string()),
            scope: Some("openid".to_string()),
            roles: vec!["viewer".to_string()],
        };
        encode_jwt(&header, &claims, sk).unwrap()
    }

    #[test]
    fn verify_jwt_accepts_and_counts() {
        let policy = TrustPolicy::permissive().with_trusted_issuer("https://issuer.example");
        let (service, sk) = build(1_500, policy);
        let out = service.verify_jwt(&token(&sk), None);
        assert!(out.valid, "reason: {:?}", out.reason);
        assert_eq!(service.stats().jwt_accepted, 1);
        assert_eq!(service.stats().jwt_rejected, 0);
    }

    #[test]
    fn override_can_tighten_audience() {
        let policy = TrustPolicy::permissive();
        let (service, sk) = build(1_500, policy);
        let over = PolicyOverride {
            audience: Some("different-api".to_string()),
            required_scopes: BTreeSet::new(),
        };
        let out = service.verify_jwt(&token(&sk), Some(&over));
        assert!(!out.valid);
        assert!(!out.checks.audience);
        assert_eq!(service.stats().jwt_rejected, 1);
    }

    #[test]
    fn override_can_require_extra_scope() {
        let policy = TrustPolicy::permissive();
        let (service, sk) = build(1_500, policy);
        let mut scopes = BTreeSet::new();
        scopes.insert("admin:write".to_string());
        let over = PolicyOverride {
            audience: None,
            required_scopes: scopes,
        };
        let out = service.verify_jwt(&token(&sk), Some(&over));
        assert!(!out.valid);
        assert!(!out.checks.scopes);
    }

    #[tokio::test]
    async fn refresh_on_static_provider_is_ok() {
        let (service, _sk) = build(1_500, TrustPolicy::permissive());
        assert!(service.refresh_jwks().await.is_ok());
    }
}
