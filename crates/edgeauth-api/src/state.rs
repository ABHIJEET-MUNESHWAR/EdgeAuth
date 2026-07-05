//! Shared application state injected into every GraphQL resolver.

use std::sync::Arc;

use edgeauth_infra::{BroadcastAuditSink, EdgeVerifier};
use edgeauth_resilience::RateLimiter;

/// Immutable, cloneable state shared across GraphQL resolvers.
///
/// The `audit` sink is the *same* broadcast channel the [`EdgeVerifier`] writes
/// to (a clone shares the underlying sender), which is how the `verifications`
/// subscription observes decisions made by the mutations.
#[derive(Clone)]
pub struct ServiceState {
    /// The verification application service.
    pub verifier: Arc<EdgeVerifier>,
    /// The broadcast audit sink backing the live subscription.
    pub audit: Arc<BroadcastAuditSink>,
    /// Per-second mutation rate limiter.
    pub rate_limiter: Arc<RateLimiter>,
}

impl ServiceState {
    /// Assembles shared state from its already-constructed components.
    #[must_use]
    pub fn new(
        verifier: Arc<EdgeVerifier>,
        audit: Arc<BroadcastAuditSink>,
        rate_limiter: Arc<RateLimiter>,
    ) -> Self {
        Self {
            verifier,
            audit,
            rate_limiter,
        }
    }
}
