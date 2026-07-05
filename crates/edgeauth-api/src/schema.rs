//! GraphQL schema: queries, mutations and subscriptions over the EdgeAuth
//! verification service.
//!
//! Verification is a pure, read-only decision, but the `verifyJwt` /
//! `verifyCredential` operations are modelled as **mutations** because each one
//! emits an audit event and increments metrics — an observable side effect. The
//! `verifications` subscription streams those audit events live.

use std::collections::BTreeSet;

use async_graphql::{Context, Enum, Object, Schema, SimpleObject, Subscription};
use futures::Stream;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;

use edgeauth_infra::{PolicyOverride, VerificationEvent};
use edgeauth_types::{Jwks, TokenKind, TrustPolicy, VerificationChecks, VerificationOutcome};

use crate::state::ServiceState;

// ---------------------------------------------------------------------------
// Enum + object mappings (domain <-> GraphQL)
// ---------------------------------------------------------------------------

/// The kind of artifact that was verified.
#[derive(Enum, Copy, Clone, Eq, PartialEq)]
pub enum GqlTokenKind {
    /// A compact EdDSA JSON Web Token.
    Jwt,
    /// A `did:key` Verifiable Credential.
    VerifiableCredential,
}

impl From<TokenKind> for GqlTokenKind {
    fn from(k: TokenKind) -> Self {
        match k {
            TokenKind::Jwt => Self::Jwt,
            TokenKind::VerifiableCredential => Self::VerifiableCredential,
        }
    }
}

/// The per-check breakdown of a verification.
#[derive(SimpleObject)]
pub struct GqlChecks {
    /// The cryptographic signature verified against a trusted key.
    pub signature: bool,
    /// The artifact has not expired.
    pub not_expired: bool,
    /// The artifact is already valid (not before its start time).
    pub not_before: bool,
    /// The issuer is trusted.
    pub issuer_trusted: bool,
    /// The audience matched.
    pub audience: bool,
    /// All required scopes were present.
    pub scopes: bool,
    /// The artifact is not revoked.
    pub not_revoked: bool,
}

impl From<VerificationChecks> for GqlChecks {
    fn from(c: VerificationChecks) -> Self {
        Self {
            signature: c.signature,
            not_expired: c.not_expired,
            not_before: c.not_before,
            issuer_trusted: c.issuer_trusted,
            audience: c.audience,
            scopes: c.scopes,
            not_revoked: c.not_revoked,
        }
    }
}

/// The full result of a verification.
#[derive(SimpleObject)]
pub struct GqlOutcome {
    /// Whether the artifact was accepted (all checks passed).
    pub valid: bool,
    /// Which kind of artifact was inspected.
    pub kind: GqlTokenKind,
    /// The authenticated subject, if any.
    pub subject: Option<String>,
    /// The issuer, if any.
    pub issuer: Option<String>,
    /// Scopes carried by the artifact.
    pub scopes: Vec<String>,
    /// Roles carried by the artifact.
    pub roles: Vec<String>,
    /// The per-check breakdown.
    pub checks: GqlChecks,
    /// The reason for the first failure, if any.
    pub reason: Option<String>,
}

impl From<VerificationOutcome> for GqlOutcome {
    fn from(o: VerificationOutcome) -> Self {
        Self {
            valid: o.valid,
            kind: o.kind.into(),
            subject: o.subject,
            issuer: o.issuer,
            scopes: o.scopes,
            roles: o.roles,
            checks: o.checks.into(),
            reason: o.reason,
        }
    }
}

/// A single Ed25519 JSON Web Key, projected for public display.
#[derive(SimpleObject)]
pub struct GqlJwk {
    /// Key type (always `OKP`).
    pub kty: String,
    /// Curve (always `Ed25519`).
    pub crv: String,
    /// Key identifier.
    pub kid: Option<String>,
}

/// The trusted key set.
#[derive(SimpleObject)]
pub struct GqlJwks {
    /// The keys in the set.
    pub keys: Vec<GqlJwk>,
}

impl From<Jwks> for GqlJwks {
    fn from(j: Jwks) -> Self {
        Self {
            keys: j
                .keys
                .into_iter()
                .map(|k| GqlJwk {
                    kty: k.kty,
                    crv: k.crv,
                    kid: k.kid,
                })
                .collect(),
        }
    }
}

/// The active trust policy, projected for display.
#[derive(SimpleObject)]
pub struct GqlTrustPolicy {
    /// Trusted issuers (empty means any issuer is accepted).
    pub trusted_issuers: Vec<String>,
    /// The required audience, if any.
    pub expected_audience: Option<String>,
    /// Scopes required on every token.
    pub required_scopes: Vec<String>,
    /// Permitted clock skew, in seconds.
    pub leeway_secs: i64,
}

impl From<&TrustPolicy> for GqlTrustPolicy {
    fn from(p: &TrustPolicy) -> Self {
        Self {
            trusted_issuers: p.trusted_issuers.iter().cloned().collect(),
            expected_audience: p.expected_audience.clone(),
            required_scopes: p.required_scopes.iter().cloned().collect(),
            leeway_secs: p.leeway_secs,
        }
    }
}

/// Aggregate verification counters.
#[derive(SimpleObject)]
pub struct GqlStats {
    /// JWTs accepted.
    pub jwt_accepted: u64,
    /// JWTs rejected.
    pub jwt_rejected: u64,
    /// Credentials accepted.
    pub vc_accepted: u64,
    /// Credentials rejected.
    pub vc_rejected: u64,
}

/// A live audit event describing a verification decision.
#[derive(SimpleObject)]
pub struct GqlVerificationEvent {
    /// Which kind of artifact was checked.
    pub kind: GqlTokenKind,
    /// Whether it was accepted.
    pub valid: bool,
    /// The subject, if any.
    pub subject: Option<String>,
    /// The issuer, if any.
    pub issuer: Option<String>,
    /// The rejection reason, if any.
    pub reason: Option<String>,
    /// When the decision was made, in Unix seconds.
    pub at: i64,
}

impl From<VerificationEvent> for GqlVerificationEvent {
    fn from(e: VerificationEvent) -> Self {
        Self {
            kind: e.kind.into(),
            valid: e.valid,
            subject: e.subject,
            issuer: e.issuer,
            reason: e.reason,
            at: e.at,
        }
    }
}

// ---------------------------------------------------------------------------
// Query root
// ---------------------------------------------------------------------------

/// GraphQL query root.
pub struct QueryRoot;

#[Object]
impl QueryRoot {
    /// Liveness probe.
    async fn health(&self) -> bool {
        true
    }

    /// The running service version.
    async fn api_version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    /// The active trust policy.
    async fn trust_policy(&self, ctx: &Context<'_>) -> async_graphql::Result<GqlTrustPolicy> {
        let state = ctx.data::<ServiceState>()?;
        Ok(GqlTrustPolicy::from(state.verifier.policy()))
    }

    /// The currently trusted key set.
    async fn jwks(&self, ctx: &Context<'_>) -> async_graphql::Result<GqlJwks> {
        let state = ctx.data::<ServiceState>()?;
        Ok(state.verifier.jwks().into())
    }

    /// Aggregate verification counters.
    async fn stats(&self, ctx: &Context<'_>) -> async_graphql::Result<GqlStats> {
        let state = ctx.data::<ServiceState>()?;
        let s = state.verifier.stats();
        Ok(GqlStats {
            jwt_accepted: s.jwt_accepted,
            jwt_rejected: s.jwt_rejected,
            vc_accepted: s.vc_accepted,
            vc_rejected: s.vc_rejected,
        })
    }
}

// ---------------------------------------------------------------------------
// Mutation root
// ---------------------------------------------------------------------------

/// GraphQL mutation root.
pub struct MutationRoot;

#[Object]
impl MutationRoot {
    /// Verifies a compact EdDSA JWT, optionally tightening the audience and
    /// required scopes for this request.
    async fn verify_jwt(
        &self,
        ctx: &Context<'_>,
        token: String,
        audience: Option<String>,
        required_scopes: Option<Vec<String>>,
    ) -> async_graphql::Result<GqlOutcome> {
        let state = ctx.data::<ServiceState>()?;
        rate_limit(state)?;
        let over = build_override(audience, required_scopes);
        let outcome = state.verifier.verify_jwt(&token, over.as_ref());
        Ok(outcome.into())
    }

    /// Verifies a JSON-encoded `did:key` Verifiable Credential.
    async fn verify_credential(
        &self,
        ctx: &Context<'_>,
        credential: String,
    ) -> async_graphql::Result<GqlOutcome> {
        let state = ctx.data::<ServiceState>()?;
        rate_limit(state)?;
        let outcome = state
            .verifier
            .verify_credential_json(&credential, None)
            .map_err(to_err)?;
        Ok(outcome.into())
    }

    /// Forces a refresh of the trusted key set from its source.
    async fn refresh_jwks(&self, ctx: &Context<'_>) -> async_graphql::Result<bool> {
        let state = ctx.data::<ServiceState>()?;
        rate_limit(state)?;
        state.verifier.refresh_jwks().await.map_err(to_err)?;
        Ok(true)
    }
}

// ---------------------------------------------------------------------------
// Subscription root
// ---------------------------------------------------------------------------

/// GraphQL subscription root.
pub struct SubscriptionRoot;

#[Subscription]
impl SubscriptionRoot {
    /// Streams every verification decision as it is made.
    async fn verifications(
        &self,
        ctx: &Context<'_>,
    ) -> async_graphql::Result<impl Stream<Item = GqlVerificationEvent>> {
        let state = ctx.data::<ServiceState>()?;
        let rx = state.audit.subscribe();
        Ok(BroadcastStream::new(rx).filter_map(|r| r.ok().map(GqlVerificationEvent::from)))
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn to_err(e: impl std::fmt::Display) -> async_graphql::Error {
    async_graphql::Error::new(e.to_string())
}

fn rate_limit(state: &ServiceState) -> async_graphql::Result<()> {
    state
        .rate_limiter
        .try_acquire()
        .map_err(|_| async_graphql::Error::new("rate limit exceeded"))
}

fn build_override(
    audience: Option<String>,
    required_scopes: Option<Vec<String>>,
) -> Option<PolicyOverride> {
    let scopes: BTreeSet<String> = required_scopes.unwrap_or_default().into_iter().collect();
    if audience.is_none() && scopes.is_empty() {
        return None;
    }
    Some(PolicyOverride {
        audience,
        required_scopes: scopes,
    })
}

/// The concrete schema type.
pub type EdgeAuthSchema = Schema<QueryRoot, MutationRoot, SubscriptionRoot>;

/// Builds the GraphQL schema with `state` injected as shared context.
#[must_use]
pub fn build_schema(state: ServiceState) -> EdgeAuthSchema {
    Schema::build(QueryRoot, MutationRoot, SubscriptionRoot)
        .data(state)
        .finish()
}
