//! Composition root: wires the verifier, ports and GraphQL API into a runnable
//! server, and provides the offline `verify` entry point.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use axum::http::StatusCode;
use axum::routing::get;
use axum::Router;
use ed25519_dalek::SigningKey;
use metrics_exporter_prometheus::PrometheusHandle;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;
use tracing::{info, warn};

use edgeauth_api::{build_schema, router as graphql_router, ServiceState};
use edgeauth_infra::{
    BroadcastAuditSink, CachedJwksProvider, EdgeVerifier, JwksProvider, StaticJwksProvider,
    SystemClock,
};
use edgeauth_resilience::RateLimiter;
use edgeauth_types::{Jwk, Jwks, TrustPolicy};

use crate::config::{CommonArgs, ServeArgs, VerifyArgs};

/// The key id advertised for the built-in local signing key.
pub const LOCAL_KID: &str = "edgeauth-local-1";

/// Derives the deterministic local signing key for `seed`.
#[must_use]
pub fn local_signer(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

/// Builds the single-key JWKS the node trusts by default.
#[must_use]
pub fn local_jwks(seed: u8) -> Jwks {
    Jwks::from_keys([Jwk::from_verifying_key(
        &local_signer(seed).verifying_key(),
        LOCAL_KID,
    )])
}

/// Builds the base trust policy from configuration.
#[must_use]
pub fn build_policy(common: &CommonArgs) -> TrustPolicy {
    let mut policy = TrustPolicy::permissive()
        .with_trusted_issuer(&common.issuer)
        .with_leeway(common.leeway_secs);
    for issuer in &common.trusted_issuers {
        policy = policy.with_trusted_issuer(issuer);
    }
    if let Some(aud) = &common.audience {
        policy = policy.with_audience(aud);
    }
    policy
}

/// Assembles shared service state from configuration.
///
/// Uses the built-in local JWKS unless `--jwks-url` is set, in which case a
/// resilient [`CachedJwksProvider`] is created (seeded with the local key as a
/// cold-start fallback and refreshed on demand).
///
/// # Errors
/// Fails if a remote JWKS provider cannot be constructed.
pub fn build_state(common: &CommonArgs, rate_limit_rps: u32) -> anyhow::Result<ServiceState> {
    let seed = local_jwks(common.signer_seed);
    let jwks: Arc<dyn JwksProvider> = match &common.jwks_url {
        Some(url) => {
            Arc::new(CachedJwksProvider::new(url, seed).context("building remote JWKS provider")?)
        }
        None => Arc::new(StaticJwksProvider::new(seed)),
    };

    let sink = BroadcastAuditSink::new(1024);
    let audit = Arc::new(sink.clone());
    let verifier = Arc::new(EdgeVerifier::new(
        jwks,
        Arc::new(SystemClock),
        Arc::new(sink),
        build_policy(common),
    ));
    let rate_limiter = Arc::new(RateLimiter::per_second(rate_limit_rps.max(1)));
    Ok(ServiceState::new(verifier, audit, rate_limiter))
}

/// Builds the full HTTP router: GraphQL, playground, subscriptions, `/metrics`,
/// `/health`, plus timeout and tracing middleware.
pub fn build_router(state: ServiceState, metrics: PrometheusHandle) -> Router {
    let schema = build_schema(state);
    graphql_router(schema)
        .route("/health", get(|| async { "ok" }))
        .route("/metrics", get(move || async move { metrics.render() }))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(15),
        ))
        .layer(TraceLayer::new_for_http())
}

/// Runs the GraphQL server until a shutdown signal is received.
///
/// # Errors
/// Fails if the metrics recorder cannot be installed or the socket cannot be
/// bound.
pub async fn serve(common: &CommonArgs, args: &ServeArgs) -> anyhow::Result<()> {
    let metrics = crate::telemetry::init_metrics()?;
    let state = build_state(common, args.rate_limit_rps)?;

    if common.jwks_url.is_some() {
        spawn_jwks_refresher(&state, common.jwks_refresh_secs).await;
    }

    let app = build_router(state, metrics);
    let listener = tokio::net::TcpListener::bind(&args.bind_addr)
        .await
        .with_context(|| format!("binding {}", args.bind_addr))?;
    info!(addr = %args.bind_addr, "edgeauth-node listening");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("server error")?;
    Ok(())
}

/// Performs an initial refresh, then spawns a periodic background refresher.
async fn spawn_jwks_refresher(state: &ServiceState, refresh_secs: u64) {
    let verifier = state.verifier.clone();
    if let Err(e) = verifier.refresh_jwks().await {
        warn!(error = %e, "initial JWKS refresh failed; serving fallback key");
    }
    let period = Duration::from_secs(refresh_secs.max(10));
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(period);
        ticker.tick().await; // consume the immediate first tick
        loop {
            ticker.tick().await;
            if let Err(e) = verifier.refresh_jwks().await {
                warn!(error = %e, "periodic JWKS refresh failed");
            }
        }
    });
}

/// Verifies a JWT and/or a credential offline, printing each outcome as JSON.
///
/// # Errors
/// Fails if the state cannot be built, a credential is malformed JSON, or the
/// outcome cannot be serialized.
pub fn run_verify(common: &CommonArgs, args: &VerifyArgs) -> anyhow::Result<()> {
    let state = build_state(common, 1000)?;
    if let Some(token) = &args.token {
        let outcome = state.verifier.verify_jwt(token, None);
        println!("{}", serde_json::to_string_pretty(&outcome)?);
    }
    if let Some(cred) = &args.credential {
        let outcome = state
            .verifier
            .verify_credential_json(cred, None)
            .context("verifying credential")?;
        println!("{}", serde_json::to_string_pretty(&outcome)?);
    }
    if args.token.is_none() && args.credential.is_none() {
        warn!("no verification input supplied; provide a JWT or a VC to verify (see --help)");
    }
    Ok(())
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    info!("shutdown signal received");
}
