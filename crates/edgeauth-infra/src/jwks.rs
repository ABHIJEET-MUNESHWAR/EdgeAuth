//! JSON Web Key Set providers.
//!
//! [`StaticJwksProvider`] serves a fixed key set (ideal for the edge, where the
//! set is baked in or pushed by config). [`CachedJwksProvider`] holds a cached
//! set and refreshes it from an HTTP endpoint behind the full resilience stack:
//! a per-attempt timeout, retry with exponential backoff, and a circuit breaker.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use edgeauth_resilience::{
    retry, with_timeout, BreakerConfig, CircuitBreaker, RetryPolicy, SystemClock as MonotonicClock,
};
use edgeauth_types::Jwks;
use parking_lot::RwLock;

use crate::error::InfraError;

/// A source of the currently-trusted [`Jwks`].
#[async_trait]
pub trait JwksProvider: Send + Sync {
    /// Returns a snapshot of the current key set. Cheap and non-blocking.
    fn current(&self) -> Jwks;

    /// Refreshes the key set from its source.
    ///
    /// # Errors
    /// Returns [`InfraError`] if the refresh fails or is unsupported.
    async fn refresh(&self) -> Result<(), InfraError>;
}

/// A provider serving a fixed, in-memory key set.
#[derive(Debug, Clone)]
pub struct StaticJwksProvider {
    jwks: Jwks,
}

impl StaticJwksProvider {
    /// Wraps a fixed key set.
    #[must_use]
    pub fn new(jwks: Jwks) -> Self {
        Self { jwks }
    }
}

#[async_trait]
impl JwksProvider for StaticJwksProvider {
    fn current(&self) -> Jwks {
        self.jwks.clone()
    }

    async fn refresh(&self) -> Result<(), InfraError> {
        Ok(()) // a static set is always fresh
    }
}

/// A provider that caches a key set and refreshes it over HTTP, resiliently.
pub struct CachedJwksProvider {
    url: String,
    client: reqwest::Client,
    cache: Arc<RwLock<Jwks>>,
    breaker: CircuitBreaker,
    retry_policy: RetryPolicy,
    per_attempt_timeout: Duration,
}

impl CachedJwksProvider {
    /// Builds a provider that refreshes from `url`, seeded with `initial`.
    ///
    /// # Errors
    /// Returns [`InfraError::Http`] if the HTTP client cannot be constructed.
    pub fn new(url: impl Into<String>, initial: Jwks) -> Result<Self, InfraError> {
        let client = reqwest::Client::builder()
            .user_agent(concat!("edgeauth/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| InfraError::Http(e.to_string()))?;
        Ok(Self {
            url: url.into(),
            client,
            cache: Arc::new(RwLock::new(initial)),
            breaker: CircuitBreaker::new(BreakerConfig::default(), Arc::new(MonotonicClock)),
            retry_policy: RetryPolicy::default(),
            per_attempt_timeout: Duration::from_secs(3),
        })
    }

    /// Overrides the per-attempt timeout, returning `self` for chaining.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.per_attempt_timeout = timeout;
        self
    }

    /// Overrides the retry policy, returning `self` for chaining.
    #[must_use]
    pub fn with_retry(mut self, policy: RetryPolicy) -> Self {
        self.retry_policy = policy;
        self
    }

    /// Performs a single HTTP GET and decodes the body as a JWKS.
    async fn fetch_once(&self) -> Result<Jwks, InfraError> {
        let resp = self
            .client
            .get(&self.url)
            .send()
            .await
            .map_err(|e| InfraError::Http(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(InfraError::Http(format!("status {}", resp.status())));
        }
        let body = resp
            .text()
            .await
            .map_err(|e| InfraError::Http(e.to_string()))?;
        Jwks::from_json(&body).map_err(|e| InfraError::Decode(e.to_string()))
    }
}

#[async_trait]
impl JwksProvider for CachedJwksProvider {
    fn current(&self) -> Jwks {
        self.cache.read().clone()
    }

    async fn refresh(&self) -> Result<(), InfraError> {
        self.breaker
            .acquire()
            .map_err(|_| InfraError::CircuitOpen)?;

        let fetched = retry(self.retry_policy, || async {
            match with_timeout(self.per_attempt_timeout, self.fetch_once()).await {
                Ok(inner) => inner,
                Err(_elapsed) => Err(InfraError::Timeout),
            }
        })
        .await;

        match fetched {
            Ok(jwks) => {
                let key_count = jwks.keys.len();
                *self.cache.write() = jwks;
                self.breaker.record_success();
                metrics::counter!("edgeauth_jwks_refresh_total", "result" => "ok").increment(1);
                tracing::info!(keys = key_count, url = %self.url, "refreshed JWKS");
                Ok(())
            }
            Err(e) => {
                self.breaker.record_failure();
                metrics::counter!("edgeauth_jwks_refresh_total", "result" => "error").increment(1);
                tracing::warn!(error = %e, url = %self.url, "JWKS refresh failed");
                Err(e)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use edgeauth_types::Jwk;

    fn sample_jwks(seed: u8, kid: &str) -> Jwks {
        let sk = SigningKey::from_bytes(&[seed; 32]);
        Jwks::from_keys([Jwk::from_verifying_key(&sk.verifying_key(), kid)])
    }

    #[tokio::test]
    async fn static_provider_returns_its_keys_and_refresh_is_noop() {
        let provider = StaticJwksProvider::new(sample_jwks(1, "k1"));
        assert_eq!(provider.current().keys.len(), 1);
        assert!(provider.refresh().await.is_ok());
        assert_eq!(provider.current().keys[0].kid.as_deref(), Some("k1"));
    }

    #[tokio::test]
    async fn cached_provider_serves_seed_before_refresh() {
        let provider =
            CachedJwksProvider::new("http://127.0.0.1:1/jwks.json", sample_jwks(2, "seed"))
                .unwrap()
                .with_timeout(Duration::from_millis(50))
                .with_retry(RetryPolicy {
                    max_attempts: 1,
                    ..RetryPolicy::default()
                });
        // Seed is served immediately.
        assert_eq!(provider.current().keys[0].kid.as_deref(), Some("seed"));
        // Unreachable endpoint: refresh fails but the cached seed is retained.
        assert!(provider.refresh().await.is_err());
        assert_eq!(provider.current().keys[0].kid.as_deref(), Some("seed"));
    }
}
