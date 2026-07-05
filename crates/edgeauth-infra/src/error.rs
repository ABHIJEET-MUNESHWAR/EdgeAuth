//! Errors raised by the native infrastructure adapters.

use thiserror::Error;

/// A failure in an infrastructure adapter (JWKS refresh, etc.).
#[derive(Debug, Error)]
pub enum InfraError {
    /// The remote JWKS endpoint could not be reached or returned an error status.
    #[error("jwks http request failed: {0}")]
    Http(String),

    /// The JWKS endpoint returned a body that was not a valid key set.
    #[error("jwks decode failed: {0}")]
    Decode(String),

    /// The JWKS refresh exceeded its timeout budget.
    #[error("jwks refresh timed out")]
    Timeout,

    /// The circuit breaker guarding the JWKS endpoint is open.
    #[error("jwks endpoint circuit is open")]
    CircuitOpen,

    /// This provider does not support refreshing (e.g. a static key set).
    #[error("this jwks provider is static and cannot be refreshed")]
    NotRefreshable,
}
