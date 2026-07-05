//! A thin wrapper over `governor` providing a token-bucket rate limiter.

use std::num::NonZeroU32;

use governor::clock::DefaultClock;
use governor::state::{InMemoryState, NotKeyed};
use governor::{Quota, RateLimiter as GovernorLimiter};
use thiserror::Error;

/// Error returned when a call is rejected by the rate limiter.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[error("rate limit exceeded")]
pub struct RateLimited;

/// A direct (non-keyed) token-bucket rate limiter.
pub struct RateLimiter {
    inner: GovernorLimiter<NotKeyed, InMemoryState, DefaultClock>,
}

impl RateLimiter {
    /// Builds a limiter permitting `per_second` operations per second with a
    /// burst capacity equal to `per_second`.
    ///
    /// # Panics
    /// Panics if `per_second` is zero.
    #[must_use]
    pub fn per_second(per_second: u32) -> Self {
        let quota = Quota::per_second(
            NonZeroU32::new(per_second).expect("rate limit must be greater than zero"),
        );
        Self {
            inner: GovernorLimiter::direct(quota),
        }
    }

    /// Attempts to consume a single permit without blocking.
    ///
    /// # Errors
    /// Returns [`RateLimited`] if no permit is currently available.
    pub fn try_acquire(&self) -> Result<(), RateLimited> {
        self.inner.check().map(|_| ()).map_err(|_| RateLimited)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_up_to_burst_then_rejects() {
        let rl = RateLimiter::per_second(3);
        assert!(rl.try_acquire().is_ok());
        assert!(rl.try_acquire().is_ok());
        assert!(rl.try_acquire().is_ok());
        assert!(rl.try_acquire().is_err());
    }
}
