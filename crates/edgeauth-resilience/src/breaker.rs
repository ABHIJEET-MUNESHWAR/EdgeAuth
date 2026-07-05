//! A three-state circuit breaker (closed / open / half-open).

use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use thiserror::Error;

use crate::clock::Clock;

/// Configuration for a [`CircuitBreaker`].
#[derive(Debug, Clone, Copy)]
pub struct BreakerConfig {
    /// Consecutive failures in the closed state that trip the breaker.
    pub failure_threshold: u32,
    /// How long the breaker stays open before allowing a trial call.
    pub open_duration: Duration,
}

impl Default for BreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            open_duration: Duration::from_secs(30),
        }
    }
}

/// Observable breaker state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    /// Calls flow freely.
    Closed,
    /// Calls are rejected until the cooldown elapses.
    Open,
    /// A single trial call is permitted to probe recovery.
    HalfOpen,
}

/// Error returned when the breaker rejects a call.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[error("circuit breaker is open")]
pub struct CircuitOpen;

struct Inner {
    failures: u32,
    state: RawState,
}

#[derive(Clone, Copy)]
enum RawState {
    Closed,
    Open { opened_at: Instant },
    HalfOpen,
}

/// A thread-safe circuit breaker guarding a fallible dependency.
pub struct CircuitBreaker {
    config: BreakerConfig,
    clock: Arc<dyn Clock>,
    inner: Mutex<Inner>,
}

impl CircuitBreaker {
    /// Creates a breaker with the given config and clock.
    #[must_use]
    pub fn new(config: BreakerConfig, clock: Arc<dyn Clock>) -> Self {
        Self {
            config,
            clock,
            inner: Mutex::new(Inner {
                failures: 0,
                state: RawState::Closed,
            }),
        }
    }

    /// Returns the current externally-visible state.
    #[must_use]
    pub fn state(&self) -> CircuitState {
        match self.inner.lock().state {
            RawState::Closed => CircuitState::Closed,
            RawState::Open { .. } => CircuitState::Open,
            RawState::HalfOpen => CircuitState::HalfOpen,
        }
    }

    /// Checks whether a call may proceed, transitioning `Open -> HalfOpen` once
    /// the cooldown has elapsed.
    ///
    /// # Errors
    /// Returns [`CircuitOpen`] while the breaker is open and cooling down.
    pub fn acquire(&self) -> Result<(), CircuitOpen> {
        let mut guard = self.inner.lock();
        match guard.state {
            RawState::Closed | RawState::HalfOpen => Ok(()),
            RawState::Open { opened_at } => {
                if self.clock.now().duration_since(opened_at) >= self.config.open_duration {
                    guard.state = RawState::HalfOpen;
                    Ok(())
                } else {
                    Err(CircuitOpen)
                }
            }
        }
    }

    /// Records a successful call, closing the breaker and clearing failures.
    pub fn record_success(&self) {
        let mut guard = self.inner.lock();
        guard.failures = 0;
        guard.state = RawState::Closed;
    }

    /// Records a failed call, tripping the breaker if the threshold is reached.
    pub fn record_failure(&self) {
        let mut guard = self.inner.lock();
        match guard.state {
            RawState::HalfOpen => {
                guard.state = RawState::Open {
                    opened_at: self.clock.now(),
                };
            }
            RawState::Closed => {
                guard.failures = guard.failures.saturating_add(1);
                if guard.failures >= self.config.failure_threshold {
                    guard.state = RawState::Open {
                        opened_at: self.clock.now(),
                    };
                }
            }
            RawState::Open { .. } => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::ManualClock;

    fn breaker(threshold: u32, clock: Arc<ManualClock>) -> CircuitBreaker {
        CircuitBreaker::new(
            BreakerConfig {
                failure_threshold: threshold,
                open_duration: Duration::from_secs(10),
            },
            clock,
        )
    }

    #[test]
    fn trips_after_threshold_failures() {
        let clock = Arc::new(ManualClock::new());
        let cb = breaker(3, clock);
        assert_eq!(cb.state(), CircuitState::Closed);
        cb.record_failure();
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Closed);
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);
        assert!(cb.acquire().is_err());
    }

    #[test]
    fn half_opens_after_cooldown_then_closes_on_success() {
        let clock = Arc::new(ManualClock::new());
        let cb = breaker(1, clock.clone());
        cb.record_failure();
        assert!(cb.acquire().is_err());
        clock.advance(Duration::from_secs(11));
        assert!(cb.acquire().is_ok());
        assert_eq!(cb.state(), CircuitState::HalfOpen);
        cb.record_success();
        assert_eq!(cb.state(), CircuitState::Closed);
    }

    #[test]
    fn half_open_failure_reopens() {
        let clock = Arc::new(ManualClock::new());
        let cb = breaker(1, clock.clone());
        cb.record_failure();
        clock.advance(Duration::from_secs(11));
        assert!(cb.acquire().is_ok());
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);
    }
}
