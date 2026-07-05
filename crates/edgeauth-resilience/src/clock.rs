//! A testable monotonic clock abstraction.

use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;

/// Provides the current monotonic instant. Abstracted so time-dependent logic
/// (e.g. the circuit breaker) can be driven deterministically in tests.
pub trait Clock: Send + Sync {
    /// Returns the current instant.
    fn now(&self) -> Instant;
}

/// A clock backed by the operating system's monotonic timer.
#[derive(Debug, Clone, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

/// A manually advanceable clock for deterministic tests.
#[derive(Clone)]
pub struct ManualClock {
    inner: Arc<Mutex<Instant>>,
}

impl ManualClock {
    /// Creates a manual clock anchored at the current instant.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(Instant::now())),
        }
    }

    /// Advances the clock by `delta`.
    pub fn advance(&self, delta: Duration) {
        let mut guard = self.inner.lock();
        *guard += delta;
    }
}

impl Default for ManualClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for ManualClock {
    fn now(&self) -> Instant {
        *self.inner.lock()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manual_clock_advances() {
        let clock = ManualClock::new();
        let t0 = clock.now();
        clock.advance(Duration::from_secs(5));
        assert!(clock.now() - t0 >= Duration::from_secs(5));
    }

    #[test]
    fn system_clock_is_monotonic() {
        let clock = SystemClock;
        let a = clock.now();
        let b = clock.now();
        assert!(b >= a);
    }
}
