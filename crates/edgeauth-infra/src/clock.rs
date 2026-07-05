//! Wall-clock time as Unix seconds.
//!
//! The pure verifier takes `now` as a parameter; this port lets the native
//! service read the real clock (or a fixed one in tests) without the verifier
//! ever depending on `SystemTime`.

use std::time::{SystemTime, UNIX_EPOCH};

/// Supplies the current time in Unix seconds.
pub trait UnixClock: Send + Sync {
    /// Returns the current time as seconds since the Unix epoch.
    fn now_unix(&self) -> i64;
}

/// A clock backed by the operating system wall clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl UnixClock for SystemClock {
    fn now_unix(&self) -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    }
}

/// A fixed clock for deterministic tests.
#[derive(Debug, Clone, Copy)]
pub struct FixedClock(pub i64);

impl UnixClock for FixedClock {
    fn now_unix(&self) -> i64 {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_clock_is_after_2020() {
        // 2020-01-01T00:00:00Z
        assert!(SystemClock.now_unix() > 1_577_836_800);
    }

    #[test]
    fn fixed_clock_returns_its_value() {
        assert_eq!(FixedClock(42).now_unix(), 42);
    }
}
