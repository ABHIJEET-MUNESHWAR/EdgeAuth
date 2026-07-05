//! Reusable resilience primitives for the EdgeAuth edge identity verifier:
//! a testable clock, timeouts, retry with exponential backoff, a circuit
//! breaker, and a token-bucket rate limiter.

#![forbid(unsafe_code)]

pub mod breaker;
pub mod clock;
pub mod rate_limit;
pub mod retry;

pub use breaker::{BreakerConfig, CircuitBreaker, CircuitOpen, CircuitState};
pub use clock::{Clock, ManualClock, SystemClock};
pub use rate_limit::{RateLimited, RateLimiter};
pub use retry::{retry, with_timeout, Elapsed, RetryPolicy};
