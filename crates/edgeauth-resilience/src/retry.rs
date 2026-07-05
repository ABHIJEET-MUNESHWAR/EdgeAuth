//! Retry with capped exponential backoff, and a timeout helper.

use std::future::Future;
use std::time::Duration;

use thiserror::Error;

/// Configuration for [`retry`].
#[derive(Debug, Clone, Copy)]
pub struct RetryPolicy {
    /// Maximum number of attempts (must be >= 1).
    pub max_attempts: u32,
    /// Initial backoff delay.
    pub initial_backoff: Duration,
    /// Multiplier applied to the delay after each failed attempt.
    pub multiplier: u32,
    /// Upper bound on any single backoff delay.
    pub max_backoff: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            initial_backoff: Duration::from_millis(50),
            multiplier: 2,
            max_backoff: Duration::from_secs(5),
        }
    }
}

impl RetryPolicy {
    /// Returns the backoff delay before the given zero-based attempt.
    #[must_use]
    pub fn backoff_for(&self, attempt: u32) -> Duration {
        let factor = self.multiplier.saturating_pow(attempt);
        let millis = self
            .initial_backoff
            .as_millis()
            .saturating_mul(u128::from(factor));
        let capped = millis.min(self.max_backoff.as_millis());
        Duration::from_millis(capped as u64)
    }
}

/// Retries `op` according to `policy`, backing off between attempts. The last
/// error is returned if every attempt fails.
///
/// # Errors
/// Returns the error from the final failed attempt.
pub async fn retry<F, Fut, T, E>(policy: RetryPolicy, mut op: F) -> Result<T, E>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, E>>,
{
    let attempts = policy.max_attempts.max(1);
    let mut last_err: Option<E> = None;
    for attempt in 0..attempts {
        match op().await {
            Ok(value) => return Ok(value),
            Err(err) => {
                last_err = Some(err);
                if attempt + 1 < attempts {
                    tokio::time::sleep(policy.backoff_for(attempt)).await;
                }
            }
        }
    }
    Err(last_err.expect("at least one attempt always runs"))
}

/// Error returned when an operation exceeds its deadline.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[error("operation timed out after {0:?}")]
pub struct Elapsed(pub Duration);

/// Runs `fut`, failing with [`Elapsed`] if it does not complete within `dur`.
///
/// # Errors
/// Returns [`Elapsed`] if the future does not finish in time.
pub async fn with_timeout<Fut, T>(dur: Duration, fut: Fut) -> Result<T, Elapsed>
where
    Fut: Future<Output = T>,
{
    tokio::time::timeout(dur, fut)
        .await
        .map_err(|_| Elapsed(dur))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    #[test]
    fn backoff_grows_and_caps() {
        let p = RetryPolicy {
            max_attempts: 10,
            initial_backoff: Duration::from_millis(100),
            multiplier: 2,
            max_backoff: Duration::from_millis(500),
        };
        assert_eq!(p.backoff_for(0), Duration::from_millis(100));
        assert_eq!(p.backoff_for(1), Duration::from_millis(200));
        assert_eq!(p.backoff_for(2), Duration::from_millis(400));
        assert_eq!(p.backoff_for(3), Duration::from_millis(500)); // capped
    }

    #[tokio::test(start_paused = true)]
    async fn retry_succeeds_after_transient_failures() {
        let calls = Arc::new(AtomicU32::new(0));
        let c = calls.clone();
        let policy = RetryPolicy {
            max_attempts: 3,
            ..RetryPolicy::default()
        };
        let out: Result<u32, &str> = retry(policy, move || {
            let c = c.clone();
            async move {
                let n = c.fetch_add(1, Ordering::SeqCst);
                if n < 2 {
                    Err("transient")
                } else {
                    Ok(n)
                }
            }
        })
        .await;
        assert_eq!(out, Ok(2));
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test(start_paused = true)]
    async fn retry_gives_up_after_max_attempts() {
        let policy = RetryPolicy {
            max_attempts: 2,
            ..RetryPolicy::default()
        };
        let out: Result<(), &str> = retry(policy, || async { Err("always") }).await;
        assert_eq!(out, Err("always"));
    }

    #[tokio::test(start_paused = true)]
    async fn timeout_fires() {
        let out: Result<(), Elapsed> =
            with_timeout(Duration::from_millis(10), std::future::pending()).await;
        assert!(out.is_err());
    }

    #[tokio::test]
    async fn timeout_passes_through_fast_future() {
        let out = with_timeout(Duration::from_secs(1), async { 7 }).await;
        assert_eq!(out, Ok(7));
    }
}
