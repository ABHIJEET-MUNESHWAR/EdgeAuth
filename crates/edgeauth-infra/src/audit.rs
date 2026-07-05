//! An audit trail of verification decisions, published over a broadcast channel.
//!
//! Every decision the service makes is emitted as a [`VerificationEvent`]. The
//! GraphQL subscription resolver turns the broadcast stream into a live feed for
//! operators; tests can use [`NoopAuditSink`] to ignore it.

use edgeauth_types::{TokenKind, VerificationOutcome};
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

/// A single verification decision, suitable for an audit log or live feed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationEvent {
    /// Which kind of artifact was checked.
    pub kind: TokenKind,
    /// Whether it was accepted.
    pub valid: bool,
    /// The authenticated subject, if any.
    pub subject: Option<String>,
    /// The issuer, if any.
    pub issuer: Option<String>,
    /// The reason for rejection, if any.
    pub reason: Option<String>,
    /// When the decision was made, in Unix seconds.
    pub at: i64,
}

impl VerificationEvent {
    /// Projects a verification outcome into an audit event stamped at `at`.
    #[must_use]
    pub fn from_outcome(outcome: &VerificationOutcome, at: i64) -> Self {
        Self {
            kind: outcome.kind,
            valid: outcome.valid,
            subject: outcome.subject.clone(),
            issuer: outcome.issuer.clone(),
            reason: outcome.reason.clone(),
            at,
        }
    }
}

/// Receives verification decisions for auditing.
pub trait AuditSink: Send + Sync {
    /// Records a verification decision. Must not block.
    fn record(&self, event: VerificationEvent);
}

/// An audit sink that fans decisions out to all live subscribers.
///
/// Cloning shares the same underlying broadcast channel, so every clone and
/// every subscriber observes the same stream of events.
#[derive(Clone)]
pub struct BroadcastAuditSink {
    tx: broadcast::Sender<VerificationEvent>,
}

impl BroadcastAuditSink {
    /// Creates a sink buffering up to `capacity` events per lagging subscriber.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        let (tx, _rx) = broadcast::channel(capacity.max(1));
        Self { tx }
    }

    /// Subscribes to the live stream of verification events.
    #[must_use]
    pub fn subscribe(&self) -> broadcast::Receiver<VerificationEvent> {
        self.tx.subscribe()
    }

    /// The number of currently active subscribers.
    #[must_use]
    pub fn subscriber_count(&self) -> usize {
        self.tx.receiver_count()
    }
}

impl AuditSink for BroadcastAuditSink {
    fn record(&self, event: VerificationEvent) {
        // A send error only means there are no subscribers; that is fine.
        let _ = self.tx.send(event);
    }
}

/// An audit sink that discards every event.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoopAuditSink;

impl AuditSink for NoopAuditSink {
    fn record(&self, _event: VerificationEvent) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(valid: bool) -> VerificationEvent {
        VerificationEvent {
            kind: TokenKind::Jwt,
            valid,
            subject: Some("user-1".to_string()),
            issuer: Some("iss".to_string()),
            reason: None,
            at: 1_000,
        }
    }

    #[tokio::test]
    async fn broadcast_delivers_to_subscribers() {
        let sink = BroadcastAuditSink::new(8);
        let mut rx = sink.subscribe();
        assert_eq!(sink.subscriber_count(), 1);
        sink.record(event(true));
        let received = rx.recv().await.unwrap();
        assert!(received.valid);
        assert_eq!(received.subject.as_deref(), Some("user-1"));
    }

    #[test]
    fn recording_without_subscribers_is_ok() {
        let sink = BroadcastAuditSink::new(8);
        sink.record(event(false)); // must not panic
        assert_eq!(sink.subscriber_count(), 0);
    }

    #[test]
    fn noop_sink_discards() {
        NoopAuditSink.record(event(true)); // must not panic
    }
}
