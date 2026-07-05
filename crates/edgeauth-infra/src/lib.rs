//! # `edgeauth-infra`
//!
//! Native (non-`wasm`) adapters and the application service for EdgeAuth:
//!
//! * [`UnixClock`] — wall-clock time as Unix seconds ([`SystemClock`], [`FixedClock`]);
//! * [`JwksProvider`] — a [`StaticJwksProvider`] or a [`CachedJwksProvider`] that
//!   refreshes over HTTP behind timeout + retry + circuit-breaker;
//! * [`AuditSink`] — a [`BroadcastAuditSink`] feeding the live subscription;
//! * [`EdgeVerifier`] — the service that ties the ports to the pure verifier and
//!   adds metrics, auditing and aggregate stats.
//!
//! The security-critical verification logic itself lives in the wasm-safe
//! `edgeauth-verifier` crate; this crate only supplies I/O and wiring.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod audit;
pub mod clock;
pub mod error;
pub mod jwks;
pub mod service;

pub use audit::{AuditSink, BroadcastAuditSink, NoopAuditSink, VerificationEvent};
pub use clock::{FixedClock, SystemClock, UnixClock};
pub use error::InfraError;
pub use jwks::{CachedJwksProvider, JwksProvider, StaticJwksProvider};
pub use service::{EdgeVerifier, PolicyOverride, StatsSnapshot};
