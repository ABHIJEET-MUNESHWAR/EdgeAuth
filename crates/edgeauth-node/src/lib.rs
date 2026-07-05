//! EdgeAuth node library: configuration, telemetry, composition root and demo.
//!
//! The binary in `main.rs` is a thin dispatcher over these modules; exposing
//! them as a library lets integration tests drive the real wiring.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod config;
pub mod demo;
pub mod startup;
pub mod telemetry;

pub use config::{Cli, Command, CommonArgs, ServeArgs, VerifyArgs};
pub use startup::{build_router, build_state, serve};
