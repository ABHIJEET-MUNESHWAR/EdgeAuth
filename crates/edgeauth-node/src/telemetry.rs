//! Telemetry: structured tracing and a Prometheus metrics recorder.

use anyhow::Context;
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use tracing_subscriber::{prelude::*, EnvFilter};

/// Initializes JSON structured logging honoring `RUST_LOG` (default `info`).
///
/// Safe to call once at startup. A second call is a no-op if a global
/// subscriber is already installed.
pub fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer().json())
        .try_init();
}

/// Installs the Prometheus recorder and returns a handle for rendering metrics.
///
/// # Errors
/// Fails if a global metrics recorder is already installed.
pub fn init_metrics() -> anyhow::Result<PrometheusHandle> {
    PrometheusBuilder::new()
        .install_recorder()
        .context("installing Prometheus recorder")
}
