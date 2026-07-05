//! Command-line and environment configuration for the EdgeAuth node.

use clap::{Args, Parser, Subcommand};

/// EdgeAuth: a stateless, WASM-deployable edge identity verifier.
#[derive(Debug, Parser)]
#[command(name = "edgeauth-node", version, about)]
pub struct Cli {
    /// Options shared by every subcommand.
    #[command(flatten)]
    pub common: CommonArgs,

    /// The subcommand to run (defaults to `demo`).
    #[command(subcommand)]
    pub command: Option<Command>,
}

/// The available subcommands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Run the GraphQL verification server.
    Serve(ServeArgs),
    /// Run a self-contained demonstration (mint sample tokens, verify them).
    Demo,
    /// Verify a single JWT and/or credential offline and print the outcome.
    Verify(VerifyArgs),
}

/// Trust configuration shared across subcommands.
#[derive(Debug, Clone, Args)]
pub struct CommonArgs {
    /// Deterministic seed for the local demo signing key (0-255). The node
    /// trusts the corresponding public key as its built-in JWKS.
    #[arg(long, env = "EA_SIGNER_SEED", default_value_t = 7)]
    pub signer_seed: u8,

    /// The issuer identifier (`iss`) the node trusts for JWTs.
    #[arg(long, env = "EA_ISSUER", default_value = "https://issuer.local")]
    pub issuer: String,

    /// Additional trusted issuers — JWT `iss` values or credential issuer DIDs
    /// — as a comma-separated list. Merged with `--issuer`.
    #[arg(long, env = "EA_TRUSTED_ISSUERS", value_delimiter = ',')]
    pub trusted_issuers: Vec<String>,

    /// The audience (`aud`) tokens must be addressed to. Unset disables the check.
    #[arg(long, env = "EA_AUDIENCE")]
    pub audience: Option<String>,

    /// Permitted clock skew, in seconds, applied to `exp`/`nbf` checks.
    #[arg(long, env = "EA_LEEWAY_SECS", default_value_t = 60)]
    pub leeway_secs: i64,

    /// Optional URL to fetch the JWKS from. When set, the node refreshes keys
    /// from this endpoint; otherwise it serves the built-in local key.
    #[arg(long, env = "EA_JWKS_URL")]
    pub jwks_url: Option<String>,

    /// How often (seconds) to refresh a remote JWKS. Ignored without `--jwks-url`.
    #[arg(long, env = "EA_JWKS_REFRESH_SECS", default_value_t = 300)]
    pub jwks_refresh_secs: u64,
}

/// Arguments for the `serve` subcommand.
#[derive(Debug, Clone, Args)]
pub struct ServeArgs {
    /// The socket address to bind.
    #[arg(long, env = "EA_BIND_ADDR", default_value = "0.0.0.0:8080")]
    pub bind_addr: String,

    /// Maximum mutations per second before requests are rejected.
    #[arg(long, env = "EA_RATE_LIMIT_RPS", default_value_t = 100)]
    pub rate_limit_rps: u32,
}

/// Arguments for the offline `verify` subcommand.
#[derive(Debug, Clone, Args)]
pub struct VerifyArgs {
    /// A compact EdDSA JWT to verify.
    #[arg(long)]
    pub token: Option<String>,

    /// A JSON-encoded Verifiable Credential to verify.
    #[arg(long)]
    pub credential: Option<String>,
}
