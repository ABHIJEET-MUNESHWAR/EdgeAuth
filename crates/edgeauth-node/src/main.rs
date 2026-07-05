//! EdgeAuth node binary entry point.

use clap::Parser;

use edgeauth_node::config::{Cli, Command};
use edgeauth_node::{demo, startup, telemetry};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = dotenvy::dotenv();
    let cli = Cli::parse();
    telemetry::init_tracing();

    match cli.command.unwrap_or(Command::Demo) {
        Command::Serve(args) => startup::serve(&cli.common, &args).await,
        Command::Demo => demo::run(&cli.common),
        Command::Verify(args) => startup::run_verify(&cli.common, &args),
    }
}
