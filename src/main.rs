mod mfa;
mod rotate;
mod storage;

use clap::{Parser, Subcommand};
use std::io;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
struct Opts {
    #[clap(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Mfa(mfa::Opts),
    Rotate(rotate::Opts),
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_writer(io::stderr)
        .init();

    let opts = Opts::parse();
    tracing::debug!(opts = ?opts);
    match opts.command {
        Command::Mfa(opts) => mfa::main(opts).await,
        Command::Rotate(opts) => rotate::main(opts).await,
    }
}
