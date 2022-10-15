mod mfa;
mod storage;

use clap::{Parser, Subcommand};
use std::io;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
struct Opts {
    #[clap(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Mfa(mfa::Opts),
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_writer(io::stderr)
        .init();

    let opts = Opts::parse();
    match opts.command {
        Command::Mfa(opts) => mfa::main(opts).await,
    }
}
