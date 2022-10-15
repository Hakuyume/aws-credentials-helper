mod mfa;
mod storage;

use clap::{Parser, Subcommand};

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
    tracing_subscriber::fmt::init();

    let opts = Opts::parse();
    match opts.command {
        Command::Mfa(opts) => mfa::main(opts).await,
    }
}
