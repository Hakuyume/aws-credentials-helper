mod mfa;

use clap::{Parser, Subcommand};
use std::env;
use std::path::PathBuf;

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

fn profile_name() -> String {
    env::var("AWS_PROFILE").unwrap_or_else(|_| "default".to_owned())
}

fn config_file() -> anyhow::Result<PathBuf> {
    file("AWS_CONFIG_FILE", "config")
}

fn credentials_file() -> anyhow::Result<PathBuf> {
    file("AWS_SHARED_CREDENTIALS_FILE", "credentials")
}

fn file(env_var: &str, file_name: &str) -> anyhow::Result<PathBuf> {
    let path = if let Some(path) = env::var_os(env_var) {
        PathBuf::from(path)
    } else {
        dirs::home_dir()
            .ok_or_else(|| anyhow::format_err!("no home directory"))?
            .join(".aws")
            .join(file_name)
    };
    anyhow::ensure!(path.exists(), "no file: {}", path.display());
    Ok(path)
}
