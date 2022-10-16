use crate::storage::Storage;
use clap::Parser;

#[derive(Debug, Parser)]
pub(super) struct Opts {
    #[clap(long)]
    iam: String,
}

pub(super) async fn main(opts: Opts) -> anyhow::Result<()> {
    let mut storage = Storage::load().await?;

    let credentials = storage
        .credentials
        .get(&opts.iam)
        .ok_or_else(|| anyhow::format_err!("missing credentials for {}", opts.iam))?;
    tracing::debug!(credentials = ?credentials);
    let config = aws_config::from_env()
        .credentials_provider(aws_types::Credentials::from(credentials.clone()))
        .load()
        .await;
    let iam_client = aws_sdk_iam::Client::new(&config);

    let output = iam_client.list_access_keys().send().await?;
    if let Some(access_key_metadata) = output.access_key_metadata() {
        for access_key_metadata in access_key_metadata {
            let access_key_id = access_key_metadata
                .access_key_id()
                .ok_or_else(|| anyhow::format_err!("missing access_key_id"))?;
            tracing::debug!(access_key_id = access_key_id);
            if access_key_id != credentials.access_key_id {
                iam_client
                    .delete_access_key()
                    .access_key_id(access_key_id)
                    .send()
                    .await?;
            }
        }
    }

    let output = iam_client.create_access_key().send().await?;
    let credentials = output
        .access_key()
        .ok_or_else(|| anyhow::format_err!("missing access_key"))?
        .try_into()?;
    tracing::debug!(credentials = ?credentials);
    storage.credentials.insert(opts.iam.clone(), credentials);

    storage.save().await?;

    Ok(())
}
