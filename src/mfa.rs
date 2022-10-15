use crate::storage::{Credentials, MfaDevice, Storage};
use chrono::offset::Utc;
use chrono::DateTime;
use clap::Parser;
use serde::Serialize;
use std::io;
use std::time::{SystemTime, UNIX_EPOCH};
use ykoath::{calculate, calculate_all, YubiKey};

#[derive(Parser)]
pub(super) struct Opts {
    #[clap(long)]
    iam: String,
    #[clap(long, default_value = "12h")]
    duration: humantime::Duration,
}

pub(super) async fn main(opts: Opts) -> anyhow::Result<()> {
    let mut storage = Storage::load().await?;

    let config = aws_config::from_env()
        .credentials_provider(aws_types::Credentials::from(
            storage
                .credentials
                .get(&opts.iam)
                .ok_or_else(|| anyhow::format_err!("missing credentials for {}", opts.iam))?
                .clone(),
        ))
        .load()
        .await;
    let iam_client = aws_sdk_iam::Client::new(&config);
    let sts_client = aws_sdk_sts::Client::new(&config);

    let output = iam_client.list_mfa_devices().send().await?;
    let mfa_device = output
        .mfa_devices()
        .into_iter()
        .flatten()
        .next()
        .ok_or_else(|| anyhow::format_err!("missing mfa device"))?;
    let serial_number = mfa_device
        .serial_number()
        .ok_or_else(|| anyhow::format_err!("missing serial number"))?;
    tracing::debug!(serial_number = serial_number);

    let credentials = storage.credentials.get(serial_number).cloned();
    tracing::debug!(credentials = ?credentials);

    let credentials = if let Some(credentials) = credentials.filter(|credentials| {
        credentials.expiration
            > Some(Utc::now() + chrono::Duration::seconds((opts.duration.as_secs() / 5) as _))
    }) {
        credentials
    } else {
        let token_code = match storage.mfa_devices.get(serial_number) {
            Some(MfaDevice::Ykoath(device)) => {
                let name = device.name.clone();
                tracing::debug!(ykoath.name = name);
                tokio::task::spawn_blocking(move || ykoath(&name))
                    .await
                    .unwrap()?
            }
            None => anyhow::bail!("missing mfa device for {}", serial_number),
        };
        tracing::debug!(token_code = token_code);

        let output = sts_client
            .get_session_token()
            .serial_number(serial_number)
            .token_code(token_code)
            .duration_seconds(opts.duration.as_secs() as _)
            .send()
            .await?;
        let credentials = Credentials::try_from(
            output
                .credentials()
                .ok_or_else(|| anyhow::format_err!("missing credentials"))?,
        )?;
        tracing::debug!(credentials = ?credentials);

        storage
            .credentials
            .insert(serial_number.to_owned(), credentials.clone());
        storage.save().await?;

        credentials
    };

    // https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sourcing-external.html
    #[derive(Serialize)]
    #[serde(rename_all = "PascalCase")]
    struct Output<'a> {
        version: u32,
        access_key_id: &'a str,
        secret_access_key: &'a str,
        session_token: Option<&'a str>,
        expiration: Option<DateTime<Utc>>,
    }
    serde_json::to_writer_pretty(
        io::stdout(),
        &Output {
            version: 1,
            access_key_id: &credentials.access_key_id,
            secret_access_key: &credentials.secret_access_key,
            session_token: credentials.session_token.as_deref(),
            expiration: credentials.expiration,
        },
    )?;

    Ok(())
}

fn ykoath(name: &str) -> anyhow::Result<String> {
    let mut buf = Vec::new();
    let yubikey = YubiKey::connect(&mut buf)?;
    yubikey.select(&mut buf)?;

    // https://github.com/Yubico/yubikey-manager/blob/b0b894906e450cff726f7ae0e71b329378b4b0c4/ykman/util.py#L400-L401
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let challenge = (timestamp / 30).to_be_bytes();
    tracing::debug!(timestamp = timestamp, challenge = ?challenge);

    let response = yubikey
        .calculate_all(true, &challenge, &mut buf)?
        .find(|response| {
            if let Ok(response) = response {
                response.name == name.as_bytes()
            } else {
                true
            }
        })
        .ok_or_else(|| anyhow::format_err!("missing account for {}", name))??;

    let calculate::Response { digits, response } = match response.inner {
        calculate_all::Inner::Response(response) => response,
        calculate_all::Inner::Hotp => anyhow::bail!("HOTP is not supported"),
        calculate_all::Inner::Touch => {
            tracing::info!("Touch YubiKey ...");
            yubikey.calculate(true, name.as_bytes(), &challenge, &mut buf)?
        }
    };

    // https://github.com/Yubico/yubikey-manager/blob/b0b894906e450cff726f7ae0e71b329378b4b0c4/ykman/util.py#L371
    let response = u32::from_be_bytes(response.try_into().unwrap());
    Ok(format!(
        "{:01$}",
        response % 10_u32.pow(u32::from(digits)),
        digits as _,
    ))
}
