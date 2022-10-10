use clap::Parser;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::fs;
use tokio::process::Command;
use ykoath::calculate::Response;
use ykoath::YubiKey;

#[derive(Parser)]
pub(super) struct Opts {
    positional: Vec<String>,
}

pub(super) async fn main(opts: Opts) -> anyhow::Result<()> {
    let config = aws_config::load_from_env().await;
    let iam_client = aws_sdk_iam::Client::new(&config);
    let sts_client = aws_sdk_sts::Client::new(&config);

    let output = iam_client.list_mfa_devices().send().await?;
    let mfa_device = output
        .mfa_devices()
        .into_iter()
        .flatten()
        .next()
        .ok_or_else(|| anyhow::format_err!("no mfa device"))?;
    let user_name = mfa_device
        .user_name()
        .ok_or_else(|| anyhow::format_err!("no user name"))?;
    let serial_number = mfa_device
        .serial_number()
        .ok_or_else(|| anyhow::format_err!("no serial number"))?;
    tracing::info!(user_name = user_name, serial_number = serial_number);

    let path = dirs::home_dir()
        .ok_or_else(|| anyhow::format_err!("no home directory"))?
        .join(".aws")
        .join("credentials-helper.toml");
    let config = toml::from_slice::<Config>(&fs::read(&path).await?)?;
    let entry = config.mfa_devices.get(serial_number).ok_or_else(|| {
        anyhow::format_err!("mfa-devices.{} not in in {}", serial_number, path.display())
    })?;

    let token_code = tokio::task::spawn_blocking({
        let name = entry.ykoath.name.clone();
        move || ykoath(&name)
    })
    .await
    .unwrap()?;
    tracing::info!(token_code = token_code);

    let output = sts_client
        .get_session_token()
        .serial_number(serial_number)
        .token_code(token_code)
        .send()
        .await?;
    let credentials = output
        .credentials()
        .ok_or_else(|| anyhow::format_err!("no credentials"))?;

    if !opts.positional.is_empty() {
        let mut command = Command::new(&opts.positional[0]);
        command.args(&opts.positional[1..]);
        if let Some(access_key_id) = credentials.access_key_id() {
            command.env("AWS_ACCESS_KEY_ID", access_key_id);
        }
        if let Some(secret_access_key) = credentials.secret_access_key() {
            command.env("AWS_SECRET_ACCESS_KEY", secret_access_key);
        }
        if let Some(session_token) = credentials.session_token() {
            command.env("AWS_SESSION_TOKEN", session_token);
        }
        anyhow::ensure!(command.status().await?.success());
    }
    Ok(())
}

fn ykoath(name: &str) -> anyhow::Result<String> {
    let mut buf = Vec::new();
    let yubikey = YubiKey::connect(&mut buf)?;
    yubikey.select(&mut buf)?;

    // https://github.com/Yubico/yubikey-manager/blob/b0b894906e450cff726f7ae0e71b329378b4b0c4/ykman/util.py#L400-L401
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let challenge = (timestamp / 30).to_be_bytes();
    let Response { digits, response } =
        yubikey.calculate(true, name.as_bytes(), &challenge, &mut buf)?;

    // https://github.com/Yubico/yubikey-manager/blob/b0b894906e450cff726f7ae0e71b329378b4b0c4/ykman/util.py#L371
    let response = u32::from_be_bytes(response.try_into().unwrap());
    Ok(format!(
        "{:01$}",
        response % 10_u32.pow(u32::from(digits)),
        digits as _,
    ))
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
struct Config {
    mfa_devices: BTreeMap<String, MfaDevice>,
}

#[derive(Deserialize, Serialize)]
struct MfaDevice {
    ykoath: Ykoath,
}

#[derive(Deserialize, Serialize)]
struct Ykoath {
    name: String,
}
