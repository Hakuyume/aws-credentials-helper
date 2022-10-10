use clap::Parser;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::fs;
use tokio::process::Command;
use ykoath::calculate;
use ykoath::YubiKey;

#[derive(Parser)]
struct Opts {
    positional: Vec<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
struct Storage {
    mfa_devices: BTreeMap<String, MfaDevice>,
}

#[derive(Deserialize, Serialize)]
struct MfaDevice {
    credentials: Option<Credentials>,
    ykoath: Ykoath,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
struct Credentials {
    access_key_id: String,
    secret_access_key: String,
    session_token: String,
    expiration: Expiration,
}

#[derive(Deserialize, Serialize)]
struct Expiration {
    secs: i64,
    nanos: u32,
}

#[derive(Deserialize, Serialize)]
struct Ykoath {
    name: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let opts = Opts::parse();

    let config = aws_config::load_from_env().await;
    let iam_client = aws_sdk_iam::Client::new(&config);
    let sts_client = aws_sdk_sts::Client::new(&config);

    let storage_path = dirs::home_dir()
        .ok_or_else(|| anyhow::format_err!("no home directory"))?
        .join(".aws")
        .join("credentials-helper.json");
    let mut storage = serde_json::from_slice::<Storage>(&fs::read(&storage_path).await?)?;

    let output = iam_client.list_mfa_devices().send().await?;
    let mfa_device = output
        .mfa_devices
        .into_iter()
        .flatten()
        .next()
        .ok_or_else(|| anyhow::format_err!("no mfa device"))?;
    let user_name = mfa_device
        .user_name
        .ok_or_else(|| anyhow::format_err!("no user name"))?;
    let serial_number = mfa_device
        .serial_number
        .ok_or_else(|| anyhow::format_err!("no serial number"))?;
    tracing::info!(user_name = user_name, serial_number = serial_number);

    let entry = storage
        .mfa_devices
        .get_mut(&serial_number)
        .ok_or_else(|| anyhow::format_err!("no entry"))?;

    let expired = if let Some(credentials) = &entry.credentials {
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?;
        let expiration = Duration::new(
            credentials.expiration.secs as _,
            credentials.expiration.nanos,
        );
        now + Duration::from_secs(600) > expiration
    } else {
        true
    };

    if expired {
        entry.credentials =
            Some(get_session_token(&sts_client, &serial_number, &entry.ykoath.name).await?);
        fs::write(&storage_path, serde_json::to_vec_pretty(&storage)?).await?;
    }

    if !opts.positional.is_empty() {
        let credentials = storage.mfa_devices[&serial_number]
            .credentials
            .as_ref()
            .unwrap();
        let status = Command::new(&opts.positional[0])
            .args(&opts.positional[1..])
            .env("AWS_ACCESS_KEY_ID", &credentials.access_key_id)
            .env("AWS_SECRET_ACCESS_KEY", &credentials.secret_access_key)
            .env("AWS_SESSION_TOKEN", &credentials.session_token)
            .status()
            .await?;
        anyhow::ensure!(status.success());
    }
    Ok(())
}

async fn get_session_token(
    client: &aws_sdk_sts::Client,
    serial_number: &str,
    ykoath_name: &str,
) -> anyhow::Result<Credentials> {
    let output = client
        .get_session_token()
        .serial_number(serial_number)
        .token_code(
            tokio::task::spawn_blocking({
                let name = ykoath_name.to_owned();
                move || ykoath(&name)
            })
            .await
            .unwrap()?,
        )
        .send()
        .await?;
    let credentials = output
        .credentials
        .ok_or_else(|| anyhow::format_err!("no credentials"))?;
    let access_key_id = credentials
        .access_key_id
        .ok_or_else(|| anyhow::format_err!("no access_key_id"))?;
    let secret_access_key = credentials
        .secret_access_key
        .ok_or_else(|| anyhow::format_err!("no secret_access_key"))?;
    let session_token = credentials
        .session_token
        .ok_or_else(|| anyhow::format_err!("no session_token"))?;
    let expiration = credentials
        .expiration
        .ok_or_else(|| anyhow::format_err!("expiration"))?;
    tracing::info!(access_key_id = access_key_id);

    Ok(Credentials {
        access_key_id,
        secret_access_key,
        session_token,
        expiration: Expiration {
            secs: expiration.secs(),
            nanos: expiration.subsec_nanos(),
        },
    })
}

fn ykoath(name: &str) -> anyhow::Result<String> {
    let mut buf = Vec::new();
    let yubikey = YubiKey::connect(&mut buf)?;
    yubikey.select(&mut buf)?;

    // https://github.com/Yubico/yubikey-manager/blob/b0b894906e450cff726f7ae0e71b329378b4b0c4/ykman/util.py#L400-L401
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let challenge = (timestamp / 30).to_be_bytes();
    let calculate::Response { digits, response } =
        yubikey.calculate(true, name.as_bytes(), &challenge, &mut buf)?;

    // https://github.com/Yubico/yubikey-manager/blob/b0b894906e450cff726f7ae0e71b329378b4b0c4/ykman/util.py#L371
    let response = u32::from_be_bytes(response.try_into().unwrap());
    Ok(format!(
        "{:01$}",
        response % 10_u32.pow(u32::from(digits)),
        digits as _,
    ))
}
