use aws_types::Credentials;
use chrono::offset::Utc;
use chrono::{DateTime, NaiveDateTime};
use clap::Parser;
use ini::Ini;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::process::Command;
use ykoath::calculate::Response;
use ykoath::YubiKey;

#[derive(Parser)]
pub(super) struct Opts {
    #[clap(long, default_value = "12h")]
    duration: humantime::Duration,
    arg: Vec<String>,
}

pub(super) async fn main(opts: Opts) -> anyhow::Result<()> {
    let profile_name = super::profile_name();
    let config_file = super::config_file()?;
    let credentials_file = super::credentials_file()?;
    tracing::debug!(
        profile = profile_name,
        config = config_file.display().to_string(),
        credentials = credentials_file.display().to_string(),
    );

    let config_ini = Ini::load_from_file(&config_file)?;
    let mut credentials_ini = Ini::load_from_file(&credentials_file)?;

    let mfa_profile_name = format!("{}/mfa", profile_name);

    let renew = if let Some(section) = credentials_ini.section(Some(&mfa_profile_name)) {
        anyhow::ensure!(
            section.contains_key("aws_access_key_id"),
            "no aws_access_key_id"
        );
        anyhow::ensure!(
            section.contains_key("aws_secret_access_key"),
            "no aws_access_key_id"
        );
        anyhow::ensure!(
            section.contains_key("aws_session_token"),
            "no aws_session_token"
        );
        let expiration = DateTime::parse_from_rfc3339(
            section
                .get("aws_expiration")
                .ok_or_else(|| anyhow::format_err!("no aws_expiration"))?,
        )?;
        tracing::debug!(expiration = expiration.to_string());
        Utc::now() + chrono::Duration::seconds((opts.duration.as_secs() / 5) as _) > expiration
    } else {
        true
    };

    if renew {
        let config = {
            let section = credentials_ini
                .section(Some(&profile_name))
                .ok_or_else(|| anyhow::format_err!("no section: {}", profile_name))?;
            aws_config::from_env()
                .credentials_provider(Credentials::new(
                    section
                        .get("aws_access_key_id")
                        .ok_or_else(|| anyhow::format_err!("no aws_access_key_id"))?,
                    section
                        .get("aws_secret_access_key")
                        .ok_or_else(|| anyhow::format_err!("no aws_secret_access_key"))?,
                    section.get("aws_session_token").map(str::to_owned),
                    section
                        .get("aws_expiration")
                        .map(DateTime::parse_from_rfc3339)
                        .transpose()?
                        .map(Into::into),
                    "ProfileFile",
                ))
                .load()
                .await
        };
        let iam_client = aws_sdk_iam::Client::new(&config);
        let sts_client = aws_sdk_sts::Client::new(&config);

        let output = iam_client.list_mfa_devices().send().await?;
        let mfa_device = output
            .mfa_devices()
            .into_iter()
            .flatten()
            .next()
            .ok_or_else(|| anyhow::format_err!("no mfa device"))?;
        let serial_number = mfa_device
            .serial_number()
            .ok_or_else(|| anyhow::format_err!("no serial number"))?;
        tracing::debug!(serial_number = serial_number);

        let token_code = {
            let section = config_ini
                .section(Some(&profile_name))
                .ok_or_else(|| anyhow::format_err!("no section: {}", profile_name))?;
            let ykoath_name = section
                .get("ykoath_name")
                .ok_or_else(|| anyhow::format_err!("no ykoath_name"))?
                .to_owned();
            tracing::info!(ykoath_name = ykoath_name);
            tokio::task::spawn_blocking(move || ykoath(&ykoath_name))
                .await
                .unwrap()?
        };
        tracing::info!(token_code = token_code);

        let output = sts_client
            .get_session_token()
            .serial_number(serial_number)
            .token_code(token_code)
            .duration_seconds(opts.duration.as_secs() as _)
            .send()
            .await?;
        let credentials = output
            .credentials
            .ok_or_else(|| anyhow::format_err!("no credentials"))?;

        {
            let section = credentials_ini
                .entry(Some(mfa_profile_name.clone()))
                .or_insert(Default::default());
            if let Some(access_key_id) = credentials.access_key_id() {
                section.insert("aws_access_key_id", access_key_id);
            }
            if let Some(secret_access_key) = credentials.secret_access_key() {
                section.insert("aws_secret_access_key", secret_access_key);
            }
            if let Some(session_token) = credentials.session_token() {
                section.insert("aws_session_token", session_token);
            }
            if let Some(expiration) = credentials.expiration() {
                section.insert(
                    "aws_expiration",
                    DateTime::<Utc>::from_utc(
                        NaiveDateTime::from_timestamp(expiration.secs(), expiration.subsec_nanos()),
                        Utc,
                    )
                    .to_rfc3339(),
                );
            }
            credentials_ini.write_to_file(&credentials_file)?;
        }
    }
    if !opts.arg.is_empty() {
        let status = Command::new(&opts.arg[0])
            .args(&opts.arg[1..])
            .env("AWS_PROFILE", &mfa_profile_name)
            .status()
            .await?;
        anyhow::ensure!(status.success());
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
