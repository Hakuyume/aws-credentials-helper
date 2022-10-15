use chrono::offset::Utc;
use chrono::{DateTime, NaiveDateTime};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::path::PathBuf;
use tokio::fs;

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct Storage {
    #[serde(default)]
    pub(crate) credentials: BTreeMap<String, Credentials>,
    #[serde(default)]
    pub(crate) mfa_devices: BTreeMap<String, MfaDevice>,
}

impl Storage {
    pub(crate) async fn load() -> anyhow::Result<Self> {
        Ok(serde_json::from_slice(&fs::read(Self::path()?).await?)?)
    }

    pub(crate) async fn save(&self) -> anyhow::Result<()> {
        Ok(fs::write(Self::path()?, serde_json::to_vec_pretty(&self)?).await?)
    }

    fn path() -> anyhow::Result<PathBuf> {
        Ok(dirs::home_dir()
            .ok_or_else(|| anyhow::format_err!("missing home directory"))?
            .join(".aws")
            .join("credentials-helper.json"))
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct Credentials {
    pub(crate) access_key_id: String,
    pub(crate) secret_access_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) session_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) expiration: Option<DateTime<Utc>>,
}

impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credentials")
            .field("access_key_id", &self.access_key_id)
            .field("secret_access_key", &"***")
            .field("session_token", &self.session_token.as_ref().map(|_| "***"))
            .field("expiration", &self.expiration)
            .finish()
    }
}

impl TryFrom<&aws_sdk_iam::model::AccessKey> for Credentials {
    type Error = anyhow::Error;
    fn try_from(value: &aws_sdk_iam::model::AccessKey) -> Result<Self, Self::Error> {
        Ok(Self {
            access_key_id: value
                .access_key_id()
                .map(str::to_owned)
                .ok_or_else(|| anyhow::format_err!("missing access_key_id"))?,
            secret_access_key: value
                .secret_access_key()
                .map(str::to_owned)
                .ok_or_else(|| anyhow::format_err!("missing secret_access_key"))?,
            session_token: None,
            expiration: None,
        })
    }
}

impl TryFrom<&aws_sdk_sts::model::Credentials> for Credentials {
    type Error = anyhow::Error;
    fn try_from(value: &aws_sdk_sts::model::Credentials) -> Result<Self, Self::Error> {
        Ok(Self {
            access_key_id: value
                .access_key_id()
                .map(str::to_owned)
                .ok_or_else(|| anyhow::format_err!("missing access_key_id"))?,
            secret_access_key: value
                .secret_access_key()
                .map(str::to_owned)
                .ok_or_else(|| anyhow::format_err!("missing secret_access_key"))?,
            session_token: value.session_token().map(str::to_owned),
            expiration: value.expiration().map(|expiration| {
                DateTime::<Utc>::from_utc(
                    NaiveDateTime::from_timestamp(expiration.secs(), expiration.subsec_nanos()),
                    Utc,
                )
            }),
        })
    }
}

impl From<Credentials> for aws_types::Credentials {
    fn from(value: Credentials) -> Self {
        Self::new(
            value.access_key_id,
            value.secret_access_key,
            value.session_token,
            value.expiration.map(Into::into),
            env!("CARGO_PKG_NAME"),
        )
    }
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum MfaDevice {
    Ykoath(Ykoath),
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct Ykoath {
    pub(crate) name: String,
}
