//! Direct Exchange Web Services mail transport.
pub mod client;
mod ntlm;
pub(crate) mod sync;

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthMode {
    #[default]
    Auto,
    Ntlm,
    Basic,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct EwsSettings {
    pub url: String,
    pub default_domain: Option<String>,
    pub auth: AuthMode,
    pub poll_seconds: u64,
}

impl Default for EwsSettings {
    fn default() -> Self {
        Self {
            url: String::new(),
            default_domain: Some("pusat".into()),
            auth: AuthMode::Auto,
            poll_seconds: 30,
        }
    }
}

impl EwsSettings {
    pub fn validate(&self) -> crate::error::Result<()> {
        let url = url::Url::parse(self.url.trim())
            .map_err(|_| crate::error::CoreError::Other("enter a valid EWS URL".into()))?;
        let local_http = url.scheme() == "http"
            && matches!(url.host_str(), Some("127.0.0.1" | "[::1]" | "localhost"));
        if !(url.scheme() == "https" || local_http)
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
            || self.url.len() > 2048
            || !(1..=86400).contains(&self.poll_seconds)
        {
            return Err(crate::error::CoreError::Other(
                "invalid EWS URL or polling interval".into(),
            ));
        }
        Ok(())
    }

    pub(crate) fn client(
        &self,
        username: &str,
        password: &str,
    ) -> crate::error::Result<client::EwsClient> {
        self.validate()?;
        client::EwsClient::new(
            &client::EwsConfig {
                url: self.url.trim().to_owned(),
                insecure: crate::net::tls::insecure(),
                default_domain: self.default_domain.clone(),
                auth: self.auth,
            },
            username,
            password,
        )
        .map_err(map_error)
    }
}

pub(crate) async fn probe(
    settings: &EwsSettings,
    username: &str,
    password: &str,
) -> crate::error::Result<()> {
    settings
        .client(username, password)?
        .well_known()
        .await
        .map_err(map_error)?;
    Ok(())
}

pub(crate) fn map_error(error: anyhow::Error) -> crate::error::CoreError {
    if error.is::<client::AuthFailed>() {
        crate::error::CoreError::Auth(error.to_string())
    } else if let Some(core) = error.downcast_ref::<crate::error::CoreError>() {
        crate::error::CoreError::Network(core.to_string())
    } else if error.is::<reqwest::Error>() {
        crate::error::CoreError::Network(error.to_string())
    } else {
        crate::error::CoreError::Other(format!("EWS: {error:#}"))
    }
}
