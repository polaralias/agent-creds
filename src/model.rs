use anyhow::{Result, bail, ensure};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
pub struct Metadata {
    pub name: String,
    pub env: String,
    pub kind: String,
    pub expires_at: Option<DateTime<Utc>>,
    pub updated_at: DateTime<Utc>,
}

// No Debug implementations for any structure containing credential material.
#[derive(Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Credential {
    Secret {
        value: String,
    },
    OAuth {
        config: Box<OAuthConfig>,
        tokens: Option<Tokens>,
    },
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OAuthConfig {
    pub authorization_url: String,
    pub token_url: String,
    pub client_id: String,
    #[serde(default)]
    pub client_secret: Option<String>,
    #[serde(default = "default_auth")]
    pub client_auth: String,
    pub redirect_uri: String,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub authorization_params: std::collections::BTreeMap<String, String>,
}

fn default_auth() -> String {
    "none".into()
}

#[derive(Serialize, Deserialize)]
pub struct Tokens {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
}

pub fn valid_name(name: &str) -> Result<()> {
    ensure!(
        !name.is_empty()
            && name.len() <= 64
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b)),
        "entry names must contain 1–64 ASCII letters, digits, hyphens or underscores"
    );
    Ok(())
}

pub fn environment(name: &str, explicit: Option<&str>) -> Result<String> {
    let env = explicit
        .map(str::to_owned)
        .unwrap_or_else(|| name.to_ascii_uppercase().replace('-', "_"));
    ensure!(
        !env.is_empty()
            && !env.starts_with(|c: char| c.is_ascii_digit())
            && env.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'),
        "invalid environment variable name"
    );
    Ok(env)
}

pub fn expiry(value: Option<&str>) -> Result<Option<DateTime<Utc>>> {
    let Some(value) = value else { return Ok(None) };
    if let Ok(date) = DateTime::parse_from_rfc3339(value) {
        ensure!(date > Utc::now(), "expiry must be in the future");
        return Ok(Some(date.with_timezone(&Utc)));
    }
    let unit_start = value
        .char_indices()
        .next_back()
        .map_or(0, |(index, _)| index);
    let (number, unit) = value.split_at(unit_start);
    let number: i64 = number.parse().map_err(|_| {
        anyhow::anyhow!("expiry must be RFC3339 or a duration such as 30m, 12h or 7d")
    })?;
    let multiplier = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86400,
        _ => bail!("invalid expiry unit"),
    };
    ensure!(number > 0, "expiry duration must be positive");
    let seconds = number
        .checked_mul(multiplier)
        .ok_or_else(|| anyhow::anyhow!("expiry too large"))?;
    Ok(Some(
        Utc::now()
            .checked_add_signed(
                chrono::Duration::try_seconds(seconds)
                    .ok_or_else(|| anyhow::anyhow!("expiry too large"))?,
            )
            .ok_or_else(|| anyhow::anyhow!("expiry too large"))?,
    ))
}

pub fn transport_url(value: &str) -> Result<url::Url> {
    let url = url::Url::parse(value).map_err(|_| anyhow::anyhow!("invalid URL"))?;
    ensure!(
        url.username().is_empty() && url.password().is_none() && url.fragment().is_none(),
        "URLs must not contain credentials or fragments"
    );
    ensure!(
        url.scheme() == "https"
            || (url.scheme() == "http"
                && matches!(url.host_str(), Some("127.0.0.1" | "[::1]" | "localhost"))),
        "HTTPS is required except for loopback fixtures"
    );
    ensure!(url.host_str().is_some(), "URL must have a host");
    Ok(url)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unsafe_identifiers_and_expiries_are_rejected() {
        assert!(expiry(None).unwrap().is_none());
        for name in ["../escape", "a/b", "", "a.b", "a\\b"] {
            assert!(valid_name(name).is_err());
        }
        assert_eq!(environment("my-token", None).unwrap(), "MY_TOKEN");
        assert!(environment("1abc", None).is_err());
        for exp in [
            "1日",
            "",
            "0m",
            "-2d",
            "999999999999999999d",
            "2000-01-01T00:00:00Z",
        ] {
            assert!(expiry(Some(exp)).is_err());
        }
        assert!(expiry(Some("30m")).unwrap().unwrap() > Utc::now());
    }
    #[test]
    fn insecure_remote_transports_are_rejected() {
        assert!(transport_url("http://example.com").is_err());
        assert!(transport_url("https://user:password@example.com").is_err());
        assert!(transport_url("http://127.0.0.1:1234").is_ok());
    }
}
