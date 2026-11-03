use crate::model::{OAuthConfig, Tokens, transport_url};
use anyhow::{Context, Result, bail, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use rand::RngCore;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    io::Read,
    time::{Duration, Instant},
};
use subtle::ConstantTimeEq;
use url::Url;
use zeroize::Zeroizing;

const RESERVED: &[&str] = &[
    "client_id",
    "client_secret",
    "redirect_uri",
    "response_type",
    "state",
    "scope",
    "code_challenge",
    "code_challenge_method",
    "code",
    "grant_type",
];

pub fn validate(config: &OAuthConfig) -> Result<Url> {
    let authorization = transport_url(&config.authorization_url)?;
    let token = transport_url(&config.token_url)?;
    ensure!(
        token.query().is_none(),
        "token endpoint must not have a query"
    );
    ensure!(
        !config.client_id.is_empty() && !config.client_id.contains('\0'),
        "client_id is required"
    );
    ensure!(
        config.scopes.iter().all(|s| !s.is_empty()
            && s.bytes()
                .all(|b| (0x21..=0x7e).contains(&b) && b != b'"' && b != b'\\')),
        "scopes must be nonempty OAuth scope tokens"
    );
    ensure!(
        matches!(config.client_auth.as_str(), "none" | "basic" | "post"),
        "client_auth must be none, basic or post"
    );
    if config.client_auth == "none" {
        ensure!(
            config.client_secret.is_none(),
            "set client_auth to basic or post when supplying a client secret"
        );
    } else {
        ensure!(
            config.client_secret.as_ref().is_some_and(|s| !s.is_empty()),
            "client authentication requires client_secret"
        );
    }
    for key in config.authorization_params.keys() {
        ensure!(
            !RESERVED.contains(&key.as_str()) && !key.is_empty(),
            "authorization_params cannot override OAuth security parameters"
        );
    }
    ensure!(
        !authorization
            .query_pairs()
            .any(|(k, _)| RESERVED.contains(&k.as_ref())),
        "authorization endpoint cannot contain reserved OAuth parameters"
    );
    let redirect =
        Url::parse(&config.redirect_uri).map_err(|_| anyhow::anyhow!("invalid redirect_uri"))?;
    ensure!(
        redirect.scheme() == "http"
            && redirect.host_str() == Some("127.0.0.1")
            && redirect.port().is_some_and(|p| p > 0)
            && redirect.query().is_none()
            && redirect.fragment().is_none()
            && redirect.username().is_empty()
            && redirect.password().is_none(),
        "redirect_uri must be http://127.0.0.1:<fixed-port>/<path> with no query or credentials"
    );
    Ok(redirect)
}

fn nonce() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn authorization_url(config: &OAuthConfig, state: &str, verifier: &str) -> Result<Url> {
    validate(config)?;
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    let mut url = Url::parse(&config.authorization_url)?;
    {
        let mut query = url.query_pairs_mut();
        query
            .append_pair("response_type", "code")
            .append_pair("client_id", &config.client_id)
            .append_pair("redirect_uri", &config.redirect_uri)
            .append_pair("state", state)
            .append_pair("code_challenge", &challenge)
            .append_pair("code_challenge_method", "S256");
        if !config.scopes.is_empty() {
            query.append_pair("scope", &config.scopes.join(" "));
        }
        for (key, value) in &config.authorization_params {
            query.append_pair(key, value);
        }
    }
    Ok(url)
}

pub fn callback_code(
    request_url: &str,
    expected_path: &str,
    state: &str,
) -> Result<Option<String>> {
    let url = Url::parse(&format!("http://127.0.0.1{request_url}"))
        .map_err(|_| anyhow::anyhow!("invalid callback"))?;
    if url.path() != expected_path {
        return Ok(None);
    }
    let pairs: Vec<_> = url.query_pairs().collect();
    let states: Vec<_> = pairs.iter().filter(|(k, _)| k == "state").collect();
    // Ignore unsolicited requests. They must not consume the login attempt.
    if states.len() != 1 || !bool::from(states[0].1.as_bytes().ct_eq(state.as_bytes())) {
        return Ok(None);
    }
    if pairs.iter().any(|(k, _)| k == "error") {
        bail!("authorization denied by provider");
    }
    let codes: Vec<_> = pairs.iter().filter(|(k, _)| k == "code").collect();
    ensure!(
        codes.len() == 1 && !codes[0].1.is_empty(),
        "callback must contain exactly one authorization code"
    );
    Ok(Some(codes[0].1.to_string()))
}

pub fn login(config: &OAuthConfig, timeout: Duration) -> Result<Tokens> {
    login_with(config, timeout, |url| {
        webbrowser::open(url.as_str())
            .map_err(|_| anyhow::anyhow!("could not open system browser"))?;
        Ok(())
    })
}

// Browser opening is injected so protocol tests can exercise the complete loopback
// flow without ever contacting a real authorization server or launching a browser.
pub fn login_with(
    config: &OAuthConfig,
    timeout: Duration,
    open: impl FnOnce(&Url) -> Result<()>,
) -> Result<Tokens> {
    let redirect = validate(config)?;
    let server = tiny_http::Server::http(("127.0.0.1", redirect.port().unwrap())).map_err(|_| anyhow::anyhow!("cannot bind OAuth loopback port; close the process using it or register another redirect"))?;
    let state = Zeroizing::new(nonce());
    let verifier = Zeroizing::new(nonce());
    let authorize = authorization_url(config, &state, &verifier)?;
    open(&authorize)?;
    eprintln!("Waiting for authorization in your browser (loopback callback only).");
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        let Some(request) = server
            .recv_timeout(Duration::from_millis(250))
            .context("OAuth callback listener failed")?
        else {
            continue;
        };
        let host_ok = request.headers().iter().any(|header| {
            header.field.equiv("Host")
                && header.value.as_str() == format!("127.0.0.1:{}", redirect.port().unwrap())
        });
        let parsed = if request.method() == &tiny_http::Method::Get && host_ok {
            callback_code(request.url(), redirect.path(), &state)
        } else {
            Ok(None)
        };
        match parsed {
            Ok(Some(code)) => {
                respond(
                    request,
                    200,
                    "agent-creds: authorization received. You may close this tab.",
                );
                return exchange(
                    config,
                    vec![
                        ("grant_type".into(), "authorization_code".into()),
                        ("code".into(), code),
                        ("redirect_uri".into(), config.redirect_uri.clone()),
                        ("code_verifier".into(), verifier.to_string()),
                    ],
                    None,
                );
            }
            Ok(None) => respond(
                request,
                400,
                "No matching agent-creds authorization request.",
            ),
            Err(error) => {
                respond(
                    request,
                    400,
                    "agent-creds: authorization failed. Return to the terminal.",
                );
                return Err(error);
            }
        }
    }
    bail!("OAuth authorization timed out; existing credentials were preserved")
}

fn respond(request: tiny_http::Request, code: u16, body: &str) {
    let mut response = tiny_http::Response::from_string(body).with_status_code(code);
    for (key, value) in [
        ("Cache-Control", "no-store"),
        (
            "Content-Security-Policy",
            "default-src 'none'; frame-ancestors 'none'",
        ),
        ("Referrer-Policy", "no-referrer"),
    ] {
        response.add_header(tiny_http::Header::from_bytes(key, value).unwrap());
    }
    let _ = request.respond(response);
}

pub fn refresh(config: &OAuthConfig, tokens: &Tokens) -> Result<Tokens> {
    validate(config)?;
    let refresh = tokens
        .refresh_token
        .as_ref()
        .context("no refresh token; run oauth login again")?;
    exchange(
        config,
        vec![
            ("grant_type".into(), "refresh_token".into()),
            ("refresh_token".into(), refresh.clone()),
        ],
        Some(refresh),
    )
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    token_type: String,
    refresh_token: Option<String>,
    expires_in: Option<u64>,
}

fn exchange(
    config: &OAuthConfig,
    mut form: Vec<(String, String)>,
    prior_refresh: Option<&String>,
) -> Result<Tokens> {
    let client = reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(30))
        .no_proxy()
        .build()
        .context("cannot create OAuth HTTP client")?;
    let mut request = client.post(&config.token_url);
    match config.client_auth.as_str() {
        "basic" => {
            // RFC 6749 §2.3.1 requires form-encoding both Basic components.
            let encode = |value: &str| {
                url::form_urlencoded::byte_serialize(value.as_bytes()).collect::<String>()
            };
            request = request.basic_auth(
                encode(&config.client_id),
                Some(encode(config.client_secret.as_deref().unwrap_or(""))),
            );
        }
        "post" => {
            form.push(("client_id".into(), config.client_id.clone()));
            form.push((
                "client_secret".into(),
                config.client_secret.clone().unwrap_or_default(),
            ));
        }
        _ => form.push(("client_id".into(), config.client_id.clone())),
    }
    let response = request.form(&form).send().map_err(|_| {
        anyhow::anyhow!("OAuth token request failed (transport error; details suppressed)")
    })?;
    ensure!(
        response.status().is_success(),
        "OAuth token endpoint refused request (HTTP {}); response body suppressed",
        response.status().as_u16()
    );
    let mut body = Zeroizing::new(Vec::new());
    response
        .take(1024 * 1024 + 1)
        .read_to_end(&mut body)
        .map_err(|_| anyhow::anyhow!("cannot read OAuth token response"))?;
    ensure!(
        body.len() <= 1024 * 1024,
        "OAuth token response exceeds limit"
    );
    let response: TokenResponse = serde_json::from_slice(&body)
        .map_err(|_| anyhow::anyhow!("invalid OAuth token response; response body suppressed"))?;
    ensure!(
        response.token_type.eq_ignore_ascii_case("bearer"),
        "only Bearer access tokens are supported"
    );
    ensure!(
        !response.access_token.is_empty() && !response.access_token.contains(['\0', '\r', '\n']),
        "provider returned unusable access token"
    );
    ensure!(
        response
            .refresh_token
            .as_ref()
            .is_none_or(|s| !s.is_empty()),
        "provider returned empty refresh token"
    );
    let expires_at = match response.expires_in {
        Some(seconds) => {
            ensure!(
                seconds > 0 && seconds <= 315_360_000,
                "invalid access token lifetime"
            );
            Some(Utc::now() + chrono::Duration::seconds(seconds as i64))
        }
        None => None,
    };
    Ok(Tokens {
        access_token: response.access_token,
        refresh_token: response.refresh_token.or_else(|| prior_refresh.cloned()),
        expires_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn config() -> OAuthConfig {
        serde_json::from_value(serde_json::json!({"authorization_url":"https://example.com/auth", "token_url":"https://example.com/token", "client_id":"public", "redirect_uri":"http://127.0.0.1:4567/callback", "scopes":["read", "offline_access"]})).unwrap()
    }
    #[test]
    fn pkce_matches_rfc7636_vector() {
        let url = authorization_url(
            &config(),
            "test-state",
            "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
        )
        .unwrap();
        let pairs: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
        assert_eq!(
            pairs["code_challenge"],
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
        assert_eq!(pairs["code_challenge_method"], "S256");
    }
    #[test]
    fn callbacks_require_exact_state_path_and_unique_parameters() {
        assert!(
            callback_code("/callback?code=ok&state=wrong", "/callback", "right")
                .unwrap()
                .is_none()
        );
        assert!(
            callback_code("/else?code=ok&state=right", "/callback", "right")
                .unwrap()
                .is_none()
        );
        assert!(
            callback_code("/callback?code=a&code=b&state=right", "/callback", "right").is_err()
        );
        assert!(
            callback_code(
                "/callback?code=a&state=right&state=right",
                "/callback",
                "right"
            )
            .unwrap()
            .is_none()
        );
        assert_eq!(
            callback_code("/callback?code=a&state=right", "/callback", "right")
                .unwrap()
                .unwrap(),
            "a"
        );
    }
    #[test]
    fn clients_cannot_override_security_parameters() {
        let mut cfg = config();
        cfg.authorization_params
            .insert("state".into(), "unsafe".into());
        assert!(validate(&cfg).is_err());
        cfg.authorization_params.clear();
        cfg.redirect_uri = "http://0.0.0.0:4567/callback".into();
        assert!(validate(&cfg).is_err());
    }
}
