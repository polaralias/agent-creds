use agent_creds::{
    model::{OAuthConfig, Tokens},
    oauth,
};
use chrono::Utc;
use serde_json::json;
use std::{collections::HashMap, net::TcpListener, sync::mpsc, thread, time::Duration};

fn fixture() -> (tiny_http::Server, String) {
    let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
    let base = format!("http://{}", server.server_addr());
    (server, base)
}

fn config(base: &str, redirect_port: u16) -> OAuthConfig {
    serde_json::from_value(json!({
        "authorization_url":format!("{base}/authorize"), "token_url":format!("{base}/token"),
        "client_id":"fixture-client", "client_secret":"fixture-secret", "client_auth":"post",
        "redirect_uri":format!("http://127.0.0.1:{redirect_port}/callback"),
        "scopes":["read", "offline_access"], "authorization_params":{"access_type":"offline"}
    }))
    .unwrap()
}

#[test]
fn complete_loopback_pkce_login_ignores_forged_callback_then_exchanges_code() {
    let (server, base) = fixture();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let cfg = config(&base, port);
    let (sender, receiver) = mpsc::channel();
    let token_thread = thread::spawn(move || {
        let mut request = server
            .recv_timeout(Duration::from_secs(10))
            .unwrap()
            .unwrap();
        assert_eq!(request.url(), "/token");
        let mut body = String::new();
        request.as_reader().read_to_string(&mut body).unwrap();
        let form: HashMap<_, _> = url::form_urlencoded::parse(body.as_bytes())
            .into_owned()
            .collect();
        assert_eq!(form["grant_type"], "authorization_code");
        assert_eq!(form["code"], "fixture-code");
        assert_eq!(form["client_secret"], "fixture-secret");
        assert_eq!(form["code_verifier"].len(), 43);
        assert_eq!(
            form["redirect_uri"],
            format!("http://127.0.0.1:{port}/callback")
        );
        request.respond(tiny_http::Response::from_string(json!({"access_token":"fixture-access", "token_type":"Bearer", "refresh_token":"fixture-refresh", "expires_in":3600}).to_string())).unwrap();
    });
    let callback_thread = thread::spawn(move || {
        let url: url::Url = receiver.recv_timeout(Duration::from_secs(10)).unwrap();
        let query: HashMap<_, _> = url.query_pairs().into_owned().collect();
        assert_eq!(query["code_challenge_method"], "S256");
        assert_eq!(query["scope"], "read offline_access");
        assert_eq!(query["access_type"], "offline");
        assert!(!query.contains_key("client_secret"));
        let client = reqwest::blocking::Client::builder()
            .no_proxy()
            .build()
            .unwrap();
        let forged = format!("http://127.0.0.1:{port}/callback?state=forged&code=no");
        assert_eq!(client.get(forged).send().unwrap().status(), 400);
        let mut callback = url::Url::parse(&query["redirect_uri"]).unwrap();
        callback
            .query_pairs_mut()
            .append_pair("state", &query["state"])
            .append_pair("code", "fixture-code");
        assert_eq!(client.get(callback).send().unwrap().status(), 200);
    });
    let tokens = oauth::login_with(&cfg, Duration::from_secs(10), |url| {
        sender.send(url.clone()).unwrap();
        Ok(())
    })
    .unwrap();
    assert_eq!(tokens.access_token, "fixture-access");
    assert_eq!(tokens.refresh_token.as_deref(), Some("fixture-refresh"));
    assert!(tokens.expires_at.unwrap() > Utc::now());
    callback_thread.join().unwrap();
    token_thread.join().unwrap();
}

#[test]
fn refresh_rotates_and_then_preserves_the_latest_refresh_token() {
    let (server, base) = fixture();
    let cfg = config(&base, 4321);
    let mock = thread::spawn(move || {
        for (expected, rotated) in [
            ("first-refresh", Some("second-refresh")),
            ("second-refresh", None),
        ] {
            let mut request = server
                .recv_timeout(Duration::from_secs(10))
                .unwrap()
                .unwrap();
            let mut body = String::new();
            request.as_reader().read_to_string(&mut body).unwrap();
            let form: HashMap<_, _> = url::form_urlencoded::parse(body.as_bytes())
                .into_owned()
                .collect();
            assert_eq!(form["refresh_token"], expected);
            assert_eq!(form["grant_type"], "refresh_token");
            let mut response =
                json!({"access_token":"new-access","token_type":"bearer","expires_in":3600});
            if let Some(token) = rotated {
                response["refresh_token"] = json!(token);
            }
            request
                .respond(tiny_http::Response::from_string(response.to_string()))
                .unwrap();
        }
    });
    let original = Tokens {
        access_token: "old-access".into(),
        refresh_token: Some("first-refresh".into()),
        expires_at: None,
    };
    let rotated = oauth::refresh(&cfg, &original).unwrap();
    assert_eq!(rotated.refresh_token.as_deref(), Some("second-refresh"));
    let preserved = oauth::refresh(&cfg, &rotated).unwrap();
    assert_eq!(preserved.refresh_token.as_deref(), Some("second-refresh"));
    mock.join().unwrap();
}

#[test]
fn token_errors_do_not_include_provider_response_or_follow_redirects() {
    let (server, base) = fixture();
    let cfg = config(&base, 4321);
    let mock = thread::spawn(move || {
        let request = server
            .recv_timeout(Duration::from_secs(10))
            .unwrap()
            .unwrap();
        let response = tiny_http::Response::from_string("fixture-sensitive-error")
            .with_status_code(302)
            .with_header(
                tiny_http::Header::from_bytes("Location", "http://127.0.0.1:1/must-not-follow")
                    .unwrap(),
            );
        request.respond(response).unwrap();
    });
    let original = Tokens {
        access_token: "old".into(),
        refresh_token: Some("refresh".into()),
        expires_at: None,
    };
    let error = match oauth::refresh(&cfg, &original) {
        Ok(_) => panic!("redirect accepted"),
        Err(e) => e.to_string(),
    };
    assert!(error.contains("302"));
    assert!(!error.contains("fixture-sensitive-error"));
    mock.join().unwrap();
}

#[test]
fn confidential_basic_client_uses_encoded_header_and_keeps_secret_out_of_body() {
    use base64::{Engine, engine::general_purpose::STANDARD};
    let (server, base) = fixture();
    let mut cfg = config(&base, 4321);
    cfg.client_auth = "basic".into();
    cfg.client_id = "client:with spaces".into();
    cfg.client_secret = Some("secret/with:punctuation".into());
    let mock = thread::spawn(move || {
        let mut request = server
            .recv_timeout(Duration::from_secs(10))
            .unwrap()
            .unwrap();
        let header = request
            .headers()
            .iter()
            .find(|h| h.field.equiv("Authorization"))
            .unwrap();
        assert_eq!(
            header.value.as_str(),
            format!(
                "Basic {}",
                STANDARD.encode("client%3Awith+spaces:secret%2Fwith%3Apunctuation")
            )
        );
        let mut body = String::new();
        request.as_reader().read_to_string(&mut body).unwrap();
        let form: HashMap<_, _> = url::form_urlencoded::parse(body.as_bytes())
            .into_owned()
            .collect();
        assert!(!form.contains_key("client_secret"));
        assert!(!form.contains_key("client_id"));
        request
            .respond(tiny_http::Response::from_string(
                json!({"access_token":"fresh","token_type":"Bearer","expires_in":3600}).to_string(),
            ))
            .unwrap();
    });
    let token = Tokens {
        access_token: "old".into(),
        refresh_token: Some("refresh".into()),
        expires_at: None,
    };
    assert_eq!(oauth::refresh(&cfg, &token).unwrap().access_token, "fresh");
    mock.join().unwrap();
}
