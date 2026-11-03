#![cfg(target_os = "linux")]

use agent_creds::{
    model::{Credential, Metadata},
    vault::Vault,
};
use assert_cmd::Command;
use chrono::Utc;
use predicates::prelude::*;
use std::{fs, os::unix::fs::PermissionsExt, path::Path};

fn cli(root: &Path) -> Command {
    let mut command = Command::new(assert_cmd::cargo::cargo_bin!("agent-creds"));
    command.arg("--vault-dir").arg(root);
    command
}

#[test]
#[ignore = "requires a real unlocked Secret Service; run under scripts/check-linux.sh"]
fn native_keyring_encrypts_and_survives_process_restart() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("vault");
    let source = temp.path().join("input");
    let fixture = "linux-synthetic-credential";
    fs::write(&source, format!("{fixture}\n")).unwrap();
    cli(&root)
        .args([
            "store",
            "demo",
            "--env",
            "AGENT_CREDS_LINUX_FIXTURE",
            "--from-file",
        ])
        .arg(&source)
        .assert()
        .success()
        .stdout(predicate::str::contains(fixture).not());
    assert!(!source.exists());
    assert_eq!(
        fs::metadata(&root).unwrap().permissions().mode() & 0o777,
        0o700
    );
    let first = fs::read_to_string(root.join("demo.json")).unwrap();
    assert!(!first.contains(fixture));
    cli(&root)
        .args([
            "exec",
            "demo",
            "--",
            "/bin/sh",
            "-c",
            "test \"$AGENT_CREDS_LINUX_FIXTURE\" = linux-synthetic-credential && exit 17; exit 91",
        ])
        .assert()
        .code(17)
        .stdout("");
    assert!(std::env::var_os("AGENT_CREDS_LINUX_FIXTURE").is_none());
    cli(&root)
        .env(
            "DBUS_SESSION_BUS_ADDRESS",
            "unix:path=/nonexistent-agent-creds-test-bus",
        )
        .args(["status", "--json"])
        .assert()
        .success()
        .stdout(predicate::str::contains(fixture).not());
    fs::write(&source, format!("{fixture}\n")).unwrap();
    cli(&root)
        .args([
            "store",
            "demo",
            "--replace",
            "--env",
            "AGENT_CREDS_LINUX_FIXTURE",
            "--from-file",
        ])
        .arg(&source)
        .assert()
        .success();
    let second = fs::read_to_string(root.join("demo.json")).unwrap();
    let first: serde_json::Value = serde_json::from_str(&first).unwrap();
    let second: serde_json::Value = serde_json::from_str(&second).unwrap();
    assert_ne!(first["protected"], second["protected"]);
    cli(&root).args(["rm", "demo"]).assert().success();
    assert!(!root.join("demo.json").exists());
}

#[test]
#[ignore = "requires a real unlocked Secret Service; run under scripts/check-linux.sh"]
fn expiry_integrity_and_lock_fail_closed() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("vault");
    let meta = Metadata {
        name: "expired".into(),
        env: "LINUX_EXPIRY_FIXTURE".into(),
        kind: "secret".into(),
        expires_at: Some(Utc::now() - chrono::Duration::hours(1)),
        updated_at: Utc::now(),
    };
    {
        let vault = Vault::open(Some(&root)).unwrap();
        vault
            .save(
                &meta,
                &Credential::Secret {
                    value: "synthetic".into(),
                },
                false,
            )
            .unwrap();
        cli(&root)
            .arg("list")
            .assert()
            .failure()
            .stderr(predicate::str::contains("busy"));
    }
    cli(&root)
        .args(["exec", "expired", "/bin/echo", "CHILD_RAN"])
        .assert()
        .failure()
        .stdout("");
    let path = root.join("expired.json");
    let mut record: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    record["metadata"]["expires_at"] = serde_json::Value::Null;
    fs::write(&path, serde_json::to_vec(&record).unwrap()).unwrap();
    cli(&root)
        .args(["exec", "expired", "/bin/echo", "CHILD_RAN"])
        .assert()
        .failure()
        .stdout("")
        .stderr(predicate::str::contains("metadata does not match"));
    record["protected"] = serde_json::json!("Zm9yZ2Vk");
    fs::write(path, serde_json::to_vec(&record).unwrap()).unwrap();
    cli(&root)
        .args(["exec", "expired", "/bin/echo", "CHILD_RAN"])
        .assert()
        .failure()
        .stdout("");
}

#[test]
fn unavailable_secret_service_preserves_source_and_never_falls_back_to_plaintext() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("vault");
    let source = temp.path().join("input");
    fs::write(&source, "synthetic-no-bus-fixture").unwrap();
    cli(&root)
        .env(
            "DBUS_SESSION_BUS_ADDRESS",
            "unix:path=/nonexistent-agent-creds-test-bus",
        )
        .args(["store", "demo", "--from-file"])
        .arg(&source)
        .assert()
        .failure()
        .stdout("")
        .stderr(predicate::str::contains("keyring"));
    assert_eq!(
        fs::read_to_string(source).unwrap(),
        "synthetic-no-bus-fixture"
    );
    assert!(!root.join("demo.json").exists());
}

#[test]
#[ignore = "requires a real unlocked Secret Service; run under scripts/check-linux.sh"]
fn oauth_refresh_rotation_is_persisted_before_linux_child_launch() {
    use agent_creds::model::Tokens;
    use serde_json::json;
    use std::{collections::HashMap, thread, time::Duration};
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("vault");
    let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
    let base = format!("http://{}", server.server_addr());
    let config=serde_json::from_value(json!({"authorization_url":format!("{base}/authorize"),"token_url":format!("{base}/token"),"client_id":"linux-fixture-client","redirect_uri":"http://127.0.0.1:43821/callback"})).unwrap();
    let meta = Metadata {
        name: "oauth-test".into(),
        env: "LINUX_OAUTH_ACCESS".into(),
        kind: "oauth".into(),
        expires_at: Some(Utc::now() - chrono::Duration::minutes(1)),
        updated_at: Utc::now(),
    };
    {
        let vault = Vault::open(Some(&root)).unwrap();
        vault
            .save(
                &meta,
                &Credential::OAuth {
                    config,
                    tokens: Some(Tokens {
                        access_token: "old-access".into(),
                        refresh_token: Some("old-refresh".into()),
                        expires_at: meta.expires_at,
                    }),
                },
                false,
            )
            .unwrap();
    }
    let mock = thread::spawn(move || {
        let mut request = server
            .recv_timeout(Duration::from_secs(10))
            .unwrap()
            .unwrap();
        let mut body = String::new();
        request.as_reader().read_to_string(&mut body).unwrap();
        let form: HashMap<_, _> = url::form_urlencoded::parse(body.as_bytes())
            .into_owned()
            .collect();
        assert_eq!(form["refresh_token"], "old-refresh");
        request.respond(tiny_http::Response::from_string(json!({"access_token":"new-linux-access","refresh_token":"rotated-linux-refresh","token_type":"Bearer","expires_in":3600}).to_string())).unwrap();
    });
    cli(&root)
        .args([
            "exec",
            "oauth-test",
            "/bin/sh",
            "-c",
            "test \"$LINUX_OAUTH_ACCESS\" = new-linux-access && exit 19; exit 90",
        ])
        .assert()
        .code(19)
        .stdout("");
    mock.join().unwrap();
    let vault = Vault::open(Some(&root)).unwrap();
    let (meta, credential) = vault.load("oauth-test").unwrap();
    assert!(meta.expires_at.unwrap() > Utc::now());
    let Credential::OAuth {
        tokens: Some(tokens),
        ..
    } = credential
    else {
        panic!("OAuth tokens missing")
    };
    assert_eq!(
        tokens.refresh_token.as_deref(),
        Some("rotated-linux-refresh")
    );
    assert!(
        !fs::read_to_string(root.join("oauth-test.json"))
            .unwrap()
            .contains("rotated-linux-refresh")
    );
}
