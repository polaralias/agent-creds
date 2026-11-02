#![cfg(windows)]
use agent_creds::{
    model::{Credential, Metadata},
    vault::Vault,
};
use assert_cmd::Command;
use chrono::Utc;
use predicates::prelude::*;
use std::{fs, path::Path};

fn cli(root: &Path) -> Command {
    let mut command = Command::new(assert_cmd::cargo::cargo_bin!("agent-creds"));
    command.arg("--vault-dir").arg(root);
    command
}

#[test]
fn dpapi_store_inject_remove_no_plaintext_and_child_exit_propagates() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("vault");
    let source = temp.path().join("input.txt");
    let fixture = "fixture-only-never-a-real-credential";
    fs::write(&source, format!("{fixture}\n")).unwrap();
    cli(&root)
        .args([
            "store",
            "demo",
            "--env",
            "AGENT_CREDS_TEST_TOKEN",
            "--from-file",
        ])
        .arg(&source)
        .assert()
        .success()
        .stdout(predicate::str::contains(fixture).not());
    assert!(!source.exists());
    let record = fs::read_to_string(root.join("demo.json")).unwrap();
    assert!(!record.contains(fixture));
    cli(&root)
        .args(["status", "--json"])
        .assert()
        .success()
        .stdout(predicate::str::contains(fixture).not());
    let script = "if ($env:AGENT_CREDS_TEST_TOKEN -eq 'fixture-only-never-a-real-credential') { exit 17 } else { exit 91 }";
    cli(&root)
        .args([
            "exec",
            "demo",
            "--",
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            script,
        ])
        .assert()
        .code(17)
        .stdout("");
    assert!(std::env::var_os("AGENT_CREDS_TEST_TOKEN").is_none());
    cli(&root)
        .args(["get", "demo", "--force"])
        .assert()
        .failure()
        .stdout("");
    cli(&root).args(["rm", "demo"]).assert().success();
    assert!(!root.join("demo.json").exists());
}

#[test]
fn tampering_expiry_or_ciphertext_fails_before_child_launch() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("vault");
    let meta = Metadata {
        name: "expired".into(),
        env: "EXPIRED_TEST".into(),
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
                    value: "fixture".into(),
                },
                false,
            )
            .unwrap();
    }
    cli(&root)
        .args([
            "exec",
            "expired",
            "--",
            "cmd.exe",
            "/c",
            "echo",
            "CHILD_RAN",
        ])
        .assert()
        .failure()
        .stdout("");
    let path = root.join("expired.json");
    let mut record: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    record["metadata"]["expires_at"] = serde_json::Value::Null;
    fs::write(&path, serde_json::to_vec(&record).unwrap()).unwrap();
    cli(&root)
        .args([
            "exec",
            "expired",
            "--",
            "cmd.exe",
            "/c",
            "echo",
            "CHILD_RAN",
        ])
        .assert()
        .failure()
        .stdout("")
        .stderr(predicate::str::contains("metadata does not match"));
    record["protected"] = serde_json::json!("Zm9yZ2Vk");
    fs::write(path, serde_json::to_vec(&record).unwrap()).unwrap();
    cli(&root)
        .args(["exec", "expired", "cmd.exe", "/c", "echo", "CHILD_RAN"])
        .assert()
        .failure()
        .stdout("");
}

#[test]
fn collision_preflight_preserves_source_and_duplicate_envs_fail() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("vault");
    let source = temp.path().join("input.txt");
    fs::write(&source, "fixture").unwrap();
    for name in ["one", "two"] {
        cli(&root)
            .args(["store", name, "--env", "DUPLICATE", "--keep", "--from-file"])
            .arg(&source)
            .assert()
            .success();
    }
    cli(&root)
        .args(["store", "one", "--from-file"])
        .arg(&source)
        .assert()
        .failure();
    assert_eq!(fs::read_to_string(&source).unwrap(), "fixture");
    cli(&root)
        .args(["exec", "one,two", "cmd.exe", "/c", "echo", "CHILD_RAN"])
        .assert()
        .failure()
        .stdout("");
    let held = Vault::open(Some(&root)).unwrap();
    cli(&root)
        .arg("list")
        .assert()
        .failure()
        .stderr(predicate::str::contains("busy"));
    drop(held);
}

#[test]
fn dotenv_dry_run_and_template_never_export_values() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("vault");
    let source = temp.path().join("fixture.env");
    fs::write(&source, "TEST_TOKEN=fixture-private\nEXCLUDED=value\n").unwrap();
    cli(&root)
        .arg("import-env")
        .arg(&source)
        .args(["--prefix", "TEST_", "--dry-run"])
        .assert()
        .success()
        .stdout(predicate::str::contains("fixture-private").not());
    assert!(!root.join("test-token.json").exists());
    cli(&root)
        .arg("import-env")
        .arg(&source)
        .args(["--prefix", "TEST_"])
        .assert()
        .success();
    assert!(source.exists());
    let out = temp.path().join("blank.env");
    cli(&root)
        .args(["template", "--out"])
        .arg(&out)
        .assert()
        .success();
    let template = fs::read_to_string(out).unwrap();
    assert!(template.contains("TEST_TOKEN="));
    assert!(!template.contains("fixture-private"));
}

#[test]
fn exec_refreshes_and_persists_rotated_oauth_credentials_before_child_launch() {
    use agent_creds::model::Tokens;
    use serde_json::json;
    use std::{collections::HashMap, thread, time::Duration};
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("vault");
    let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
    let base = format!("http://{}", server.server_addr());
    let config = serde_json::from_value(json!({
        "authorization_url":format!("{base}/authorize"),"token_url":format!("{base}/token"),
        "client_id":"fixture-client","redirect_uri":"http://127.0.0.1:43821/callback"
    }))
    .unwrap();
    let metadata = Metadata {
        name: "oauth-test".into(),
        env: "OAUTH_FIXTURE_ACCESS".into(),
        kind: "oauth".into(),
        expires_at: Some(Utc::now() - chrono::Duration::minutes(1)),
        updated_at: Utc::now(),
    };
    {
        let vault = Vault::open(Some(&root)).unwrap();
        vault
            .save(
                &metadata,
                &Credential::OAuth {
                    config,
                    tokens: Some(Tokens {
                        access_token: "old-access".into(),
                        refresh_token: Some("old-refresh".into()),
                        expires_at: metadata.expires_at,
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
        request.respond(tiny_http::Response::from_string(json!({"access_token":"new-access","refresh_token":"rotated-refresh","token_type":"Bearer","expires_in":3600}).to_string())).unwrap();
    });
    let script = "if ($env:OAUTH_FIXTURE_ACCESS -eq 'new-access') { exit 19 } else { exit 90 }";
    cli(&root)
        .args([
            "exec",
            "oauth-test",
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            script,
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
    assert_eq!(tokens.refresh_token.as_deref(), Some("rotated-refresh"));
    assert!(
        !fs::read_to_string(root.join("oauth-test.json"))
            .unwrap()
            .contains("rotated-refresh")
    );
}

#[test]
fn oauth_configure_encrypts_client_secret_removes_source_and_requires_login() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("vault");
    let source = temp.path().join("client.json");
    fs::write(
        &source,
        serde_json::json!({
            "authorization_url":"https://identity.example.com/authorize",
            "token_url":"https://identity.example.com/token", "client_id":"fixture-client-id",
            "client_secret":"fixture-config-secret","client_auth":"basic",
            "redirect_uri":"http://127.0.0.1:43821/callback","scopes":["read"]
        })
        .to_string(),
    )
    .unwrap();
    cli(&root)
        .args([
            "oauth",
            "configure",
            "example",
            "--env",
            "EXAMPLE_ACCESS",
            "--from-file",
        ])
        .arg(&source)
        .assert()
        .success()
        .stdout(predicate::str::contains("fixture-config-secret").not());
    assert!(!source.exists());
    let record = fs::read_to_string(root.join("example.json")).unwrap();
    assert!(!record.contains("fixture-config-secret"));
    assert!(!record.contains("fixture-client-id"));
    cli(&root)
        .args(["status", "--json"])
        .assert()
        .success()
        .stdout(predicate::str::contains("fixture-config-secret").not());
    cli(&root)
        .args(["exec", "example", "cmd.exe", "/c", "echo", "CHILD_RAN"])
        .assert()
        .failure()
        .stdout("")
        .stderr(predicate::str::contains("login required"));
}
