use agent_creds::browser::{self, Options};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};

// Explicit opt-in: this opens a real visible browser on a local fixture only.
#[test]
#[ignore = "opens an installed browser; run cargo test --test browser_local -- --ignored"]
fn captures_httponly_cookie_after_inert_overlay_appears() {
    let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
    let url = format!("http://{}/", server.server_addr());
    let overlay_seen = Arc::new(AtomicBool::new(false));
    let observed = overlay_seen.clone();
    let stop = Arc::new(AtomicBool::new(false));
    let stopped = stop.clone();
    let mock = thread::spawn(move || {
        while !stopped.load(Ordering::Relaxed) {
            let Some(request) = server.recv_timeout(Duration::from_millis(100)).unwrap() else {
                continue;
            };
            let response = match request.url() {
                "/" => tiny_http::Response::from_string(r#"<!doctype html><title>Local fixture</title>
                    <style>div {color:red!important; background:black!important; opacity:0!important}</style>
                    <script>const wait = setInterval(async () => {
                      const h = document.getElementById('__agent_credentials_notice');
                      if (!h || !document.title.startsWith('agent-creds — ')) return;
                      const style = getComputedStyle(h);
                      if (style.pointerEvents !== 'none' || style.opacity !== '1') return;
                      clearInterval(wait); await fetch('/overlay-ok'); await fetch('/set');
                    },100);</script>"#).with_header(tiny_http::Header::from_bytes("Content-Type","text/html; charset=utf-8").unwrap()),
                "/overlay-ok" => { observed.store(true, Ordering::Relaxed); tiny_http::Response::from_string("ok") },
                "/set" => tiny_http::Response::from_string("ok")
                    .with_header(tiny_http::Header::from_bytes("Set-Cookie","session_fixture=fixture-cookie; HttpOnly; Path=/; SameSite=Lax").unwrap())
                    .with_header(tiny_http::Header::from_bytes("Set-Cookie","tracking_fixture=must-not-capture; Path=/").unwrap()),
                _ => tiny_http::Response::from_string("missing").with_status_code(404),
            };
            let _ = request.respond(response);
        }
    });
    let result = browser::scrape(&Options {
        url: &url,
        cookie: "session_fixture",
        browser: "auto",
        executable: None,
        timeout: Duration::from_secs(20),
        no_banner: false,
        header: false,
    });
    stop.store(true, Ordering::Relaxed);
    mock.join().unwrap();
    let capture = result.unwrap();
    assert_eq!(capture.value, "fixture-cookie");
    assert!(overlay_seen.load(Ordering::Relaxed));
    assert!(capture.expires_at.is_none());
}

#[test]
#[ignore = "opens an installed browser; run cargo test --test browser_local -- --ignored"]
fn wrong_path_cookie_times_out_and_no_banner_is_honoured() {
    let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
    let url = format!("http://{}/public/", server.server_addr());
    let clean = Arc::new(AtomicBool::new(false));
    let observed = clean.clone();
    let stop = Arc::new(AtomicBool::new(false));
    let stopped = stop.clone();
    let mock = thread::spawn(move || {
        while !stopped.load(Ordering::Relaxed) {
            let Some(request) = server.recv_timeout(Duration::from_millis(100)).unwrap() else {
                continue;
            };
            let response = if request.url() == "/no-banner" {
                observed.store(true, Ordering::Relaxed);
                tiny_http::Response::from_string("ok")
            } else {
                tiny_http::Response::from_string(r#"<!doctype html><title>Fixture</title><script>
                  setTimeout(() => {if (!document.getElementById('__agent_credentials_notice') && document.title==='Fixture') fetch('/no-banner')},500);
                </script>"#)
                .with_header(tiny_http::Header::from_bytes("Content-Type","text/html; charset=utf-8").unwrap())
                .with_header(tiny_http::Header::from_bytes("Set-Cookie","path_fixture=wrong-scope; Path=/private/; HttpOnly").unwrap())
            };
            let _ = request.respond(response);
        }
    });
    let result = browser::scrape(&Options {
        url: &url,
        cookie: "path_fixture",
        browser: "auto",
        executable: None,
        timeout: Duration::from_secs(3),
        no_banner: true,
        header: false,
    });
    stop.store(true, Ordering::Relaxed);
    mock.join().unwrap();
    let error = match result {
        Ok(_) => panic!("wrong-path cookie captured"),
        Err(error) => error.to_string(),
    };
    assert!(error.contains("timed out"), "unexpected capture error: {error}");
    assert!(clean.load(Ordering::Relaxed));
}
