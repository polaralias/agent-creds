use crate::model::transport_url;
use anyhow::{Context, Result, bail, ensure};
use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    fs,
    net::TcpStream,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};
use tungstenite::{Message, WebSocket, stream::MaybeTlsStream};
use url::Url;

pub struct Capture {
    pub value: String,
    pub expires_at: Option<DateTime<Utc>>,
}

pub struct Options<'a> {
    pub url: &'a str,
    pub cookie: &'a str,
    pub browser: &'a str,
    pub executable: Option<&'a Path>,
    pub timeout: Duration,
    pub no_banner: bool,
    pub header: bool,
}

struct Browser {
    child: Child,
    // Profile is deleted only after the owned browser process has exited.
    _profile: tempfile::TempDir,
}
impl Drop for Browser {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub fn executable(browser: &str, explicit: Option<&Path>) -> Result<PathBuf> {
    if let Some(path) = explicit {
        ensure!(path.is_file(), "browser executable not found");
        return Ok(path.to_owned());
    }
    ensure!(
        matches!(browser, "auto" | "chrome" | "edge" | "chromium"),
        "browser must be auto, chrome, edge or chromium"
    );
    let mut candidates: Vec<(&str, PathBuf)> = Vec::new();
    #[cfg(windows)]
    for base in ["PROGRAMFILES", "PROGRAMFILES(X86)", "LOCALAPPDATA"] {
        if let Some(root) = std::env::var_os(base) {
            let root = PathBuf::from(root);
            candidates.push(("chrome", root.join("Google/Chrome/Application/chrome.exe")));
            candidates.push(("edge", root.join("Microsoft/Edge/Application/msedge.exe")));
            candidates.push(("chromium", root.join("Chromium/Application/chrome.exe")));
        }
    }
    #[cfg(target_os = "macos")]
    {
        candidates.push((
            "chrome",
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome".into(),
        ));
        candidates.push((
            "edge",
            "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge".into(),
        ));
        candidates.push((
            "chromium",
            "/Applications/Chromium.app/Contents/MacOS/Chromium".into(),
        ));
    }
    #[cfg(target_os = "linux")]
    for (kind, path) in [
        ("chrome", "/usr/bin/google-chrome"),
        ("edge", "/usr/bin/microsoft-edge"),
        ("chromium", "/usr/bin/chromium"),
        ("chromium", "/usr/bin/chromium-browser"),
    ] {
        candidates.push((kind, path.into()));
    }
    // Auto preference is stable regardless of installation root.
    for kind in ["chrome", "edge", "chromium"] {
        if browser == "auto" || browser == kind {
            if let Some((_, path)) = candidates.iter().find(|(k, p)| *k == kind && p.is_file()) {
                return Ok(path.clone());
            }
        }
    }
    bail!("requested browser not installed; use --browser-path to select a Chromium-based browser")
}

struct Cdp {
    socket: WebSocket<MaybeTlsStream<TcpStream>>,
    next_id: u64,
}
impl Cdp {
    fn connect(endpoint: &str) -> Result<Self> {
        let url = Url::parse(endpoint).context("invalid browser debug endpoint")?;
        ensure!(
            url.scheme() == "ws" && matches!(url.host_str(), Some("127.0.0.1" | "localhost")),
            "browser debug endpoint must be loopback"
        );
        let (mut socket, _) = tungstenite::connect(endpoint)
            .map_err(|_| anyhow::anyhow!("cannot connect to owned browser"))?;
        if let MaybeTlsStream::Plain(stream) = socket.get_mut() {
            stream.set_read_timeout(Some(Duration::from_millis(100)))?;
            stream.set_write_timeout(Some(Duration::from_secs(15)))?;
        }
        Ok(Self { socket, next_id: 0 })
    }
    fn call(&mut self, method: &str, params: Value, session: Option<&str>) -> Result<Value> {
        self.next_id += 1;
        let id = self.next_id;
        let mut request = json!({"id":id,"method":method,"params":params});
        if let Some(session) = session {
            request["sessionId"] = json!(session);
        }
        self.socket
            .send(Message::Text(request.to_string().into()))
            .map_err(|_| anyhow::anyhow!("browser connection lost"))?;
        let deadline = Instant::now() + Duration::from_secs(15);
        while Instant::now() < deadline {
            let message = match self.socket.read() {
                Ok(message) => message,
                Err(tungstenite::Error::Io(error))
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    // A short socket timeout is a scheduling delay, not a lost
                    // browser. Keep polling until this operation's deadline.
                    continue;
                }
                Err(_) => bail!("browser closed or stopped responding"),
            };
            if let Message::Text(text) = message {
                let response: Value = serde_json::from_str(&text)
                    .map_err(|_| anyhow::anyhow!("invalid browser response"))?;
                if response["id"].as_u64() == Some(id) {
                    // Protocol errors can include evaluated script or cookie data.
                    ensure!(
                        response.get("error").is_none(),
                        "browser operation failed; details suppressed"
                    );
                    return Ok(response["result"].clone());
                }
            }
        }
        bail!("browser operation timed out")
    }
}

pub fn overlay(name: &str, target: &str) -> String {
    let label = serde_json::to_string(&format!(
        "agent-creds · waiting for cookie {name} at {target} · log in normally"
    ))
    .unwrap();
    // Build text nodes, never HTML. Shadow DOM prevents the site's broad selectors
    // from styling the label; no inputs, links or pointer handling are installed.
    format!(
        r#"(() => {{
      if (window.__agentCredentialsOverlay) return;
      window.__agentCredentialsOverlay = true;
      const paint = () => {{
        if (!document.documentElement) return;
        let host = document.getElementById('__agent_credentials_notice');
        if (!host) {{
          host = document.createElement('div'); host.id = '__agent_credentials_notice';
          host.style.cssText = 'all:initial!important;position:fixed!important;bottom:0!important;left:0!important;right:0!important;z-index:2147483647!important;pointer-events:none!important;opacity:1!important;filter:none!important;mix-blend-mode:normal!important;display:block!important;';
          const root = host.attachShadow({{mode:'closed'}});
          const text = document.createElement('div');
          text.textContent = {label};
          text.style.cssText = 'all:initial;display:block;background:white;color:black;border:2px solid black;padding:10px 14px;font:14px/1.5 system-ui;pointer-events:none;';
          root.append(text); document.documentElement.append(host);
        }}
        if (!document.title.startsWith('agent-creds — ')) document.title = 'agent-creds — ' + document.title;
      }};
      paint(); setInterval(paint, 400);
    }})()"#
    )
}

pub fn select_cookie(cookies: &Value, name: &str, header: bool) -> Result<Option<Capture>> {
    let matches: Vec<_> = cookies
        .as_array()
        .context("invalid browser cookie result")?
        .iter()
        .filter(|cookie| cookie["name"].as_str() == Some(name))
        .collect();
    if matches.is_empty() {
        return Ok(None);
    }
    ensure!(
        matches.len() == 1,
        "multiple cookies with that name match the URL; specify a URL with an unambiguous host/path"
    );
    let cookie = matches[0];
    let value = cookie["value"].as_str().context("cookie value missing")?;
    ensure!(
        !value.is_empty() && !value.contains(['\0', '\r', '\n']),
        "cookie is empty or cannot be injected safely"
    );
    let expires_at = cookie["expires"]
        .as_f64()
        .filter(|v| *v > 0.0)
        .and_then(|v| DateTime::from_timestamp(v as i64, 0));
    ensure!(
        expires_at.is_none_or(|date| date > Utc::now()),
        "matching cookie is expired"
    );
    Ok(Some(Capture {
        value: if header {
            format!("{name}={value}")
        } else {
            value.to_owned()
        },
        expires_at,
    }))
}

pub fn scrape(options: &Options<'_>) -> Result<Capture> {
    let target = transport_url(options.url)?;
    ensure!(
        !options.cookie.is_empty()
            && options
                .cookie
                .bytes()
                .all(|b| b.is_ascii_graphic() && !b"()<>@,;:\\\"/[]?={} ".contains(&b)),
        "invalid cookie name"
    );
    let binary = executable(options.browser, options.executable)?;
    let profile = tempfile::Builder::new()
        .prefix("agent-creds-browser-")
        .tempdir()?;
    let child = Command::new(binary)
        .arg(format!("--user-data-dir={}", profile.path().display()))
        .args([
            "--remote-debugging-address=127.0.0.1",
            "--remote-debugging-port=0",
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-sync",
            "about:blank",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("cannot launch browser")?;
    let mut browser = Browser {
        child,
        _profile: profile,
    };
    let port_file = browser._profile.path().join("DevToolsActivePort");
    let startup = Instant::now() + Duration::from_secs(20);
    let endpoint = loop {
        ensure!(
            browser.child.try_wait()?.is_none(),
            "browser exited before capture started"
        );
        if let Ok(contents) = fs::read_to_string(&port_file) {
            let mut lines = contents.lines();
            if let (Some(port), Some(path)) = (lines.next(), lines.next()) {
                let port: u16 = port.parse().context("invalid debug port")?;
                ensure!(
                    path.starts_with("/devtools/browser/"),
                    "invalid browser debug path"
                );
                break format!("ws://127.0.0.1:{port}{path}");
            }
        }
        ensure!(
            Instant::now() < startup,
            "browser did not start its debugging interface"
        );
        thread::sleep(Duration::from_millis(100));
    };
    let mut cdp = Cdp::connect(&endpoint)?;
    let script = overlay(options.cookie, target.host_str().unwrap_or("target"));
    let mut sessions: HashMap<String, String> = HashMap::new();
    let created = cdp.call("Target.createTarget", json!({"url":"about:blank"}), None)?;
    let initial = created["targetId"]
        .as_str()
        .context("no browser target")?
        .to_owned();
    let mut navigated = false;
    let deadline = Instant::now() + options.timeout;
    let capture = (|| -> Result<Capture> {
        while Instant::now() < deadline {
            ensure!(
                browser.child.try_wait()?.is_none(),
                "capture browser closed; nothing stored"
            );
            let targets = cdp.call("Target.getTargets", json!({}), None)?;
            let mut capture_session = None;
            for info in targets["targetInfos"]
                .as_array()
                .context("invalid browser target list")?
            {
                if info["type"] != "page" {
                    continue;
                }
                let id = info["targetId"]
                    .as_str()
                    .context("invalid browser target")?;
                if !sessions.contains_key(id) {
                    let attached = cdp.call(
                        "Target.attachToTarget",
                        json!({"targetId":id,"flatten":true}),
                        None,
                    )?;
                    let session = attached["sessionId"]
                        .as_str()
                        .context("cannot attach browser page")?
                        .to_owned();
                    cdp.call("Page.enable", json!({}), Some(&session))?;
                    if !options.no_banner {
                        cdp.call(
                            "Page.addScriptToEvaluateOnNewDocument",
                            json!({"source":script}),
                            Some(&session),
                        )?;
                        cdp.call(
                            "Runtime.evaluate",
                            json!({"expression":script}),
                            Some(&session),
                        )?;
                    }
                    sessions.insert(id.into(), session);
                }
                if Url::parse(info["url"].as_str().unwrap_or(""))
                    .is_ok_and(|url| url.origin() == target.origin())
                {
                    capture_session = sessions.get(id).cloned();
                }
            }
            if !navigated {
                if let Some(session) = sessions.get(&initial) {
                    cdp.call(
                        "Page.navigate",
                        json!({"url":target.as_str()}),
                        Some(session),
                    )?;
                    navigated = true;
                }
            }
            if let Some(session) = capture_session {
                // Network.getCookies filters by URL using the browser's own
                // secure/domain/path rules and includes HttpOnly cookies.
                let result = cdp.call(
                    "Network.getCookies",
                    json!({"urls":[target.as_str()]}),
                    Some(&session),
                )?;
                if let Some(cookie) =
                    select_cookie(&result["cookies"], options.cookie, options.header)?
                {
                    return Ok(cookie);
                }
            }
            thread::sleep(Duration::from_millis(300));
        }
        bail!("cookie capture timed out; nothing stored")
    })();
    let _ = cdp.call("Browser.close", json!({}), None);
    capture
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn delayed_browser_response_survives_short_socket_timeouts() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("ws://{}", listener.local_addr().unwrap());
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut socket = tungstenite::accept(stream).unwrap();
            let request = socket.read().unwrap().into_text().unwrap();
            let request: Value = serde_json::from_str(&request).unwrap();
            thread::sleep(Duration::from_millis(350));
            socket
                .send(Message::Text(
                    json!({"id":request["id"],"result":{"ok":true}})
                        .to_string()
                        .into(),
                ))
                .unwrap();
        });
        let response = Cdp::connect(&endpoint)
            .unwrap()
            .call("Fixture.delay", json!({}), None)
            .unwrap();
        assert_eq!(response["ok"], true);
        server.join().unwrap();
    }
    #[test]
    fn only_requested_cookie_is_captured_and_ambiguity_is_rejected() {
        let cookies = json!([{"name":"tracking","value":"excluded","expires":-1},{"name":"session","value":"wanted","expires":-1}]);
        assert_eq!(
            select_cookie(&cookies, "session", false)
                .unwrap()
                .unwrap()
                .value,
            "wanted"
        );
        assert_eq!(
            select_cookie(&cookies, "session", true)
                .unwrap()
                .unwrap()
                .value,
            "session=wanted"
        );
        assert!(select_cookie(&cookies, "absent", false).unwrap().is_none());
        assert!(
            select_cookie(
                &json!([{"name":"session","value":"a"},{"name":"session","value":"b"}]),
                "session",
                false
            )
            .is_err()
        );
    }
    #[test]
    fn overlay_uses_safe_text_content() {
        let script = overlay("x</script>", "example.com");
        assert!(script.contains("textContent"));
        assert!(!script.contains("innerHTML"));
        assert!(script.contains("pointer-events:none"));
    }
}
