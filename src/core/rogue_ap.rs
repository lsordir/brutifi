/*!
 * Fake (rogue) open access point hosting
 *
 * Broadcasts an open — i.e. password-less — test access point that nearby
 * clients can join freely. On macOS the built-in Wi-Fi card can only act as
 * an AP through the system's Internet Sharing service, so this module drives
 * that service programmatically:
 *
 * 1. `com.apple.nat.plist` is rewritten with a sharing configuration that has
 *    no network key (open network) and the requested `NetworkName`. The
 *    previous file is backed up and put back on stop.
 * 2. The shared network name also defaults to the Mac's *Computer Name*, so
 *    the name is temporarily changed to the requested SSID and restored on
 *    stop (belt and braces with `NetworkName`).
 * 3. The sharing daemon is enabled + kicked. Its label is
 *    `com.apple.NetworkSharing` on macOS 26+ and `com.apple.InternetSharing`
 *    on older systems — resolved at runtime.
 *
 * Everything is reversible: `stop_fake_ap()` undoes all steps. Wi-Fi is the
 * hosting adapter, so Internet Sharing needs an uplink service other than
 * Wi-Fi (Ethernet, USB adapter, or the Thunderbolt bridge).
 *
 * Every step is appended to /tmp/brutifi_fakeap.log for debugging.
 */

use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};

const NAT_PLIST: &str = "/Library/Preferences/SystemConfiguration/com.apple.nat.plist";
const BACKUP_PLIST: &str = "/tmp/brutifi_nat.plist.bak";
const STATE_FILE: &str = "/tmp/brutifi_fakeap_state.json";
const LOG_FILE: &str = "/tmp/brutifi_fakeap.log";
const START_SCRIPT: &str = "/tmp/brutifi_fakeap_start.swift";
const STATUS_SCRIPT: &str = "/tmp/brutifi_fakeap_status.swift";

/// How long `start_fake_ap` waits for the hosted network to appear.
const AP_UP_TIMEOUT: Duration = Duration::from_secs(15);
/// Interval between AP-up status checks.
const AP_POLL_INTERVAL: Duration = Duration::from_millis(700);

/// Live state of the hosted access point.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FakeApStatus {
    /// The Mac is broadcasting a hosted network (`Some` = broadcast SSID).
    Up(Option<String>),
    /// No hosted network.
    Down,
}

impl FakeApStatus {
    pub fn is_up(&self) -> bool {
        matches!(self, FakeApStatus::Up(_))
    }
}

/// Snapshot of everything `start_fake_ap` changes, restored by `stop_fake_ap`.
/// The Linux fields are only set by the hostapd backend.
#[derive(Default, serde::Serialize, serde::Deserialize)]
struct SavedConfig {
    #[serde(default)]
    computer_name: String,
    #[serde(default)]
    had_nat_plist: bool,
    /// Linux: PID of the spawned hostapd process.
    #[serde(default)]
    hostapd_pid: Option<u32>,
    /// Linux: PID of the spawned dnsmasq process.
    #[serde(default)]
    dnsmasq_pid: Option<u32>,
    /// Linux: wireless interface hosting the AP.
    #[serde(default)]
    iface: Option<String>,
}

/// Start broadcasting an open (no password) fake access point.
///
/// Blocks until the hosted network is confirmed up (or times out and rolls
/// every change back).
pub fn start_fake_ap(ssid: &str) -> Result<()> {
    ensure_root()?;

    let ssid = ssid.trim();
    if ssid.is_empty() {
        return Err(anyhow!("SSID must not be empty"));
    }
    if ssid.len() > 32 {
        return Err(anyhow!(
            "SSID too long: {} bytes (Wi-Fi allows at most 32)",
            ssid.len()
        ));
    }

    log_step(&format!("start_fake_ap('{ssid}')"));

    // Refuse to hijack a hosted network we did not start (e.g. one enabled
    // from System Settings) — stopping it later would kill the user's setup.
    if let FakeApStatus::Up(current) = fake_ap_status() {
        return Err(anyhow!(
            "a hosted network is already broadcasting ('{}'). Stop it (here or in System Settings → Sharing) first.",
            current.unwrap_or_else(|| "<unknown>".to_string())
        ));
    }

    // Linux backend: real AP via hostapd + dnsmasq (no Internet Sharing).
    if cfg!(target_os = "linux") {
        return start_fake_ap_linux(ssid);
    }

    // 1. Snapshot everything we are about to change.
    let saved = snapshot_config()?;

    // 2..=5. Bring the AP up; roll back fully on any failure.
    match bring_up_ap(ssid) {
        Ok(()) => {
            log_step("AP is up");
            Ok(())
        }
        Err(e) => {
            log_step(&format!("failed, rolling back: {e}"));
            let _ = rollback(&saved);
            Err(e)
        }
    }
}

/// Stop the fake AP and restore the previous configuration exactly.
pub fn stop_fake_ap() -> Result<()> {
    ensure_root()?;
    log_step("stop_fake_ap()");

    if cfg!(target_os = "linux") {
        return stop_fake_ap_linux();
    }

    let disable_result = disable_internet_sharing();
    log_step(&format!("disable daemon: {:?}", disable_result));

    // Restore the saved computer name / NAT config if this app started the AP.
    if let Ok(data) = fs::read_to_string(STATE_FILE) {
        if let Ok(saved) = serde_json::from_str::<SavedConfig>(&data) {
            rollback(&saved)?;
        }
    }

    log_step("stop_fake_ap done");
    disable_result
}

/// Whether a hosted (AP mode) network is currently broadcasting.
pub fn fake_ap_status() -> FakeApStatus {
    if cfg!(target_os = "linux") {
        return fake_ap_status_linux();
    }
    match run_swift(STATUS_SCRIPT, STATUS_SCRIPT_SOURCE, &[]) {
        Ok(out) if out.starts_with("up:") => {
            let ssid = out[3..].trim();
            FakeApStatus::Up(if ssid.is_empty() {
                None
            } else {
                Some(ssid.to_string())
            })
        }
        // CoreWLAN does not report hostAP on every macOS build; fall back to
        // the sharing daemon + NAT config state.
        _ => {
            if sharing_daemon_active() && nat_airport_enabled() {
                FakeApStatus::Up(None)
            } else {
                FakeApStatus::Down
            }
        }
    }
}

// --- Steps -----------------------------------------------------------------

/// Snapshot the computer name + sharing plist so `rollback` can restore them.
fn snapshot_config() -> Result<SavedConfig> {
    let computer_name = run_command("scutil", &["--get", "ComputerName"])
        .context("failed to read the current computer name")?;

    let had_nat_plist = Path::new(NAT_PLIST).exists();
    if had_nat_plist {
        fs::copy(NAT_PLIST, BACKUP_PLIST).context("failed to back up the sharing configuration")?;
    }

    log_step(&format!(
        "snapshot: computer_name='{computer_name}', had_nat_plist={had_nat_plist}"
    ));

    let saved = SavedConfig {
        computer_name,
        had_nat_plist,
        ..SavedConfig::default()
    };

    if let Ok(json) = serde_json::to_string(&saved) {
        let _ = fs::write(STATE_FILE, json);
    }

    Ok(saved)
}

/// Steps 2..=5 of `start_fake_ap`: configure, rename, enable, verify.
fn bring_up_ap(ssid: &str) -> Result<()> {
    // 2. Write the open (no network key) sharing configuration. The script
    //    also powers Wi-Fi on and disassociates it as a client.
    let uplink_info = run_swift(START_SCRIPT, START_SCRIPT_SOURCE, &[ssid])
        .context("failed to configure Internet Sharing")?;
    if !uplink_info.is_empty() {
        log_step(&uplink_info);
    }

    // 3. The shared network name also mirrors the computer name.
    run_command("scutil", &["--set", "ComputerName", ssid])
        .context("failed to set the network name")?;
    log_step(&format!("computer name set to '{ssid}'"));

    // 4. Enable + start the sharing daemon.
    enable_internet_sharing()?;

    // 5. Wait until the Wi-Fi interface (or the daemon) confirms hosting.
    let deadline = Instant::now() + AP_UP_TIMEOUT;
    loop {
        if fake_ap_status().is_up() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(anyhow!(
                "the open AP did not come up within {} s. See {} for details. Keep Wi-Fi turned ON (BrutiFi disconnects it from any network itself); a VPN can also block sharing — try disconnecting it.",
                AP_UP_TIMEOUT.as_secs(),
                LOG_FILE
            ));
        }
        std::thread::sleep(AP_POLL_INTERVAL);
    }
}

/// Undo every change made by `start_fake_ap` (best effort per step).
fn rollback(saved: &SavedConfig) -> Result<()> {
    disable_internet_sharing().ok();

    if saved.had_nat_plist {
        fs::copy(BACKUP_PLIST, NAT_PLIST).context("failed to restore the sharing configuration")?;
    } else if Path::new(NAT_PLIST).exists() {
        fs::remove_file(NAT_PLIST).context("failed to remove the sharing configuration")?;
    }

    run_command("scutil", &["--set", "ComputerName", &saved.computer_name])
        .context("failed to restore the computer name")?;

    let _ = fs::remove_file(STATE_FILE);
    Ok(())
}

// --- Internet Sharing daemon -------------------------------------------------

/// The sharing daemon is `com.apple.NetworkSharing` on macOS 26+ and
/// `com.apple.InternetSharing` on older systems. Returns `(label, plist)`.
fn sharing_daemon() -> (&'static str, &'static str) {
    const NEW_PLIST: &str = "/System/Library/LaunchDaemons/com.apple.NetworkSharing.plist";
    const OLD_PLIST: &str = "/System/Library/LaunchDaemons/com.apple.InternetSharing.plist";
    if Path::new(NEW_PLIST).exists() {
        ("com.apple.NetworkSharing", NEW_PLIST)
    } else {
        ("com.apple.InternetSharing", OLD_PLIST)
    }
}

fn enable_internet_sharing() -> Result<()> {
    let (label, plist) = sharing_daemon();
    let service = format!("system/{label}");

    let enabled = run_command("launchctl", &["load", "-w", plist]).is_ok()
        || (run_command("launchctl", &["enable", service.as_str()]).is_ok()
            && run_command("launchctl", &["kickstart", "-k", service.as_str()]).is_ok());

    if !enabled {
        return Err(anyhow!(
            "launchctl could not enable {label} — see {LOG_FILE} for command output"
        ));
    }

    // Nudge the daemon so it (re)reads the NAT configuration.
    let kick = run_command("launchctl", &["kickstart", "-k", service.as_str()]);
    log_step(&format!(
        "enable {label}: load/enable ok, kickstart: {kick:?}"
    ));
    Ok(())
}

fn disable_internet_sharing() -> Result<()> {
    let (label, plist) = sharing_daemon();
    let service = format!("system/{label}");

    // Stop the daemon if it is running (best effort — bootout errors when idle).
    let _ = run_command("launchctl", &["bootout", service.as_str()]);
    let _ = run_command("launchctl", &["kill", "SIGTERM", service.as_str()]);

    let disabled = run_command("launchctl", &["unload", "-w", plist]).is_ok()
        || run_command("launchctl", &["disable", service.as_str()]).is_ok();

    if disabled {
        Ok(())
    } else {
        Err(anyhow!("launchctl could not disable {label}"))
    }
}

/// launchd reports the sharing daemon as `state = running`.
fn sharing_daemon_active() -> bool {
    let (label, _) = sharing_daemon();
    let service = format!("system/{label}");
    run_command("launchctl", &["print", service.as_str()])
        .map(|out| out.contains("state = running"))
        .unwrap_or(false)
}

/// Whether the NAT plist asks for a Wi-Fi (AirPort) shared network.
fn nat_airport_enabled() -> bool {
    run_command(
        "plutil",
        &["-extract", "NAT.AirPort.Enabled", "raw", NAT_PLIST],
    )
    .map(|v| v.trim() == "1")
    .unwrap_or(false)
}

// --- Helpers ----------------------------------------------------------------

fn ensure_root() -> Result<()> {
    if unsafe { libc::geteuid() } == 0 {
        Ok(())
    } else {
        Err(anyhow!(
            "root privileges required — run BrutiFi with sudo to host a fake AP"
        ))
    }
}

/// Append a timestamped step to the fake AP log for debugging.
fn log_step(msg: &str) {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    println!("[rogue_ap] {msg}");
    if let Ok(mut file) = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(LOG_FILE)
    {
        let _ = writeln!(file, "{ts}  {msg}");
    }
}

fn run_command(program: &str, args: &[&str]) -> Result<String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("failed to spawn '{}'", program))?;

    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(anyhow!(
            "'{} {}' failed: {}",
            program,
            args.join(" "),
            stderr
        ));
    }
    Ok(stdout)
}

/// Write a Swift script to /tmp and run it, returning its trimmed stdout.
fn run_swift(script_path: &str, source: &str, args: &[&str]) -> Result<String> {
    fs::write(script_path, source).with_context(|| format!("failed to write {}", script_path))?;

    let output = Command::new("swift")
        .arg(script_path)
        .args(args)
        .output()
        .context("failed to execute Swift. Is Xcode Command Line Tools installed?")?;

    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();

    if !output.status.success() {
        let detail = if stderr.is_empty() {
            format!("exit code {:?}", output.status.code())
        } else {
            stderr
        };
        log_step(&format!("swift {script_path} failed: {detail}"));
        return Err(anyhow!("Swift script failed: {}", detail));
    }

    Ok(stdout)
}

// --- Swift scripts ----------------------------------------------------------

const START_SCRIPT_SOURCE: &str = r#"
import CoreWLAN
import Foundation
import SystemConfiguration

// Configure Internet Sharing for an open (password-less) hosted network.
// Wi-Fi is the hosting adapter, so the shared "from" service must be a
// non-Wi-Fi service. Also makes sure Wi-Fi is powered on and disassociated.

func fail(_ code: Int32, _ message: String) -> Never {
    FileHandle.standardError.write((message + "\n").data(using: .utf8)!)
    exit(code)
}

let client = CWWiFiClient.shared()

// The Wi-Fi adapter must be powered on (but not associated) to host.
if let iface = client.interface() {
    if !iface.powerOn() {
        try? iface.setPower(true)
        print("wifi powered on")
    }
    // Free the adapter if it is still associated as a client.
    iface.disassociate()
}

// Wait briefly until the interface reports itself.
var wifiNames = client.interfaceNames() ?? []
for _ in 0..<20 where wifiNames.isEmpty {
    Thread.sleep(forTimeInterval: 0.2)
    wifiNames = client.interfaceNames() ?? []
}
guard !wifiNames.isEmpty else {
    fail(2, "no Wi-Fi interface found — keep Wi-Fi turned on, BrutiFi disconnects it itself")
}

guard let prefs = SCPreferencesCreate(nil, "brutifi" as CFString, nil),
      let services = SCPreferencesGetValue(prefs, kSCPrefNetworkServices) as? [String: [String: Any]]
else {
    fail(3, "cannot read network services")
}

let store = SCDynamicStoreCreate(nil, "brutifi" as CFString, nil, nil)
func hasIPv4(_ device: String) -> Bool {
    guard let store = store,
          let v = SCDynamicStoreCopyValue(store, "State:/Network/Interface/\(device)/IPv4" as CFString) as? [String: Any],
          let addrs = v["Addresses"] as? [String]
    else { return false }
    return !addrs.isEmpty
}

// Uplink candidates: Ethernet-typed services (built-in, USB/Thunderbolt
// adapters, the Thunderbolt bridge). Wi-Fi is excluded because it hosts the
// network itself.
var wired: [(uuid: String, device: String, name: String, active: Int)] = []
for (uuid, service) in services {
    guard let iface = service["Interface"] as? [String: Any],
          let device = iface["DeviceName"] as? String,
          (iface["Type"] as? String) == "Ethernet",
          !wifiNames.contains(device)
    else { continue }
    let name = (service["UserDefinedName"] as? String) ?? device
    let active = hasIPv4(device) ? 1 : 0
    wired.append((uuid, device, name, active))
}
// Deterministic order: active first, then by device name (dict order is random).
wired.sort { l, r in
    if l.active != r.active { return l.active > r.active }
    return l.device < r.device
}

var uplink = wired.first
if let store = store,
   let global = SCDynamicStoreCopyValue(store, "State:/Network/Global/IPv4" as CFString) as? [String: Any],
   let primary = global["PrimaryService"] as? String,
   let match = wired.first(where: { $0.uuid == primary })
{
    uplink = match
}

guard let chosen = uplink else {
    fail(4, "no uplink service found — Internet Sharing needs a non-Wi-Fi service (Ethernet/USB adapter or Thunderbolt bridge)")
}

let ssid = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : ""

print("uplink: '\(chosen.name)' (\(chosen.device))\(chosen.active == 1 ? ", active" : ", inactive")")

// "AirPort" without a "NetworkKey" => open network, no password.
var airport: [String: Any] = ["Enabled": 1, "Channel": 0]
if !ssid.isEmpty {
    airport["NetworkName"] = ssid
}

let nat: [String: Any] = [
    "NAT": [
        "AirPort": airport,
        "Enabled": 1,
        "PrimaryService": chosen.uuid,
    ] as [String: Any],
]

let url = URL(fileURLWithPath: "/Library/Preferences/SystemConfiguration/com.apple.nat.plist")
if !(nat as NSDictionary).write(to: url, atomically: true) {
    fail(5, "failed to write com.apple.nat.plist (running as root?)")
}

print("nat plist written — open network'\(ssid.isEmpty ? "" : " '\(ssid)'")' configured")
"#;

const STATUS_SCRIPT_SOURCE: &str = r#"
import CoreWLAN
import Foundation

// While Internet Sharing hosts a network, the Wi-Fi interface reports
// hostAP mode and its SSID is the hosted network name.
guard let iface = CWWiFiClient.shared().interface(), iface.interfaceMode() == .hostAP else {
    print("down")
    exit(0)
}
print("up:\(iface.ssid() ?? "")")
"#;

// ============================================================================
// Linux backend: real open AP via hostapd + dnsmasq
//
// Unlike macOS (Internet Sharing), Linux hosts a proper AP directly on the
// Wi-Fi adapter. hostapd broadcasts the open network, dnsmasq serves DHCP
// and answers every DNS query with this host, and the portal's iptables
// rule captures port 80 — so captive-portal detection pops the login page
// without needing any internet uplink.
// ============================================================================

const HOSTAPD_CONF: &str = "/tmp/brutifi_hostapd.conf";
const DNSMASQ_CONF: &str = "/tmp/brutifi_dnsmasq.conf";
/// Gateway/host address of the AP subnet on Linux (portal.rs looks for it).
pub(crate) const AP_GATEWAY: &str = "192.168.87.1";

fn start_fake_ap_linux(ssid: &str) -> Result<()> {
    let iface = crate::core::network::first_wireless_interface_linux()
        .ok_or_else(|| anyhow!("no wireless interface found (checked 'iw dev')"))?;
    log_step(&format!("linux fake ap: iface={iface} ssid='{ssid}'"));

    for tool in ["hostapd", "dnsmasq"] {
        if !tool_available(tool) {
            return Err(anyhow!(
                "'{tool}' is not installed — on Kali/Debian: sudo apt install {tool}"
            ));
        }
    }

    // Stop NetworkManager from fighting us for the interface, and make sure
    // it is in managed mode (a leftover monitor capture would break hostapd).
    let _ = run_command("nmcli", &["device", "set", &iface, "managed", "no"]);
    let _ = run_command("ip", &["link", "set", "dev", &iface, "down"]);
    let _ = run_command("iw", &["dev", &iface, "set", "type", "managed"]);

    // 1. Static host address on the AP interface.
    run_command("ip", &["addr", "flush", "dev", &iface])
        .context("failed to flush interface addresses")?;
    run_command("ip", &["link", "set", "dev", &iface, "up"])
        .context("failed to bring the interface up")?;
    run_command(
        "ip",
        &["addr", "add", &format!("{AP_GATEWAY}/24"), "dev", &iface],
    )
    .context("failed to set the AP address")?;

    // 2. hostapd config: open network (no wpa_* keys => no password).
    let hostapd_conf = format!(
        "interface={iface}\ndriver=nl80211\nssid={ssid}\nchannel=6\nhw_mode=g\nauth_algs=1\nmacaddr_acl=0\nignore_broadcast_ssid=0\n"
    );
    fs::write(HOSTAPD_CONF, hostapd_conf).context("failed to write the hostapd config")?;

    // 3. dnsmasq: DHCP + DNS — every query resolves to this host so
    //    captive-portal probes reach the portal (iptables redirects :80).
    let dnsmasq_conf = format!(
        "interface={iface}\nbind-interfaces\ndhcp-range=192.168.87.10,192.168.87.150,12h\ndhcp-option=3,{AP_GATEWAY}\ndhcp-option=6,{AP_GATEWAY}\naddress=/#/{AP_GATEWAY}\nno-resolv\n"
    );
    fs::write(DNSMASQ_CONF, dnsmasq_conf).context("failed to write the dnsmasq config")?;

    // 4. Launch dnsmasq (keep in foreground so the PID is ours) + hostapd.
    let dnsmasq = Command::new("dnsmasq")
        .args(["--keep-in-foreground", "--conf-file", DNSMASQ_CONF])
        .spawn()
        .context("failed to start dnsmasq (is port 53 already in use?)")?;
    let dnsmasq_pid = dnsmasq.id();

    let hostapd = Command::new("hostapd")
        .arg(HOSTAPD_CONF)
        .spawn()
        .context("failed to start hostapd")?;
    let hostapd_pid = hostapd.id();

    // A bad driver/channel makes hostapd exit almost immediately.
    std::thread::sleep(Duration::from_millis(1800));
    if !pid_alive(hostapd_pid) {
        log_step("hostapd exited immediately — rolling back");
        let _ = stop_fake_ap_linux();
        return Err(anyhow!(
            "hostapd exited immediately — run 'hostapd {HOSTAPD_CONF}' manually to see why (the driver may not support AP mode)"
        ));
    }

    let saved = SavedConfig {
        hostapd_pid: Some(hostapd_pid),
        dnsmasq_pid: Some(dnsmasq_pid),
        iface: Some(iface),
        ..SavedConfig::default()
    };
    if let Ok(json) = serde_json::to_string(&saved) {
        let _ = fs::write(STATE_FILE, json);
    }

    log_step("linux fake AP is up (hostapd + dnsmasq)");
    Ok(())
}

fn stop_fake_ap_linux() -> Result<()> {
    let saved: SavedConfig = fs::read_to_string(STATE_FILE)
        .ok()
        .and_then(|data| serde_json::from_str(&data).ok())
        .unwrap_or_default();

    if let Some(pid) = saved.hostapd_pid {
        signal_term(pid);
    }
    if let Some(pid) = saved.dnsmasq_pid {
        signal_term(pid);
    }
    // Orphans from a crashed session (best effort).
    let _ = run_command("pkill", &["-f", DNSMASQ_CONF]);
    let _ = run_command("pkill", &["-f", HOSTAPD_CONF]);

    if let Some(iface) = &saved.iface {
        let _ = run_command("ip", &["addr", "flush", "dev", iface]);
        let _ = run_command("ip", &["link", "set", "dev", iface, "down"]);
        // Hand the interface back to NetworkManager.
        let _ = run_command("nmcli", &["device", "set", iface, "managed", "yes"]);
    }

    let _ = fs::remove_file(HOSTAPD_CONF);
    let _ = fs::remove_file(DNSMASQ_CONF);
    let _ = fs::remove_file(STATE_FILE);
    log_step("linux fake AP stopped, interface restored");
    Ok(())
}

fn fake_ap_status_linux() -> FakeApStatus {
    let saved: SavedConfig = fs::read_to_string(STATE_FILE)
        .ok()
        .and_then(|data| serde_json::from_str(&data).ok())
        .unwrap_or_default();

    match saved.hostapd_pid {
        Some(pid) if pid_alive(pid) => {
            let ssid = fs::read_to_string(HOSTAPD_CONF).ok().and_then(|conf| {
                conf.lines()
                    .find_map(|line| line.strip_prefix("ssid="))
                    .map(str::to_string)
            });
            FakeApStatus::Up(ssid)
        }
        _ => FakeApStatus::Down,
    }
}

fn tool_available(name: &str) -> bool {
    Command::new("which")
        .arg(name)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Signal-0 existence check for a PID.
fn pid_alive(pid: u32) -> bool {
    unsafe { libc::kill(pid as libc::pid_t, 0) == 0 }
}

fn signal_term(pid: u32) {
    unsafe {
        libc::kill(pid as libc::pid_t, libc::SIGTERM);
    }
}
