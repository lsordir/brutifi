/*!
 * Fake AP handlers
 *
 * Drives the rogue open (no password) access point. The heavy lifting is
 * done by `brutifi::core::rogue_ap` inside a background worker.
 */

use iced::Task;
use tokio::sync::mpsc;

use crate::app::BruteforceApp;
use crate::messages::Message;
use crate::workers::{self, FakeApProgress, PortalProgress};

impl BruteforceApp {
    /// Fake AP SSID text field changed
    pub fn handle_fake_ap_ssid_changed(&mut self, ssid: String) -> Task<Message> {
        self.scan_capture_screen.fake_ap_ssid = ssid;
        Task::none()
    }

    /// Copy the selected target network's SSID into the fake AP field
    /// (classic evil-twin setup: same name, but open security).
    pub fn handle_use_target_ssid_for_fake_ap(&mut self) -> Task<Message> {
        if let Some(ref network) = self.scan_capture_screen.target_network {
            let ssid = network.ssid.trim().to_string();
            if !ssid.is_empty() {
                self.scan_capture_screen.fake_ap_ssid = ssid.clone();
                self.add_capture_log(format!(
                    "👾 Fake AP name set to '{}' (evil-twin of the target)",
                    ssid
                ));
            }
        }
        Task::none()
    }

    /// Start broadcasting the open fake AP
    pub fn handle_start_fake_ap(&mut self) -> Task<Message> {
        // macOS drives Internet Sharing; Linux drives hostapd + dnsmasq.
        if !cfg!(any(target_os = "macos", target_os = "linux")) {
            self.scan_capture_screen.error_message =
                Some("Fake AP is supported on macOS and Linux only.".to_string());
            return Task::none();
        }

        if self.scan_capture_screen.fake_ap_busy {
            return Task::none();
        }

        let ssid = self.scan_capture_screen.fake_ap_ssid.trim().to_string();
        if ssid.is_empty() {
            self.scan_capture_screen.error_message =
                Some("Fake AP: enter a network name (SSID) first".to_string());
            return Task::none();
        }

        // Root is required to drive Internet Sharing.
        if !self.is_root {
            self.scan_capture_screen.error_message =
                Some("Requesting admin privileges for the fake AP…".to_string());
            self.persist_state();
            let envs = self.build_relaunch_envs_for_capture(false);
            if crate::relaunch_as_root_with_env(&envs) {
                std::process::exit(0);
            }
            self.scan_capture_screen.error_message = Some(
                "Failed to request admin privileges. Please try again or launch with sudo."
                    .to_string(),
            );
            return Task::none();
        }

        // Internet Sharing grabs the Wi-Fi adapter as host, so warn when a
        // client association is still active — sharing usually disassociates
        // on its own, but failures are far more likely while connected.
        if let Some(ssid) = brutifi::wifi_connected_ssid() {
            self.add_capture_log(format!(
                "⚠️ WiFi still associated to '{}' — if the AP fails to start, disconnect first.",
                ssid
            ));
        }

        self.scan_capture_screen.fake_ap_busy = true;
        self.scan_capture_screen.fake_ap_ssid = ssid.clone();
        self.scan_capture_screen.error_message = None;

        let (tx, rx) = mpsc::unbounded_channel();
        self.fake_ap_progress_rx = Some(rx);

        Task::perform(
            workers::fake_ap_start_async(ssid, tx),
            Message::FakeApProgress,
        )
    }

    /// Stop the fake AP and restore the previous configuration
    pub fn handle_stop_fake_ap(&mut self) -> Task<Message> {
        if self.scan_capture_screen.fake_ap_busy {
            return Task::none();
        }
        self.scan_capture_screen.fake_ap_busy = true;
        self.stop_portal();

        let (tx, rx) = mpsc::unbounded_channel();
        self.fake_ap_progress_rx = Some(rx);

        Task::perform(workers::fake_ap_stop_async(tx), Message::FakeApProgress)
    }

    /// Ask a running portal to shut down (worker confirms via its message).
    fn stop_portal(&mut self) {
        if let Some(ref state) = self.portal_state {
            state.stop();
        }
    }

    /// Background progress for the fake AP
    pub fn handle_fake_ap_progress(&mut self, progress: FakeApProgress) -> Task<Message> {
        // Started may chain the captive portal right after the AP comes up.
        let mut follow_up: Option<Task<Message>> = None;
        let terminal = match progress {
            FakeApProgress::Log(msg) => {
                self.add_capture_log(msg);
                false
            }
            FakeApProgress::Started { ssid } => {
                self.scan_capture_screen.fake_ap_running = true;
                self.scan_capture_screen.fake_ap_active_ssid = Some(ssid.clone());
                self.scan_capture_screen.fake_ap_busy = false;
                self.add_capture_log(format!(
                    "📡 Fake AP '{}' is up — open network, clients can join without a password",
                    ssid
                ));
                self.add_capture_log(
                    "ℹ️ The Mac's computer name was renamed to the SSID; 'Stop Fake AP' restores it."
                        .to_string(),
                );
                // The captive portal rides along with the AP when enabled.
                if self.scan_capture_screen.portal_enabled && self.is_root {
                    follow_up = Some(self.start_portal_task());
                }
                true
            }
            FakeApProgress::Stopped => {
                self.stop_portal();
                self.scan_capture_screen.fake_ap_running = false;
                self.scan_capture_screen.fake_ap_active_ssid = None;
                self.scan_capture_screen.fake_ap_busy = false;
                self.add_capture_log(
                    "✓ Fake AP stopped and previous settings restored".to_string(),
                );
                true
            }
            FakeApProgress::Error(msg) => {
                self.stop_portal();
                self.scan_capture_screen.fake_ap_busy = false;
                self.scan_capture_screen.error_message = Some(msg.clone());
                self.add_capture_log(format!("❌ Fake AP error: {}", msg));
                true
            }
        };

        if terminal {
            self.fake_ap_progress_rx = None;
            self.persist_state();
        }
        follow_up.take().unwrap_or(Task::none())
    }

    /// Result of the startup check for an already-broadcasting fake AP
    pub fn handle_fake_ap_status_checked(
        &mut self,
        status: brutifi::FakeApStatus,
    ) -> Task<Message> {
        if let brutifi::FakeApStatus::Up(Some(ssid)) = status {
            self.scan_capture_screen.fake_ap_running = true;
            self.scan_capture_screen.fake_ap_active_ssid = Some(ssid.clone());
            self.add_capture_log(format!(
                "📡 Hosted network '{}' is already broadcasting (Internet Sharing is on)",
                ssid
            ));
        }
        Task::none()
    }

    /// Captive portal checkbox toggled
    pub fn handle_portal_toggled(&mut self, enabled: bool) -> Task<Message> {
        self.scan_capture_screen.portal_enabled = enabled;
        self.persist_state();
        Task::none()
    }

    /// Launch the captive portal alongside a running fake AP.
    fn start_portal_task(&mut self) -> Task<Message> {
        const PORTAL_PORT: u16 = 8080;

        let ssid = self
            .scan_capture_screen
            .fake_ap_active_ssid
            .clone()
            .unwrap_or_else(|| self.scan_capture_screen.fake_ap_ssid.clone());

        // Verify submitted codes when a captured handshake of the real
        // network is on file.
        let handshake_path = std::path::PathBuf::from(&self.crack_screen.handshake_path);
        let verify_ssid = if !self.crack_screen.ssid.is_empty() {
            self.crack_screen.ssid.clone()
        } else {
            self.scan_capture_screen
                .target_network
                .as_ref()
                .map(|n| n.ssid.clone())
                .unwrap_or_else(|| ssid.clone())
        };
        let verify = if handshake_path.exists() {
            Some((handshake_path, verify_ssid))
        } else {
            self.add_capture_log(
                "ℹ️ No handshake on file — portal codes will be logged without verification"
                    .to_string(),
            );
            None
        };

        let state = std::sync::Arc::new(brutifi::PortalState::new(PORTAL_PORT));
        self.portal_state = Some(state.clone());

        let config = brutifi::PortalConfig {
            ssid,
            port: PORTAL_PORT,
            verify,
            codes_file: "/tmp/brutifi_portal_codes.txt".to_string(),
            // Without a handshake on file: any code of 8+ characters is
            // accepted and the client is let through to the internet.
            accept_min_len: 8,
        };

        let (tx, rx) = mpsc::unbounded_channel();
        self.portal_progress_rx = Some(rx);
        self.scan_capture_screen.portal_running = true;
        self.scan_capture_screen.portal_codes.clear();

        Task::perform(
            workers::portal_async(config, state, tx),
            Message::PortalProgress,
        )
    }

    /// Background progress for the captive portal
    pub fn handle_portal_progress(&mut self, progress: PortalProgress) -> Task<Message> {
        let terminal = match progress {
            PortalProgress::Started {
                port,
                redirect_active,
                verifying,
            } => {
                let redirect = if redirect_active {
                    "login interception ON"
                } else {
                    "no port-80 redirect"
                };
                let verifying = if verifying {
                    ", verifying codes against the handshake"
                } else {
                    ", accepting codes of 8+ characters"
                };
                self.add_capture_log(format!(
                    "🪟 Captive portal live on :{port} ({redirect}{verifying})"
                ));
                false
            }
            PortalProgress::Log(msg) => {
                self.add_capture_log(msg);
                false
            }
            PortalProgress::Code { code, valid } => {
                let codes = &mut self.scan_capture_screen.portal_codes;
                codes.push((code.clone(), valid));
                if codes.len() > 20 {
                    codes.remove(0);
                }
                match valid {
                    Some(true) => {
                        self.add_capture_log(format!(
                            "🎉 Access code '{}' accepted — internet unblocked (AP stays up)",
                            code
                        ));
                        self.crack_screen.found_password = Some(code);
                    }
                    Some(false) => {
                        self.add_capture_log(format!("✗ Code '{}' rejected", code));
                    }
                    None => {
                        self.add_capture_log(format!("📝 Code submitted: '{}'", code));
                    }
                }
                false
            }
            PortalProgress::Stopped => {
                self.add_capture_log("✓ Captive portal stopped".to_string());
                true
            }
            PortalProgress::Error(msg) => {
                self.scan_capture_screen.error_message = Some(msg.clone());
                self.add_capture_log(format!("❌ Captive portal error: {}", msg));
                true
            }
        };

        if terminal {
            self.portal_progress_rx = None;
            self.portal_state = None;
            self.scan_capture_screen.portal_running = false;
            self.persist_state();
        }
        Task::none()
    }
}
