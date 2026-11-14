/*!
 * Main application state and logic
 *
 * Manages the application state machine and handles all messages.
 */

use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

use iced::time;
use iced::widget::{button, column, container, horizontal_rule, row, text};
use iced::{Element, Length, Subscription, Task, Theme};
use pcap::Device;

use crate::messages::Message;
use crate::persistence::{
    PersistedCaptureState, PersistedCrackState, PersistedScanState, PersistedState,
};
use crate::screens::{CrackScreen, ScanCaptureScreen};
use crate::theme::colors;
use crate::workers::{self, CaptureState, CrackState};

/// Application screens
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Screen {
    #[default]
    ScanCapture,
    Crack,
}

/// Main application state
pub struct BruteforceApp {
    pub(crate) screen: Screen,
    pub(crate) scan_capture_screen: ScanCaptureScreen,
    pub(crate) crack_screen: CrackScreen,
    pub(crate) is_root: bool,
    pub(crate) capture_state: Option<Arc<CaptureState>>,
    pub(crate) capture_progress_rx:
        Option<tokio::sync::mpsc::UnboundedReceiver<workers::CaptureProgress>>,
    pub(crate) crack_state: Option<Arc<CrackState>>,
    pub(crate) crack_progress_rx:
        Option<tokio::sync::mpsc::UnboundedReceiver<workers::CrackProgress>>,
    pub(crate) fake_ap_progress_rx:
        Option<tokio::sync::mpsc::UnboundedReceiver<workers::FakeApProgress>>,
    pub(crate) portal_state: Option<Arc<brutifi::PortalState>>,
    pub(crate) portal_progress_rx:
        Option<tokio::sync::mpsc::UnboundedReceiver<workers::PortalProgress>>,
}

impl BruteforceApp {
    pub fn new(is_root: bool) -> (Self, Task<Message>) {
        let interface_list = list_interfaces();
        let selected_interface = choose_default_interface(&interface_list);

        let mut app = Self {
            screen: Screen::ScanCapture,
            scan_capture_screen: ScanCaptureScreen {
                interface_list,
                selected_interface,
                ..ScanCaptureScreen::default()
            },
            crack_screen: CrackScreen::default(),
            is_root,
            capture_state: None,
            capture_progress_rx: None,
            crack_state: None,
            crack_progress_rx: None,
            fake_ap_progress_rx: None,
            portal_state: None,
            portal_progress_rx: None,
        };

        if let Some(persisted) = load_persisted_state() {
            app.apply_persisted_state(persisted);
        }

        if let Ok(screen) = std::env::var("BRUTIFI_START_SCREEN") {
            if screen.eq_ignore_ascii_case("crack") {
                app.screen = Screen::Crack;
            } else if screen.eq_ignore_ascii_case("scan") || screen.eq_ignore_ascii_case("capture")
            {
                app.screen = Screen::ScanCapture;
            }
        }

        if let Ok(path) = std::env::var("BRUTIFI_HANDSHAKE_PATH") {
            if !path.is_empty() {
                app.crack_screen.handshake_path = path;
            }
        }

        if let Ok(ssid) = std::env::var("BRUTIFI_SSID") {
            if !ssid.is_empty() {
                app.crack_screen.ssid = ssid;
            }
        }

        if let Ok(path) = std::env::var("BRUTIFI_WORDLIST_PATH") {
            if !path.is_empty() {
                app.crack_screen.wordlist_path = path;
            }
        }

        let auto_capture = std::env::var("BRUTIFI_AUTO_CAPTURE")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        // Optional auto-capture
        if auto_capture
            && is_root
            && app.screen == Screen::ScanCapture
            && app.scan_capture_screen.target_network.is_some()
        {
            let startup_tasks = vec![
                Task::done(Message::StartCapture),
                Task::perform(
                    workers::fake_ap_status_async(),
                    Message::FakeApStatusChecked,
                ),
            ];
            (app, Task::batch(startup_tasks))
        } else if is_root {
            // Detect an already-broadcasting fake AP (e.g. left over from a
            // previous session) so the UI can offer to stop it.
            (
                app,
                Task::perform(
                    workers::fake_ap_status_async(),
                    Message::FakeApStatusChecked,
                ),
            )
        } else {
            (app, Task::none())
        }
    }

    pub fn theme(&self) -> Theme {
        Theme::Dark
    }

    pub fn subscription(&self) -> Subscription<Message> {
        // Poll for capture and crack progress updates
        // Reduced from 100ms to 50ms for more responsive UI while maintaining performance
        if self.capture_progress_rx.is_some()
            || self.crack_progress_rx.is_some()
            || self.fake_ap_progress_rx.is_some()
            || self.portal_progress_rx.is_some()
        {
            time::every(std::time::Duration::from_millis(50)).map(|_| Message::Tick)
        } else {
            Subscription::none()
        }
    }

    pub fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            // Navigation
            Message::GoToScanCapture => self.handle_go_to_scan_capture(),
            Message::GoToCrack => self.handle_go_to_crack(),

            // Scan
            Message::StartScan => self.handle_start_scan(),
            Message::StopScan => self.handle_stop_scan(),
            Message::ResetScanState => self.handle_reset_scan_state(),
            Message::ScanComplete(result) => self.handle_scan_complete(result),
            Message::SelectNetwork(idx) => self.handle_select_network(idx),
            Message::SelectChannel(channel) => self.handle_select_channel(channel),
            Message::InterfaceSelected(interface) => self.handle_interface_selected(interface),

            // Capture
            Message::BrowseCaptureFile => self.handle_browse_capture_file(),
            Message::CaptureFileSelected(path) => self.handle_capture_file_selected(path),
            Message::DownloadCapturedPcap => self.handle_download_captured_pcap(),
            Message::SaveCapturedPcap(path) => self.handle_save_captured_pcap(path),
            Message::DisconnectWifi => self.handle_disconnect_wifi(),
            Message::WifiDisconnectResult(result) => self.handle_wifi_disconnect_result(result),
            Message::StartCapture => self.handle_start_capture(),
            Message::StopCapture => self.handle_stop_capture(),
            Message::SendDeauth => self.handle_send_deauth(),
            Message::CaptureProgress(progress) => self.handle_capture_progress(progress),
            Message::EnableAdminMode => self.handle_enable_admin_mode(),

            // Fake AP (rogue open access point)
            Message::FakeApSsidChanged(ssid) => self.handle_fake_ap_ssid_changed(ssid),
            Message::UseTargetSsidForFakeAp => self.handle_use_target_ssid_for_fake_ap(),
            Message::StartFakeAp => self.handle_start_fake_ap(),
            Message::StopFakeAp => self.handle_stop_fake_ap(),
            Message::FakeApStatusChecked(status) => self.handle_fake_ap_status_checked(status),
            Message::FakeApProgress(progress) => self.handle_fake_ap_progress(progress),
            Message::PortalToggled(enabled) => self.handle_portal_toggled(enabled),
            Message::PortalProgress(progress) => self.handle_portal_progress(progress),

            // Crack
            Message::HandshakePathChanged(path) => self.handle_handshake_path_changed(path),
            Message::EngineChanged(engine) => self.handle_engine_changed(engine),
            Message::MethodChanged(method) => self.handle_method_changed(method),
            Message::MinDigitsChanged(val) => self.handle_min_digits_changed(val),
            Message::MaxDigitsChanged(val) => self.handle_max_digits_changed(val),
            Message::WordlistPathChanged(path) => self.handle_wordlist_path_changed(path),
            Message::BrowseHandshake => self.handle_browse_handshake(),
            Message::BrowseWordlist => self.handle_browse_wordlist(),
            Message::HandshakeSelected(path) => self.handle_handshake_selected(path),
            Message::WordlistSelected(path) => self.handle_wordlist_selected(path),
            Message::DownloadDefaultWordlist => self.handle_download_default_wordlist(),
            Message::WordlistDownloadComplete(result) => {
                self.handle_wordlist_download_complete(result)
            }
            Message::StartCrack => self.handle_start_crack(),
            Message::StopCrack => self.handle_stop_crack(),
            Message::CrackProgress(progress) => self.handle_crack_progress(progress),
            Message::CopyPassword => self.handle_copy_password(),

            // General
            Message::Tick => self.handle_tick(),
        }
    }

    pub fn view(&self) -> Element<'_, Message> {
        // --- Brand / logo block ---
        let brand = row![
            container(text("B").size(22).color(colors::BACKGROUND))
                .padding([2, 12])
                .style(|_: &Theme| container::Style {
                    background: Some(iced::Background::Color(colors::PRIMARY)),
                    border: iced::Border {
                        radius: 10.0.into(),
                        ..Default::default()
                    },
                    ..Default::default()
                }),
            column![
                text("BrutiFi").size(19).color(colors::TEXT),
                text("WPA / WPA2 Security Auditor")
                    .size(11)
                    .color(colors::TEXT_DIM),
            ]
            .spacing(1),
        ]
        .spacing(11)
        .align_y(iced::Alignment::Center);

        // --- Privilege status chip ---
        let (chip_label, chip_color) = if self.is_root {
            ("● Admin mode", colors::SUCCESS)
        } else {
            ("● Limited (crack only)", colors::WARNING)
        };
        let status_chip = container(text(chip_label).size(11).color(chip_color))
            .padding([5, 12])
            .style(crate::theme::badge_style(chip_color));

        // --- Segmented navigation ---
        let nav = row![
            nav_button("Scan & Capture", "1", Screen::ScanCapture, self.screen),
            nav_button("Crack", "2", Screen::Crack, self.screen),
        ]
        .spacing(6);

        let nav_segment = container(nav)
            .padding(4)
            .style(|_: &Theme| container::Style {
                background: Some(iced::Background::Color(colors::BACKGROUND)),
                border: iced::Border {
                    color: colors::BORDER,
                    width: 1.0,
                    radius: 11.0.into(),
                },
                ..Default::default()
            });

        // --- Header bar ---
        let header = container(
            row![
                brand,
                iced::widget::horizontal_space(),
                nav_segment,
                iced::widget::horizontal_space().width(16),
                status_chip,
            ]
            .align_y(iced::Alignment::Center)
            .padding([12, 20]),
        )
        .width(Length::Fill)
        .style(crate::theme::header_style);

        // Current screen content
        let content = match self.screen {
            Screen::ScanCapture => self.scan_capture_screen.view(self.is_root),
            Screen::Crack => self.crack_screen.view(self.is_root),
        };

        let main_col = column![header, horizontal_rule(1), content];

        container(main_col)
            .style(|_: &Theme| container::Style {
                background: Some(iced::Background::Color(colors::BACKGROUND)),
                ..Default::default()
            })
            .into()
    }

    fn apply_persisted_state(&mut self, state: PersistedState) {
        if !state.scan.selected_interface.is_empty() {
            self.scan_capture_screen.selected_interface = state.scan.selected_interface;
        }
        self.scan_capture_screen.networks = state.scan.networks;
        self.scan_capture_screen.selected_network = state
            .scan
            .selected_network
            .filter(|idx| *idx < self.scan_capture_screen.networks.len());
        self.scan_capture_screen.target_network = state.capture.target_network;
        if self.scan_capture_screen.target_network.is_none() {
            if let Some(idx) = self.scan_capture_screen.selected_network {
                if let Some(net) = self.scan_capture_screen.networks.get(idx) {
                    self.scan_capture_screen.target_network = Some(net.clone());
                }
            }
        }
        if !state.capture.output_file.is_empty() {
            self.scan_capture_screen.output_file = state.capture.output_file;
        }
        if !state.capture.fake_ap_ssid.is_empty() {
            self.scan_capture_screen.fake_ap_ssid = state.capture.fake_ap_ssid;
        }
        self.scan_capture_screen.portal_enabled = state.capture.portal_enabled;
        self.scan_capture_screen.handshake_complete = state.capture.handshake_complete;
        if self.scan_capture_screen.handshake_complete {
            self.scan_capture_screen.handshake_progress.m1_received = true;
            self.scan_capture_screen.handshake_progress.m2_received = true;
        }
        self.scan_capture_screen.packets_captured = state.capture.packets_captured;
        self.scan_capture_screen.last_saved_capture_path = state.capture.last_saved_capture_path;

        if let Some(path) = self.scan_capture_screen.last_saved_capture_path.clone() {
            if self.scan_capture_screen.log_messages.is_empty() {
                self.scan_capture_screen
                    .log_messages
                    .push(format!("✅ Last saved capture: {}", path));
            }
        }

        if !state.crack.handshake_path.is_empty() {
            self.crack_screen.handshake_path = state.crack.handshake_path;
        }
        self.crack_screen.ssid = state.crack.ssid;
        self.crack_screen.engine = state.crack.engine;
        self.crack_screen.method = state.crack.method;
        if !state.crack.min_digits.is_empty() {
            self.crack_screen.min_digits = state.crack.min_digits;
        }
        if !state.crack.max_digits.is_empty() {
            self.crack_screen.max_digits = state.crack.max_digits;
        }
        if !state.crack.wordlist_path.is_empty() {
            self.crack_screen.wordlist_path = state.crack.wordlist_path;
        }
        if state.crack.threads > 0 {
            self.crack_screen.threads = state.crack.threads;
        }
    }

    pub(crate) fn persist_state(&self) {
        let state = PersistedState {
            version: 1,
            scan: PersistedScanState {
                networks: self.scan_capture_screen.networks.clone(),
                selected_network: self.scan_capture_screen.selected_network,
                selected_interface: self.scan_capture_screen.selected_interface.clone(),
            },
            capture: PersistedCaptureState {
                target_network: self.scan_capture_screen.target_network.clone(),
                output_file: self.scan_capture_screen.output_file.clone(),
                handshake_complete: self.scan_capture_screen.handshake_complete,
                packets_captured: self.scan_capture_screen.packets_captured,
                last_saved_capture_path: self.scan_capture_screen.last_saved_capture_path.clone(),
                fake_ap_ssid: self.scan_capture_screen.fake_ap_ssid.clone(),
                portal_enabled: self.scan_capture_screen.portal_enabled,
            },
            crack: PersistedCrackState {
                handshake_path: self.crack_screen.handshake_path.clone(),
                ssid: self.crack_screen.ssid.clone(),
                engine: self.crack_screen.engine,
                method: self.crack_screen.method,
                min_digits: self.crack_screen.min_digits.clone(),
                max_digits: self.crack_screen.max_digits.clone(),
                wordlist_path: self.crack_screen.wordlist_path.clone(),
                threads: self.crack_screen.threads,
            },
        };

        if let Err(err) = save_persisted_state(&state) {
            eprintln!("[WARN] Failed to save state: {}", err);
        }
    }

    pub(crate) fn build_relaunch_envs_for_capture(
        &self,
        auto_capture: bool,
    ) -> Vec<(&'static str, String)> {
        let mut envs = Vec::new();
        envs.push(("BRUTIFI_START_SCREEN", "scan".to_string()));
        if auto_capture {
            envs.push(("BRUTIFI_AUTO_CAPTURE", "1".to_string()));
        }
        envs
    }
}

fn list_interfaces() -> Vec<String> {
    let mut interfaces: Vec<String> = Device::list()
        .unwrap_or_default()
        .into_iter()
        .map(|d| d.name)
        .collect();
    interfaces.sort();
    interfaces.dedup();
    if interfaces.is_empty() {
        interfaces.push("en0".to_string());
    }
    interfaces
}

fn choose_default_interface(interfaces: &[String]) -> String {
    if interfaces.iter().any(|name| name.as_str() == "en0") {
        return "en0".to_string();
    }
    if let Some(name) = interfaces.iter().find(|name| name.as_str() == "wlan0") {
        return name.clone();
    }
    if let Some(name) = interfaces
        .iter()
        .find(|name| name.as_str().starts_with("wl"))
    {
        return name.clone();
    }
    interfaces
        .first()
        .cloned()
        .unwrap_or_else(|| "en0".to_string())
}

fn state_file_path() -> Option<PathBuf> {
    let home = std::env::var("HOME").ok()?;
    if home.is_empty() {
        return None;
    }
    let dir = PathBuf::from(home).join(".brutifi");
    if fs::create_dir_all(&dir).is_err() {
        return None;
    }
    Some(dir.join("state.json"))
}

fn load_persisted_state() -> Option<PersistedState> {
    let path = state_file_path()?;
    let data = fs::read_to_string(path).ok()?;
    serde_json::from_str(&data).ok()
}

fn save_persisted_state(state: &PersistedState) -> std::io::Result<()> {
    if let Some(path) = state_file_path() {
        let data = serde_json::to_string_pretty(state).unwrap_or_default();
        fs::write(path, data)?;
    }
    Ok(())
}

/// Segmented-control navigation tab.
fn nav_button<'a>(
    label: &'a str,
    number: &'a str,
    target: Screen,
    current: Screen,
) -> Element<'a, Message> {
    let is_active = target == current;

    let msg = match target {
        Screen::ScanCapture => Message::GoToScanCapture,
        Screen::Crack => Message::GoToCrack,
    };

    let num_color = if is_active {
        colors::BACKGROUND
    } else {
        colors::TEXT_FAINT
    };
    let text_color = if is_active {
        colors::BACKGROUND
    } else {
        colors::TEXT_DIM
    };

    let inner = row![
        text(number).size(12).color(num_color),
        text(label).size(13).color(text_color),
    ]
    .spacing(7)
    .align_y(iced::Alignment::Center);

    button(inner)
        .padding([8, 16])
        .style(move |_, status| {
            let bg = if is_active {
                Some(iced::Background::Color(colors::PRIMARY))
            } else {
                match status {
                    iced::widget::button::Status::Hovered => {
                        Some(iced::Background::Color(colors::SURFACE_HOVER))
                    }
                    _ => None,
                }
            };
            iced::widget::button::Style {
                background: bg,
                text_color,
                border: iced::Border {
                    radius: 8.0.into(),
                    ..Default::default()
                },
                ..Default::default()
            }
        })
        .on_press(msg)
        .into()
}
