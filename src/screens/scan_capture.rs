/*!
 * Combined Scan & Capture Screen
 *
 * Unified screen for WiFi network scanning and handshake capture.
 * Shows network list on the left, capture panel on the right.
 */

use iced::widget::{
    button, checkbox, column, container, horizontal_rule, horizontal_space, pick_list, row,
    scrollable, text, text_input, Column,
};
use iced::{Element, Length, Theme};

use super::components;
use crate::messages::Message;
use crate::theme::{self, colors};
use brutifi::WifiNetwork;

/// EAPOL message tracking
#[derive(Debug, Clone, Default)]
pub struct HandshakeProgress {
    pub m1_received: bool,
    pub m2_received: bool,
    pub pmkid_captured: bool,
}

impl HandshakeProgress {
    pub fn is_complete(&self) -> bool {
        self.pmkid_captured || (self.m1_received && self.m2_received)
    }

    pub fn capture_type(&self) -> &str {
        if self.pmkid_captured {
            "PMKID (client-less)"
        } else if self.m1_received && self.m2_received {
            "4-way handshake"
        } else {
            "In progress"
        }
    }
}

/// Combined Scan & Capture screen state
#[derive(Debug)]
pub struct ScanCaptureScreen {
    // Scan state
    pub networks: Vec<WifiNetwork>,
    pub selected_network: Option<usize>,
    pub is_scanning: bool,
    pub interface_list: Vec<String>,
    pub selected_interface: String,

    // Capture state
    pub target_network: Option<WifiNetwork>,
    pub output_file: String,
    pub is_capturing: bool,
    pub packets_captured: u64,
    pub handshake_progress: HandshakeProgress,
    pub handshake_complete: bool,

    // Shared
    pub error_message: Option<String>,
    pub log_messages: Vec<String>,
    pub last_saved_capture_path: Option<String>,

    // Channel selection for multi-channel networks
    pub available_channels: Vec<String>,
    pub selected_channel: Option<String>,

    // Fake AP (rogue open access point)
    pub fake_ap_ssid: String,
    pub fake_ap_active_ssid: Option<String>,
    pub fake_ap_running: bool,
    pub fake_ap_busy: bool,

    // Captive portal (rides along with the fake AP)
    pub portal_enabled: bool,
    pub portal_running: bool,
    /// Last submitted codes: (code, validity when a handshake is on file).
    pub portal_codes: Vec<(String, Option<bool>)>,
}

impl Default for ScanCaptureScreen {
    fn default() -> Self {
        Self {
            networks: Vec::new(),
            selected_network: None,
            is_scanning: false,
            interface_list: Vec::new(),
            selected_interface: "en0".to_string(),
            target_network: None,
            output_file: "/tmp/capture.pcap".to_string(),
            is_capturing: false,
            packets_captured: 0,
            handshake_progress: HandshakeProgress::default(),
            handshake_complete: false,
            error_message: None,
            log_messages: Vec::new(),
            last_saved_capture_path: None,
            available_channels: Vec::new(),
            selected_channel: None,
            fake_ap_ssid: "FreeWiFi".to_string(),
            fake_ap_active_ssid: None,
            fake_ap_running: false,
            fake_ap_busy: false,
            portal_enabled: true,
            portal_running: false,
            portal_codes: Vec::new(),
        }
    }
}

impl ScanCaptureScreen {
    pub fn view(&self, is_root: bool) -> Element<'_, Message> {
        // Left panel: Network list
        let left_panel = self.view_network_list();

        // Right panel: Capture
        let right_panel = self.view_capture_panel(is_root);

        // Main layout: two columns
        let content = row![left_panel, right_panel,]
            .spacing(15)
            .height(Length::Fill);

        container(content.padding(20))
            .width(Length::Fill)
            .height(Length::Fill)
            .style(|_: &Theme| container::Style {
                background: Some(iced::Background::Color(colors::BACKGROUND)),
                ..Default::default()
            })
            .into()
    }

    fn view_network_list(&self) -> Element<'_, Message> {
        let title = text("WiFi Networks").size(20).color(colors::TEXT);

        // Scan button
        let scan_btn = if self.is_scanning {
            button(
                row![text("Scanning...").size(13),]
                    .spacing(6)
                    .align_y(iced::Alignment::Center),
            )
            .padding([8, 16])
            .style(theme::secondary_button_style)
            .on_press(Message::StopScan)
        } else {
            button(text("Scan").size(13))
                .padding([8, 16])
                .style(theme::primary_button_style)
                .on_press(Message::StartScan)
        };

        let reset_btn = button(text("Reset").size(13))
            .padding([8, 16])
            .style(theme::secondary_button_style)
            .on_press(Message::ResetScanState);

        let header = row![
            title,
            horizontal_space(),
            reset_btn,
            horizontal_space().width(10),
            scan_btn,
        ]
        .align_y(iced::Alignment::Center);

        let interface_picker: Element<Message> = if self.interface_list.is_empty() {
            container(text("No interfaces found").size(11).color(colors::TEXT_DIM)).into()
        } else {
            let options = self.interface_list.clone();
            pick_list(
                options,
                Some(self.selected_interface.clone()),
                Message::InterfaceSelected,
            )
            .placeholder("Select interface")
            .style(theme::pick_list_style)
            .into()
        };

        let interface_row = row![
            text("Interface").size(11).color(colors::TEXT_DIM),
            interface_picker,
        ]
        .spacing(10)
        .align_y(iced::Alignment::Center);

        // Network list
        let network_list: Element<Message> = if self.networks.is_empty() {
            if self.is_scanning {
                container(
                    column![
                        text("Scanning the airwaves…").size(14).color(colors::TEXT),
                        text("Discovering nearby WiFi networks")
                            .size(11)
                            .color(colors::TEXT_DIM),
                    ]
                    .spacing(4)
                    .align_x(iced::Alignment::Center),
                )
                .center_x(Length::Fill)
                .center_y(Length::Fill)
                .into()
            } else {
                container(
                    column![
                        text("No networks yet").size(15).color(colors::TEXT),
                        text("Click Scan to discover nearby WiFi networks")
                            .size(11)
                            .color(colors::TEXT_DIM),
                    ]
                    .spacing(6)
                    .align_x(iced::Alignment::Center),
                )
                .center_x(Length::Fill)
                .center_y(Length::Fill)
                .into()
            }
        } else {
            // Column header (table-style)
            let col_header = row![
                text("NETWORK")
                    .size(10)
                    .color(colors::TEXT_FAINT)
                    .width(Length::Fill),
                text("CH")
                    .size(10)
                    .color(colors::TEXT_FAINT)
                    .width(Length::Fixed(36.0)),
                text("SIGNAL")
                    .size(10)
                    .color(colors::TEXT_FAINT)
                    .width(Length::Fixed(92.0)),
                text("SECURITY")
                    .size(10)
                    .color(colors::TEXT_FAINT)
                    .width(Length::Fixed(88.0)),
            ]
            .spacing(10)
            .padding([2, 12]);

            // Sort display order by signal strength (strongest first), keeping
            // the original indices for selection.
            let mut order: Vec<usize> = (0..self.networks.len()).collect();
            order.sort_by(|&a, &b| {
                let ra = self.networks[a]
                    .signal_strength
                    .parse::<i32>()
                    .unwrap_or(i32::MIN);
                let rb = self.networks[b]
                    .signal_strength
                    .parse::<i32>()
                    .unwrap_or(i32::MIN);
                rb.cmp(&ra)
            });

            let items: Vec<Element<Message>> = order
                .iter()
                .map(|&idx| {
                    let network = &self.networks[idx];
                    let is_selected = self.selected_network == Some(idx);
                    let rssi = network.signal_strength.parse::<i32>().ok();

                    // Attack methods available for this network.
                    let attack_methods: Vec<&str> = if network.security.contains("WPA") {
                        vec!["PMKID", "Handshake"]
                    } else {
                        vec!["Open"]
                    };
                    let badges = row(attack_methods
                        .iter()
                        .map(|m| components::pill(m, colors::ACCENT))
                        .collect::<Vec<Element<Message>>>())
                    .spacing(4);

                    let item_style = if is_selected {
                        theme::network_item_selected_style
                    } else {
                        theme::network_item_style
                    };

                    let ssid_label = if network.ssid.trim().is_empty() {
                        "<hidden>".to_string()
                    } else {
                        network.ssid.clone()
                    };

                    button(
                        container(
                            row![
                                column![
                                    text(ssid_label).size(13).color(if is_selected {
                                        colors::ACCENT
                                    } else {
                                        colors::TEXT
                                    }),
                                    text(network.bssid.clone())
                                        .size(9)
                                        .color(colors::TEXT_FAINT),
                                    badges,
                                ]
                                .spacing(3)
                                .width(Length::Fill),
                                text(network.channel.clone())
                                    .size(12)
                                    .color(colors::TEXT_DIM)
                                    .width(Length::Fixed(36.0)),
                                container(signal_cell(rssi)).width(Length::Fixed(92.0)),
                                container(security_badge(&network.security))
                                    .width(Length::Fixed(88.0)),
                            ]
                            .align_y(iced::Alignment::Center)
                            .spacing(10)
                            .padding([8, 12]),
                        )
                        .style(item_style),
                    )
                    .padding(0)
                    .style(|_, _| button::Style {
                        background: None,
                        ..Default::default()
                    })
                    .on_press(Message::SelectNetwork(idx))
                    .into()
                })
                .collect();

            column![
                col_header,
                horizontal_rule(1),
                scrollable(Column::with_children(items).spacing(6).width(Length::Fill))
                    .height(Length::Fill),
            ]
            .spacing(8)
            .into()
        };

        let network_count = if !self.networks.is_empty() {
            Some(
                text(format!(
                    "{} networks found · sorted by signal",
                    self.networks.len()
                ))
                .size(11)
                .color(colors::TEXT_DIM),
            )
        } else {
            None
        };

        let mut content = column![header, interface_row].spacing(10);

        content = content.push(
            container(network_list)
                .height(Length::Fill)
                .width(Length::Fill)
                .style(theme::card_style)
                .padding(8),
        );

        if let Some(count) = network_count {
            content = content.push(count);
        }

        container(content)
            .width(Length::FillPortion(2))
            .height(Length::Fill)
            .into()
    }

    fn view_capture_panel(&self, _is_root: bool) -> Element<'_, Message> {
        let title = text("Capture Handshake").size(20).color(colors::TEXT);
        let handshake_done = self.handshake_complete || self.handshake_progress.is_complete();

        // ========== NETWORK INFO BLOCK ==========
        let network_info_block: Element<'_, Message> = if let Some(network) = &self.target_network {
            let mut col_elements: Vec<Element<Message>> = vec![
                components::section_title("Target"),
                components::labeled_value("Network", &network.ssid, colors::TEXT),
                components::labeled_value("Channel", &network.channel, colors::TEXT),
                components::labeled_value("Security", &network.security, colors::PRIMARY),
            ];

            // Add channel selector if multiple channels
            if self.available_channels.len() > 1 {
                col_elements.push(horizontal_rule(1).into());
                col_elements.push(
                    text("Select channel to monitor:")
                        .size(10)
                        .color(colors::TEXT_DIM)
                        .into(),
                );
                col_elements.push(
                    pick_list(
                        self.available_channels.as_slice(),
                        self.selected_channel.as_ref(),
                        Message::SelectChannel,
                    )
                    .placeholder("Choose channel...")
                    .style(theme::pick_list_style)
                    .width(Length::Fill)
                    .into(),
                );
            }

            col_elements.push(horizontal_rule(1).into());
            col_elements.push(components::labeled_value(
                "Output",
                &self.output_file,
                colors::SUCCESS,
            ));
            col_elements.push(
                button(text("Change location").size(11))
                    .padding([6, 12])
                    .style(theme::secondary_button_style)
                    .on_press(Message::BrowseCaptureFile)
                    .into(),
            );

            components::card(column(col_elements).spacing(8))
        } else {
            components::card(column![
                components::section_title("No network selected"),
                text("Select a network from the list on the left to begin.")
                    .size(11)
                    .color(colors::TEXT_DIM),
            ])
        };

        // ========== STATUS BLOCK ==========
        let status_block: Element<'_, Message> = if handshake_done {
            // Success state
            let capture_type = self.handshake_progress.capture_type();
            container(
                column![
                    row![
                        text("✅").size(20),
                        text("Capture Complete!").size(14).color(colors::SUCCESS),
                    ]
                    .spacing(8)
                    .align_y(iced::Alignment::Center),
                    text(format!("Type: {}", capture_type))
                        .size(11)
                        .color(colors::PRIMARY),
                    text("The capture file is ready for cracking.")
                        .size(10)
                        .color(colors::TEXT_DIM),
                ]
                .spacing(6),
            )
            .padding(14)
            .width(Length::Fill)
            .style(theme::callout_style(colors::SUCCESS))
            .into()
        } else if self.is_capturing {
            // Capturing state
            let hp = &self.handshake_progress;
            container(
                column![
                    row![
                        text("🔍").size(14),
                        text("Listening for capture...")
                            .size(12)
                            .color(colors::TEXT),
                    ]
                    .spacing(6),
                    if hp.pmkid_captured {
                        row![text("✅ PMKID (client-less)")
                            .size(10)
                            .color(colors::SUCCESS),]
                        .spacing(12)
                    } else {
                        row![
                            text("⏳ PMKID").size(10).color(colors::TEXT_DIM),
                            text("or").size(9).color(colors::TEXT_DIM),
                            if hp.m1_received {
                                text("✅ M1").size(10).color(colors::SUCCESS)
                            } else {
                                text("⏳ M1").size(10).color(colors::TEXT_DIM)
                            },
                            if hp.m2_received {
                                text("✅ M2").size(10).color(colors::SUCCESS)
                            } else {
                                text("⏳ M2").size(10).color(colors::TEXT_DIM)
                            },
                        ]
                        .spacing(12)
                    },
                    text("No client reconnecting? Press 'Send Deauth' to force a reconnect.")
                        .size(10)
                        .color(colors::TEXT_DIM),
                ]
                .spacing(6),
            )
            .padding(12)
            .width(Length::Fill)
            .style(theme::card_style)
            .into()
        } else {
            // Ready state
            container(
                column![
                    text("Ready to capture").size(12).color(colors::TEXT_DIM),
                    text("Click 'Start Capture' to begin listening for the handshake")
                        .size(10)
                        .color(colors::TEXT_DIM),
                ]
                .spacing(4),
            )
            .padding(12)
            .width(Length::Fill)
            .style(theme::card_style)
            .into()
        };

        // ========== LOGS BLOCK ==========
        let logs_block = components::log_panel(&self.log_messages);

        // ========== ERROR BLOCK ==========
        let error_block = self
            .error_message
            .as_ref()
            .map(|msg| components::error_banner(msg));

        // ========== ACTION BUTTONS ==========
        let action_buttons: Element<'_, Message> = {
            let mut buttons_vec: Vec<Element<'_, Message>> = Vec::new();

            // Disconnect WiFi button (always visible)
            buttons_vec.push(
                button(text("Disconnect WiFi").size(12))
                    .padding([8, 16])
                    .style(theme::secondary_button_style)
                    .on_press(Message::DisconnectWifi)
                    .into(),
            );

            if handshake_done {
                // Show Continue and Download buttons
                buttons_vec.push(
                    button(text("Continue to Crack").size(12))
                        .padding([8, 16])
                        .style(theme::primary_button_style)
                        .on_press(Message::GoToCrack)
                        .into(),
                );
                buttons_vec.push(
                    button(text("Download pcap").size(12))
                        .padding([8, 16])
                        .style(theme::secondary_button_style)
                        .on_press(Message::DownloadCapturedPcap)
                        .into(),
                );
            } else if self.is_capturing {
                // Send Deauth: force connected clients to reconnect so a fresh
                // handshake can be captured.
                buttons_vec.push(
                    button(text("Send Deauth").size(12))
                        .padding([8, 16])
                        .style(theme::primary_button_style)
                        .on_press(Message::SendDeauth)
                        .into(),
                );
                // Show Stop button
                buttons_vec.push(
                    button(text("Stop Capture").size(12))
                        .padding([8, 16])
                        .style(theme::danger_button_style)
                        .on_press(Message::StopCapture)
                        .into(),
                );
            } else {
                // Show Start button
                let network_selected = self.target_network.is_some();
                let channel_ok = if self.available_channels.len() > 1 {
                    self.selected_channel.is_some()
                } else {
                    true
                };
                let can_capture = network_selected && channel_ok;

                let start_btn = button(text("Start Capture").size(12))
                    .padding([8, 16])
                    .style(theme::primary_button_style);

                buttons_vec.push(if can_capture {
                    start_btn.on_press(Message::StartCapture).into()
                } else {
                    start_btn.into()
                });
            }

            container(row(buttons_vec).spacing(8))
                .padding(8)
                .width(Length::Fill)
                .into()
        };

        // ========== BUILD FINAL LAYOUT WITH SCROLLVIEW ==========
        let mut content = column![title, horizontal_rule(1)].spacing(10);

        // Add info message only if no network selected
        if self.target_network.is_none() {
            content = content.push(
                container(
                    column![
                        text("ℹ️ Getting Started").size(11).color(colors::TEXT),
                        text("1. Select a network from the list on the left")
                            .size(10)
                            .color(colors::TEXT_DIM),
                        text("2. If connected to WiFi, disconnect first")
                            .size(10)
                            .color(colors::TEXT_DIM),
                        text("3. Click 'Start Capture' to begin")
                            .size(10)
                            .color(colors::TEXT_DIM),
                    ]
                    .spacing(4),
                )
                .padding(12)
                .width(Length::Fill)
                .style(theme::callout_style(colors::SECONDARY)),
            );
        }

        content = content.push(network_info_block);
        content = content.push(status_block);
        content = content.push(self.view_fake_ap_block());

        if let Some(logs) = logs_block {
            content = content.push(logs);
        }

        if let Some(error) = error_block {
            content = content.push(error);
        }

        content = content.push(action_buttons);

        // Wrap in scrollable
        let scrollable_content = scrollable(content).height(Length::Fill);

        container(scrollable_content)
            .width(Length::FillPortion(3))
            .height(Length::Fill)
            .into()
    }

    /// Fake AP card: broadcast an open (no password) network clients can join.
    fn view_fake_ap_block(&self) -> Element<'_, Message> {
        let running = self.fake_ap_running;
        let busy = self.fake_ap_busy;

        // SSID input — applies on next start; editing while running is allowed
        // but does not touch the live network.
        let ssid_field = text_input("Network name (SSID)", &self.fake_ap_ssid)
            .on_input(Message::FakeApSsidChanged)
            .size(13)
            .style(theme::text_input_style);

        // One-click evil twin: clone the selected target's name.
        let use_target_btn = self
            .target_network
            .as_ref()
            .map(|n| n.ssid.trim().to_string())
            .filter(|ssid| !ssid.is_empty())
            .map(|_| {
                button(text("Use target SSID").size(11))
                    .padding([6, 12])
                    .style(theme::secondary_button_style)
                    .on_press(Message::UseTargetSsidForFakeAp)
            });

        let toggle: Element<Message> = if running {
            let label = if busy { "Stopping…" } else { "Stop Fake AP" };
            button(text(label).size(12))
                .padding([8, 16])
                .style(theme::danger_button_style)
                .on_press_maybe((!busy).then_some(Message::StopFakeAp))
                .into()
        } else {
            let label = if busy { "Starting…" } else { "Start Fake AP" };
            let can_start = !busy && !self.fake_ap_ssid.trim().is_empty();
            button(text(label).size(12))
                .padding([8, 16])
                .style(theme::primary_button_style)
                .on_press_maybe(can_start.then_some(Message::StartFakeAp))
                .into()
        };

        let status_line = if running {
            let ssid = self
                .fake_ap_active_ssid
                .clone()
                .unwrap_or_else(|| self.fake_ap_ssid.clone());
            components::labeled_value(
                "Status",
                &format!("● Broadcasting '{}' — open, no password", ssid),
                colors::SUCCESS,
            )
        } else {
            components::labeled_value("Status", "○ Not broadcasting", colors::TEXT_DIM)
        };

        // Captive portal toggle + live status of captured codes.
        let portal_toggle = checkbox(
            "Captive portal — ask clients for the network access code",
            self.portal_enabled,
        )
        .on_toggle(Message::PortalToggled)
        .size(13)
        .text_size(11);

        let portal_line: Option<Element<Message>> = if self.portal_running {
            Some(components::labeled_value(
                "Portal",
                "● Live on :8080 — intercepting client logins",
                colors::SUCCESS,
            ))
        } else {
            None
        };

        let last_code_line: Option<Element<Message>> =
            self.portal_codes.last().map(|(code, valid)| {
                let (label, color) = match valid {
                    Some(true) => (format!("'{}' ✔ verified correct", code), colors::SUCCESS),
                    Some(false) => (format!("'{}' ✘ rejected", code), colors::DANGER),
                    None => (format!("'{}' (unverified)", code), colors::TEXT),
                };
                components::labeled_value(
                    "Codes",
                    &format!("{} captured — last: {}", self.portal_codes.len(), label),
                    color,
                )
            });

        let hint = if running {
            components::callout(
                colors::WARNING,
                "Hosting an open network",
                &[
                    "Anyone nearby can connect — stop it when you are done testing.",
                    "'Stop Fake AP' disables sharing and restores the previous computer name.",
                ],
            )
        } else {
            components::callout(
                colors::SECONDARY,
                "Open, password-less test network",
                &[
                    "Broadcasts through macOS Internet Sharing — clients connect without a password.",
                    "Needs an uplink other than Wi-Fi (Ethernet or USB adapter); Wi-Fi hosts the network.",
                    "The Mac's computer name is used as the network name and restored on stop.",
                ],
            )
        };

        let mut controls_row = row![].spacing(8).align_y(iced::Alignment::Center);
        controls_row = controls_row.push(container(ssid_field).width(Length::Fill));
        if let Some(btn) = use_target_btn {
            controls_row = controls_row.push(btn);
        }
        controls_row = controls_row.push(toggle);

        let mut body = column![
            components::section_title("Fake Access Point"),
            text("Spin up a rogue open network clients can join freely — no password.")
                .size(11)
                .color(colors::TEXT_DIM),
            controls_row,
            status_line,
            portal_toggle,
        ]
        .spacing(8);
        if let Some(portal_line) = portal_line {
            body = body.push(portal_line);
        }
        if let Some(last_code_line) = last_code_line {
            body = body.push(last_code_line);
        }
        body = body.push(hint);

        components::card(body)
    }
}

/// Render a compact 4-bar signal meter plus the dBm value, colored by strength.
fn signal_cell(rssi: Option<i32>) -> Element<'static, Message> {
    let (active_bars, color, label) = match rssi {
        Some(r) => {
            let bars = if r >= -55 {
                4
            } else if r >= -67 {
                3
            } else if r >= -78 {
                2
            } else {
                1
            };
            let color = if r >= -55 {
                colors::SUCCESS
            } else if r >= -67 {
                colors::PRIMARY
            } else if r >= -78 {
                colors::WARNING
            } else {
                colors::DANGER
            };
            (bars, color, format!("{} dBm", r))
        }
        None => (0, colors::TEXT_FAINT, "—".to_string()),
    };

    let heights = [6.0_f32, 9.0, 12.0, 15.0];
    let bars = row((0..4)
        .map(|i| {
            let on = (i as i32) < active_bars;
            container(text(""))
                .width(Length::Fixed(4.0))
                .height(Length::Fixed(heights[i]))
                .style(move |_: &Theme| container::Style {
                    background: Some(iced::Background::Color(if on {
                        color
                    } else {
                        colors::BORDER_STRONG
                    })),
                    border: iced::Border {
                        radius: 1.0.into(),
                        ..Default::default()
                    },
                    ..Default::default()
                })
                .into()
        })
        .collect::<Vec<Element<Message>>>())
    .spacing(2)
    .align_y(iced::Alignment::End);

    row![
        container(bars).height(Length::Fixed(16.0)),
        text(label).size(9).color(color),
    ]
    .spacing(6)
    .align_y(iced::Alignment::Center)
    .into()
}

/// Render a rounded security badge, colored by protocol.
fn security_badge(security: &str) -> Element<'static, Message> {
    let is_open = security.is_empty()
        || security.eq_ignore_ascii_case("none")
        || security.to_lowercase().contains("open");
    let color = if security.contains("WPA3") {
        colors::SECONDARY
    } else if security.contains("WPA") {
        colors::PRIMARY
    } else if is_open {
        colors::SUCCESS
    } else {
        colors::TEXT_DIM
    };
    let label = if is_open { "Open" } else { security };
    components::pill(label, color)
}
