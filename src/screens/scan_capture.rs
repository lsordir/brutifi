/*!
 * Combined Scan & Capture Screen
 *
 * Unified screen for WiFi network scanning and handshake capture.
 * Shows network list on the left, capture panel on the right.
 */

use iced::widget::{
    button, column, container, horizontal_rule, horizontal_space, pick_list, row, scrollable, text,
    Column,
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
