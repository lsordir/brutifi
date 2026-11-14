/*!
 * Navigation handlers
 *
 * Handles screen navigation and related state transitions.
 */

use iced::Task;

use crate::app::{BruteforceApp, Screen};
use crate::messages::Message;

impl BruteforceApp {
    /// Handle navigation to scan/capture screen
    pub fn handle_go_to_scan_capture(&mut self) -> Task<Message> {
        // Stop capture if currently capturing
        if self.scan_capture_screen.is_capturing {
            if let Some(ref state) = self.capture_state {
                state.stop();
            }
            self.scan_capture_screen.is_capturing = false;
            self.capture_state = None;
            self.capture_progress_rx = None;
        }

        self.screen = Screen::ScanCapture;
        Task::none()
    }

    /// Handle navigation to crack screen
    pub fn handle_go_to_crack(&mut self) -> Task<Message> {
        // Stop capture if currently capturing
        if self.scan_capture_screen.is_capturing {
            if let Some(ref state) = self.capture_state {
                state.stop();
            }
            self.scan_capture_screen.is_capturing = false;
            self.capture_state = None;
            self.capture_progress_rx = None;

            // Add log message about stopping capture
            self.scan_capture_screen
                .log_messages
                .push("⏹️ Capture stopped (navigated to crack screen)".to_string());
            if self.scan_capture_screen.log_messages.len() > 50 {
                self.scan_capture_screen.log_messages.remove(0);
            }

            self.persist_state();
        }

        // Note: we intentionally stay in the same process here. Previously the
        // app relaunched itself as the normal user (dropping root) and exited,
        // which closed the window and lost the captured result. Cracking does
        // not need root, so we simply navigate in-process.

        // Set handshake path from capture
        if let Some(ref saved) = self.scan_capture_screen.last_saved_capture_path {
            if !saved.is_empty() {
                self.crack_screen.handshake_path = saved.clone();
            }
        } else if !self.scan_capture_screen.output_file.is_empty() {
            self.crack_screen.handshake_path = self.scan_capture_screen.output_file.clone();
        }

        // Set SSID from captured network
        if let Some(ref network) = self.scan_capture_screen.target_network {
            self.crack_screen.ssid = network.ssid.clone();
        }

        // Only reset crack screen state if NOT currently cracking AND no results to show
        let has_results = self.crack_screen.found_password.is_some()
            || self.crack_screen.password_not_found
            || self.crack_screen.error_message.is_some();

        if !self.crack_screen.is_cracking && !has_results {
            self.crack_screen.error_message = None;
            self.crack_screen.found_password = None;
            self.crack_screen.password_not_found = false;
            self.crack_screen.current_attempts = 0;
            self.crack_screen.progress = 0.0;
            self.crack_screen.log_messages.clear();
        }

        self.screen = Screen::Crack;
        Task::none()
    }

    /// Handle reset of scan state
    pub fn handle_reset_scan_state(&mut self) -> Task<Message> {
        if let Some(ref state) = self.capture_state {
            state.stop();
        }
        self.capture_state = None;
        self.capture_progress_rx = None;

        let interface_list = self.scan_capture_screen.interface_list.clone();
        let selected_interface = self.scan_capture_screen.selected_interface.clone();
        self.scan_capture_screen = crate::screens::ScanCaptureScreen {
            interface_list,
            selected_interface,
            ..Default::default()
        };
        self.persist_state();
        Task::none()
    }
}
