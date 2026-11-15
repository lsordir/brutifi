/*!
 * General handlers
 *
 * Handles general application operations like tick.
 */

use iced::Task;

use crate::app::BruteforceApp;
use crate::messages::Message;

impl BruteforceApp {
    /// Global kill switch: stop every running background task at once —
    /// capture (which also halts the parallel deauth thread via its running
    /// flag), cracking, and the fake AP / captive portal.
    pub fn handle_stop_all(&mut self) -> Task<Message> {
        let mut tasks = Vec::new();

        if self.capture_state.is_some() || self.scan_capture_screen.is_capturing {
            tasks.push(self.handle_stop_capture());
        }
        if self.crack_state.is_some() || self.crack_screen.is_cracking {
            tasks.push(self.handle_stop_crack());
        }
        // Tear down the rogue AP / portal if one is up (protective shutdown).
        tasks.push(self.handle_stop_fake_ap());

        self.add_capture_log("🛑 Stop All — halting capture, deauth, cracking and AP.".to_string());

        Task::batch(tasks)
    }

    /// Handle tick for polling progress channels
    pub fn handle_tick(&mut self) -> Task<Message> {
        let mut messages = Vec::new();

        // Poll for capture progress
        if let Some(ref mut rx) = self.capture_progress_rx {
            while let Ok(progress) = rx.try_recv() {
                messages.push(Message::CaptureProgress(progress));
            }
        }

        // Poll for crack progress
        if let Some(ref mut rx) = self.crack_progress_rx {
            while let Ok(progress) = rx.try_recv() {
                messages.push(Message::CrackProgress(progress));
            }
        }

        // Poll for fake AP / captive portal progress
        if let Some(ref mut rx) = self.fake_ap_progress_rx {
            while let Ok(progress) = rx.try_recv() {
                messages.push(Message::FakeApProgress(progress));
            }
        }
        if let Some(ref mut rx) = self.portal_progress_rx {
            while let Ok(progress) = rx.try_recv() {
                messages.push(Message::PortalProgress(progress));
            }
        }

        if !messages.is_empty() {
            return Task::batch(messages.into_iter().map(Task::done));
        }
        Task::none()
    }
}
