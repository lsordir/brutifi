/*!
 * General handlers
 *
 * Handles general application operations like tick.
 */

use iced::Task;

use crate::app::BruteforceApp;
use crate::messages::Message;

impl BruteforceApp {
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
