/*!
 * State persistence types
 *
 * Defines the structures for persisting application state.
 */

use serde::{Deserialize, Serialize};

use crate::screens::{CrackEngine, CrackMethod};
use brutifi::WifiNetwork;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PersistedState {
    pub version: u32,
    pub scan: PersistedScanState,
    pub capture: PersistedCaptureState,
    pub crack: PersistedCrackState,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PersistedScanState {
    pub networks: Vec<WifiNetwork>,
    pub selected_network: Option<usize>,
    pub selected_interface: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PersistedCaptureState {
    pub target_network: Option<WifiNetwork>,
    pub output_file: String,
    pub handshake_complete: bool,
    pub packets_captured: u64,
    pub last_saved_capture_path: Option<String>,
    /// Last used fake AP network name (open, password-less).
    #[serde(default)]
    pub fake_ap_ssid: String,
    /// Whether the captive portal rides along with the fake AP.
    #[serde(default = "default_portal_enabled")]
    pub portal_enabled: bool,
}

fn default_portal_enabled() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PersistedCrackState {
    pub handshake_path: String,
    pub ssid: String,
    pub engine: CrackEngine,
    pub method: CrackMethod,
    pub min_digits: String,
    pub max_digits: String,
    pub wordlist_path: String,
    pub threads: usize,
}
