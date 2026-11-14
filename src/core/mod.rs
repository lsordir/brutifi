// Core library modules
pub mod bruteforce;
pub mod crypto;
pub mod handshake;
pub mod hashcat;
pub mod network;
pub mod passive_pmkid;
pub mod password_gen;
pub mod portal;
pub mod rogue_ap;
pub mod security;
pub mod session;

// Re-exports
pub use bruteforce::OfflineBruteForcer;
pub use crypto::{calculate_mic, calculate_pmk, calculate_ptk, verify_password};
pub use handshake::{extract_eapol_from_packet, parse_cap_file, EapolPacket, Handshake};
pub use hashcat::{
    are_external_tools_available, convert_to_hashcat_format, crack_with_hashcat, HashcatParams,
    HashcatProgress, HashcatResult,
};
pub use network::{
    capture_traffic, compact_duplicate_networks, disconnect_wifi, scan_networks,
    wifi_connected_ssid, CaptureOptions, WifiNetwork,
};
pub use passive_pmkid::{
    check_hcxdumptool_available, load_captured_pmkids, run_passive_pmkid_capture,
    save_captured_pmkids, CapturedPmkid, PassivePmkidConfig, PassivePmkidProgress,
    PassivePmkidResult, PassivePmkidState,
};
pub use portal::{run_portal, PortalConfig, PortalEvent, PortalState};
pub use rogue_ap::{fake_ap_status, start_fake_ap, stop_fake_ap, FakeApStatus};
pub use session::{
    AttackType, SessionConfig, SessionData, SessionManager, SessionMetadata, SessionProgress,
    SessionStatus,
};
