/*!
 * Application messages
 *
 * Defines all messages that can be sent in the application.
 */

use std::path::PathBuf;

use brutifi::FakeApStatus;

use crate::screens::{CrackEngine, CrackMethod};
use crate::workers::{CaptureProgress, CrackProgress, FakeApProgress, PortalProgress, ScanResult};

/// Application messages
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum Message {
    // Navigation
    GoToScanCapture,
    GoToCrack,

    // Scan & Capture screen
    StartScan,
    StopScan,
    ResetScanState,
    ScanComplete(ScanResult),
    SelectNetwork(usize),
    SelectChannel(String),
    InterfaceSelected(String),
    RefreshInterfaces,
    BrowseCaptureFile,
    CaptureFileSelected(Option<PathBuf>),
    DownloadCapturedPcap,
    SaveCapturedPcap(Option<PathBuf>),
    DisconnectWifi,
    WifiDisconnectResult(Result<(), String>),
    StartCapture,
    StopCapture,
    SendDeauth,
    CaptureProgress(CaptureProgress),
    #[allow(dead_code)]
    EnableAdminMode,

    // Fake AP (rogue open access point)
    FakeApSsidChanged(String),
    UseTargetSsidForFakeAp,
    StartFakeAp,
    StopFakeAp,
    FakeApStatusChecked(FakeApStatus),
    FakeApProgress(FakeApProgress),
    PortalToggled(bool),
    PortalProgress(PortalProgress),

    // Crack screen
    HandshakePathChanged(String),
    EngineChanged(CrackEngine),
    MethodChanged(CrackMethod),
    MinDigitsChanged(String),
    MaxDigitsChanged(String),
    WordlistPathChanged(String),
    BrowseHandshake,
    BrowseWordlist,
    HandshakeSelected(Option<PathBuf>),
    WordlistSelected(Option<PathBuf>),
    DownloadDefaultWordlist,
    WordlistDownloadComplete(Result<String, String>),
    StartCrack,
    StopCrack,
    CrackProgress(CrackProgress),
    CopyPassword,

    // General
    Tick,
}
