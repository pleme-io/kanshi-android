#![allow(clippy::module_name_repetitions)]

use chrono::{DateTime, NaiveDate, Utc};
use clap::{Parser, Subcommand};
use rmcp::{
    ServerHandler, ServiceExt,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{ServerCapabilities, ServerInfo},
    schemars, tool, tool_handler, tool_router,
    transport::stdio,
};
use serde::{Deserialize, Serialize};
use std::process::ExitCode;
use std::sync::{Arc, Mutex};

// ── CLI ──────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(name = "kanshi-android", about = "Continuous device attestation daemon for GrapheneOS")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Start continuous polling daemon
    Daemon,
    /// One-shot device attestation
    Attest {
        /// Device serial number
        serial: String,
    },
    /// Baseline management
    Baseline {
        #[command(subcommand)]
        action: BaselineAction,
    },
    /// Show daemon status
    Status,
    /// Start MCP server
    Mcp,
}

#[derive(Subcommand)]
enum BaselineAction {
    /// Set current device state as baseline
    Set {
        /// Device serial number
        serial: String,
    },
    /// Compare current state against baseline
    Compare {
        /// Device serial number
        serial: String,
    },
}

// ── Config ───────────────────────────────────────────────────────────

/// Daemon configuration loaded from YAML or defaults.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Config {
    /// Polling interval in seconds for daemon mode.
    #[serde(default = "default_poll_interval")]
    pub poll_interval_secs: u64,
    /// ADB server host.
    #[serde(default = "default_adb_host")]
    pub adb_host: String,
    /// ADB server port.
    #[serde(default = "default_adb_port")]
    pub adb_port: u16,
    /// List of device serial numbers to monitor.
    #[serde(default)]
    pub devices: Vec<String>,
}

fn default_poll_interval() -> u64 {
    30
}

fn default_adb_host() -> String {
    "127.0.0.1".into()
}

fn default_adb_port() -> u16 {
    5037
}

impl Default for Config {
    fn default() -> Self {
        Self {
            poll_interval_secs: default_poll_interval(),
            adb_host: default_adb_host(),
            adb_port: default_adb_port(),
            devices: Vec::new(),
        }
    }
}

// ── Device State ─────────────────────────────────────────────────────

/// Collected state snapshot of a single Android device.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceState {
    /// Device serial number.
    pub serial: String,
    /// Device model (e.g. "Pixel 8 Pro").
    pub model: String,
    /// Android OS version (e.g. "14").
    pub os_version: String,
    /// Security patch level date string (e.g. "2026-03-01").
    pub patch_level: String,
    /// Verified boot state (e.g. "green", "orange").
    pub boot_state: String,
    /// Encryption state (e.g. "encrypted", "unencrypted").
    pub encryption_state: String,
    /// BLAKE3 hash computed over all fields for tamper detection.
    pub blake3_hash: String,
    /// When this state was collected.
    pub checked_at: DateTime<Utc>,
}

// ── NIST 800-53 Compliance ───────────────────────────────────────────

/// NIST 800-53 controls checked against Android device state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NistControl {
    /// AC-3: Access Enforcement (AVB locked bootloader).
    AC3,
    /// SC-28: Protection of Information at Rest (encryption).
    SC28,
    /// SI-2: Flaw Remediation (security patch age).
    SI2,
}

impl std::fmt::Display for NistControl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AC3 => write!(f, "AC-3"),
            Self::SC28 => write!(f, "SC-28"),
            Self::SI2 => write!(f, "SI-2"),
        }
    }
}

/// Result of evaluating a single NIST control against device state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlStatus {
    pub control: NistControl,
    pub passed: bool,
    pub evidence: String,
}

/// Aggregate compliance result for a device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceResult {
    pub serial: String,
    pub controls: Vec<ControlStatus>,
    pub overall_passed: bool,
    pub compliance_hash: String,
}

/// Check AC-3: AVB verified boot state is "green" (locked bootloader).
#[must_use]
pub fn check_avb(state: &DeviceState) -> ControlStatus {
    let passed = state.boot_state == "green";
    ControlStatus {
        control: NistControl::AC3,
        passed,
        evidence: if passed {
            "verifiedbootstate=green (AVB locked)".into()
        } else {
            format!(
                "verifiedbootstate={} (AVB unlocked or unknown)",
                state.boot_state
            )
        },
    }
}

/// Check SC-28: Device encryption is active.
#[must_use]
pub fn check_encryption(state: &DeviceState) -> ControlStatus {
    let passed = state.encryption_state == "encrypted";
    ControlStatus {
        control: NistControl::SC28,
        passed,
        evidence: if passed {
            "crypto.state=encrypted (FBE/FDE active)".into()
        } else {
            format!(
                "crypto.state={} (not encrypted)",
                state.encryption_state
            )
        },
    }
}

/// Check SI-2: Security patch level is within acceptable age.
///
/// `max_age_days` is the maximum number of days the patch may be old.
#[must_use]
pub fn check_patch_level(state: &DeviceState, max_age_days: u32) -> ControlStatus {
    match NaiveDate::parse_from_str(&state.patch_level, "%Y-%m-%d") {
        Ok(patch_date) => {
            let today = Utc::now().date_naive();
            let age = today.signed_duration_since(patch_date).num_days();
            let passed = age >= 0 && age <= i64::from(max_age_days);
            ControlStatus {
                control: NistControl::SI2,
                passed,
                evidence: format!(
                    "security_patch={}, age={age} days, max_allowed={max_age_days}",
                    state.patch_level
                ),
            }
        }
        Err(_) => ControlStatus {
            control: NistControl::SI2,
            passed: false,
            evidence: format!(
                "security_patch='{}' (invalid or missing date)",
                state.patch_level
            ),
        },
    }
}

/// Run all compliance checks against collected device state.
#[must_use]
pub fn assess_compliance(state: &DeviceState) -> ComplianceResult {
    let controls = vec![
        check_avb(state),
        check_encryption(state),
        check_patch_level(state, 90),
    ];

    let overall_passed = controls.iter().all(|c| c.passed);

    let mut hasher = blake3::Hasher::new();
    hasher.update(state.serial.as_bytes());
    for control in &controls {
        hasher.update(format!("{}:{}", control.control, control.passed).as_bytes());
    }
    let compliance_hash = hasher.finalize().to_hex().to_string();

    ComplianceResult {
        serial: state.serial.clone(),
        controls,
        overall_passed,
        compliance_hash,
    }
}

// ── Getprop Parsing ──────────────────────────────────────────────────

/// Extract a property value from ADB `getprop` output.
///
/// Supports both `key=value` and `[key]: [value]` formats.
fn extract_prop(props: &str, key: &str) -> String {
    let bracket_prefix = format!("[{key}]: [");
    let equals_prefix = format!("{key}=");

    for line in props.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix(&bracket_prefix) {
            if let Some(val) = rest.strip_suffix(']') {
                return val.to_string();
            }
        }
        if let Some(val) = trimmed.strip_prefix(&equals_prefix) {
            return val.to_string();
        }
    }

    String::new()
}

/// Collect device state from raw `getprop` output.
///
/// The `shell_fn` closure executes an ADB shell command and returns its stdout.
/// This is a pure function — the closure abstracts the ADB transport.
#[must_use]
pub fn collect_device_state<F>(serial: &str, shell_fn: F) -> DeviceState
where
    F: Fn(&str) -> String,
{
    let props = shell_fn("getprop");

    let model = extract_prop(&props, "ro.product.model");
    let os_version = extract_prop(&props, "ro.build.version.release");
    let patch_level = extract_prop(&props, "ro.build.version.security_patch");
    let boot_state = extract_prop(&props, "ro.boot.verifiedbootstate");
    let encryption_state = extract_prop(&props, "ro.crypto.state");

    let mut hasher = blake3::Hasher::new();
    hasher.update(serial.as_bytes());
    hasher.update(model.as_bytes());
    hasher.update(os_version.as_bytes());
    hasher.update(patch_level.as_bytes());
    hasher.update(boot_state.as_bytes());
    hasher.update(encryption_state.as_bytes());
    let blake3_hash = hasher.finalize().to_hex().to_string();

    DeviceState {
        serial: serial.into(),
        model,
        os_version,
        patch_level,
        boot_state,
        encryption_state,
        blake3_hash,
        checked_at: Utc::now(),
    }
}

// ── Drift Detection ──────────────────────────────────────────────────

/// A single field that changed between two device states.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DriftField {
    pub field: String,
    pub previous: String,
    pub current: String,
}

/// Detect drift between a previous and current device state.
///
/// Returns a list of fields that changed. Empty list means no drift.
#[must_use]
pub fn detect_drift(previous: &DeviceState, current: &DeviceState) -> Vec<DriftField> {
    let mut drifts = Vec::new();

    let fields: &[(&str, &str, &str)] = &[
        ("model", &previous.model, &current.model),
        ("os_version", &previous.os_version, &current.os_version),
        ("patch_level", &previous.patch_level, &current.patch_level),
        ("boot_state", &previous.boot_state, &current.boot_state),
        (
            "encryption_state",
            &previous.encryption_state,
            &current.encryption_state,
        ),
    ];

    for &(name, prev_val, cur_val) in fields {
        if prev_val != cur_val {
            drifts.push(DriftField {
                field: name.into(),
                previous: prev_val.into(),
                current: cur_val.into(),
            });
        }
    }

    drifts
}

// ── DevicePoller Trait ────────────────────────────────────────────────

/// Abstraction over device polling for testability.
///
/// Real implementation calls ADB. Mock returns fixed state.
pub trait DevicePoller: Send + Sync + std::fmt::Debug {
    /// Poll a single device and return its current state.
    ///
    /// # Errors
    ///
    /// Returns an error if the device cannot be reached or the
    /// response cannot be parsed.
    fn poll(&self, serial: &str) -> Result<DeviceState, String>;
}

/// Real ADB-based device poller.
#[derive(Debug)]
pub struct AdbPoller {
    /// ADB server host.
    pub host: String,
    /// ADB server port.
    pub port: u16,
}

impl DevicePoller for AdbPoller {
    fn poll(&self, serial: &str) -> Result<DeviceState, String> {
        let output = std::process::Command::new("adb")
            .args(["-s", serial, "-H", &self.host, "-P", &self.port.to_string(), "shell", "getprop"])
            .output()
            .map_err(|e| format!("adb exec failed: {e}"))?;

        if !output.status.success() {
            return Err(format!(
                "adb shell getprop failed: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        let props = String::from_utf8_lossy(&output.stdout).to_string();
        Ok(collect_device_state(serial, |_cmd| props.clone()))
    }
}

/// Mock poller for testing — returns a fixed device state.
#[derive(Debug)]
pub struct MockPoller {
    /// The fixed state to return. Set `None` to simulate an error.
    pub state: Option<DeviceState>,
}

impl DevicePoller for MockPoller {
    fn poll(&self, serial: &str) -> Result<DeviceState, String> {
        match &self.state {
            Some(s) => {
                let mut state = s.clone();
                state.serial = serial.into();
                // Recompute hash for the new serial.
                let mut hasher = blake3::Hasher::new();
                hasher.update(state.serial.as_bytes());
                hasher.update(state.model.as_bytes());
                hasher.update(state.os_version.as_bytes());
                hasher.update(state.patch_level.as_bytes());
                hasher.update(state.boot_state.as_bytes());
                hasher.update(state.encryption_state.as_bytes());
                state.blake3_hash = hasher.finalize().to_hex().to_string();
                Ok(state)
            }
            None => Err(format!("mock: device {serial} unreachable")),
        }
    }
}

// ── Daemon State ─────────────────────────────────────────────────────

/// Runtime state tracked by the continuous polling daemon.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonStatus {
    /// Whether the daemon is currently running.
    pub running: bool,
    /// Timestamp of the last poll cycle.
    pub last_check: Option<DateTime<Utc>>,
    /// Configured poll interval in seconds.
    pub interval_secs: u64,
    /// Number of devices being monitored.
    pub devices_monitored: usize,
    /// Total drift events detected since daemon start.
    pub drift_events: u64,
}

impl Default for DaemonStatus {
    fn default() -> Self {
        Self {
            running: false,
            last_check: None,
            interval_secs: default_poll_interval(),
            devices_monitored: 0,
            drift_events: 0,
        }
    }
}

// ── MCP Input Schemas ────────────────────────────────────────────────

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct DeviceInput {
    /// Device serial number
    serial: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct EmptyInput {}

// ── MCP Helpers ──────────────────────────────────────────────────────

fn json_ok<T: serde::Serialize>(value: &T) -> String {
    serde_json::to_string_pretty(value).unwrap_or_else(|e| json_err(&e))
}

fn json_err(e: &dyn std::fmt::Display) -> String {
    format!(r#"{{"error":"{}"}}"#, e.to_string().replace('"', "'"))
}

// ── MCP Server ───────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct KanshiMcp {
    poller: Arc<dyn DevicePoller>,
    daemon_status: Arc<Mutex<DaemonStatus>>,
    tool_router: ToolRouter<Self>,
}

// Manual Debug for Arc<dyn DevicePoller> is not needed since KanshiMcp
// already derives Debug and Arc<dyn DevicePoller> implements Debug if
// DevicePoller: Debug. We handle this via the derive on the struct and
// the explicit Debug bounds are not required for tool_router.

#[tool_router]
impl KanshiMcp {
    fn new(poller: Arc<dyn DevicePoller>, config: &Config) -> Self {
        let daemon_status = DaemonStatus {
            interval_secs: config.poll_interval_secs,
            devices_monitored: config.devices.len(),
            ..DaemonStatus::default()
        };
        Self {
            poller,
            daemon_status: Arc::new(Mutex::new(daemon_status)),
            tool_router: Self::tool_router(),
        }
    }

    #[tool(description = "Perform one-shot device attestation: collect device properties via ADB shell, compute BLAKE3 hash, return JSON report")]
    async fn device_attestation(
        &self,
        Parameters(input): Parameters<DeviceInput>,
    ) -> String {
        match self.poller.poll(&input.serial) {
            Ok(state) => json_ok(&state),
            Err(e) => json_err(&e),
        }
    }

    #[tool(description = "Check device compliance against NIST 800-53 controls: AC-3 (AVB locked), SC-28 (encryption), SI-2 (patch freshness)")]
    async fn device_compliance(
        &self,
        Parameters(input): Parameters<DeviceInput>,
    ) -> String {
        match self.poller.poll(&input.serial) {
            Ok(state) => {
                let result = assess_compliance(&state);
                json_ok(&result)
            }
            Err(e) => json_err(&e),
        }
    }

    #[tool(description = "Get continuous attestation daemon status: last_check, interval, devices_monitored, drift_events")]
    async fn continuous_status(
        &self,
        Parameters(_input): Parameters<EmptyInput>,
    ) -> String {
        let status = self
            .daemon_status
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        json_ok(&status)
    }
}

#[tool_handler]
impl ServerHandler for KanshiMcp {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            instructions: Some(
                "Continuous device attestation daemon for GrapheneOS — 3 tools: \
                 device_attestation (collect + BLAKE3 hash), device_compliance \
                 (NIST 800-53 checks: AC-3, SC-28, SI-2), continuous_status \
                 (daemon polling state)."
                    .into(),
            ),
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            ..Default::default()
        }
    }
}

async fn run_mcp() -> ExitCode {
    let config = Config::default();
    let poller: Arc<dyn DevicePoller> = Arc::new(AdbPoller {
        host: config.adb_host.clone(),
        port: config.adb_port,
    });
    let server = KanshiMcp::new(poller, &config);
    match server.serve(stdio()).await {
        Ok(ct) => {
            if let Err(e) = ct.waiting().await {
                eprintln!("MCP server error: {e}");
                return ExitCode::FAILURE;
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("MCP server error: {e}");
            ExitCode::FAILURE
        }
    }
}

// ── Main ─────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();

    match cli.command {
        None | Some(Command::Mcp) => run_mcp().await,
        Some(Command::Daemon) => {
            eprintln!("kanshi-android: daemon mode — use MCP continuous_status tool to query state");
            ExitCode::FAILURE
        }
        Some(Command::Attest { serial }) => {
            let config = Config::default();
            let poller = AdbPoller {
                host: config.adb_host,
                port: config.adb_port,
            };
            match poller.poll(&serial) {
                Ok(state) => {
                    println!("{}", json_ok(&state));
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("{}", json_err(&e));
                    ExitCode::FAILURE
                }
            }
        }
        Some(Command::Baseline { action }) => match action {
            BaselineAction::Set { serial } => {
                println!(
                    "{}",
                    json_ok(&serde_json::json!({
                        "serial": serial,
                        "action": "baseline_set",
                        "status": "not yet implemented — requires persistent storage",
                    }))
                );
                ExitCode::SUCCESS
            }
            BaselineAction::Compare { serial } => {
                println!(
                    "{}",
                    json_ok(&serde_json::json!({
                        "serial": serial,
                        "action": "baseline_compare",
                        "status": "not yet implemented — requires persistent storage",
                    }))
                );
                ExitCode::SUCCESS
            }
        },
        Some(Command::Status) => {
            let status = DaemonStatus::default();
            println!("{}", json_ok(&status));
            ExitCode::SUCCESS
        }
    }
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Test Fixtures ────────────────────────────────────────────────

    const COMPLIANT_PROPS: &str = "\
ro.product.model=Pixel 8 Pro
ro.build.version.release=14
ro.build.version.security_patch=2026-03-01
ro.boot.verifiedbootstate=green
ro.crypto.state=encrypted
";

    const NONCOMPLIANT_PROPS: &str = "\
ro.product.model=Generic Phone
ro.build.version.release=12
ro.build.version.security_patch=2024-01-01
ro.boot.verifiedbootstate=orange
ro.crypto.state=unencrypted
";

    const GETPROP_FORMAT: &str = "\
[ro.product.model]: [Pixel 8 Pro]
[ro.build.version.release]: [14]
[ro.build.version.security_patch]: [2026-02-05]
[ro.boot.verifiedbootstate]: [green]
[ro.crypto.state]: [encrypted]
";

    const MINIMAL_PROPS: &str = "\
ro.product.model=Test
ro.build.version.release=13
ro.build.version.security_patch=2026-03-15
ro.boot.verifiedbootstate=green
ro.crypto.state=encrypted
";

    fn compliant_state() -> DeviceState {
        collect_device_state("TEST001", |_| COMPLIANT_PROPS.into())
    }

    fn noncompliant_state() -> DeviceState {
        collect_device_state("TEST002", |_| NONCOMPLIANT_PROPS.into())
    }

    fn mock_poller_compliant() -> MockPoller {
        MockPoller {
            state: Some(compliant_state()),
        }
    }

    // ── collect_device_state tests ───────────────────────────────────

    #[test]
    fn collect_state_parses_key_equals_value() {
        let state = collect_device_state("DEV1", |_| COMPLIANT_PROPS.into());
        assert_eq!(state.serial, "DEV1");
        assert_eq!(state.model, "Pixel 8 Pro");
        assert_eq!(state.os_version, "14");
        assert_eq!(state.patch_level, "2026-03-01");
        assert_eq!(state.boot_state, "green");
        assert_eq!(state.encryption_state, "encrypted");
        assert!(!state.blake3_hash.is_empty());
    }

    #[test]
    fn collect_state_parses_getprop_bracket_format() {
        let state = collect_device_state("DEV2", |_| GETPROP_FORMAT.into());
        assert_eq!(state.model, "Pixel 8 Pro");
        assert_eq!(state.os_version, "14");
        assert_eq!(state.patch_level, "2026-02-05");
        assert_eq!(state.boot_state, "green");
        assert_eq!(state.encryption_state, "encrypted");
    }

    #[test]
    fn collect_state_missing_props_returns_empty_strings() {
        let state = collect_device_state("DEV3", |_| "some.other.prop=value\n".into());
        assert_eq!(state.model, "");
        assert_eq!(state.os_version, "");
        assert_eq!(state.patch_level, "");
        assert_eq!(state.boot_state, "");
        assert_eq!(state.encryption_state, "");
    }

    #[test]
    fn collect_state_empty_props() {
        let state = collect_device_state("DEV4", |_| String::new());
        assert_eq!(state.serial, "DEV4");
        assert_eq!(state.model, "");
        assert!(!state.blake3_hash.is_empty());
    }

    // ── BLAKE3 hash tests ────────────────────────────────────────────

    #[test]
    fn blake3_hash_deterministic() {
        let s1 = collect_device_state("HASH1", |_| COMPLIANT_PROPS.into());
        let s2 = collect_device_state("HASH1", |_| COMPLIANT_PROPS.into());
        assert_eq!(s1.blake3_hash, s2.blake3_hash);
    }

    #[test]
    fn blake3_hash_differs_for_different_serials() {
        let s1 = collect_device_state("SERIAL_A", |_| COMPLIANT_PROPS.into());
        let s2 = collect_device_state("SERIAL_B", |_| COMPLIANT_PROPS.into());
        assert_ne!(s1.blake3_hash, s2.blake3_hash);
    }

    #[test]
    fn blake3_hash_differs_for_different_props() {
        let s1 = collect_device_state("SAME", |_| COMPLIANT_PROPS.into());
        let s2 = collect_device_state("SAME", |_| NONCOMPLIANT_PROPS.into());
        assert_ne!(s1.blake3_hash, s2.blake3_hash);
    }

    // ── Config tests ─────────────────────────────────────────────────

    #[test]
    fn config_defaults() {
        let config = Config::default();
        assert_eq!(config.poll_interval_secs, 30);
        assert_eq!(config.adb_host, "127.0.0.1");
        assert_eq!(config.adb_port, 5037);
        assert!(config.devices.is_empty());
    }

    #[test]
    fn config_yaml_roundtrip() {
        let config = Config {
            poll_interval_secs: 60,
            adb_host: "192.168.1.100".into(),
            adb_port: 5038,
            devices: vec!["DEV1".into(), "DEV2".into()],
        };
        let yaml = serde_yaml_ng::to_string(&config).expect("serialize");
        let parsed: Config = serde_yaml_ng::from_str(&yaml).expect("deserialize");
        assert_eq!(config, parsed);
    }

    #[test]
    fn config_partial_yaml_uses_defaults() {
        let yaml = "poll_interval_secs: 120\n";
        let config: Config = serde_yaml_ng::from_str(yaml).expect("parse");
        assert_eq!(config.poll_interval_secs, 120);
        assert_eq!(config.adb_host, "127.0.0.1");
        assert_eq!(config.adb_port, 5037);
        assert!(config.devices.is_empty());
    }

    // ── DeviceState serialization tests ──────────────────────────────

    #[test]
    fn device_state_json_roundtrip() {
        let state = compliant_state();
        let json = serde_json::to_string(&state).expect("serialize");
        let parsed: DeviceState = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(state, parsed);
    }

    // ── Compliance tests ─────────────────────────────────────────────

    #[test]
    fn compliance_passes_for_compliant_device() {
        let state = compliant_state();
        let result = assess_compliance(&state);
        assert!(result.overall_passed);
        assert_eq!(result.controls.len(), 3);
        assert!(result.controls.iter().all(|c| c.passed));
    }

    #[test]
    fn compliance_fails_for_noncompliant_device() {
        let state = noncompliant_state();
        let result = assess_compliance(&state);
        assert!(!result.overall_passed);
        // At minimum AVB (orange) and encryption (unencrypted) fail.
        let failed: Vec<_> = result.controls.iter().filter(|c| !c.passed).collect();
        assert!(failed.len() >= 2);
    }

    #[test]
    fn compliance_hash_deterministic() {
        let s1 = compliant_state();
        let s2 = compliant_state();
        let r1 = assess_compliance(&s1);
        let r2 = assess_compliance(&s2);
        assert_eq!(r1.compliance_hash, r2.compliance_hash);
    }

    #[test]
    fn compliance_hash_differs_between_states() {
        let r1 = assess_compliance(&compliant_state());
        let r2 = assess_compliance(&noncompliant_state());
        assert_ne!(r1.compliance_hash, r2.compliance_hash);
    }

    #[test]
    fn avb_check_green_passes() {
        let state = compliant_state();
        let status = check_avb(&state);
        assert!(status.passed);
        assert_eq!(status.control, NistControl::AC3);
    }

    #[test]
    fn avb_check_orange_fails() {
        let state = noncompliant_state();
        let status = check_avb(&state);
        assert!(!status.passed);
    }

    #[test]
    fn encryption_check_encrypted_passes() {
        let state = compliant_state();
        let status = check_encryption(&state);
        assert!(status.passed);
        assert_eq!(status.control, NistControl::SC28);
    }

    #[test]
    fn encryption_check_unencrypted_fails() {
        let state = noncompliant_state();
        let status = check_encryption(&state);
        assert!(!status.passed);
    }

    #[test]
    fn patch_level_check_recent_passes() {
        let state = compliant_state();
        let status = check_patch_level(&state, 90);
        assert!(status.passed);
        assert_eq!(status.control, NistControl::SI2);
    }

    #[test]
    fn patch_level_check_old_fails() {
        let state = noncompliant_state();
        let status = check_patch_level(&state, 90);
        assert!(!status.passed);
    }

    #[test]
    fn patch_level_invalid_date_fails() {
        let mut state = compliant_state();
        state.patch_level = "not-a-date".into();
        let status = check_patch_level(&state, 90);
        assert!(!status.passed);
        assert!(status.evidence.contains("invalid"));
    }

    // ── Drift detection tests ────────────────────────────────────────

    #[test]
    fn no_drift_when_identical() {
        let s1 = compliant_state();
        let s2 = compliant_state();
        let drifts = detect_drift(&s1, &s2);
        assert!(drifts.is_empty());
    }

    #[test]
    fn drift_detected_on_boot_state_change() {
        let s1 = compliant_state();
        let mut s2 = compliant_state();
        s2.boot_state = "orange".into();
        let drifts = detect_drift(&s1, &s2);
        assert_eq!(drifts.len(), 1);
        assert_eq!(drifts[0].field, "boot_state");
        assert_eq!(drifts[0].previous, "green");
        assert_eq!(drifts[0].current, "orange");
    }

    #[test]
    fn drift_detected_on_multiple_changes() {
        let s1 = compliant_state();
        let s2 = noncompliant_state();
        let drifts = detect_drift(&s1, &s2);
        // model, os_version, patch_level, boot_state, encryption_state all differ.
        assert!(drifts.len() >= 4);
    }

    // ── MockPoller trait tests ───────────────────────────────────────

    #[test]
    fn mock_poller_returns_state_with_serial() {
        let poller = mock_poller_compliant();
        let state = poller.poll("MOCK_SERIAL").expect("should succeed");
        assert_eq!(state.serial, "MOCK_SERIAL");
        assert_eq!(state.model, "Pixel 8 Pro");
    }

    #[test]
    fn mock_poller_error_when_none() {
        let poller = MockPoller { state: None };
        let result = poller.poll("FAIL_DEV");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("unreachable"));
    }

    #[test]
    fn mock_poller_implements_trait() {
        let poller: Box<dyn DevicePoller> = Box::new(mock_poller_compliant());
        let state = poller.poll("TRAIT_TEST").expect("should succeed");
        assert_eq!(state.serial, "TRAIT_TEST");
    }

    #[test]
    fn mock_poller_recomputes_hash_for_serial() {
        let poller = mock_poller_compliant();
        let s1 = poller.poll("A").expect("ok");
        let s2 = poller.poll("B").expect("ok");
        assert_ne!(s1.blake3_hash, s2.blake3_hash);
    }

    // ── NistControl display tests ────────────────────────────────────

    #[test]
    fn nist_control_display() {
        assert_eq!(NistControl::AC3.to_string(), "AC-3");
        assert_eq!(NistControl::SC28.to_string(), "SC-28");
        assert_eq!(NistControl::SI2.to_string(), "SI-2");
    }

    // ── DaemonStatus default tests ───────────────────────────────────

    #[test]
    fn daemon_status_defaults() {
        let status = DaemonStatus::default();
        assert!(!status.running);
        assert!(status.last_check.is_none());
        assert_eq!(status.interval_secs, 30);
        assert_eq!(status.devices_monitored, 0);
        assert_eq!(status.drift_events, 0);
    }

    // ── extract_prop tests ───────────────────────────────────────────

    #[test]
    fn extract_prop_key_equals_value() {
        let val = extract_prop("ro.product.model=Pixel 8 Pro\n", "ro.product.model");
        assert_eq!(val, "Pixel 8 Pro");
    }

    #[test]
    fn extract_prop_bracket_format() {
        let val = extract_prop(
            "[ro.product.model]: [Pixel 8 Pro]\n",
            "ro.product.model",
        );
        assert_eq!(val, "Pixel 8 Pro");
    }

    #[test]
    fn extract_prop_missing_returns_empty() {
        let val = extract_prop("ro.other.prop=value\n", "ro.product.model");
        assert_eq!(val, "");
    }

    // ── Integration: collect + assess pipeline ───────────────────────

    #[test]
    fn end_to_end_collect_then_assess() {
        let state = collect_device_state("E2E_DEV", |_| MINIMAL_PROPS.into());
        let result = assess_compliance(&state);
        assert!(result.overall_passed);
        assert_eq!(result.serial, "E2E_DEV");
        assert!(!result.compliance_hash.is_empty());
    }
}
