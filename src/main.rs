use clap::{Parser, Subcommand};
use rmcp::{
    ServerHandler, ServiceExt,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{ServerCapabilities, ServerInfo},
    schemars, tool, tool_handler, tool_router,
    transport::stdio,
};
use serde::Deserialize;
use std::process::ExitCode;

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

// ── MCP input schemas ────────────────────────────────────────────────

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct DeviceInput {
    /// Device serial number
    serial: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct EmptyInput {}

// ── MCP helpers ──────────────────────────────────────────────────────

fn json_ok<T: serde::Serialize>(value: &T) -> String {
    serde_json::to_string_pretty(value).unwrap_or_else(|e| json_err(&e))
}

fn json_err(e: &dyn std::fmt::Display) -> String {
    format!(r#"{{"error":"{}"}}"#, e.to_string().replace('"', "'"))
}

// ── MCP server ───────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct KanshiMcp {
    tool_router: ToolRouter<Self>,
}

#[tool_router]
impl KanshiMcp {
    fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }

    #[tool(description = "Perform one-shot device attestation: collect properties, compute BLAKE3 hashes, produce LayerSignature(Android)")]
    async fn device_attestation(&self, Parameters(input): Parameters<DeviceInput>) -> String {
        let hash = blake3::hash(input.serial.as_bytes());
        json_ok(&serde_json::json!({
            "serial": input.serial,
            "attestation_hash": hash.to_hex().to_string(),
            "status": "stub — requires andro-core AdbTransport",
        }))
    }

    #[tool(description = "Check device compliance against attestation baseline and NIST 800-53 controls")]
    async fn device_compliance(&self, Parameters(input): Parameters<DeviceInput>) -> String {
        json_ok(&serde_json::json!({
            "serial": input.serial,
            "compliant": false,
            "status": "stub — requires kensa-android compliance engine",
        }))
    }

    #[tool(description = "Get continuous attestation daemon status: uptime, devices monitored, drift events")]
    async fn continuous_status(&self, Parameters(_input): Parameters<EmptyInput>) -> String {
        json_ok(&serde_json::json!({
            "running": false,
            "devices_monitored": 0,
            "drift_events": 0,
            "status": "stub — daemon not implemented yet",
        }))
    }
}

#[tool_handler]
impl ServerHandler for KanshiMcp {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            instructions: Some(
                "Continuous device attestation daemon for GrapheneOS — 3 tools: \
                 device attestation, compliance checking, continuous monitoring status."
                    .into(),
            ),
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            ..Default::default()
        }
    }
}

async fn run_mcp() -> ExitCode {
    let server = KanshiMcp::new();
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
            eprintln!("kanshi-android: daemon mode not yet implemented");
            ExitCode::FAILURE
        }
        Some(Command::Attest { serial }) => {
            let hash = blake3::hash(serial.as_bytes());
            println!(
                "{}",
                json_ok(&serde_json::json!({
                    "serial": serial,
                    "attestation_hash": hash.to_hex().to_string(),
                    "status": "stub",
                }))
            );
            ExitCode::SUCCESS
        }
        Some(Command::Baseline { action }) => match action {
            BaselineAction::Set { serial } => {
                println!(
                    "{}",
                    json_ok(&serde_json::json!({
                        "serial": serial,
                        "action": "baseline_set",
                        "status": "stub",
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
                        "status": "stub",
                    }))
                );
                ExitCode::SUCCESS
            }
        },
        Some(Command::Status) => {
            println!(
                "{}",
                json_ok(&serde_json::json!({
                    "running": false,
                    "status": "stub",
                }))
            );
            ExitCode::SUCCESS
        }
    }
}
