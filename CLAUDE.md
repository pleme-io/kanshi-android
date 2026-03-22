# kanshi-android -- Continuous Device Attestation Daemon

Continuous device attestation daemon for GrapheneOS. Polls device state via
AdbTransport, computes BLAKE3 hashes, creates tameshi LayerSignature(Android),
detects drift, alerts on changes. 14 MCP tools. Consumes: AdbTransport,
AttestationVerifier, UsbEnumerator from andro-core. Publishes: LayerSignature,
Blake3Hash, DeviceAttestation to tameshi Merkle tree.

## Build & Test

```bash
cargo build          # build binary
cargo test           # run tests
cargo run -- --help  # CLI usage
cargo run            # MCP server (default, no args)
```

## CLI Reference

```
kanshi-android                           # start MCP server (default)
kanshi-android mcp                       # start MCP server
kanshi-android daemon                    # start continuous polling daemon
kanshi-android attest <serial>           # one-shot device attestation
kanshi-android baseline set <serial>     # set current state as baseline
kanshi-android baseline compare <serial> # compare against baseline
kanshi-android status                    # show daemon status
```

## MCP Tools (3 stub, 14 planned)

| Tool | Description |
|------|-------------|
| `device_attestation` | One-shot attestation: collect props, BLAKE3 hash, LayerSignature |
| `device_compliance` | Check device against NIST 800-53 controls |
| `continuous_status` | Daemon status: uptime, devices, drift events |

## Key Dependencies

| Crate | Version | Purpose |
|-------|---------|---------|
| `blake3` | 1 | Content-addressed hashing |
| `rmcp` | 0.15 | MCP server (stdio transport) |
| `clap` | 4 | CLI argument parsing |
| `tokio` | 1 | Async runtime |
| `schemars` | 0.8 | MCP tool JSON schemas |
| `chrono` | 0.4 | Timestamp handling |

## Conventions

- Edition 2024, Rust 1.91.0+, MIT, clippy pedantic
- Release: codegen-units=1, lto=true, opt-level="z", strip=true
- No subcommand -> MCP server mode (stdin/stdout)
