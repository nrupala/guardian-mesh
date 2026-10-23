# Guardian Mesh Fuzz Targets

This directory contains libFuzzer-based fuzz targets for Guardian Mesh's boundary-facing APIs.

## What's covered

Three targets exercise the daemon's input-handling surfaces:

1. **`fuzz_envelope_decode`** — Protobuf decoding of `EvaluateRequest` messages (the envelope-bearing request type) and envelope size validation via `ProtocolFirewall::check_envelope_size`. Fuzzes the daemon's ability to handle malformed protobuf input and payload size bounds.

2. **`fuzz_payload_parse`** — JSON payload parsing and Protocol Firewall validation: `check_envelope_size`, `check_unknown_fields` (PF-12), and `check_nesting_depth` (PF-13). Fuzzes the WebUI's action descriptor JSON shape and the firewall's field/depth validation.

3. **`fuzz_proof_verify`** — ML-DSA-65 signature verification via `verify_proto_envelope`. The fuzzer splits input as: first 4 bytes = CRC32C digest (little-endian), next up to 3500 bytes = signature, remainder = payload. Verification runs against a fixed verifying key (generated from a fixed 32-byte seed) and also attempts to decode the whole input as a verifying key to test attacker-controlled key handling.

Each target exercises the daemon's **public APIs** only — no verdict logic, no LLM, no reimplementation. Decode errors and validation failures are expected; panics are bugs.

## How to run locally

**Proven surface:** Linux with Rust nightly + cargo-fuzz. The nightly CI runs these targets on `ubuntu-latest`.

**Unproven surface:** Windows runs are unproven. libFuzzer and sanitizers may not work on Windows. If you encounter errors on Windows, the targets' home run surface is Linux CI and the Arch isolation bench (when it exists).

### Prerequisites

- Rust nightly toolchain (`rustup toolchain install nightly`)
- cargo-fuzz (`cargo install cargo-fuzz`)
- protoc (same version CI uses; see `.github/workflows/rust-ci.yml`)

### Run a target

From the repository root or the `fuzz/` directory:

```bash
cd fuzz
cargo +nightly fuzz run fuzz_envelope_decode
cargo +nightly fuzz run fuzz_payload_parse
cargo +nightly fuzz run fuzz_proof_verify
```

Brief runs (60 seconds each, matching nightly CI):

```bash
cargo +nightly fuzz run fuzz_envelope_decode -- -max_total_time=60
cargo +nightly fuzz run fuzz_payload_parse -- -max_total_time=60
cargo +nightly fuzz run fuzz_proof_verify -- -max_total_time=60
```

### Crash handling

Any crash found becomes a **P0 work order**.

Crash artifacts land in `fuzz/artifacts/<target_name>/`. When a crash is found:

1. **Minimize the input**: `cargo fuzz cmin <target>` to reduce the corpus, then `cargo fuzz tmin <target> <crash_file>` to minimize the crashing input.
2. **Add as regression seed**: Copy the minimized input to `corpus/<target_name>/` with a descriptive name (e.g., `regression_issue_N`).
3. **File a work order**: The crash input and stack trace go into the issue; the fix must include a test proving the crash no longer reproduces.

Crash files (`corpus/**/crash-*`, `corpus/**/leak-*`, `corpus/**/timeout-*`) are gitignored. Seed corpora (non-crash files in `corpus/<target>/`) are committed.

## Nightly CI

`.github/workflows/fuzz.yml` runs each target for 60 seconds nightly at 02:00 UTC. On failure, `fuzz/artifacts/` uploads as a workflow artifact.

The workflow triggers on:
- `schedule` (nightly cron)
- `workflow_dispatch` (manual run)

NOT on push/PR — the main CI must stay fast and stable-only.

## Detached workspace

`fuzz/Cargo.toml` is a **detached package** with its own `[workspace]` table. The root workspace (`members = ["guardian-meshd"]`) never tries to build fuzz targets with the stable toolchain. Root `cargo test` and `cargo build` stay green.
