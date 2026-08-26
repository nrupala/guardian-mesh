# Guardian Mesh Daemon — Agent Handover

## Project Overview

gRPC service daemon (`guardian-meshd`) that evaluates actions through a 5-stage
enclave pipeline with ML-DSA-65 post-quantum signatures and HMAC-secured
handshake sessions. Written in Rust (edition 2024).

## Architecture (Enclave Pipeline)

```
Request → Sentinel → Gatekeeper → Witness → Arbiter → Vault → Response
   PF check    HMAC auth    Sign proof    Policy      Audit log
```

## Source Layout

```
guardian-meshd/
├── Cargo.toml
├── build.rs              # protobuf codegen via tonic-prost-build
├── proto/
│   └── guardian_mesh.proto   # gRPC: Evaluate / VerifyProof / Health
├── src/
│   ├── main.rs               # tonic server, GuardianMeshService
│   ├── lib.rs                # module tree, include_proto!()
│   ├── config.rs             # Config with env-var overrides
│   ├── handshake_bus.rs      # HMAC-SHA256 session manager (5-min TTL)
│   ├── policy.rs             # PolicyEngine with allow/block rules
│   ├── protocol_firewall.rs  # 18-rule framework (4 implemented)
│   ├── sealed_envelope.rs    # CRC32C + ML-DSA-65 sealed envelopes
│   └── enclave/
│       ├── mod.rs            # EnclaveContext, Verdict, ContainmentStage
│       ├── sentinel.rs       # Protocol firewall checks
│       ├── gatekeeper.rs     # HMAC session validation
│       ├── witness.rs        # ML-DSA-65 signature of verdict
│       ├── arbiter.rs        # PolicyEngine decision
│       └── vault.rs          # In-memory + JSONL audit trail
```

## Fixed Faults

| # | Fault | Location | Fix |
|---|-------|----------|-----|
| 1 | `clippy::field_reassign_with_default` | `protocol_firewall.rs:97` | Moved `total_count: 18` into struct literal |
| 2 | `unsafe` seed mutation via raw pointer | `sealed_envelope.rs:101-104` | Replaced with safe `try_from(&[u8; 32])` |
| 3 | Hardcoded handshake secret in source | `config.rs:96` | Added `GUARDIAN_MESH_HANDSHAKE_SECRET` env var |
| 4 | u128→u64 timestamp truncation | `sealed_envelope.rs:23` | Used `try_into().unwrap_or(u64::MAX)` |
| 5 | Witness signature never in AuditProof | `main.rs:99` / `witness.rs` | Stored in `EnclaveContext.witness_signature` |
| 6 | Unix-only paths on Windows | `config.rs:89-92` | Changed to `guardian-mesh-data/` relative paths |
| 7 | No session TTL / leak | `handshake_bus.rs`, `gatekeeper.rs` | Added `SESSION_TTL_SECS: 300` + `evict_expired()` |
| 8 | Only 4/18 PF rules implemented | `protocol_firewall.rs` | Noted as intentional: framework for future rules |
| 9 | 0 tests | `tests/` | Added **31 tests** across all modules |

## Current Test Coverage (31 tests, all pass)

| Module | Tests |
|--------|-------|
| `sealed_envelope` | 5 (keygen, verify, tamper, wrong-key, roundtrip) |
| `protocol_firewall` | 8 (empty, oversized, timestamp, context, traversal, counts) |
| `handshake_bus` | 5 (create, missing, tampered, remove, TTL) |
| `policy` | 5 (allow, block, unknown, overrides) |
| `enclave::mod` | 3 (context, verdict, stage) |
| `enclave::sentinel` | 1 (clean request) |
| `enclave::arbiter` | 2 (allow, block) |
| `enclave::vault` | 3 (seal, max-entries, persist) |
| **Total** | **31** |

## Env Configuration

| Variable | Default | Purpose |
|----------|---------|---------|
| `GUARDIAN_MESH_BIND_ADDR` | `127.0.0.1` | gRPC bind address |
| `GUARDIAN_MESH_PORT` | `50051` | gRPC port |
| `GUARDIAN_MESH_WORKSPACE` | `guardian-mesh-data/workspace` | Workspace directory |
| `GUARDIAN_MESH_OUTPUT` | `guardian-mesh-data/output` | Output directory |
| `GUARDIAN_MESH_HANDSHAKE_SECRET` | (embedded) | HMAC master secret |

## Build

```sh
cargo clippy --all-targets -- -D warnings  # must be clean
cargo test                                  # all 31 tests pass
cargo build --release
```

## Known Gaps

1. **PF rules 2-3, 5-9, 12-18** are defined in the enum but not checked
   in `run_full_check` — only PF-01, PF-04, PF-10, PF-11 are live.
2. **No TLS/mTLS** — the gRPC server uses plaintext.
3. **No authentication/authorization** beyond HMAC sessions.
4. **Policy overrides** are in-memory only (lost on restart).
5. **Nonce replay detection** (PF-05) and rate limiting (PF-14) are not implemented.

## Session 2 — CI, WebUI, Governance & Docs

Fixes beyond the Rust daemon itself (see repo root `README.md`):

| Area | Change |
|------|--------|
| **WebUI CI failure** | `webui/src/lib/auth.tsx:58` unused `_totpCode` → added `@typescript-eslint/no-unused-vars` `argsIgnorePattern: '^_'` to `webui/eslint.config.js`. Lint + build now pass. |
| **APK build** | Verified `npx cap add android`; a stale empty `webui/android/` dir blocks re-add. Documented in `webui/README.md`. `android/` is gitignored (generated). |
| **Branch protection** | GitHub rulesets need Pro on private repos (403). Added `PR Gate` (fails direct push to `main`) + `Version Snapshot` (tags `release/v<N>`, records `releases/manifest.json`, archives prior release). |
| **Docs** | Rewrote root `README.md`, added `guardian-meshd/README.md`, `webui/README.md`, `specs/README.md`, `templates/README.md`, `.github/workflows/README.md`; rewrote `CONTRIBUTING.md` (was wrongly labeled "agentic-OS"), `SECURITY.md`. |
| **witness.rs import** | Restored `use sha2::{Sha256, Digest}` (dropped during 2022 refactor of the signature wiring). |

**Build state:** `cargo clippy -- -D warnings` clean; `cargo test` 31/31 pass;
`npm run lint` + `npm run build` in `webui/` pass.
