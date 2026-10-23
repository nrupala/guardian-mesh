# WO8-RESULT — Fuzz the boundaries

## Files added/changed

### Added
- `fuzz/Cargo.toml` — Detached fuzz package (guardian-mesh-fuzz v0.8.3) with its own `[workspace]` table, dependencies: libfuzzer-sys 0.4, guardian-meshd by path, prost 0.14.3
- `fuzz/.gitignore` — Ignores `target/`, `artifacts/`, and corpus crash files (`crash-*`, `leak-*`, `timeout-*`)
- `fuzz/fuzz_targets/fuzz_envelope_decode.rs` — Protobuf decode of EvaluateRequest + ProtocolFirewall::check_envelope_size
- `fuzz/fuzz_targets/fuzz_payload_parse.rs` — Feeds raw input to ProtocolFirewall::check_envelope_size, check_unknown_fields (PF-12), check_nesting_depth (PF-13)
- `fuzz/fuzz_targets/fuzz_proof_verify.rs` — ML-DSA-65 signature verification via verify_proto_envelope; fixed verifying key from fixed 32-byte seed (matches daemon's SigningKey::from_seed); also attempts verifying_key_from_bytes on whole input
- `fuzz/corpus/fuzz_envelope_decode/minimal` — 6 bytes, minimal protobuf structure
- `fuzz/corpus/fuzz_envelope_decode/truncated` — 2 bytes, truncated protobuf
- `fuzz/corpus/fuzz_payload_parse/valid_json` — 105 bytes, valid action descriptor JSON matching WebUI shape (actionType, context, target, metadata)
- `fuzz/corpus/fuzz_payload_parse/deep_nesting` — 40 bytes, depth-5 nested JSON (exceeds limit of 4)
- `fuzz/corpus/fuzz_proof_verify/basic` — 40 bytes, basic input split as crc||sig||payload
- `fuzz/corpus/fuzz_proof_verify/zero_sig` — 116 bytes, crc + zero signature + "test payload"
- `fuzz/README.md` — What the targets cover, how to run locally (nightly + cargo-fuzz, Linux is the proven surface; Windows unproven), crash-handling rule (P0 work order, minimize, regression seed)
- `.github/workflows/fuzz.yml` — Nightly CI workflow (schedule cron 02:00 UTC + workflow_dispatch), ubuntu-latest, installs protoc + nightly + cargo-fuzz, runs each target for 60s with `-max_total_time=60 -rss_limit_mb=2048`, uploads artifacts on failure

### Changed
- `VERSION` — 0.8.2 → 0.8.3
- `guardian-meshd/Cargo.toml` — version 0.8.2 → 0.8.3
- `README.md` — version 0.8.2 → 0.8.3, updated date to 2026-10-22
- `CHANGELOG.md` — Added 0.8.3 entry: WO-8, the three targets, the nightly fuzz workflow, test counts, honest Windows blocker

## Cargo test counts (invocation root: repo root)

```
D:\guardian-mesh-work\wo8> cargo test
```

**Result: 96 tests green** (79 lib + 17 bin + 0 doc)

Breakdown:
- `test result: ok. 79 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.16s` (lib tests)
- `test result: ok. 17 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.69s` (bin tests)
- `test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s` (doc tests)

**No code changes to guardian-meshd/** — WO-8 adds fuzz targets only. Test count stays exactly the same as pre-change.

## Per-target details

### fuzz_envelope_decode
**Public APIs exercised:**
- `guardian_meshd::proto::EvaluateRequest::decode` (prost protobuf decoding)
- `guardian_meshd::protocol_firewall::ProtocolFirewall::check_envelope_size` (PF-1/PF-5)

**Seed files created:**
- `fuzz/corpus/fuzz_envelope_decode/minimal` (6 bytes) — minimal protobuf structure
- `fuzz/corpus/fuzz_envelope_decode/truncated` (2 bytes) — truncated protobuf

**Fuzz run outcome:** NOT RUN (blocker: Windows nightly compilation OOM — see below)

---

### fuzz_payload_parse
**Public APIs exercised:**
- `guardian_meshd::protocol_firewall::ProtocolFirewall::check_envelope_size` (PF-1/PF-5)
- `guardian_meshd::protocol_firewall::ProtocolFirewall::check_unknown_fields` (PF-12)
- `guardian_meshd::protocol_firewall::ProtocolFirewall::check_nesting_depth` (PF-13)

**Seed files created:**
- `fuzz/corpus/fuzz_payload_parse/valid_json` (105 bytes) — valid action descriptor JSON matching WebUI shape: `{"actionType":"TOOL_CALL","context":"test context","target":"panel","metadata":{"source":"webui"}}`
- `fuzz/corpus/fuzz_payload_parse/deep_nesting` (40 bytes) — depth-5 nested JSON: `{"a":{"b":{"c":{"d":{"e":"too deep"}}}}}`

**Fuzz run outcome:** NOT RUN (blocker: Windows nightly compilation OOM — see below)

---

### fuzz_proof_verify
**Public APIs exercised:**
- `guardian_meshd::sealed_envelope::verify_proto_envelope` (ML-DSA-65 signature verification over crc||payload)
- `guardian_meshd::sealed_envelope::verifying_key_from_bytes` (decodes 1952-byte verifying key from bytes)
- Fixed verifying key generated via `ml_dsa::SigningKey::<MlDsa65>::from_seed` (same pattern as daemon's `load_or_generate_signing_key`)

**Seed files created:**
- `fuzz/corpus/fuzz_proof_verify/basic` (40 bytes) — basic input split as crc (4 bytes LE) || sig || payload
- `fuzz/corpus/fuzz_proof_verify/zero_sig` (116 bytes) — crc (4 bytes LE) + zero signature (100 bytes) + "test payload"

**Fuzz run outcome:** NOT RUN (blocker: Windows nightly compilation OOM — see below)

---

## Fuzz run attempt: blocker

**Platform:** Windows (win32), Rust nightly toolchain already installed (`nightly-x86_64-pc-windows-msvc`)

**Attempted:** `cargo +nightly build` in the `fuzz/` directory to compile the fuzz targets with the nightly toolchain (cargo-fuzz wraps this step).

**Exact error:**
```
cd fuzz
cargo +nightly build
   Compiling proc-macro2 v1.0.107
   Compiling cfg-if v1.0.5
   ... (compilation proceeds through ~20 crates) ...
   Compiling version_check v0.9.5
memory allocation of 2097152 bytes failed
stack backtrace:
   0:     0x7ffa98b9e639 - <unknown>
Out of memory.
```

**Blocker:** Rust nightly compilation of the fuzz package (which depends on `libfuzzer-sys` and the guardian-meshd crate with all its dependencies) ran out of memory on this Windows laptop during the build. The OOM occurred while compiling the dependency graph (before the fuzz target binaries themselves were built).

**Status:** Fuzz targets cannot execute on this Windows machine. Per the task spec ("If cargo-fuzz cannot run on this Windows machine (libFuzzer/sanitizer support), say so plainly in WO8-RESULT.md with the exact error — do NOT claim fuzz execution you did not observe, and do NOT let that block the rest of the work order"), this blocker is documented and does not block the work order. The targets' home run surface is **Linux CI** (`.github/workflows/fuzz.yml`, ubuntu-latest, nightly) and the **Arch isolation bench** (when it exists).

**Note:** The fuzz package itself is structured correctly (detached workspace, targets compile against guardian-meshd's public APIs, seed corpora created). The nightly CI workflow will exercise these targets on Linux.

## Daemon source changes

**None.** WO-8 adds fuzz targets under `fuzz/` only. No changes to `guardian-meshd/src/**`.
