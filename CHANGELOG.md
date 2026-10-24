# Changelog

All notable changes to this project will be documented in this file.

This project adheres to [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.8.4] - 2026-10-23

### Added
- **WO-9: Public release log on the site.** Added a `/releases` page to the WebUI fed from the CHANGELOG and gate records. The page displays every release with its version, date, summary, highlights, gate verdict, and testing record — updated as part of each release, not after.
  - **Release data file (`webui/src/data/releases.ts`)**: A typed, exported array with one entry for every version section in CHANGELOG.md (0.8.4, 0.8.3, 0.8.2, 0.8.1, 0.8.0, 0.7.0, 0.6.0, 0.1.0). Each entry carries: version, date, summary (1–2 plain sentences distilled from the CHANGELOG section), highlights (array of short plain-language strings), gateVerdict (the verdict string the CHANGELOG records, or "Not recorded" where none exists), tests (test counts and what ran, condensed to one short string, or "Not recorded"), status ("Release candidate" for 0.8.0–0.8.4 — each still in its one-week soak per the RC register; "Released" for 0.7.0, 0.6.0, 0.1.0).
  - **Drift guard (`webui/scripts/check-releases.mjs`)**: A dependency-free Node script that reads CHANGELOG.md and releases.ts, extracts the version lists from both, and exits non-zero with a clear message if the two lists differ in content or order. Wired into `webui/package.json`: new script `check:releases` runs the guard explicitly; the `build` script now runs `node scripts/check-releases.mjs && ...` before the TypeScript and Vite steps, so a forgotten release-log update is a build failure, not a hope.
  - **The page (`webui/src/pages/ReleasesPage.tsx`)**: Renders RELEASES data: for each release, version + date, status badge (green for Released, blue for Release candidate), summary, highlights list, and a clearly labelled testing record section (gate verdict + tests). Intro paragraph states what the page is: the public release log fed from CHANGELOG and gate records, updated as part of each release, and correctly states the licensing as "Apache License 2.0 + Payment Rider". Follows existing page structure and CSS conventions (section/card/plain-list classes; new release-prefixed classes in index.css).
  - **Routing + navigation**: App.tsx adds public route `releases` → ReleasesPage inside the Layout route group (NOT behind ProtectedRoute); Layout.tsx adds "Releases" NavLink to the main nav after "For Agents".
  - **llms.txt and guardian-mesh.json**: Neither enumerates the site's pages/routes (they describe the gRPC interface, not website pages), so both left untouched per task instructions.
- Version bumped `0.8.3` → `0.8.4` (`VERSION`, `guardian-meshd/Cargo.toml`, `README.md`).

### Tests
- No daemon source changes (WO-9 is WebUI-only). Full suite, Wright-verified independently on Linux from the workspace root (CI's invocation): **97/97 (80 lib + 17 bin)**. The lane's Windows run from the same root reported 96 (79 lib + 17 bin) — one lib test is `#[cfg(unix)]`; counts name their platform + invocation root per GMSI-75.
- WebUI, Wright-verified from a fresh checkout: `npm ci` (526 packages) + `npm run build` (drift guard runs first inside the build) + `npm run lint` + `npm run check:releases` — all passing. Built asset `index-etCHDYxC.js` — byte-identical hash to the lane's Windows build.
- Drift guard negative case, Wright-proven on a scratch copy: a single mismatched version in releases.ts makes check-releases exit 1 with a position-specific DRIFT message; the unmodified tree exits 0.
- **Gate verdict: PASS WITH FINDINGS** (release gate, 2026-10-23; pack `~/workspace/release-gate-runs/guardian-mesh-wo9-2026-10-23/`). Scanner BLOCKED only on the GMSI-6 "tests" false lead (ninth occurrence), resolved by the direct suite evidence; 0 secrets, 0 known-vulnerable dependencies (159 deps). F1 (Medium): the lane marked v0.8.0–v0.8.3 as "Released" — all four are still RELEASE CANDIDATES in soak per the RC register (rows 26, 28, 29, 30) — FIXED in the Wright carry commit (statuses now read from the status artifact, and the CHANGELOG wording above matches). F2 (Low): the lane's draft CHANGELOG claimed the Linux 97 count as its own measurement before Wright ran it — corrected above to name each count's platform and verifier. GMSI-83 filed from this run (a published release-status claim must name its status artifact). v0.8.4 is a RELEASE CANDIDATE under the one-week soak.
- Wright carry fixes over the lane commit: the F1 status corrections in `webui/src/data/releases.ts` (0.8.0–0.8.3 → "Release candidate") and this Tests section; the 0.8.4 entry's gateVerdict in releases.ts set to the real verdict.

## [0.8.3] - 2026-10-22

### Added
- **WO-8: Fuzz the boundaries (hardening rule H6).** Added three libFuzzer-based fuzz targets for Guardian Mesh's boundary-facing APIs, exercising the daemon's input-handling surfaces without reimplementing verdict logic. Each target is thin — it only feeds attacker bytes into the daemon's existing public APIs; decode errors and validation failures are expected; panics are bugs.
  - **`fuzz_envelope_decode`**: Protobuf decoding of `EvaluateRequest` messages (the envelope-bearing request type) and envelope size validation via `ProtocolFirewall::check_envelope_size`. Fuzzes the daemon's ability to handle malformed protobuf input and payload size bounds.
  - **`fuzz_payload_parse`**: JSON payload parsing and Protocol Firewall validation: `check_envelope_size`, `check_unknown_fields` (PF-12), and `check_nesting_depth` (PF-13). Fuzzes the WebUI's action descriptor JSON shape and the firewall's field/depth validation.
  - **`fuzz_proof_verify`**: ML-DSA-65 signature verification via `verify_proto_envelope`. The fuzzer splits input as: first 4 bytes = CRC32C digest (little-endian), next 3309 bytes = signature (the exact encoded ML-DSA-65 length), remainder = payload. Verification runs against a fixed verifying key (generated from a fixed 32-byte seed, using the daemon's own `SigningKey::from_seed`) and also attempts to decode the whole input as a verifying key to test attacker-controlled key handling via `verifying_key_from_bytes`.
- **Fuzz package (`fuzz/`)**: A new detached Rust package named `guardian-mesh-fuzz` with its own `[workspace]` table, so the root workspace (`members = ["guardian-meshd"]`) never tries to build it with the stable toolchain. Root `cargo test` and `cargo build` stay green. Dependencies: `libfuzzer-sys` and `guardian-meshd` by path, plus `prost` at the same version the daemon uses (0.14.3).
- **Seed corpora**: Each target has at least two seed files under `fuzz/corpus/<target_name>/`, real inputs (not random noise): the envelope target's `valid_request` is a genuine prost-encoded `EvaluateRequest` carrying a real ML-DSA-65-signed envelope (generated with the daemon's own types; it decodes and round-trips), plus its first-64-bytes `truncated` variant; the payload target has valid JSON matching the WebUI's action descriptor shape (`actionType`, `context`, `target`, `metadata` within nesting depth 4) and a deeply-nested JSON value (depth 5, exceeds limit); the proof target's `valid_signed` is a real signed payload in the target's crc||sig||payload layout that VERIFIES through `verify_proto_envelope` under the target's fixed-seed key, plus a `zero_sig` variant with the correct CRC and an all-zero signature. Seed corpora are committed; crash files (`crash-*`, `leak-*`, `timeout-*`) are gitignored.
- **Nightly CI workflow (`.github/workflows/fuzz.yml`)**: Runs each of the three targets for 60 seconds nightly at 02:00 UTC (and on `workflow_dispatch`). The workflow installs protoc (same action as Rust CI), Rust nightly, and cargo-fuzz, then runs each target with `-max_total_time=60 -rss_limit_mb=2048`. On failure, `fuzz/artifacts/` uploads as a workflow artifact. NOT on push/PR — the main CI must stay fast and stable-only.
- **Documentation (`fuzz/README.md`)**: What the targets cover, how to run them locally (nightly + cargo-fuzz, Linux is the proven surface; Windows runs are unproven), and the rule that any crash found becomes a P0 work order with the crashing input minimized and added as a regression seed/test. Honest about Windows: if libFuzzer/sanitizers do not work on Windows, the targets' home run surface is Linux CI and the Arch isolation bench (when it exists).
- Version bumped `0.8.2` → `0.8.3` (`VERSION`, `guardian-meshd/Cargo.toml`, `README.md`).

### Tests
- No daemon source changes (WO-8 adds fuzz targets only, not daemon code). Full suite, Wright-verified independently on Linux from the workspace root (CI's invocation): **97/97 (80 lib + 17 bin)**. The lane's Windows run from the same root reported 96 (79 lib + 17 bin) — one lib test is `#[cfg(unix)]` (key-file permission bits), absent on Windows; counts name their platform + invocation root per GMSI-75.
- Fuzz execution, Wright-verified on Linux (nightly + cargo-fuzz 0.13.2): each target built and ran against its seed corpus with zero crashes (per-target evidence in the gate record). The lane could not run cargo-fuzz on the Windows laptop (its cargo-fuzz install hit an out-of-memory failure during compilation) — recorded honestly in the lane's result; the targets' home run surface is Linux CI + the Arch bench.
- **Gate verdict: PASS WITH FINDINGS** (release gate, 2026-10-22; pack `~/workspace/release-gate-runs/guardian-mesh-wo8-2026-10-22/`). Scanner BLOCKED only on the GMSI-6 "tests" false lead (eighth occurrence), resolved by the direct suite evidence; 0 secrets, 0 known-vulnerable dependencies. Findings F1–F5 (the lane's fuzz package had never been built) all fixed in the carry commit. GMSI-82 filed from this run (unbuilt test infrastructure is not a capability). v0.8.3 is a RELEASE CANDIDATE under the one-week soak.
- Wright carry fixes over the lane commit: (F1) The fuzz package had never been built by the lane and could not build: `fuzz/Cargo.toml` lacked the `[package.metadata] cargo-fuzz = true` marker cargo-fuzz requires, `fuzz_proof_verify` imported the `ml-dsa` crate without declaring it, and it used the `Keypair` trait without importing it. All three fixed (`ml-dsa = "0.1.0"` declared; marker + trait import added) — the package now builds and runs under cargo-fuzz on Linux. (F2) The proof target's signature slice was "up to 3500 bytes", a layout in which no real ML-DSA-65 proof (exact 3309-byte signature) could ever verify; the split now uses the exact 3309-byte length and the seeds are real (above). (F3) The nightly workflow's `continue-on-error` on every fuzz step would have swallowed a crash (job green, artifacts never uploaded); a crash-artifact gate step now fails the job when any `crash-*` artifact exists. (F5) The nightly workflow ran cargo-fuzz from inside `fuzz/` — cargo-fuzz resolves the fuzz directory from the project root and would have failed instantly (`fuzz/fuzz/Cargo.toml` not found, reproduced locally); the steps now run from the repo root. (F4) The lane's placeholder envelope/proof seeds were replaced with the real generated seeds above, and the lane's `WO8-RESULT.md` (a lane artifact) is not shipped in the tree.

### Changed
- `fuzz/.gitignore` ignores `target/`, `artifacts/`, and corpus crash files (`corpus/**/crash-*`, `corpus/**/leak-*`, `corpus/**/timeout-*`). Seed corpora (non-crash files in `corpus/<target>/`) are committed.

## [0.8.2] - 2026-10-21

### Changed
- **WO-7: Scope documentation reconciliation.** Rewrote `revised_project_scope.md` to accurately reflect the shipped v0.8.1 system. The document now correctly describes the Sentinel → Gatekeeper → Witness → Arbiter → Vault pipeline (not the pre-implementation Auth/Compute/Storage/Network/Policy design), the Apache License 2.0 + Payment Rider licensing (not MIT), the shipped audit logging with ReadAuditLog RPC, the real THROTTLE/ESCALATE verdicts, the certificate issuance capability (IssueCertificate/RevokeCertificate/CertificateStatus RPCs), the GitHub repository location (nrupala/guardian-mesh), and the actual development tooling (npm for WebUI, not pnpm). The gaps section is now honest: TEE attestation, BFT consensus, and other designed-but-not-built capabilities are labeled as design only, not as shipped features.
- Removed duplicate file `specs/GUARDIAN_MESH_GAP_ANALYSIS (1).md` (byte-identical copy of the canonical `specs/GUARDIAN_MESH_GAP_ANALYSIS.md`).
- Version bumped `0.8.1` → `0.8.2` (`VERSION`, `guardian-meshd/Cargo.toml`, `README.md`).

### Tests
- Full test suite: **97 tests green** (80 lib + 17 bin) on Wright's independent verification from the workspace root (CI's invocation) — no code changes, docs-only release. (The lane's 96 count came from running inside `guardian-meshd/`; see GMSI-75.)
- WebUI build + lint: pass.
- **Gate verdict: PASS WITH FINDINGS** (release gate, 2026-10-21; pack `~/workspace/release-gate-runs/guardian-mesh-wo7-2026-10-21/`). F1 (Low): lane test-count slip, fixed by Wright carry edits. v0.8.2 is a RELEASE CANDIDATE under the one-week soak.

## [0.8.1] - 2026-10-20

### Fixed
- **WO-6.1: Chain-concurrency fix (GMSI-69 / issue #50).** Fixed a race condition in `VaultEnclave` where concurrent writers to the audit chain (`seal()` and `record_certificate_event()`) could interleave on the same predecessor hash, producing duplicate chain hashes and breaking chain verification. The defect was observed in production at position 557 and reproduced locally with a 115-request burst that produced 32 consecutive duplicate chain hashes and a chain break at position 2.
  - **Root cause**: Both `seal()` and `record_certificate_event()` read `last_chain_hash` under a short lock, computed the digest, persisted the entry to disk outside any lock, and only then re-locked to update `last_chain_hash`. Concurrent callers could read the same predecessor hash, compute different digests, and persist entries out of chain order.
  - **Fix**: Each chain append now holds the `last_chain_hash` lock for the entire critical section: predecessor read + digest computation + disk persistence + predecessor update. This fully serializes chain appends across both writers, ensuring that on-disk entry order always matches chain order and no two entries share a chain hash. The in-memory audit-trail push happens inside the same critical section, so trail order matches file order.
  - **Sequential behaviour unchanged**: The digest formula, on-disk line format, genesis hash, and entry fields remain identical. A log written sequentially before this fix verifies after it, and vice versa. No new runtime dependencies. No changes to Evaluate, the firewall, handshake, certificates, or proof format.

### Tests
- Added `concurrent_seal_and_certificate_events_chain_verifies`: a concurrency regression test that drives the real vault handlers (16 threads × 8 seals + 4 threads × 8 certificate events = 160 total appends) through one shared `VaultEnclave`, then verifies the chain reports VERIFIED, the entry count equals the exact number of appends, and no two entries share a chain hash. This test would FAIL on the pre-fix code due to the race.
- Full test suite: **97 tests green** (80 lib + 17 bin) after Wright's independent verification (see the PR gate record).
- **Gate verdict: PASS WITH FINDINGS** (release gate, 2026-10-20; pack `~/workspace/release-gate-runs/guardian-mesh-wo61-2026-10-20/`). Wire proof pair: identical 150-append burst — v0.8.0 control: 7 duplicate hashes, chain break at position 1; v0.8.1: 0 duplicates, chain VERIFIED. v0.8.1 is a RELEASE CANDIDATE under the one-week soak.
- WebUI build + lint: pass.

### Changed
- Version bumped `0.8.0` → `0.8.1` (`VERSION`, `guardian-meshd/Cargo.toml`, `README.md`).
- README test count updated to reflect the new total (97 tests).

## [0.8.0] - 2026-10-19

### Added
- **WO-6: Release-evidence certification (GMSI-1).** Guardian Mesh can now issue certificates that bind a gate verdict to an evidence pack under the daemon's cryptographic signature. This is Guardian Mesh's first certificate issuance capability.
  - **Certificate schema v1** (`specs/CERTIFICATE_SCHEMA.md`): A certificate is a sealed envelope (the existing `SealedEnvelope` wire format) carrying a structured JSON body. The certificate attests to the binding between a specific release artifact (identified by its SHA-256 evidence hash), the gate verdict issued over that evidence, test results and policy declared by the presenter, the issuing daemon's identity (its signing-key fingerprint from WO-3), and the issuance timestamp. All fields needed to verify a certificate travel inside the sealed envelope (GMSI-3: self-contained; verifiable by a second lane through the existing `VerifyProof` RPC).
  - **Three new RPCs**: `IssueCertificate`, `RevokeCertificate`, `CertificateStatus`. Issuance enforces all rules in the specification:
    - The daemon computes SHA-256 over the presented evidence bytes and refuses issuance if it does not match the claimed hash (GMSI-2: hash-verifiable handoff).
    - Evidence size cap: **10 MB**. Evidence packs larger than this are refused with a clear error. (This is separate from the 64 KiB `SealedEnvelope` cap, which applies to envelopes, not evidence documents.)
    - `verdict == "BLOCKED"` → NO issuance. If an ACTIVE certificate exists for that product+version, it is REVOKED (registry + audit log), and the refusal message states that revocation occurred.
    - `verdict == "PASS"` or `verdict == "PASS WITH FINDINGS"` → issue the certificate. Assign a unique serial (persistent across restarts), build the body, seal it with the daemon's persistent signing key (WO-3), persist the registry record as ACTIVE, append the issuance event to the audit log. Any previously ACTIVE certificate for the product (any version) becomes SUPERSEDED, and the new certificate's `supersedes` field names the old serial.
    - Any other verdict string → refusal (clear error, nothing recorded).
  - **Lifecycle management**: Certificates have four states (ACTIVE, SUPERSEDED, REVOKED, UNKNOWN). Issuance, supersession, and revocation events are appended to the daemon's hash-chained audit log (the WO-4/WO-6 audit trail). The certificate registry persists under the daemon's workspace directory (following the WO-3 persistence pattern) and survives restarts.
  - **Verification**: A certificate holder verifies a certificate by (1) presenting the sealed envelope to `VerifyProof` (any Guardian Mesh daemon can verify the ML-DSA-65 signature), (2) recomputing the fingerprint (SHA-256 of the exact payload bytes) and verifying it matches the fingerprint presented alongside the envelope in the `IssueCertificate`/`CertificateStatus` responses — the fingerprint is not a field inside the sealed payload (GMSI-2: the copy presented, not the copy at mint), and (3) querying `CertificateStatus(serial)` to verify the certificate is ACTIVE (not SUPERSEDED or REVOKED).
  - **Trust posture (v1)**: Issuance is a daemon-local operation. The daemon binds to localhost (or sits behind access control, as the production deployment does). There is no public issuance endpoint in v1. The issued certificate can be presented to **any** Guardian Mesh daemon for verification via `VerifyProof`.
  - **Honesty clauses**: The certificate certifies the **binding** (this evidence, this verdict, this issuer, this time), not the truth of the declarations. The daemon vouches for: the evidence hash match at issuance, the signature, the lifecycle state transitions it performed, and the issuer identity. The daemon does NOT vouch for: the truth of the `scope`, `tests`, or `policy` declarations (these are the presenter's claims, bound under the daemon's signature), or deployment choices / runtime behavior / operational posture. A certificate warrants only the exact artifact tested (identified by `evidence_hash`), against the policy named (`policy`), on the date stamped (`issued_at`).
  - **GMSI-5: History scope**. The certificate schema includes an `evidence_scope` field: `"working-tree"` (only the working tree was scanned) or `"full-history"` (the full git history was scanned). A secret ever committed stays in git history; certification of a repository must state whether history was scanned, not only the working tree.
  - **GMSI-7 (reserved)**: The certificate schema reserves a `pf_outcomes` field for future use. In v1, this field is `null` and MUST NOT carry placeholder or constant values. Future versions (after WO-19 lands) will populate this field with the daemon's measured per-rule Protocol Firewall pass/fail counts at issuance time.

### Changed
- Version bumped `0.7.0` → `0.8.0` (`VERSION`, `guardian-meshd/Cargo.toml`, `README.md`).
- README now documents the certificate RPCs, lifecycle, and how a holder verifies a certificate.

### Tests
- Added comprehensive certificate tests (11 test cases on the certificate path):
  - `issue_certificate_happy_path`: verifies issuance with PASS verdict, body fields, and seal.
  - `hash_mismatch_refuses_issuance`: verifies that evidence hash mismatch refuses issuance (nothing recorded).
  - `blocked_verdict_refuses_and_revokes`: verifies that a BLOCKED verdict refuses issuance and revokes any ACTIVE certificate for the product+version.
  - `supersession_across_versions`: verifies that issuing a new certificate for a product supersedes the old ACTIVE certificate (across different versions).
  - `explicit_revocation`: verifies that `RevokeCertificate` transitions a certificate from ACTIVE to REVOKED.
  - `status_of_unknown_serial`: verifies that querying an unknown serial returns UNKNOWN status.
  - `certificate_verifies_after_restart`: verifies that a certificate issued by one service instance can be queried from a second instance over the same workspace (registry persistence).
  - `evidence_size_cap_enforced`: verifies that evidence larger than 10 MB is refused with a clear error.
  - `fingerprint_recomputable_from_sealed_payload`: verifies the fingerprint recomputes from the sealed payload bytes and matches the status body (gate fix round 1).
  - `lifecycle_events_in_vault_audit_log`: verifies lifecycle events land in the hash-chained Vault audit log (gate fix round 1).
  - `mixed_evaluate_and_certificate_audit_log_verifies`: service-level regression — Evaluate → IssueCertificate → Evaluate on one daemon, then ReadAuditLog verifies the chain (gate fix round 2).
- Full suite: 96 tests green (79 lib + 17 bin), independently re-run by Wright from the pushed branch.
- **Release gate: PASS WITH FINDINGS** (2026-10-19 nightly run). Two gate fix rounds: round 1 — the lane's first commit did not compile and its fingerprint was not recomputable from the sealed payload; lifecycle events moved into the hash-chained Vault log. Round 2 — two VaultEnclave instances over one audit directory broke chain verification under mixed Evaluate+certificate traffic (wire-proven); fixed to one shared instance with the regression test above. Carried: the checked-in Python client (`guardian_mesh_pb2.py`) was not regenerated (protoc version mismatch, 29.3 vs the file's 6.31.1 gencode); the TypeScript client was regenerated. Machine pass BLOCKED only on the known GMSI-6 scanner false lead for Rust inline tests, resolved by the direct suite evidence. Guardian Mesh Spec Input filed: GMSI-68 (mixed-traffic chain proof).

## [0.7.0] - 2026-10-19

### Added
- **WO-5: Real THROTTLE and ESCALATE verdicts.** Both verdicts now exist as actual code paths in the daemon and are rendered distinctly in the control panel.
  - **THROTTLE verdict** is emitted on PF-18 rate breaches (100 msg/s per external session) and on a policy-configurable per-session rate (`GUARDIAN_MESH_POLICY_THROTTLE_RATE`, default 100 msg/s). PF-18 breaches now return an `EvaluateResponse` with verdict "THROTTLE", a reason naming PF-18, and a Witness-signed proof envelope, instead of a bare `permission_denied` gRPC error. The Vault audit log records THROTTLE verdicts like any other verdict. This is a **deliberate, documented behaviour change** from WO-2: the firewall still refuses excess traffic, but as a signed judgment the caller can act on (slow down), not a transport error. All other PF rules stay exactly as they are (malformed input stays a `permission_denied` error). The policy rate is configurable via `GUARDIAN_MESH_POLICY_THROTTLE_RATE` environment variable and defaults to 100 msg/s (matching PF-18's ceiling, so PF-18 fires first by default). Breaching the policy rate likewise returns verdict "THROTTLE" with a reason naming the policy rate. The Gatekeeper checks the policy rate first, then PF-18, and both use independent rate limiters per session.
  - **ESCALATE verdict** is emitted for action types on a policy-configured escalation list (`GUARDIAN_MESH_POLICY_ESCALATE_ACTIONS` environment variable, comma-separated, defaults to empty). Actions on the list (and not blocked by policy) return verdict "ESCALATE" with a reason naming the matched action type. **Precedence is pinned**: an action type the policy blocks still returns BLOCK; an action type on the escalate list (and not blocked) returns ESCALATE; everything else follows the existing policy unchanged. The proof envelope is issued for ESCALATE like any verdict, and the audit log records the escalation.
  - **Panel changes**: The control panel (`DashboardPage.tsx`) now renders THROTTLE and ESCALATE verdicts distinctly with their own styles (orange/amber, matching the existing CSS classes `verdict-throttle` and `verdict-escalate`) alongside ALLOW (green) and BLOCK (red). Verdict tags in the audit log and the live verdict panel display THROTTLE and ESCALATE with plain-language descriptions: THROTTLE means "the action is slowed down"; ESCALATE means "a human decides". The CSS for these verdict styles was already present in `index.css` from a previous iteration; this release wires them to real verdicts.

### Changed
- Version bumped `0.6.0` → `0.7.0` (`VERSION`, `guardian-meshd/Cargo.toml`, `README.md`).
- **Behaviour change (WO-5)**: PF-18 rate limit breaches (100 msg/s per external session) now return an `EvaluateResponse` with verdict "THROTTLE" and a signed proof envelope, instead of a `permission_denied` gRPC error. Callers that expected an error for rate limiting must now check for `verdict == "THROTTLE"` in the response. This is a deliberate, documented change: the firewall still refuses excess traffic, but as a signed judgment (with a proof) the caller can act on, not a bare transport error.

### Tests
- Added integration tests for THROTTLE and ESCALATE verdicts:
  - `throttle_verdict_has_proof_and_proper_structure`: verifies that the THROTTLE verdict and ThrottleReason enum serialize correctly.
  - `policy_throttle_rate_is_configurable`: verifies the policy throttle rate config is set correctly.
  - `escalate_verdict_for_configured_actions`: verifies that actions on the escalate list return ESCALATE with a valid proof.
  - `blocked_action_stays_blocked_even_if_on_escalate_list`: verifies precedence (BLOCK > ESCALATE).
  - `unlisted_action_allows_normally`: verifies actions not on the escalate list still ALLOW.
- All existing tests (68 unit tests, 16 integration tests) remain green. The protocol_firewall unit tests now verify that `check_rate_limit` and `check_policy_rate` return `Ok(Some(ThrottleReason))` instead of `Err` when the rate is exceeded.

## [0.6.0] - 2026-10-19

### Added
- Audit trail read RPC (`ReadAuditLog`) returns the Vault's hash-chained
  audit log in append order with chain verification computed at read time.
  The RPC returns all stored fields (sequence, timestamp, action_id,
  verdict, enclave_chain, chain_hash, reason) plus a verification status
  that re-walks the chain from the genesis hash, reports whether the chain
  is intact, how many entries were checked, and — if broken — the position
  of the first break. Chain verification is honest: a hand-edited log line
  causes verification to report the break at that position, never silently
  repaired or skipped. Empty logs return zero entries with a verified
  status honestly saying zero entries were checked. Read path is read-only:
  no mutation of the log or daemon state.
- Live panel audit view wired to the new RPC. In live mode (builds with
  `VITE_GUARDIAN_MESH_ENDPOINT` set) the panel fetches and displays audit
  entries in order plus the chain verification status in plain words (chain
  verified/broken, entries checked, first break position if any). Demo
  mode (public site build) keeps working unchanged.
- Documentation added to `guardian-meshd/README.md` describing the audit
  read path RPC, what chain verification proves and does not prove, and
  operator actions when verification reports a break.

- Release gate: **PASS WITH FINDINGS** (2026-10-19, pack
  `release-gate-runs/guardian-mesh-wo4-2026-10-18/`). Wright-verified
  independently of the build lane: cargo 78/78, webui build + lint
  green, tamper/legacy/malformed-hash/mixed-chain probes all passing.
  The gate's fix loop closed F1 (verify panic on a malformed stored
  hash) and F2 (pre-0.6.0 entries falsely reporting a break) on this
  branch before merge. NOT RUN: Kali/Arch benches (not yet built),
  dependency-vuln scan, real-browser panel click-through.

### Changed
- Version bumped `0.5.0` → `0.6.0` (`VERSION`, `guardian-meshd/Cargo.toml`).
- Audit chain verification now accepts both pre-0.6.0 legacy entries (which verify only over action_id, verdict, timestamp) and 0.6.0+ fully-chained entries (which cover all fields including reason and enclave_chain). Mixed logs verify correctly.

### Added
- Portfolio certification rollout: `NOTICE` (attribution); MIT SPDX license
  headers on Rust sources, the `.proto` file, and webui sources/config;
  CONTRIBUTING.md gains the portfolio-certification standing section
  (draft PRs, CHANGELOG + semver per PR, no direct pushes).

### Changed
- Version bumped `0.1.0` → `0.1.1` (`VERSION`, `guardian-meshd/Cargo.toml`).
- Version bumped `0.1.1` → `0.1.2` (`VERSION`, `guardian-meshd/Cargo.toml`).
- Version bumped `0.1.2` → `0.1.3` (`VERSION`, `guardian-meshd/Cargo.toml`).
- Version bumped `0.1.3` → `0.1.4` (`VERSION`, `guardian-meshd/Cargo.toml`).
- Version bumped `0.1.4` → `0.1.5` (`VERSION`, `guardian-meshd/Cargo.toml`).
- Version bumped `0.1.5` → `0.1.6` (`VERSION`, `guardian-meshd/Cargo.toml`).
- Version bumped `0.1.6` → `0.1.7` (`VERSION`, `guardian-meshd/Cargo.toml`).
- Licensing corrected from the interim MIT boilerplate to the owner's
  split model: interface (`webui/`, `specs/`, and the generated client
  bindings) under the Apache License, Version 2.0, and core
  (`guardian-meshd/`) under the GNU Affero General Public License,
  version 3 or later (AGPL-3.0-or-later). `LICENSE` is now a licensing
  map with the full texts in `webui/LICENSE` and
  `guardian-meshd/LICENSE`; SPDX headers and package manifests updated
  to match.

### Fixed
- Version Snapshot workflow now exports `NEW_ENTRY` before the manifest
  step reads it from the Python environment, so release snapshots can be
  recorded instead of failing with `KeyError`.
- WebUI Pages deployment is skipped until GitHub Pages is enabled and the
  `ENABLE_GITHUB_PAGES` repository variable is set to `true`; the build,
  lint, and artifact upload still run on every change.
- Version Snapshot archive step now flattens the previous release tag
  (`release/v<N>` → `release-v<N>.tar`) when writing the prior-version
  archive; the slash in the tag name pointed `git archive` at a
  subdirectory that does not exist, so the step failed once the manifest
  step was fixed.
- Android APK workflow now passes an explicit package list to
  setup-android (`platform-tools`, `platforms;android-36`,
  `build-tools;36.0.0` — matching the pinned Capacitor 8.3.4 template's
  compileSdk 36). The action's default list includes the legacy `tools`
  package, which Google removed from the SDK repository, so the SDK
  setup step failed before any project code ran.
- WebUI on GitHub Pages no longer 404s on app routes: the build now
  also emits `dist/404.html` (a copy of the built `index.html`), which
  Pages serves for unknown paths so direct loads and refreshes of
  routes like `/guardian-mesh/login` render the app instead of the
  GitHub Pages 404 page.
- PWA manifest paths corrected: `start_url` is now `/guardian-mesh/`
  (was `/`, outside the app scope) and the icon URLs carry the
  `/guardian-mesh` prefix (they previously 404'd).
- The WebUI is now a real public site, not only a login shell: a public
  overview explains what Guardian Mesh is, what the five guardians do,
  and what the system does for the people who deploy it; an Architecture
  page publishes the system's topology as measured by a codetopo scan of
  this repository (24 files, 581 symbols, 1,176 edges) with the full
  graph snapshot downloadable; a User guide & help page describes the
  verdicts, the vocabulary, operator instructions, and the demonstration
  panel honestly; and a For Agents page states the contract — how an
  agent calls Evaluate/VerifyProof and the verdict rules it must
  respect. Machine-readable companions ship alongside: `llms.txt`,
  `guardian-mesh.json` (also under `.well-known/`), and the codetopo
  snapshot JSON.
- The control panel moved to `/panel` and is labeled as a demonstration:
  its status values are marked as samples rather than presented as live
  measurements, and the disabled actions say plainly that no daemon is
  connected.
- The Control Panel navigation button now goes to `/panel` (which
  itself redirects signed-out visitors to the login page) instead of
  linking to `/login` directly, and the login page redirects to the
  panel when a demo session already exists — signing in once now
  sticks until Sign Out, instead of the form reappearing on every
  visit to the login route.
- An open tab now reloads itself once when an updated service worker
  takes control, instead of running the previous build for the rest of
  the session (a tab opened before a deploy otherwise keeps the old
  build's behavior until manually refreshed). First visits are
  unaffected.
- The daemon's client protocol is completed. A new `Handshake` RPC
  opens a handshake session and returns its ID and HMAC key —
  previously sessions could never be created through the API, so no
  client could pass the Gatekeeper. `Evaluate` now also returns the
  audit proof sealed with the daemon's signing key
  (`proof_envelope`), so a caller can present it to `VerifyProof`
  and have it re-checked independently. The server speaks gRPC-web
  alongside native gRPC, so browsers can call the same API.
- The control panel can now run live against a daemon. Builds that
  set `VITE_GUARDIAN_MESH_ENDPOINT` (the guardian.aimlds.org build)
  get a working panel: real health values, a real evaluation flow —
  handshake, sealed envelope (CRC32C + ML-DSA-65 signature),
  session HMAC, verdict with its sealed proof — and proof
  verification against the daemon. Builds without the endpoint
  (the public GitHub Pages site) keep the labeled demonstration
  panel. The router base path is build-time configurable
  (`VITE_BASE_PATH`) so the same source serves both.
- Version bumped `0.1.7` → `0.2.0` (`VERSION`, `guardian-meshd/Cargo.toml`).
- Version bumped `0.2.0` → `0.2.1` (`VERSION`, `guardian-meshd/Cargo.toml`).
- Guardian Mesh is live at guardian.aimlds.org: the daemon and the
  live control panel run on the Aetheris box behind a Cloudflare
  Access sign-in (owner-only while the deployment matures). The
  public site's Control Panel button now points there, and the
  site copy and machine-readable files (llms.txt, descriptor JSON)
  describe the four-call interface and the live deployment.
- Version bumped `0.2.1` → `0.2.2` (`VERSION`, `guardian-meshd/Cargo.toml`).
- The daemon now verifies the request signature on Evaluate (WO-1).
  Handshake takes the caller's ML-DSA-65 verifying key
  (`source_public_key`, 1952 bytes — a handshake without it is
  refused) and binds it to the session; the Gatekeeper checks every
  envelope's signature against the bound key after the session HMAC
  check. A missing, malformed, or non-verifying signature is denied
  with a reason naming the signature failure, and the evaluation
  never reaches the Arbiter. This is a breaking change for pre-0.3.0
  clients, which sent no key: they must register one at Handshake.
  The WebUI client does. Test suite: 47 tests (was 32), including
  service-level tests that valid signatures evaluate and tampered,
  wrong-key, and unsigned requests are permission-denied.
- Version bumped `0.2.2` → `0.3.0` (`VERSION`, `guardian-meshd/Cargo.toml`).
- The daemon now enforces the Protocol Firewall rule table on the
  Evaluate path (WO-2). All applicable rules from the formal spec
  §1.4 are enforced on client envelopes: PF-1/PF-5 envelope/payload
  size bounds (64 KiB limit); PF-12 unknown-field rejection for
  ActionDescriptor JSON (strict field set matching the shipped
  client — actionType, context, target, metadata); PF-13 payload
  nesting depth max 4; PF-14 nonce uniqueness (sliding window of
  10,000 nonces per session, reuse rejected); PF-15/PF-16 envelope
  timestamp windows (stale > 5 s, future > 1 s, nanosecond
  precision); PF-17 ML-DSA-65 signature format budget (length in
  [2420, 3500] bytes); PF-18 rate limit (100 msg/s per external
  session, excess rejected with permission_denied naming
  E_RATE_LIMITED). Every rejection is a permission_denied error with
  a plain reason naming the PF rule. Rules PF-2..PF-11 (internal bus
  routing, magic/version/CRC checks) do not apply to the external
  Evaluate path where the shipped client speaks gRPC, not the raw
  envelope wire format; the gRPC layer handles framing and the
  Gatekeeper operates on the parsed protobuf message. PF-6 (CRC32C)
  is verified as part of WO-1's signature check (the signature covers
  crc32c || payload). Test suite: 58 tests (was 47), including named
  tests for each enforced rule (pf01_envelope_size_*, pf12_*, pf13_*,
  pf14_*, pf15_*, pf16_*, pf17_*, pf18_*) plus service-level tests
  confirming valid envelopes evaluate and PF violations are denied.
- Version bumped `0.3.0` → `0.4.0` (`VERSION`, `guardian-meshd/Cargo.toml`).
- The daemon now persists its ML-DSA-65 signing key across restarts
  (WO-3). On first start, the daemon generates a fresh keypair and
  writes the seed to `{workspace}/keys/daemon_signing_key.bin` with
  0600 permissions on Unix (restrictive file permissions on all
  platforms). On later starts, it loads the existing seed and
  reconstructs the same keypair, so proofs issued across restarts
  verify against the same public key. If the stored key file exists
  but is corrupt or the wrong length, the daemon fails closed: it
  exits with a clear FATAL log naming the problem and never silently
  regenerates over an existing file (silently changing the signing
  identity would invalidate outstanding proofs and must be an operator
  decision). The Health RPC now reports the signing-key fingerprint
  (the lowercase hex SHA-256 of the daemon's ML-DSA-65 public key,
  never the key material itself) in the new `signing_key_fingerprint`
  field. Operators can back up the key by copying
  `daemon_signing_key.bin`; to rotate, stop the daemon, move the old
  key aside, and restart (proofs issued under the old key will stop
  verifying against the new fingerprint, which is expected behavior).
  Test suite: 64 tests (was 58), including tests that a key generated
  on first start is loaded byte-identical on second start, that the
  fingerprint equals the SHA-256 of the public key, that a proof from
  one instance verifies against a second instance on the same
  workspace, and that a corrupt key triggers startup failure.
- Version bumped `0.4.0` → `0.5.0` (`VERSION`, `guardian-meshd/Cargo.toml`).

### Notes
- No deploy target found (no wrangler/Pages/deploy script; Android APK is a
  CI artifact build) — signed-deploys Track 2 not wired.

## [0.1.0] - 2026-08-30

### Added
- Rust gRPC daemon (`guardian-meshd`) with ML-DSA-65, CRC32C, and HMAC handshake bus.
- React + Vite + PWA control panel (`webui`).
- CI/CD workflows for Rust, WebUI, and APK builds.

### Fixed
- Documentation and README to clearly distinguish between implemented features and aspirational designs.
