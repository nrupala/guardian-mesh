# Changelog

All notable changes to this project will be documented in this file.

This project adheres to [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
