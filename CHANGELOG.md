# Changelog

All notable changes to this project will be documented in this file.

This project adheres to [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
