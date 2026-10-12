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
