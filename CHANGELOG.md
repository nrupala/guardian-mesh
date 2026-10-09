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
