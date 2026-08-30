# Versioning — guardian-mesh

**Standard:** Documentation & Versioning Standard v1.0 (SemVer 2.0.0 + Keep a Changelog 1.1.0).

guardian-mesh is a **hybrid repo**: a Rust daemon (`guardian-meshd`) plus a `webui` control panel. Versioning uses a documented split so each surface has exactly one source of truth.

## Source of truth

| Surface | Source of truth | Notes |
|---|---|---|
| Rust daemon (`guardian-meshd` crate) | top-level `VERSION` file | Mirrors the `Cargo.toml` package version. Bump both together. |
| `webui` control-panel app | `webui/package.json` `version` | Governs the app / PWA / APK build and any native version stamp. |

The repo-level `VERSION` is the canonical repository version and drives the README status header and `CHANGELOG.md`. Bump `webui/package.json` when only the webui changes; bump top-level `VERSION` (and `Cargo.toml`) when the daemon or a repo-wide surface changes.

## Changelog

`CHANGELOG.md` follows Keep a Changelog 1.1.0. Entries are truth-labeled (**Added / Changed / Fixed / Removed**), and unshipped work stays under a **Planned** heading — never listed as shipped.

## Build-time stamping

App-build version stamping for native / APK / PWA surfaces is handled by the app-versioning-standard mechanics (`scripts/stamp-app-version.sh`, `scripts/bump-version.mjs`) plus a CI tag-vs-`package.json` guard. Those mechanics land via a separate, rebased PR once its build check is green; this document defines the source-of-truth policy they implement.
