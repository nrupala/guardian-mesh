# Test plan — Guardian Mesh

<!--
  One page, kept current with the repo's real CI. This file exists because an
  estate-wide review found suites and CI in place everywhere but a written plan
  nowhere: what is tested, to what bar, on what cadence was undocumented.
  Generate the tables below from the CI that actually runs; when CI changes,
  this file changes in the same pull request.
-->

## Scope

Testing covers the Rust daemon (`guardian-meshd/` — protocol firewall verdicts,
sealed proofs, tenant isolation, persisted audit chain), its conformance suite,
the WebUI (`webui/` — build and lint), the Android APK build, and the three
cargo-fuzz targets (envelope decode, payload parse, proof verify). Static
analysis of the Rust product code runs via CodeQL (`codeql.yml`, build-mode:
none). Out of scope: load/performance testing and external penetration testing
— neither is wired into CI.

## Suites

| Suite | Covers | Run it | Runs in CI |
|---|---|---|---|
| Rust test suite | `guardian-meshd` unit and integration tests | `cargo test` | Yes — Rust CI (`rust-ci.yml`, build + test on push/PR to `main` for `guardian-meshd/**`, `proto/**`, `Cargo.toml`, `Cargo.lock`) |
| Conformance suite (WO-17 / RG-7, RG-8) | Protocol conformance group within the Rust suite | `cargo test conformance_` | Yes — Rust CI, as its own step after the full suite |
| WebUI build + lint | TypeScript compile, Vite build, ESLint over `webui/` | `npm ci && npm run build && npm run lint` (in `webui/`) | Yes — WebUI CI (`webui-ci.yml`, on push/PR to `main` for `webui/**`) |
| Android APK build | Capacitor sync + Gradle `assembleDebug` for the WebUI app shell | CI workflow only | Yes — Android APK (`android-apk.yml`, on push to `main` for `webui/**`, and on manual dispatch) |
| Fuzz targets | `fuzz_envelope_decode`, `fuzz_payload_parse`, `fuzz_proof_verify` (cargo-fuzz) | `cargo fuzz run <target> -- -max_total_time=60 -rss_limit_mb=2048` | Yes — Nightly Fuzz (`fuzz.yml`, nightly 02:00 UTC + manual dispatch) |

## CI gates

- Rust CI green (build, full `cargo test`, conformance subset) on every pull
  request touching the daemon, proto definitions, or Cargo manifests.
- WebUI CI green (build + lint) on every pull request touching `webui/`.
- PR Gate (`pr-gate.yml`) on every pull request: changes must arrive via a
  pull request; direct pushes to `main` fail the check.
- CodeQL (`codeql.yml`) analyses the Rust code on push/PR to `main` and
  weekly; findings are dispositioned per the house alert SLA.
- Nightly Fuzz fails the job if any target produces a crash artifact; a crash
  becomes a P0 work order.
- Code standards per CONTRIBUTING.md: Rust `rustfmt` + `cargo clippy
  --all-targets -- -D warnings`; WebUI `npm run lint` + `npm run build`; all
  code must pass CI before merge.

## Cadence

- Every pull request: Rust CI (when daemon paths change), WebUI CI (when
  `webui/` changes), PR Gate, CodeQL (Rust).
- Nightly / weekly (if any): Nightly Fuzz runs every night at 02:00 UTC
  (three targets, 60 s each); CodeQL also runs on a weekly schedule
  (Mondays 05:23 UTC).
- Every release candidate: the release-readiness run (checker + evidence reads),
  per the house Release-Readiness Standard.

## Coverage bar

No numeric coverage floor is set. The bar is: new functionality lands with
tests (the 0.16.0 conformance suite is the standing example), the full suite
and the conformance subset pass in CI before merge, and the fuzz targets run
nightly against the three input-facing surfaces.
