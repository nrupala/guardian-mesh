# Contributing to Guardian Mesh

Thank you for contributing. This project follows a **PR-based governance
model**: every change to `main` lands through a reviewed pull request, and every
merge is captured as a version snapshot so prior versions are always restorable.

## Workflow

1. **Branch.** Create a feature branch off `main`:
   ```bash
   git checkout -b feat/<short-description>
   ```
2. **Commit.** Write focused commits. Sign off every commit (DCO):
   ```bash
   git commit -s -m "feat: <description>"
   ```
3. **Open a pull request** against `main`. The `PR Gate` workflow runs and must
   pass. Wire it as a required status check on `main` for full enforcement.
4. **Merge.** Squash-merge into `main`. The `Version Snapshot` workflow then
   tags the merge as `release/v<N>` and records it in `releases/manifest.json`.

## DCO

All commits must include `Signed-off-by: Your Name <email>` (`git commit -s`),
certifying compliance with the [Developer Certificate of Origin 1.1](https://developercertificate.org/).

## Code Standards

- **Rust** (`guardian-meshd/`): `rustfmt` + `cargo clippy --all-targets -- -D warnings`.
- **WebUI** (`webui/`): `npm run lint` (ESLint) + `npm run build` (tsc + vite).
- All code must pass CI before merge.

## Governance & snapshots

- All changes to `main` go through a **pull request** (`PR Gate` workflow).
- Every merge is tagged `release/v<N>` and archived in
  `releases/archive/` (`Version Snapshot` workflow).
- See `README.md` → "Development governance" for details.

## License

Apache License 2.0 + AIMLDS Payment Rider for the whole
repository — see [LICENSE](LICENSE) and [LICENSE-RIDER.md](LICENSE-RIDER.md).
## Portfolio certification (2026-10-05)

Standing process additions, alongside the governance above:

- **Draft PRs.** Open every PR as a draft; mark ready only when CI is green.
- **Changelog.** Each PR adds its entry under `## [Unreleased]` in
  `CHANGELOG.md` (already Keep-a-Changelog).
- **Semver.** Bump the version per PR — patch = fix/chore, minor = feature,
  major = breaking — in both `VERSION` and `guardian-meshd/Cargo.toml`
  together (per `docs/VERSIONING.md`).
- **No direct pushes to `main`.** Every change ships through a PR.
- **Releases.** After merge, releases are tagged `vX.Y.Z`.
- **Signed deploys.** This repo has no Cloudflare deploy target, so the
  signed-deploy wrapper is not wired in. Any future deploy script must
  delegate to it (unsigned paths are deleted, not kept alongside).
