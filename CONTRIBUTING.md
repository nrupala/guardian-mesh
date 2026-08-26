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

MIT — see [LICENSE](LICENSE).