# .github/workflows — CI/CD & Governance

Automated pipelines for Guardian Mesh. All workflows are trigger-scoped to the
paths they own.

| Workflow | Trigger | Purpose |
|----------|---------|---------|
| `rust-ci.yml` | push/PR touching `guardian-meshd/**` | Build + test the daemon (needs `protoc`) |
| `webui-ci.yml` | push/PR touching `webui/**` | `npm ci` → build → lint → publish PWA to GitHub Pages |
| `android-apk.yml` | push touching `webui/**` or manual | Build + upload the debug **Android APK** |
| `pr-gate.yml` | any PR/push to `main` | Enforce **PR-based** updates to `main` |
| `version-snapshot.yml` | push to `main` | Tag `release/v<N>` + record manifest on `release-snapshots` |

## Governance model

**All changes to `main` land via pull request, and every merge is snapshotted.**

- `pr-gate.yml` fails any **direct push** to `main` and passes on pull requests.
- `version-snapshot.yml` tags each merge `release/v<N>` and appends to
  `releases/manifest.json`, archiving the prior release in `releases/archive/`.

### Why not a hard branch-protection rule?

GitHub branch-protection **rulesets** require **GitHub Pro** for private repos
(confirmed `403` on this account). The free-tier equivalent we use:

1. **PR Gate** as a status check — wire it as *required* on `main`:
   Repo → Settings → Branches → Add rule for `main` → "Require status checks"
   → select **PR Gate** → "Do not allow bypassing the above settings".
2. **Version Snapshot** — guarantees a durable copy of the version *before*
   every update even without hard enforcement.

## Running locally

```bash
cd guardian-meshd && cargo build && cargo test       # mirrors rust-ci
cd webui && npm ci && npm run build && npm run lint   # mirrors webui-ci
```

## Secrets

Workflows use only `GITHUB_TOKEN` (default). The APK workflow needs no extra
secrets; if you later add signing, add `KEYSTORE_*` secrets and reference them
in `android-apk.yml`.