# Guardian Mesh

**Status:** Current/active development · **Version:** 0.1.0 · **Updated:** 2026-08-30

See [CHANGELOG.md](CHANGELOG.md).

**Post-quantum, enclave-based security enforcement for agentic AI workloads.**

Guardian Mesh is a complete, working security kit that evaluates and governs every
action an AI agent attempts before it is allowed to execute. It is built on a
5-enclave enforcement pipeline where **no single component has full system
visibility** — compromise of any one enclave does not compromise the system.

```
Agent action ─▶ SENTINEL ─▶ GATEKEEPER ─▶ WITNESS ─▶ ARBITER ─▶ VAULT ─▶ verdict
                (observe)   (enforce)    (audit)   (decide)   (seal)
```

| Layer | What it is | Status |
|-------|-----------|--------|
| `guardian-meshd/` | **Rust gRPC daemon** — the enforcement engine (ML-DSA-65, CRC32C, HMAC handshake bus) | Implemented, tested |
| `webui/` | **React + Vite + PWA control panel** — 2FA login, dashboards | Implemented |
| `specs/` | **Formal design docs** — architecture v2, threat model, gap analysis | Spec (exceeds code) |
| `.github/workflows/` | **CI/CD** — Rust, WebUI, APK builds + release snapshots | Implemented |

> **Honest status:** the enforcement pipeline in `guardian-meshd/` is functional
> and unit-tested. The ambitious v2 architecture described in `specs/` (TEE
> attestation, BFT consensus, formal Lean-4 verification) is **design** that
> exceeds the current implementation — see `specs/GUARDIAN_MESH_GAP_ANALYSIS.md`.

---

## Why Guardian Mesh is useful

1. **No god-process.** Unlike a single "security daemon" that can be compromised
   wholesale, Guardian Mesh splits authority across 5 peer enclaves. Compromising
   the observer (Sentinel) cannot let you *block* actions; compromising the
   enforcer (Gatekeeper) cannot let you *read* the audit trail; compromising the
   auditor (Witness) cannot *enforce* anything.
2. **Post-quantum by default.** All proofs and envelopes are signed with
   **ML-DSA-65** (FIPS 204), integrity-checked with **CRC32C**, and authenticated
   between enclaves with **HMAC-SHA256** over a rotating handshake session.
3. **Deterministic enforcement.** The Gatekeeper is a pure, total function — same
   input, same verdict, every time. No LLM, no floating point, no probabilistic
   reasoning in the hot path.
4. **Tamper-evident audit.** The Witness signs every decision; the Vault persists
   an append-only JSONL audit trail that survives restart.
5. **Immediately useful.** The daemon runs as a real gRPC service; the WebUI
   gives a PWA dashboard; CI produces an installable Android APK. It is a
   turn-key reference architecture you can extend, not a slide deck.

---

## Repository layout

```
guardian-mesh/
├── README.md                    ← you are here
├── specs/                       ← formal design documents
├── guardian-meshd/              ← Rust daemon (see its README)
├── webui/                       ← React control plane (see its README)
├── templates/                   ← reusable architecture templates
├── workspace/                   ← runtime data (audit, sessions, keys)
├── output/                      ← generated output
└── .github/workflows/          ← CI/CD + release governance
```

## Quick start

### 1. Build & run the daemon

```bash
cd guardian-meshd
cargo build --release
cargo run --release
# listening on 127.0.0.1:50051 (override with GUARDIAN_MESH_PORT)
```

Configuration is all environment-driven — see `guardian-meshd/src/config.rs`:

| Variable | Default | Purpose |
|----------|---------|---------|
| `GUARDIAN_MESH_BIND_ADDR` | `127.0.0.1` | Bind address |
| `GUARDIAN_MESH_PORT` | `50051` | gRPC port |
| `GUARDIAN_MESH_WORKSPACE` | `guardian-mesh-data/workspace` | Runtime data |
| `GUARDIAN_MESH_OUTPUT` | `guardian-mesh-data/output` | Output data |
| `GUARDIAN_MESH_HANDSHAKE_SECRET` | embedded | HMAC master secret |

### 2. Run the tests

```bash
cd guardian-meshd
cargo clippy --all-targets -- -D warnings   # must be clean
cargo test                                   # 31 unit tests
```

### 3. Run the WebUI

```bash
cd webui
npm ci
npm run dev        # local dev server
npm run build      # production bundle (dist/)
npm run lint       # ESLint gate (CI enforces this)
```

### 4. Build the Android APK

```bash
cd webui
npm ci
npm run build
npx cap add android          # if not present
npx cap sync
cd android && ./gradlew assembleDebug
# APK at android/app/build/outputs/apk/debug/
```

> Note: `android/` is gitignored (generated). A stale empty `android/` folder
> blocks `npx cap add android` — remove it and re-add if that error appears.

---

## API surface

The daemon exposes a single gRPC service (`proto/guardian_mesh.proto`):

```proto
rpc Evaluate   (EvaluateRequest)   returns (EvaluateResponse)   // run the pipeline
rpc VerifyProof(VerifyProofRequest)returns (VerifyProofResponse) // validate an audit proof
rpc Health     (HealthRequest)     returns (HealthResponse)     // readiness
```

See `guardian-meshd/README.md` for the full protocol, the 18 protocol-firewall
rules, and the enclave contract.

---

## Development governance

- **PR-based updates.** All changes to `main` must land through a pull request
  (see `PR Gate` workflow). On the free tier a private repo cannot hard-block
  direct pushes via GitHub rulesets (that needs Pro); wire the **PR Gate**
  status check as required on `main` to enforce it.
- **Version snapshots.** Every merge to `main` is tagged `release/v<N>` and
  recorded in `releases/manifest.json` (see `Version Snapshot` workflow). This
  preserves the exact version before each update.

## Documentation map

| Document | Contents |
|----------|----------|
| `specs/GUARDIAN_MESH_FORMAL_SPEC.md` | Formal spec of the implemented daemon |
| `specs/GUARDIAN_MESH_ARCHITECTURE_v2.md` | Aspirational v2 design (TEE, BFT, formal proofs) |
| `specs/GUARDIAN_MESH_GAP_ANALYSIS.md` | Honest gaps between spec and code |
| `guardian-meshd/README.md` | Daemon internals & protocol |
| `webui/README.md` | Control-plane UI & Capacitor/APK guide |

## License

MIT — see [LICENSE](LICENSE).