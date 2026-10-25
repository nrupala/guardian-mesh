# Guardian Mesh

**Status:** Current/active development · **Version:** 0.8.5 · **Updated:** 2026-10-24

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
| `GUARDIAN_MESH_POLICY_THROTTLE_RATE` | `100` | Per-session rate limit (msg/s) before THROTTLE verdict |
| `GUARDIAN_MESH_POLICY_ESCALATE_ACTIONS` | (empty) | Comma-separated action types requiring human escalation |

### 2. Run the tests

```bash
cd guardian-meshd
cargo clippy --all-targets -- -D warnings   # must be clean
cargo test                                   # 97 tests (80 lib + 17 bin)
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
rpc Evaluate         (EvaluateRequest)          returns (EvaluateResponse)          // run the pipeline
rpc VerifyProof      (VerifyProofRequest)       returns (VerifyProofResponse)       // validate an audit proof
rpc Health           (HealthRequest)            returns (HealthResponse)            // readiness
rpc Handshake        (HandshakeRequest)         returns (HandshakeResponse)         // open a session
rpc ReadAuditLog     (ReadAuditLogRequest)      returns (ReadAuditLogResponse)      // read the audit trail
rpc IssueCertificate (IssueCertificateRequest)  returns (IssueCertificateResponse)  // issue a release certificate
rpc RevokeCertificate(RevokeCertificateRequest) returns (RevokeCertificateResponse) // revoke a certificate
rpc CertificateStatus(CertificateStatusRequest) returns (CertificateStatusResponse) // query certificate status
```

See `guardian-meshd/README.md` for the full protocol, the 18 protocol-firewall
rules, and the enclave contract.

### Certificate Issuance (v0.8.0+)

Guardian Mesh can issue **release-evidence certificates** that bind a gate verdict to an evidence pack under the daemon's cryptographic signature. A certificate attests to:

- A specific release artifact (identified by its SHA-256 evidence hash)
- The gate verdict issued over that evidence (`PASS` or `PASS WITH FINDINGS`)
- Test results and policy version declared by the presenter
- The issuing daemon's identity (its signing-key fingerprint)
- The issuance timestamp

**How to verify a certificate:**

1. **Re-verify the signature**: Present the sealed certificate envelope to the `VerifyProof` RPC of any Guardian Mesh daemon. The daemon verifies the ML-DSA-65 signature.
2. **Recompute the fingerprint**: Compute SHA-256 over the exact payload bytes of the presented certificate envelope and verify it matches the fingerprint presented alongside the envelope (from the `IssueCertificate` response or the `CertificateStatus` response; the fingerprint is not a field inside the sealed payload). This proves the copy presented is byte-identical to the copy issued (GMSI-2).
3. **Check lifecycle status**: Query the issuer's `CertificateStatus(serial)` RPC to verify the certificate is ACTIVE (not SUPERSEDED or REVOKED).

A certificate that passes all three checks is valid.

**Certificate lifecycle:**

- **ACTIVE**: The current, valid certificate for the product+version.
- **SUPERSEDED**: A newer certificate was issued for the product, and this one is no longer current.
- **REVOKED**: The certificate was explicitly revoked or automatically revoked due to a `BLOCKED` gate verdict.
- **UNKNOWN**: The serial is not found (never issued, or registry lost).

**Trust posture (v1):** Issuance is a daemon-local operation. The daemon binds to localhost (or sits behind access control). There is no public issuance endpoint in v1. The issued certificate can be presented to **any** Guardian Mesh daemon for verification via `VerifyProof`.

See `specs/CERTIFICATE_SCHEMA.md` for the complete certificate schema and lifecycle specification.

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

**Apache License, Version 2.0, plus the AIMLDS Payment Rider** —
one license for the whole repository (the interface, the core
daemon, and the specifications). The code is free to use, study,
modify, and self-host at any scale; the Rider reserves two things
to paid commercial license: offering Guardian Mesh's verdicts or
certification as a service to third parties, and issuing
certificates under the Guardian Mesh name. See [LICENSE](LICENSE)
and [LICENSE-RIDER.md](LICENSE-RIDER.md).