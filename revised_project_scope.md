# Guardian Mesh — Revised Project Scope

## Current State

**Type:** Rust gRPC daemon with post-quantum cryptography and 5-enclave enforcement pipeline.
**Phase:** Shipped and operational — v0.8.1 running in production at guardian.aimlds.org.
**License:** Apache License, Version 2.0, plus the AIMLDS Payment Rider
**Location:** GitHub repository at https://github.com/nrupala/guardian-mesh

### Architecture (5-Enclave Pipeline, No God-Process)

Guardian Mesh evaluates every action an AI agent attempts through a fixed 5-enclave pipeline where **no single component has full system visibility**:

```
Agent action ─▶ SENTINEL ─▶ GATEKEEPER ─▶ WITNESS ─▶ ARBITER ─▶ VAULT ─▶ verdict
                (observe)   (enforce)    (audit)   (decide)   (seal)
```

| Enclave | Role | What it sees | What it cannot do |
|---------|------|--------------|-------------------|
| **Sentinel** | Protocol Firewall (PF-1…PF-18) | Envelope structure, sizes, timestamps, nonces | Cannot enforce policy or read audit |
| **Gatekeeper** | Identity and permission over handshake session | Session ID, HMAC tag, caller public key | Cannot see policy rules or audit trail |
| **Witness** | Signs the verdict record | Hashed proof digest only | Cannot block actions or read raw behavior |
| **Arbiter** | Final decision (undecided defaults to BLOCK) | Action type, target, policy rules | Cannot enforce verdicts or access audit |
| **Vault** | Seals proof and persists hash-chained audit log | Sealed records only | Cannot export raw keys or modify verdicts |

Compromising the observer (Sentinel) cannot let you block actions; compromising the enforcer (Gatekeeper) cannot let you read the audit trail; compromising the auditor (Witness) cannot let you enforce anything.

### Verdicts

Guardian Mesh emits **four real verdicts**, all with signed proof envelopes:

- **ALLOW** — the action passes all checks and is permitted.
- **BLOCK** — the action is denied by policy or firewall rules.
- **THROTTLE** — the action exceeds rate limits (PF-18: 100 msg/s per session, or the policy-configurable rate). Shipped in v0.7.0.
- **ESCALATE** — the action type is on the policy-configured escalation list and requires human approval. Shipped in v0.7.0.

### Key Features

- **Post-Quantum Cryptography:** ML-DSA-65 (FIPS 204) signatures for proofs and envelopes; CRC32C integrity checks; HMAC-SHA256 handshake bus.
- **Protocol Firewall:** 18 rules (PF-1…PF-18) enforced on the Evaluate path, including signature verification (WO-1, v0.3.0), size/structure/nesting/nonce/timestamp/rate checks (WO-2, v0.4.0).
- **Persistent Signing Key:** The daemon's ML-DSA-65 signing key is generated on first start and persisted across restarts (WO-3, v0.5.0). The Health RPC reports the signing-key fingerprint (SHA-256 hash of the public key, never key material).
- **Hash-Chained Audit Log:** Append-only JSONL trail with ReadAuditLog RPC returning entries and chain-verification status (WO-4, v0.6.0). Chain appends are atomic per entry under concurrency (WO-6.1, v0.8.1).
- **Release-Evidence Certification:** IssueCertificate, RevokeCertificate, and CertificateStatus RPCs (WO-6, v0.8.0). A certificate warrants only the exact item tested (identified by evidence hash), against the policy named, on the date stamped. Certificates have four lifecycle states: ACTIVE, SUPERSEDED, REVOKED, UNKNOWN.
- **gRPC API Surface (8 RPCs):** Handshake, Evaluate, VerifyProof, Health, ReadAuditLog, IssueCertificate, RevokeCertificate, CertificateStatus.
- **React + Vite PWA Control Panel:** Live panel at guardian.aimlds.org (owner-only access); demo build published via GitHub Pages.
- **CI/CD:** Rust tests, WebUI build/lint, APK builds, and release snapshots in GitHub Actions.

### Specifications Present

The `specs/` directory contains the formal design documents:

| Document | Contents |
|----------|----------|
| `GUARDIAN_MESH_FORMAL_SPEC.md` | Formal specification of the implemented daemon |
| `GUARDIAN_MESH_ARCHITECTURE_v2.md` | Aspirational v2 design (TEE, BFT, formal proofs) |
| `GUARDIAN_MESH_REVISED_SPEC.md` | Governing target specification v3.1 |
| `GUARDIAN_MESH_GAP_ANALYSIS.md` | Honest gaps between spec and shipped code |
| `CERTIFICATE_SCHEMA.md` | Certificate schema and lifecycle specification |
| `STANDARDS_COMPLIANCE_REVIEW.md` | Standards compliance review |
| `COMPLIANCE_DEVELOPMENT_PLAN.md` | Compliance development roadmap |
| `README.md` | Overview of the specifications |

### Gaps (Designed, Not Built)

The following capabilities are **design only** and are not shipped features:

| Priority | Gap | Status |
|----------|-----|--------|
| P1 | TEE attestation (AMD SEV-SNP, Intel TDX, AWS Nitro) | Design only |
| P1 | Enclave-to-enclave mTLS | Design only |
| P1 | Remote attestation verification | Design only |
| P1 | Multi-node / BFT consensus | Design only |
| P2 | External proof anchoring | Design only |
| P2 | Lean 4 formal verification | Design only |
| P2 | Rego/OPA policy engine | Design only |

Additional gaps are documented in `specs/GUARDIAN_MESH_GAP_ANALYSIS.md`. Capabilities that have shipped (audit logging with ReadAuditLog, hash-chained verification, THROTTLE/ESCALATE verdicts, certificate issuance) are **not** gaps.

## Role in the Ecosystem

Guardian Mesh is a **security enforcement engine** for AI agent actions. Its shipped role:

- **Pre-execution evaluation:** Guardian Mesh evaluates agent actions **before** they run. An agent calls the Evaluate RPC with an action descriptor; Guardian Mesh returns a verdict (ALLOW, BLOCK, THROTTLE, or ESCALATE) plus a cryptographically signed proof.
- **Release-evidence certification (v0.8.0+):** Guardian Mesh issues release-evidence certificates that bind a release-gate verdict to an evidence pack. A certificate attests to a specific release artifact (identified by SHA-256 evidence hash), the gate verdict, test results, policy version, issuing daemon identity (signing-key fingerprint), and issuance timestamp.
- **Integration with the owner's fleet:** The release gate across the owner's fleet feeds Guardian Mesh spec inputs (the GMSI series in `docs/nightly/OPENCODE-INSTRUCTIONS.md`). Guardian Mesh evolves with the gate.

Guardian Mesh does **not** vouch for deployment choices, runtime behavior, or operational posture. A certificate warrants only the exact item tested, against the policy named, on the date stamped.

## Development

### Daemon (Rust)

```bash
cd guardian-meshd
cargo build --release       # build the daemon
cargo test                  # run the test suite (97 tests: 80 lib + 17 bin)
cargo clippy --all-targets -- -D warnings  # must be clean
```

### WebUI (React + Vite)

```bash
cd webui
npm ci                      # install dependencies
npm run dev                 # local dev server
npm run build               # production bundle (dist/)
npm run lint                # ESLint gate (CI enforces this)
```

### Configuration

The daemon is configured entirely via environment variables (see `guardian-meshd/src/config.rs`):

| Variable | Default | Purpose |
|----------|---------|---------|
| `GUARDIAN_MESH_BIND_ADDR` | `127.0.0.1` | Bind address |
| `GUARDIAN_MESH_PORT` | `50051` | gRPC port |
| `GUARDIAN_MESH_WORKSPACE` | `guardian-mesh-data/workspace` | Runtime data (audit, sessions, keys) |
| `GUARDIAN_MESH_OUTPUT` | `guardian-mesh-data/output` | Generated output |
| `GUARDIAN_MESH_HANDSHAKE_SECRET` | embedded | HMAC master secret |
| `GUARDIAN_MESH_POLICY_THROTTLE_RATE` | `100` | Per-session rate limit (msg/s) before THROTTLE verdict |
| `GUARDIAN_MESH_POLICY_ESCALATE_ACTIONS` | (empty) | Comma-separated action types requiring human escalation |

## Verification

- **Test suite:** `cargo test` in `guardian-meshd/` — 97 tests green (80 lib + 17 bin) as of v0.8.1.
- **WebUI:** `npm run build` and `npm run lint` in `webui/` — both must pass.
- **Release gate:** Every release carries a gate verdict recorded in the CHANGELOG and the release record.
- **Independent verification:** Wright re-runs the full test suite from a fresh checkout of the pushed branch before merge.

## License

**Apache License, Version 2.0, plus the AIMLDS Payment Rider** — one license for the whole repository (the interface, the core daemon, and the specifications).

The code is free to use, study, modify, and self-host at any scale. The Rider reserves two things to paid commercial license:

1. Offering Guardian Mesh's verdicts or certification as a service to third parties.
2. Issuing certificates under the Guardian Mesh name.

See [LICENSE](LICENSE) and [LICENSE-RIDER.md](LICENSE-RIDER.md) for the full text.
