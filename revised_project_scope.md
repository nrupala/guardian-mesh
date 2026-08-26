# Guardian Mesh — Revised Project Scope

## Current State

**Type:** Rust gRPC daemon with post-quantum cryptography and secure enclave architecture.
**Phase:** Design-complete with partial implementation — specs exceed code (positive gap).
**License:** MIT
**Location:** `D:\guardian-mesh\`

### Architecture (5-Enclave Design, No God-Process)
```
┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐
│  Auth        │  │  Compute     │  │  Storage     │  │  Network     │  │  Policy      │
│  Enclave     │  │  Enclave     │  │  Enclave     │  │  Enclave     │  │  Enclave     │
│  (identity,  │  │  (workload   │  │  (encrypted  │  │  (egress,    │  │  (governance,│
│   tokens,    │  │   execution) │  │   at-rest)   │  │   filtering) │  │   audit)     │
│   mTLS)      │  │              │  │              │  │              │  │              │
└──────────────┘  └──────────────┘  └──────────────┘  └──────────────┘  └──────────────┘
```

### Key Features
- **Post-Quantum Cryptography:** ML-KEM (FIPS 203), ML-DSA (FIPS 204), hybrid key exchange
- **TEE Abstraction:** AMD SEV-SNP, Intel TDX, AWS Nitro — unified attestation interface
- **No God-Process:** All enclaves are peer — no single point of compromise
- **Formal Specs:** Threat models, gap analyses, attestation flows
- **Web UI:** React-based management console (auto-generated)

### Specs Present (Exceed Implementation)
| Document | Coverage |
|----------|----------|
| `specs/ARCHITECTURE.md` | 5-enclave design, mTLS, attestation |
| `specs/ATTESTATION.md` | Remote attestation flows, DICE, certificate chain |
| `specs/THREAT_MODEL.md` | STRIDE per enclave, supply chain, side channels |
| `specs/GAP_ANALYSIS.md` | 12 identified gaps with priorities |
| `specs/VERIFICATION.md` | Test plan, formal methods roadmap |

### Gaps (From self-analysis)
| Priority | Gap | Status |
|----------|-----|--------|
| P0 | Enclave-to-enclave mTLS | Spec'd, not implemented |
| P0 | Remote attestation verification | Spec'd, not implemented |
| P0 | Policy engine (Rego/OPA) | Spec'd, not implemented |
| P1 | Audit logging | Spec'd, not implemented |
| P1 | Secret distribution | Spec'd, not implemented |
| P2 | Side-channel mitigations | Research phase |
| P2 | Supply-chain security | Research phase |
| P2 | Integration testing | Not started |

## Role in the Ecosystem

Guardian Mesh is the **foundational security layer**:

| Project | Integration |
|---------|------------|
| **AlphaForge** | Secure enclave for insider-trading computations |
| **AetherStream** | Secure enclave for cloud API credential management |
| **simplicity-new** | Secure enclave for sensitive query processing |
| **LocalForge** | Complements with local-first AI (not security-critical) |

## Development
- `cargo build` — build the daemon
- `cargo test` — run tests
- `cargo doc --open` — generate docs
- Web UI: `cd webui && pnpm dev`

## Verification
- `cargo test --workspace` — all tests
- `cargo clippy` — lint
- `cargo audit` — dependency security audit
