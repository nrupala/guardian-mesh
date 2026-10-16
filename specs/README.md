# specs — Guardian Mesh Design Documents

This folder contains the **formal design documentation** for Guardian Mesh.
Read these in order to understand *why* the system is shaped the way it is.

| Document | Status | What it covers |
|----------|--------|----------------|
| `GUARDIAN_MESH_REVISED_SPEC.md` | **Governing target (v3.1)** | The consolidated specification: product boundary charter (§0.5), closed-path Doctrine 0, universal deployment, trust boundaries + the two-confirmation rule, pluggable authorization (PGP/GPG incl.), hyperscaler-aligned checkpoints (CP-01…CP-24), data-center readiness (DC), complete mediation (CM), securing the guardian (SG), product completeness (PC), the release gate as criteria of record (RG), evidence & certificates (EV). Read this first for direction; honesty labels mark what is shipped vs target |
| `STANDARDS_COMPLIANCE_REVIEW.md` | Review of record (2026-10-16) | Alignment review against ISO/IEC 22989 (AI terminology), the SC 42 family, and the cybersecurity standards family (NIST CSF / 800-53 / 800-207, ISO/IEC 27001, CIS v8, FIPS 203/204/140-3, OWASP, SLSA, SOC 2, EU AI Act) — alignment, not certification; statuses honest per standard |
| `COMPLIANCE_DEVELOPMENT_PLAN.md` | Plan of record (2026-10-16) | The build plan that closes the review's gaps as evidence-producing machinery: phases (language & risk → attestation machinery → crypto/supply-chain standing), the organizational track for AIMLDS (42001/27001/SOC 2, demand-led), acceptance evidence per item, work-order mapping |
| `GUARDIAN_MESH_FORMAL_SPEC.md` | Implemented | Formal spec of the **daemon** that actually exists today — the 5-enclave pipeline, handshake bus, protocol firewall, sealed envelopes |
| `GUARDIAN_MESH_ARCHITECTURE_v2.md` | Design | Aspirational v2 — TEE abstraction (SEV-SNP/TDX/Nitro), ATTP compat, BFT consensus levels, Lean-4 formal verification, EU AI Act / CAC mapping |
| `GUARDIAN_MESH_GAP_ANALYSIS.md` | Design | Honest gap analysis between the vision and the shipped code |
| `GUARDIAN_MESH_GAP_ANALYSIS (1).md` | Duplicate | Same as above (candidate copy — safe to delete) |

## How to read this

1. Start with `GUARDIAN_MESH_REVISED_SPEC.md` for the governing target —
   what Guardian Mesh is becoming, with honesty labels on what already is.
2. Read `GUARDIAN_MESH_FORMAL_SPEC.md` to see **what is built and tested**.
3. Read `GUARDIAN_MESH_GAP_ANALYSIS.md` to see **what is missing**.
4. Read `GUARDIAN_MESH_ARCHITECTURE_v2.md` for the earlier vision layer —
   its consensus/TEE/formal-verification material is carried forward by
   the revised specification (§6, §7.3), which supersedes its direction.

> The implementation lives in `../guardian-meshd/`. If a spec and the code
> disagree, **the code and its tests win**; file the discrepancy in the gap
> analysis.