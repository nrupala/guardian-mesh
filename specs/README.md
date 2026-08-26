# specs — Guardian Mesh Design Documents

This folder contains the **formal design documentation** for Guardian Mesh.
Read these in order to understand *why* the system is shaped the way it is.

| Document | Status | What it covers |
|----------|--------|----------------|
| `GUARDIAN_MESH_FORMAL_SPEC.md` | Implemented | Formal spec of the **daemon** that actually exists today — the 5-enclave pipeline, handshake bus, protocol firewall, sealed envelopes |
| `GUARDIAN_MESH_ARCHITECTURE_v2.md` | Design | Aspirational v2 — TEE abstraction (SEV-SNP/TDX/Nitro), ATTP compat, BFT consensus levels, Lean-4 formal verification, EU AI Act / CAC mapping |
| `GUARDIAN_MESH_GAP_ANALYSIS.md` | Design | Honest gap analysis between the vision and the shipped code |
| `GUARDIAN_MESH_GAP_ANALYSIS (1).md` | Duplicate | Same as above (candidate copy — safe to delete) |

## How to read this

1. Start with `GUARDIAN_MESH_FORMAL_SPEC.md` to see **what is built and tested**.
2. Read `GUARDIAN_MESH_GAP_ANALYSIS.md` to see **what is missing**.
3. Read `GUARDIAN_MESH_ARCHITECTURE_v2.md` for the **target vision** only after
   the first two — it describes hardware TEEs and formal proofs that are not
   yet implemented.

> The implementation lives in `../guardian-meshd/`. If a spec and the code
> disagree, **the code and its tests win**; file the discrepancy in the gap
> analysis.