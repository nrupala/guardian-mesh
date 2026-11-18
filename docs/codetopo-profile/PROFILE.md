# Codetopo Profile — Guardian Mesh (nrupala/guardian-mesh)

**What this is.** The agent-facing map of this repository, generated with
Codetopo 0.9.1 (local engine) so an arriving agent can see the machine —
topology, trust boundaries, money surface — before it submits or changes
anything. The graph snapshot beside it (`snapshot.json`, `stats.json`) is
the measured evidence.

- **Repo:** nrupala/guardian-mesh (public)
- **Commit profiled:** `562354082c06af1401cbb2f68948581cd4185674` (main, 2026-11-18)
- **Engine:** codetopo 0.9.1 · index run 2026-11-18
- **Graph:** 94 files walked · 4,707 nodes · 15,909 edges · audit chain valid
- **Nodes by kind:** function 631 · method 409 · class 138 · interface 50 · variable 90 · module 93 · file 94 · doc 41 · external 3,157 · package 4
- **Edges by kind:** calls 8,630 · reads 4,750 · contains 1,546 · defines 728 · imports 204 · writes 48 · implements 2 · inherits 1

## Coverage honesty

Codetopo extracts Rust, TypeScript/JavaScript and Python. This repo is
Rust (daemon, 27 `.rs`) + TypeScript/TSX (WebUI, 21 files) + Python
(generated protobuf stubs, 3 files) — all extracted at symbol level.
Markdown (42 files) is indexed as Doc nodes. Not parsed into the graph:
YAML/TOML config, the `.proto` definition (its generated Rust/Python
stubs *are* extracted), shell scripts, and the fuzz corpus. Symbol
coverage of the codebase is complete for the languages present.

## Topology

A post-quantum, enclave-based security enforcement kit for agentic
workloads (README): every agent action passes a 5-enclave pipeline —
SENTINEL (observe) → GATEKEEPER (enforce) → WITNESS (audit) → ARBITER
(decide) → VAULT (seal) → verdict — split so no single component has
full system visibility.

- `guardian-meshd/` — the Rust gRPC daemon, the enforcement engine.
  Core modules in `guardian-meshd/src/`: `enclave/` (the five enclaves,
  incl. `enclave/gatekeeper.rs` — the Gatekeeper is a pure, total
  function: same input, same verdict), `policy.rs` (policy bundles),
  `handshake_bus.rs` (inter-enclave bus), `sealed_envelope.rs`,
  `execution_token.rs`, `certificate.rs`, `attestation.rs`,
  `authenticators.rs`, `revocation.rs`, `protocol_firewall.rs`,
  `tenant.rs`, `config.rs`. Binaries in `src/bin/`: `gm` (CLI),
  `gm-mcp` (MCP surface), `gm-attest`.
- `webui/` — React + Vite + PWA control panel (`webui/src/`), with
  dashboards and the release register (`webui/src/data/releases.ts`).
- `specs/` — formal design docs; the v2 architecture there (TEE
  attestation, BFT consensus, Lean-4 verification) **exceeds the code**
  — the README says so plainly; do not treat spec as implementation.
- `fuzz/` — cargo-fuzz targets + corpus for the daemon's parsers.
- `.github/workflows/` — Rust, WebUI and APK CI + release snapshots.

## Trust boundaries

- **Enclave separation is the boundary:** compromising the Sentinel
  cannot block actions; the Gatekeeper cannot read the audit trail;
  the Witness cannot enforce (README). Authority is split by design.
- **Cryptography:** proofs and envelopes are signed with ML-DSA-65
  (FIPS 204); integrity via CRC32C; inter-enclave authentication is
  HMAC-SHA256 over a rotating handshake session (`handshake_bus.rs`).
- **Audit:** the Witness signs every decision; the Vault persists an
  append-only JSONL audit trail that survives restart.
- **Access:** the WebUI login is 2FA (README). Execution is gated by
  execution tokens (`execution_token.rs`) and revocation is a
  first-class path (`revocation.rs`).
- **Secrets:** key material lives in the runtime workspace (keys,
  sessions — runtime data, not source); no credential values appear in
  this profile, by design. When working here, reference keys by name
  and fingerprint only.
- **Blast radius:** `policy.rs` and the Gatekeeper are the hubs — a
  policy-semantics change alters every verdict the mesh returns; the
  graph's 8,630 call edges concentrate through the enclave pipeline.

## Money surface

**No money surface found.** Grep over `guardian-meshd/src` and
`webui/src` for stripe / paddle / checkout / billing / payment finds no
payment integration (the only "checkout" hits are git-checkout wording
in release notes). The daemon sells nothing, charges nothing, and holds
no payment credentials. Its commercial terms live in `TERMS.md` /
`COMMERCIAL`-style docs, not in code paths.

## How an agent should approach

1. Read `README.md` (including its honest-status note), `SECURITY.md`,
   then this profile and the snapshot.
2. Treat `specs/` as design intent, never as proof of behaviour; the
   daemon source is the truth.
3. Query the graph (blast-radius, symbol, descendants) before touching
   `enclave/`, `policy.rs` or the handshake bus.
4. Run the repo's own suites (`cargo test`, WebUI build/lint) after any
   change; regenerate this profile at every release.

## Regeneration

`docs/codetopo-profile/refresh.sh` (in this pack) re-fetches the repo at
a named ref, re-runs the index, and rewrites `snapshot.json`,
`stats.json` and `verify.txt`. Regenerate at every release.

## Standing-condition lines for this change

- Documentation at par: this pack *is* the documentation change, shipped
  in the same PR as it describes; no behaviour changed.
- Release gate: NOT RUN for this profile PR · Guardian Mesh approval:
  NOT RUN. Merging this PR is not "shipped" under the standing
  conditions; the pack enters the gate queue as part of the Stage-1
  evidence pack.
- OpenSSF Best Practices: no project registered for this repo on
  bestpractices.dev (checked 2026-11-18) — a named gap; this additive
  docs change does not degrade any criterion.
