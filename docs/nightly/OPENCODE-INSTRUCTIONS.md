# Guardian Mesh — Nightly Build Instructions (for OpenCode and worker lanes)

This file is the single work order for Guardian Mesh development. It unifies
two sources, refreshed nightly by Wright:

- **Part A — the repo's own pending build/update list**: `specs/` (formal
  spec, architecture v2, gap analysis), `revised_project_scope.md`, the
  CHANGELOG, and gaps verified against the shipped code.
- **Part B — Guardian Mesh Spec Inputs (GMSI) from the release gate**: the
  release-gate thread is Guardian Mesh's source of specs. Every gate run
  across the fleet files what Guardian Mesh must be able to *prove* — the
  evaluation input, the ALLOW/BLOCK rule, the sealed-proof fields, the
  tamper behaviour, and the certificate-lifecycle impact.

Owner direction (2026-10-14): this pack is worked **nightly**. Wright runs
worker lanes (OpenCode primary builder; DeepSeek for bulk drafting and
first-pass generation on dev material only; Claude/OpenAI lanes for review
and hard protocol work), then **independently verifies** every lane's output
from a fresh checkout of the pushed branch. Nothing merges on a lane's own
tests. Nothing merges red. Every release carries a release-gate verdict.

## Guardrails (never violated)

1. **Honesty boundary.** Public surfaces claim only what the machinery does.
   TEE attestation, multi-node/BFT consensus, external anchoring, and
   Lean 4 verification are design, not shipped — never present them as built.
2. **Liability boundary.** A certificate warrants only the exact item tested,
   against the policy named, on the date stamped — never deployment choices.
3. **Licensing split.** `guardian-meshd/` (core) is AGPL-3.0-or-later;
   `webui/` (interface) is Apache-2.0. New webui files carry the Apache-2.0
   SPDX header; new core files carry the AGPL header.
4. **Fail closed.** No answer from the daemon means BLOCK. Undecided means
   BLOCK. A check that cannot run is reported NOT RUN, never PASS.
5. **Deterministic enforcement.** No LLM in any verdict path.
6. **No secrets in the repo or in logs.** Pattern + location only.
7. Every change lands as a draft PR, full CI green, Wright-verified, then
   merged. Version bump + CHANGELOG entry + public release-log update ride
   with every release.

## Part A — Work orders from the repo

### WO-1 (P0) Verify the request signature on Evaluate
The client envelope carries an ML-DSA-65 signature over
`crc32c_le_bytes || payload`, and the WebUI produces a real one — but the
daemon never verifies it. Close the authentication gap:
- Gatekeeper (or Witness step) verifies the envelope signature against the
  public key bound at Handshake time; Handshake therefore also registers the
  caller's ML-DSA-65 public key with the session.
- Missing, malformed, or non-verifying signature → `permission_denied` with
  a plain reason; the evaluation never reaches the Arbiter.
- Acceptance: unit + integration tests — valid signature evaluates;
  tampered payload, wrong key, and unsigned envelope each BLOCK; the
  existing 32-test suite stays green.

### WO-2 (P0) Enforce the Protocol Firewall rule table
`specs/GUARDIAN_MESH_FORMAL_SPEC.md` §1.4 defines PF-1…PF-18. The shipped
Sentinel enforces only the subset adapted to client envelopes (structure/
size, timestamp drift, context size, target traversal). Implement the
remainder as they apply to the Evaluate path, each with a named test:
- PF-1/PF-5 size and payload-length bounds (64 KiB envelope budget);
  PF-6 CRC32C already checked — keep and test.
- PF-12 unknown-field rejection and PF-13 nesting depth ≤ 4 for the payload.
- PF-14 nonce uniqueness: sliding window of the last 10,000 nonces per
  session; reuse → reject.
- PF-15/PF-16 timestamp windows per spec (stale > 5 s, future > 1 s) for the
  envelope timestamp, kept distinct from the existing drift counter.
- PF-17 signature format budget (ML-DSA-65 length in [2420, 3500]).
- PF-18 rate limit: 100 msg/s per external session → THROTTLE-grade reject.
- Every rejection logs step + error code into the audit trail (spec §1.4).

### WO-3 (P1) Persistent daemon signing key
The Witness/daemon signing key is currently generated per boot, so proofs
verify only against the running instance. Persist it:
- On first start, generate the ML-DSA-65 keypair into the daemon workspace
  (file permissions 0600); load it on later starts.
- Health reports the signing-key fingerprint (hash, never key material).
- Document generation, storage, backup, and rotation in the guide.
- Acceptance: restart the daemon; a proof issued before the restart still
  verifies VALID after it.

### WO-4 (P1) Audit trail read path
The Vault appends to a hash-chained audit log but exposes no read RPC, and
the panel's "View Audit Log" therefore does not exist in live mode.
- Add a read RPC returning audit entries (and chain-verification status).
- Wire the live panel's audit view to it.
- Acceptance: entries from real evaluations list in order; a hand-edited
  log line makes chain verification report the break.

### WO-5 (P1) Real THROTTLE and ESCALATE verdicts
Both verdicts exist in the protocol but no code path emits them.
- THROTTLE: PF-18 rate breaches and a policy-configurable per-session rate.
- ESCALATE: a policy list of action types/targets that require a human;
  the verdict carries the reason and the proof records the escalation.
- Acceptance: tests drive each verdict end to end; panel renders both with
  plain words.

### WO-6 (P1) Release-evidence certification (from Part B, GMSI-1)
See Part B. Spec first (certificate schema binding a gate evidence pack),
then the minimal implementation.

### WO-7 (P2) Reconcile stale scope docs with shipped reality
`revised_project_scope.md` predates the shipped system: it names a
different enclave set, says "License: MIT", and lists audit logging and
the policy engine as not implemented — all superseded. Rewrite it to the
shipped Sentinel/Gatekeeper/Witness/Arbiter/Vault design and the
AGPL-core/Apache-interface licensing. Remove the duplicate
`specs/GUARDIAN_MESH_GAP_ANALYSIS (1).md` (byte-identical copy).

### WO-8 (P2) Fuzz the boundaries (hardening rule H6)
Add fuzz targets (cargo-fuzz / libFuzzer) for envelope decoding, payload
parsing, and proof verification; a nightly CI job runs them briefly.
Crashes become P0 work orders.

### WO-9 (P1) Public release log on the site
Standing fleet rule: every product keeps a public release log — changes
plus the testing record (gate verdict, what was tested, counts, journey
proof). Add a `/releases` page to the WebUI fed from the CHANGELOG and
gate records; update it as part of each release, not after.

### Designed, not yet scheduled (do not build without owner direction)
TEE attestation (SEV-SNP/TDX/Nitro), enclave-to-enclave mTLS, remote
attestation verification, multi-node consensus, external proof anchoring,
Lean 4 formal verification, Rego/OPA policy engine.

## Part B — Spec inputs from the release gate (GMSI)

Guardian Mesh evolves with the gate. Each item below states what Guardian
Mesh must be able to prove. A capability becomes a gate MUST only after it
is behaviour-proven here (valid → VALID, tampered → NOT VALID, no answer →
BLOCK).

- **GMSI-1 — Certify a release evidence pack.** Input: product, version,
  gate verdict, evidence-pack hash, test counts. Rule: ALLOW (certificate
  issues) only when the pack hash matches the presented evidence and the
  verdict is recorded; BLOCK otherwise. Proof fields: product, version,
  verdict, evidence hash, policy (gate version), timestamp, issuer.
  Lifecycle: issuing a certificate for a newer release supersedes the old;
  a gate verdict of BLOCKED revokes. → implemented by WO-6.
- **GMSI-2 — Hash-verifiable handoff of one-time secrets.** Born of a real
  escape (reviewer keys corrupted in transcription). Any key or secret
  Guardian Mesh issues or carries must ship with a fingerprint the holder
  can check (SHA-256 of the value), and verification tooling must compare
  the *copy presented*, not the copy at mint. → lands with WO-3
  (fingerprint in Health) and WO-6 (fingerprint field in certificates).
- **GMSI-3 — Independent re-verification.** Proofs must verify on a second
  lane that never built them (the Arch evidence-bench doctrine). Until the
  bench exists, VerifyProof from a separate client/process is the stand-in
  — keep proofs self-contained (all fields needed to verify travel inside
  the sealed envelope).
- **GMSI-4 — Auth-attack resistance is evaluated, not assumed.** Login and
  session surfaces must prove rate limiting and lockout actually fire.
  For Guardian Mesh itself: Handshake attempt throttling and session
  abuse limits → covered by WO-2 (PF-18) and WO-5 (THROTTLE).
- **GMSI-5 — History is part of the artifact.** A secret ever committed
  stays in git history; certification of a repository must state whether
  history was scanned, not only the working tree. Certificate schema
  (WO-6) carries a `scope` field: `working-tree` | `full-history`.
- **Backbone note.** The gate's Kali (offensive) and Arch (crypto /
  isolation / evidence benches) backbones are gate infrastructure, not
  repo code; their NOT RUN status is recorded by the gate thread. The
  repo-side contribution is WO-8's fuzz targets, which the Arch isolation
  bench will consume.

## Development home and engine routing

Owner direction (2026-10-14, replacing the original routing): **development
happens on the owner's laptop, driven by OpenCode there — never on the
Aetheris box.** The box is a deployment target only (the daemon and live
panel services); no building and no OpenCode runs on it. **GitHub is the
repo's home of record** — every lane works on branches and PRs here, and
the laptop checkouts are working copies, never the source of truth.

- **OpenCode on the laptop** — the primary builder, one work order per
  branch/PR. It works in a fresh clone per work order
  (`D:\guardian-mesh-work\<work-order>`, cloned from GitHub main). The
  pre-existing `D:\guardian-mesh` checkout is stale and carries the
  owner's own local changes — never build in it, never clean it.
  OpenCode's output is never trusted on its own tests (owner's standing
  rule: "sometimes it screws up").
- **Model lanes OpenCode may drive, all owner-authorized**: DeepSeek AI,
  OpenAI, Claude, and OpenCode Zen. DeepSeek stays dev-material-only
  (specs and code, never production data or real credentials).
- **Wright** — direction, the whole-app read before changes, independent
  re-testing from the pushed branch (fresh checkout; full suites),
  the release-gate run for each release, merge (green only), deploy to
  the box, and this file's nightly refresh.
- **Testing is always the Release Gate** — machine pass + deep review +
  behaviour proof, verdict recorded in the release record — plus the
  gate's security tuning for the change's families. No gate verdict, no
  merge, no deploy.

## The nightly loop

1. Re-read this file, open issues/PRs, and the release gate's latest
   GMSI filings; refresh this file by PR when new inputs arrived.
2. Take the highest-priority unfinished work order; the laptop's
   OpenCode builds it in a fresh per-work-order clone, on a branch, as
   a draft PR.
3. Wright verifies independently: fresh checkout of the pushed branch,
   full test suites (`cargo test`, webui build + lint), and behaviour
   proof on the live surface where the change touches one.
4. Release gate: run the gate on the change; record the verdict in the
   PR and the CHANGELOG; file this run's GMSI (or "none").
5. Merge only when CI is green and the gate is not BLOCKED. Deploy
   (box services + Pages) per the established paths and re-verify live.
6. One consolidated report to the owner: what advanced, what verified,
   what is NOT RUN and why. No per-step drips.

## Status ledger

- 2026-10-14 — pack created from repo inventory (zero open issues/PRs;
  pending work lives in `specs/` + verified implementation gaps) and the
  release gate's founding GMSI set. WO-1 dispatched first.
- 2026-10-14 — **WO-1 shipped as v0.3.0** (PR #26, merged a6b7d195):
  Handshake binds the caller's ML-DSA-65 public key; Evaluate verifies
  the envelope signature against it, fail-closed. Wright-verified
  independently: 47 cargo tests green on a fresh checkout; wire-level
  proof 9/9 on the branch daemon and again 9/9 against the deployed
  daemon on the Aetheris box (valid → ALLOW + VALID proof; garbage /
  wrong-key / tampered → permission_denied; keyless handshake →
  invalid_argument). Release gate: PASS WITH FINDINGS (scanner "tests"
  failure was a false lead — inline Rust tests; GMSI filed to teach
  the scanner `#[test]` detection; optional: `.gitignore` name `.env`).
  Deployed to guardian.aimlds.org the same night. Next: WO-2.
- 2026-10-14 — **Development home moved to the laptop** (owner's order):
  OpenCode on the laptop builds (fresh clone per work order;
  `D:\guardian-mesh` is stale + owner-dirty, hands off), authorized
  model lanes are DeepSeek / OpenAI / Claude / OpenCode Zen, GitHub
  stays the repo home, the Aetheris box is deployment-only, and
  testing is always the Release Gate + security tuning. Recon the
  same night: OpenCode 1.18.32 runnable on the laptop, git 2.52,
  node 26.
- 2026-10-14 (later) — **Laptop lane at full strength**: the owner
  made the laptop `muse` account an administrator and placed Wright's
  key in `C:\ProgramData\ssh\administrators_authorized_keys` (the
  Windows rule for admin accounts). Wright installed the toolchain
  under `muse` itself: rustup stable (cargo/rustc 1.99.0), protoc
  29.3, OpenCode on muse's PATH. Proof: a fresh clone at
  `D:\guardian-mesh-work\probe` ran `cargo test` on the laptop —
  47/47 passed. The earlier "cargo shim does not execute" note is
  superseded; laptop-side builds and tests are proven.
