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
3. **License: Apache 2.0 + Payment Rider** (owner's decision
   2026-10-16, replacing the former AGPL/Apache split). The whole
   repo — core, interface, specs — is Apache License, Version 2.0
   plus the AIMLDS Payment Rider (`LICENSE-RIDER.md`): free to use,
   modify, and self-host at any scale; offering Guardian Mesh
   verdicts/certification as a service to third parties, or issuing
   certificates under the Guardian Mesh name, requires a paid
   commercial license. New files carry the Apache-2.0 SPDX header.
   Never describe the license as unmodified Apache 2.0.
4. **Fail closed.** No answer from the daemon means BLOCK. Undecided means
   BLOCK. A check that cannot run is reported NOT RUN, never PASS.
5. **Deterministic enforcement.** No LLM in any verdict path.
6. **No secrets in the repo or in logs.** Pattern + location only.
7. Every change lands as a draft PR, full CI green, Wright-verified, then
   merged. Version bump + CHANGELOG entry + public release-log update ride
   with every release.
8. **System-level language only.** Guardian Mesh is a system-level product
   and the daemon is Rust because execution speed is a security property
   (owner's doctrine, 2026-10-14). No Python — or any slow interpreted
   language — in the product runtime: core and performance/security-
   critical components are Rust (POSIX-class system languages only: Rust,
   C, C++). The browser interface is TypeScript because that is the
   browser's native layer. Interpreted languages may appear only as
   throwaway scaffolding outside the shipped product (test harnesses,
   one-off verification scripts) and are never shipped as components.

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
Apache License 2.0 + Payment Rider licensing (2026-10-16). Remove
the duplicate
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

## Part C — Work orders from the Revised Specification v3.0 (2026-10-15)

`specs/GUARDIAN_MESH_REVISED_SPEC.md` is the governing target spec
(owner-approved 2026-10-15). It folds in the data-center readiness set,
the hyperscaler-aligned checkpoint catalogue (CP-01…CP-24), the
trust-boundary map with the two-confirmation rule, pluggable
authorization (PGP/GPG included), and the release gate as criteria of
record. Owner direction of 2026-10-15 supersedes the "designed, not
yet scheduled" line above for the items below (clustered verdicts,
attestation package, workload mTLS) — they are scheduled here.
Work these after Part A, in this order, one per night unless the
nightly run's judgment says otherwise:

### WO-19 (P1) Firewall session eviction + measured Health counters
Closes v0.4.0 gate findings F1/F2: call ProtocolFirewall::evict_session
on bus session expiry (or TTL-sweep), and make Health report measured
per-rule pass/fail counts instead of constants (spec EV-5 groundwork).

### WO-10 (P1) Simulate call + structured verdict reasons
Simulate/dry-run RPC running identical verdict logic, marked as
simulation in its proof (spec DC-9); every denial carries structured
rule IDs + "what would have to change" fields (DC-10).

### WO-11 (P1) Policy governance
Signed, versioned policy bundles; dual-control change path;
publication endpoint so judged agents can read current policy
(spec DC-18, DC-19, BM-6/BM-12).

### WO-12 (P1) Revocation service
Session/key/certificate revocation with a propagation bound
(default ≤ 60 s), behaviour-proven by test (spec DC-14, EV-4).

### WO-14 (P2) Boundary authenticators
SPIFFE/mTLS workload identity (AZ-3) and PGP/GPG administrator
authorization (AZ-4) plugged into the handshake as second-factor
framework (spec BM-9, §5).

### WO-13 (P2) Guardian attestation package
Signed, reproducible release builds with provenance published per
release (spec CP-19/CP-21, DC-17). Builds on the cargo-zigbuild
cross-build route recorded in the ledger.

### WO-15 (P2) Multi-tenancy
Tenant-scoped policy, keys, rate budgets, audit partitions, with
isolation behaviour-proven in tests (spec DC-15, DC-16, CP-14).
Status 2026-10-31: built, Wright-verified, gated PASS WITH
FINDINGS and merged as v0.14.0 (PR #78) — but the deploy was
ROLLED BACK at production proof (gate F6: the tenant budget
pre-empted Gatekeeper THROTTLE verdicts under burst, box E2E
PF-18). Production remained on v0.13.0. Status 2026-11-02:
COMPLETE — WO-15.1 shipped as v0.14.1 (PR #81) and deployed
the same night; production proof PF-18 PASS (100/15/0). See
the 2026-11-02 ledger entry.

### WO-15.1 (P1) Tenant-budget ordering fix (WO-15 completion)
Move the per-tenant budget check AFTER Gatekeeper evaluation:
the budget gates only requests the Gatekeeper allowed, so
THROTTLE verdicts are never converted to resource_exhausted
errors (gate F6 / GMSI-100). Acceptance: box-E2E PF-18 verdict
mix restored (excess = THROTTLE, other = 0) in Wright's
pre-merge wire proof AND on the box after deploy; WO-15's
tenant tests stay green. Then v0.14.0 (or the next patch
version) deploys with the standing attestation + certification
ceremony. Also carries WO-15 F4 if it falls out naturally
(bogus-session budget burn) — otherwise F4 stays fodder.
Status 2026-11-02: SHIPPED as v0.14.1 (PR #81, merged
b8d5d067) and deployed the same night; box-E2E PF-18 PASS
(allowed=100 throttled=15 other=0) in Wright's pre-merge
proof AND on the box after deploy; F4 proven closed
(bogus-session regression test in tree). The fix also
converted the tenant budget from a lifetime quota to a
per-window rate budget (gate F2 of the WO-15.1 gate).

### WO-16 (P2) Clustered verdicts + degraded modes
Multi-node verdict issuance per architecture v2 consensus levels;
declared fail-closed degraded modes (spec DC-1…DC-5).
Status: **v1 SHIPPED 2026-11-03 as v0.15.1** — the DC-4 declared
degraded modes + DC-5 entry/exit audit events + DC-2 issuing-node
slice (PR #84 v0.15.0 + PR #85 fix, gate PASS WITH FINDINGS —
guardian-mesh-wo16-2026-11-03). v0.15.0 was deployed and rolled back
the same night (its full-history startup chain check degraded the
daemon on the production audit archive; the fix scopes the startup
check to the live tail segment — GMSI-118). **WO-16 stays OPEN** for
the DC-1/DC-3 cluster slice (multi-node verdict issuance per
architecture v2 consensus levels — a phase-scale build, sequenced
with the cluster program, not a nightly slice).

### WO-17 (P2) Conformance suite + chaos drills
Spec-as-tests in CI: PF table, boundary rules, authorization
combinations, tenant isolation, tamper behaviour; kill-mid-verdict
chaos cases (spec RG-7, RG-8).
Status: **v1 SHIPPED 2026-11-04 as v0.16.0** — the named
conformance suite (13 `conformance_` tests: PF table per implemented
rule, payload/signature/timestamp boundaries, §5 authorization
matrix, DC-16 tenant isolation, EV-2 proof-tamper table) plus the
in-process RG-8 chaos slice (restart-fails-closed, corrupt-log
detection, revoked-session stop), a dedicated CI step
(`cargo test conformance_`), and docs/CONFORMANCE.md (PR #88, gate
PASS WITH FINDINGS — guardian-mesh-wo17-2026-11-04). Multi-node
chaos is NOT built (no cluster exists — WO-16 DC-1/DC-3 open);
CM-8 non-catalogued probes remain WO-27. **WO-17 stays OPEN** for
those extensions.

### WO-18 (P3) Deployment matrix
Sidecar form (DP-3), edge profile (DP-6), CLI (CC-4), MCP server
surface (CC-5) — one profile per run, in that order.
Status 2026-11-06: **profile 1 (DP-3 sidecar form) SHIPPED as
v0.17.0** — PR #91 merged 3dd6aeb9. The 2026-11-05 gate was
BLOCKED on the never-built image; the 2026-11-06 retry built
the shipped Dockerfile unmodified (podman on Wright's VM) and
behaviour-proved the container end to end: Health SERVING with
PF counters 18/18 and build identity 0.17.0@9bda0b22, signed
Evaluate ALLOW + proof VALID, restart on the same volume kept
the fingerprint/node_id and the pre-restart proof verifies
VALID, daemon uid 10001, no secret in the image env. Gate PASS
WITH FINDINGS (guardian-mesh-wo18-retry-2026-11-06): F1 PF-18
local-environmental (standing; PASS on the production box at
this deploy, 100/15/0); F2 base-image tags float (low,
standing); kubectl dry-run NOT RUN (no cluster context).
Production v0.17.0 live 2026-11-06: build 0.17.0@3dd6aeb9,
binary sha256 a2374b93... == installed == attested,
attestation VALID signer == pin dd2cf1a3..., self-cert
cert-20261107-000046 ACTIVE, box E2E 15/16 (sole miss the
standing stale Health-fields harness check), box dist asset
== merged build == Pages asset, site 302. RC soak to
2026-11-13. WO-18 stays OPEN; the next run takes profile 2
(DP-6 edge profile).


Status 2026-11-07: **profile 2 (DP-6 edge profile) SHIPPED as
v0.18.0** — PR #94 merged 6107c602. deploy/edge/ carries the
systemd form (MemoryMax=256M / CPUQuota=50% / TasksMax=64
ceilings, loopback bind default, hardening) and the compose
form (mem_limit 256m / cpus 0.5), an env example with the
handshake secret comment-only, and docs/EDGE.md. The honest
core: ceilings are enforced by systemd/the container runtime —
the daemon has NO ceiling setting in config.rs — and no
edge-to-core sync is built (BM-7 design). Gate PASS WITH
FINDINGS (guardian-mesh-wo18-edge-2026-11-07): offline verdict
operation behaviour-proven in a loopback-only network
namespace (Health SERVING, Evaluate ALLOW, proof VALID, all
egress unreachable); measured footprint RSS 5.8–10.2 MB, peak
10.6 MB (>24x headroom under the 256M ceiling); container
proof on the shipped image (fingerprint stable across a
same-volume re-run, pre-restart proof VALID). F3: ceiling
enforcement NOT RUN in the verifying sandbox (nested cgroup
controllers not delegated) — GMSI-122 filed. Production
v0.18.0 live 2026-11-07: build 0.18.0@6107c602, binary sha256
3083e08d... == installed == attested, attestation VALID
signer == pin dd2cf1a3..., self-cert cert-20261108-000047
ACTIVE, box E2E 15/16 (PF-18 PASS 100/15/0), box dist asset
== merged build == Pages asset, site 302. RC soak to
2026-11-14. WO-18 stays OPEN; the next run takes profile 3
(CC-4 CLI).

Status 2026-11-08: **profile 3 (CC-4 CLI) SHIPPED as v0.19.0**
— PR #97 merged f25cfd51c69af370b551faeb64b1d58d1653fe6b. The
`gm` operator CLI (guardian-meshd/src/bin/gm.rs, no new
dependencies) provides health / handshake / evaluate (real +
--simulate) / verify / audit over gRPC: JSON on stdout, exit
0 success / 1 refusal-or-invalid / 2 usage-transport-session
errors with stderr-only diagnostics, session file 0600 holding
the session key + signing seed as bearer secrets (never
printed), proof envelopes saved as hex JSON. Gate PASS WITH
FINDINGS (guardian-mesh-wo18-cli-2026-11-08): F1 (High, FIXED
in the Wright carry) the lane's gm did not compile — build.rs
generated server-only stubs; fixed with build_client(true) +
the sealed_envelope encode idiom; F2 (Low, open) evaluate
stdout does not name the proof file written; F3 base-image
tags float (low, standing). Production v0.19.0 live
2026-11-08: build 0.19.0@f25cfd51, binary sha256 e280e5c8...
== installed == attested, attestation VALID signer == pin
dd2cf1a3..., self-cert cert-20261109-000048 ACTIVE, box E2E
15/16 (PF-18 PASS 100/15/0), **gm itself proven against the
production daemon on the box** (health SERVING, handshake,
evaluate TOOL_CALL -> ALLOW, verify VALID; its audit read
reports the standing F4 production-history interleave — first
break at entry 557, the documented 2026-10-26/27 segment,
live tail clean by design since v0.15.1), box dist asset ==
merged build == Pages asset, site 302. RC soak to
2026-11-15. WO-18 stays OPEN; the next run takes profile 4
(CC-5 MCP server surface) — the last WO-18 profile.

## Part D — Work orders from the v3.1 amendment (2026-10-15)

Owner-directed the same day as v3.0: the product boundary charter
(spec §0.5), Doctrine 0 (only desired paths exist), complete
mediation (unguarded path = vulnerability), securing the guardian,
and the product-completeness set. Spec §§11–13 + map §9A.

### WO-30 (P1) Threat model of record
Author `specs/THREAT_MODEL.md` (SG-1): named adversaries, assets,
countermeasure mapping to spec requirement IDs. Maintained per
release thereafter; docs-only, Wright lane acceptable.

### WO-22 (P1) Secure by default
Production posture MUST refuse the built-in default handshake
secret (SG-4); add the posture doctor (config scan naming insecure
settings). Behaviour-prove: default secret + production posture =
refusal to start.

### WO-20 (P1) Complete-mediation core
Execution tokens bound to the sealed action hash + tool-side
checker (CM-2); credential escrow mode (CM-1); resource-side
identity lockdown hooks (CM-3).

### WO-27 (P2) Mediation conformance
Direct-access (skip-the-guardian) probe + non-catalogued
invocation suite as gate MUSTs (CM-8); extends WO-17.

### WO-21 (P2) Coverage + reconciliation
Coverage inventory + drift alarms (CM-6), receipt reconciliation
with bypass alarms (CM-5), coverage statement in certificates
(CM-7). After WO-6 (certificate schema).

### WO-23 (P2) External witnessing
Periodic anchoring of the audit chain head to an operator-external
witness, with verification (SG-5).

### WO-24 (P2) Payload data protection
Secret/PII detection in payloads, audit redaction by default,
exfiltration block rules (PC-1).

### WO-25 (P2) Tool/model supply chain
Tool manifest pinning + change detection; MODEL_LOAD signed
provenance verification (PC-2).

### WO-26 (P2) Admin RBAC + agent registry
Role model on the guardian's own surfaces (PC-6); agent
enrollment/owner/risk-tier lifecycle (PC-5).

### WO-28 (P3) Delegation attenuation
Subset-only delegated capability tokens, chain recorded in the
proof (PC-3).

### WO-29 (P3) Compliance exports + alerting
CP-catalogue auditor evidence packs, SIEM formats, OTel export
(PC-7); anomaly alerting hooks (PC-10).

### WO-31 (P2) Standards alignment upkeep
From the 2026-10-16 standards compliance review
(`specs/STANDARDS_COMPLIANCE_REVIEW.md`): add a terminology annex
to the revised specification adopting ISO/IEC 22989 terms (AI
agent, AI system, human oversight, verification vs validation,
trustworthiness characteristics) with Guardian Mesh's product
terms defined against them; add 22989 + the SC 42 family to the
§3 standards spine. Keep the compliance review refreshed per
release (RG-3). Docs-only; Wright lane acceptable.

### Compliance development plan items (2026-10-16)
From `specs/COMPLIANCE_DEVELOPMENT_PLAN.md` — build the missing
compliances as evidence-producing machinery, never as prose:

### WO-32 (P1) AI risk register + process
`specs/RISK_REGISTER.md` per ISO/IEC 23894: risks scored, owned,
tied to THREAT_MODEL entries and their mitigations; reviewed at
every release gate run, review recorded in the gate verdict.
After WO-30. Docs-only; Wright lane acceptable.

### WO-33 (P2) NIST AI RMF profile
Profile doc mapping Govern/Map/Measure/Manage to real Guardian
Mesh mechanisms only (gate, risk register, policy governance);
zero aspirational mappings. After WO-32. Docs-only.

### WO-35 (P2) Validated-module crypto path (FIPS 140-3)
Cryptographic provider boundary in the daemon + PKCS#11 provider
so keys can live in an HSM/KMS; documented validated-module
deployment profile (validation is the module vendor's, cited,
never implied ours). Acceptance: daemon runs end-to-end with
signing keys in an external PKCS#11 token (software token in
test). After WO-3. Laptop lane.

### WO-36 (P3) EU AI Act deployer pack
Customer-facing mapping from the WO-29 evidence export to
deployer obligations (Art. 9/12/14/15), generated from a real
export — framed "supports deployer obligations", never
"compliant product". After WO-29.

Note on WO-29: the compliance plan sets its acceptance bar —
every CP-01…CP-24 checkpoint emits a machine-readable result per
deployment (PASS/FAIL/N/A/NOT RUN + evidence pointer), exportable
mapped to NIST CSF 2.0 + SP 800-53 + ISO 27001 Annex A themes.

### WO-37 (P1) Touchpoint wiring program (dogfood coverage)
Owner's directive 2026-10-16: Guardian Mesh connected at every
touchpoint. The map of record is the goal file
`touchpoint-wiring-map.md` (T1 release gate, T2 publishing
pipeline, T3 Conduit, T4 fleet repos, T5 nightly lane, T6
oc-bridge, T7 MyMilo loop, T8 GM's own surfaces). Wire one
touchpoint per run in map order: verdict before the action, proof
after it, coverage entry updated. A touchpoint counts as wired
only when its proof verifies offline (CM-6/CM-7 discipline
applied to our own fleet first).

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

The founding set above (GMSI-1…5) dates to 2026-10-14. GMSI-6…47 were
filed by the WO-1/WO-2 gate runs and the release gate's 2026-10-15
fleet re-gate (13 product packs: RA/devinfo, codetopo, Conduit
filings, Conduit DCR, dogear, FareSutra, KalaBodha, LetsAskIt,
Linktary, MyKey, site tier, thinkwithfinance, Verdict). Repeats are
consolidated into one canonical item with every filing named;
onsmartgrid and the Conduit Router re-run filed none. These inputs
queue behind the Part A work orders: they land as proof fields in
WO-6's certificate schema and as standing probe sets in the gate,
and none becomes a gate MUST until behaviour-proven here.

- **GMSI-6 — The gate scanner must detect inline Rust tests.**
  WO-1 and WO-2 both drew a false scanner BLOCKED ("no test suite")
  on a repo whose tests are Rust `#[test]` functions. Gate tooling
  input, filed from both runs: the scanner learns inline-test
  detection so the class cannot false-block a third release.
- **GMSI-7 — Evidence packs bind measured firewall outcomes.**
  WO-6 certificates carry the daemon's measured per-rule PF
  pass/fail counts, never constants (WO-2 gate finding F2). The
  measurement itself is WO-19 (Health counters + session eviction).
- **GMSI-8 — Transport floor proof.** Filed seven times in one day
  (aimlds M1, Conduit filings F-R1, codetopo F-R1, FareSutra,
  LetsAskIt N1, KalaBodha, thinkwithfinance M3): GM must prove, per
  host and from outside, that plain HTTP refuses or redirects, HSTS
  is served, the TLS floor holds, and a baseline header set exists —
  on every origin, workers.dev and second origins included. Header
  inventories read off HTTPS responses alone missed this class
  repeatedly; the probe set includes an http:// fetch of every host.
- **GMSI-9 — Deployed == gated, continuously.** (aimlds worker-drift
  sentinel + source-of-record census; Conduit filings currency
  markers; dogear cross-surface version census.) Deployed artifacts
  are hash/marker-compared against the repo of record on a cadence;
  where hashes are unavailable from outside, behaviour markers (a
  response only current code produces) are the standing check.
  Every deployment maps to a repo + commit; unmapped deployments
  are findings by construction.
- **GMSI-10 — A claimed safeguard must be proven armed.** (aimlds
  gate-activation probe; Linktary provisioned-safeguard sentinel.)
  Every safeguard whose code says "activates when configured" gets
  a production probe proving it is ON — key/discovery endpoints
  fetched on a cadence, an empty published key set on a product
  claiming signed artifacts is an alert. Code review cannot see
  config; only the probe can.
- **GMSI-11 — Public-claims / copy-vs-state differ.** (KalaBodha
  public-claims sentinel; Conduit filings cross-surface copy;
  codetopo copy-vs-code drift incl. executing the published
  quickstart against the current CLI; site-tier claims-vs-state;
  thinkwithfinance claims-vs-record; dogear claims-vs-config.)
  Load-bearing public claims — what is live, who the processor is,
  licence, price, feature availability, "no tracking" — are diffed
  against the live surface, the served bytes, the zone config, and
  the repo of record at every gate and on a cadence.
- **GMSI-12 — Release-record completeness.** (codetopo C-P1;
  thinkwithfinance M4; Linktary release-log monitor.) GM diffs every
  product's public release record against the gate register: an
  entry must carry changes + testing record + gate verdict + GM
  verifier record, and the log's freshness is monitored against
  deploys. A release whose notes carry no verdict word is
  detectable mechanically — C-P1 escaped because nobody diffed.
- **GMSI-13 — Payment-state truth.** (codetopo built-but-not-live;
  LetsAskIt payment-mode proof; site-tier checkout-liveness.) GM
  distinguishes *code exists* / *deployed* / *purchasable* for every
  payment surface, proves a rail's mode (test vs live) from the
  deployed surface + config-in-VC, and flags present-tense sales
  copy that outruns it. A checkout configured with a zero or
  placeholder vendor id, or sitting on a closed rail, is detectable
  from served bytes alone and pages the owner.
- **GMSI-14 — Rate-limit proof that survives reality.** (Conduit
  filings egress rotation; Verdict F1 eventual consistency.) Per-IP
  caps are unprovable from a rotating egress: GM needs a
  fixed-egress probe lane (or a counter-state test hook) so cap
  proofs are live, not code-read — and must state and prove the
  enforcement bound a counter actually delivers under eventual
  consistency.
- **GMSI-15 — Soft-404, catch-all, and well-known correctness.**
  (Conduit filings F-R2; dogear catch-all detector; LetsAskIt
  well-known.) Unknown paths and the /.well-known/* space are
  probed against the product's declared documents, never assumed:
  a 200 + homepage (or HTML shell) on an unknown path hides missing
  privacy/changelog/security pages behind green statuses.
- **GMSI-16 — Auth-surface proof runs on the deployed server.**
  (Conduit DCR 1–3, the 2026-10-15 escape class.) Validation rules
  on registration/auth endpoints are behaviour-proven on the
  DEPLOYED server at every auth-surface release — fragment,
  userinfo, non-loopback http, and loopback redirect variants
  probed with requests + responses filed; the served consent
  screen's content is proven (redirect hostname + unverified-client
  warning present); token-binding negative probes (code reuse,
  wrong PKCE verifier, mismatched redirect_uri) must all fail live
  before an OAuth release may call itself tested. The 2026-10-14
  gate shipped a rate cap on this endpoint without ever probing its
  validation rules.
- **GMSI-17 — Silent-failure sentinel.** (dogear F1.) Surfaces whose
  core act depends on a runtime capability (browser speech voices
  is the filed case) are probed from a capability-less vantage, and
  a user-visible fallback message is required. The defect was
  invisible to every code-level check.
- **GMSI-18 — Deploy attestation coverage.** (dogear.) Every
  production deployment id maps to a ledger certificate; an
  unattested production deployment is a mechanical management
  signal, not a judgment call.
- **GMSI-19 — Exposure proofs, probed from the internet side.**
  (FareSutra H1/H2.) GM enumerates unauthenticated WRITE endpoints
  and "private to this deployment" data stores on public URLs, and
  flags any public GET returning accumulated operator/user activity
  (search history, watches, ledgers), classifying what it discloses.
  The single-tenant assumption is probed, never read off the code
  comment that asserts it.
- **GMSI-20 — Amplification accounting.** (FareSutra.) Features that
  convert anonymous reads into recurring operator spend
  (auto-watch → daily re-search is the filed shape) carry a cost
  proof: entries minted per anonymous request × recheck cost ×
  retention, plus cap-eviction effects on legitimate entries.
- **GMSI-21 — One product, one verdict.** (FareSutra H3.) When two
  engines emit judgments, GM diffs them on identical inputs in the
  served response; a contradiction (BUY NOW vs WAIT on the same
  item) is a finding.
- **GMSI-22 — Fallback truth per route.** (FareSutra M2.) A
  fixture/demo fallback is verified against the REQUESTED route,
  not merely labelled in the response — an honest warning over the
  wrong city's deals is still a wrong answer.
- **GMSI-23 — Artifact-link liveness.** (FareSutra M6.) Links
  presented as verifiable proof (certificates) are re-fetched after
  an isolate-recycle interval; in-memory registries fail this by
  construction.
- **GMSI-24 — Audit-chain independent verification.** (KalaBodha.)
  A hash-chained audit log is re-computed independently from its
  public endpoint as a standing GM proof for any product claiming
  tamper-evidence (done by hand there for entries 1–4). For
  Guardian Mesh itself this lands with WO-4's audit read path.
- **GMSI-25 — Public-metadata exposure census.** (KalaBodha
  Medium 4 class.) For transparency endpoints, what an
  unauthenticated seq/id walk actually discloses per tenant is
  enumerated and measured, so "public by design" is a measured
  quantity, not a posture.
- **GMSI-26 — Fingerprint-binding probe.** (KalaBodha; extends
  GMSI-2.) For envelope stores, a probe stores under a mismatched
  registered fingerprint and records accept/reject; GM holds the
  standing probe-key pattern for it (the probe needs an
  operator-minted key).
- **GMSI-27 — Returning-user data rights.** (LetsAskIt F4/N2, an
  escape that survived in-session-only testing twice.) GM's probe
  identity returns in a NEW session with persisted state
  (cookie/localStorage) and re-tests read/delete; deletion proven
  in-session is not deletion proven.
- **GMSI-28 — Origin parity.** (LetsAskIt.) Any origin serving the
  same worker is exposure: GM inventories every origin and probes
  each at parity; the parity itself needs a standing proof.
- **GMSI-29 — Subprocessor differ.** (Linktary.) Third-party origins
  extracted from served pages (fonts/CDN/analytics) are diffed
  against the privacy page's declared subprocessor list; drift is
  an alert.
- **GMSI-30 — SSRF probe set, reusable.** (Linktary spelling
  battery; Verdict SSRF class.) For any feature fetching a
  user-supplied URL: integer/octal/hex IPv4, IPv6 tunnelled forms,
  metadata hosts, and private ranges must all be refused before
  fetch — proven as a battery, not spot-checked.
- **GMSI-31 — Data-minimisation proofs.** (Verdict 2 + 6.) A
  share/summary token must provably contain no source content, and
  a channel reply (the email channel is the filed case) must
  contain no raw source content beyond the derived verdict
  summary — proven by rendering inspection, not by code reading.
- **GMSI-32 — Signed-token tamper proof.** (Verdict 4; extends
  GMSI-1.) A signed verdict/certificate token must fail
  verification after ANY payload mutation — proven by forgery
  probes (mutated payload + stale signature reads NOT VALID, never
  partially verified).
- **GMSI-33 — Connector-bound parity.** (Verdict 5.) A connector
  endpoint (MCP is the filed case) enforces the same free-tier /
  rate bound as the web surface it mirrors; the bound is proven on
  the connector, not inferred from shared code.
- **GMSI-34 — Encrypted-file tamper battery.** (MyKey, passed 9/9 by
  hand there.) Nine mutations — bitflip per blob class, cross-entry
  blob swap, header/KDF downgrade, version downgrade, truncation —
  all must reject. GM runs this battery against any encrypted-file
  product and diffs the outcomes.
- **GMSI-35 — Dependency-ceiling detector.** (MyKey M1.) Auditors
  report vulnerable versions; nobody flags a pin whose upper bound
  excludes *every* patched release, which makes the vuln
  unfixable-by-construction. GM diffs pin ranges against
  fix-version sets.
- **GMSI-36 — Version-label integrity.** (MyKey F7; Linktary
  version-coherence.) One version string names exactly one code
  state across tag, main, and shipped artifacts; /health vs
  service-descriptor vs package/tag coherence is checked per
  product with a drift alarm.
- **GMSI-37 — Claim-vs-binary permission diff.** (MyKey.) A
  capability claim ("makes no network calls") is diffed against the
  shipped binary's permission manifest. Filed as PROVEN aligned
  there — keep the check; it is cheap and decisive.
- **GMSI-38 — Bootstrap-trust asymmetry.** (MyKey F9.) When two
  import paths protect the same asset, their fresh-device trust
  requirements are diffed; the weaker one is a finding even when
  each is defensible alone.
- **GMSI-39 — Download-chain pinning.** (MyKey F4.) Binaries and
  their checksums served from one mutable source are a single point
  of compromise: GM requires at least one out-of-band pinned value
  per shipped artifact and flags branch-tip download URLs.
- **GMSI-40 — Advertised-endpoint liveness.** (site-tier DNS
  sentinel.) Hosts/paths advertised in well-known / llms.txt /
  discovery docs are continuously resolved + probed; a dead
  advertised API host or an HTML-serving keys URL is mechanically
  detectable drift.
- **GMSI-41 — Policy-behind-form census.** (site-tier.) Live POST
  routes are enumerated fleet-wide and each form-hosting page is
  checked for a linked privacy policy; three of five properties in
  the filed run collected PII with no policy.
- **GMSI-42 — Attribution-line verifier.** (site-tier.) The footer
  attribution line is fetched on every public surface and its link
  targets + referral code verified against the standing rule (it
  was absent on the flagship and stripped on AxiomCode in the
  filed run).
- **GMSI-43 — Integrity-enrolment census.** (site-tier.) Every live
  customer host appears in the site-integrity baselines; an
  unenrolled live host is the gap this census catches mechanically.
- **GMSI-44 — Liveness beyond reachability.** (thinkwithfinance
  M1/M2.) A publisher/scheduled job whose last-run age exceeds ~2×
  its cadence alerts, and N consecutive scheduled-run failures
  alert — the filed site was HTTP-200 and dead for 5 days, its
  filler failing 7 straight days unnoticed. Reachability
  monitoring is structurally blind to this class.
- **GMSI-45 — Doctrine-source monitor.** (aimlds H1.) A scheduled
  sample of served output asserts the declared provenance/source
  equals the doctrine registry's production source; a silent
  fallback to a development-only source is a finding, never a
  default.
- **GMSI-46 — Paid-surface probe.** (aimlds.) An unauthenticated
  request to every endpoint the product copy calls paid/gated
  expects 401 — run at every gate and weekly in the sweep.
- **GMSI-47 — Capability-token storage.** (codetopo F-R3.) Bearer
  tokens stored as lookup keys are hashed at rest by default; GM's
  store inspection flags any table whose key column is itself a
  live capability.

GMSI-48…52 were filed by the release gate's 2026-10-17 independent
re-gate of Verdict (pack: release-gate-runs/verdict-regate-2026-10-17;
verdict BLOCKED on F-R1, with the v1.2.2 fix-batch addendum the same
evening). They queue behind the Part A work orders exactly as
GMSI-6…47 do, and none becomes a gate MUST until behaviour-proven
here.

- **GMSI-48 — Served-script parse proof.** (Verdict re-gate F-R1;
  the verdict.md item 7 there.) GM must be able to prove a served
  page's scripts PARSE — extract every script from every served
  page and parse it byte-exact; a green API must never again
  certify a dead page. (Third fleet occurrence of the dead-page
  class; also Gate 1's served-script parse + deployed==tree proof.)
- **GMSI-49 — SSRF literal-spelling + resolution posture.** (Verdict
  re-gate item 8.) GM's SSRF proof must span the full literal
  spelling space (IPv6 loopback/ULA/link-local/v4-mapped in both
  spellings, bracketed forms) and must state each product's
  resolution-based (DNS→private) posture explicitly:
  guard-covered, platform-covered, or uncovered.
- **GMSI-50 — Judgment differential battery.** (Verdict re-gate
  item 9.) For verdict products, GM must carry a JUDGMENT
  DIFFERENTIAL battery: direction pairs (payment vs prize, demand
  vs receipt), brand placement (subdomain label / hyphen label /
  subdomain-of-brand / path / punycode), cross-surface consistency,
  and calibration bounds (single weak flag ceiling;
  canonical-script floor). The fixed owner-case regression set
  from the Verdict v1.2.1 escape is this battery's first case set.
- **GMSI-51 — Concurrent fresh-identity rate proof.** (Verdict
  re-gate item 10.) GM must prove a rate bound from a FRESH
  identity under CONCURRENCY, not only sequentially from a warm
  identity.
- **GMSI-52 — Pattern-coverage canaries.** (Verdict re-gate
  item 11.) Canonical scam scripts (ransom note, advance-fee,
  prize lure) in their most common phrasings, including
  apostrophe/contraction variants — a one-word spelling variant
  must not flip a verdict class.

GMSI-54…67 were filed by the release gate's 2026-10-19 billing
sweep and adjudication runs (packs: release-gate-runs/
linktary-billing-2026-10-19, mykey-billing-2026-10-19,
sovereign-billing-2026-10-19, twf-pro-2026-10-19,
codetopo-2026-10-19, codetopo-2026-10-19-delta-email, and
verdict-v130-adjudication-2026-10-19). GMSI-53 was filed by the
WO-5 gate the same day and is recorded in that ledger entry.
They queue behind the Part A work orders exactly as GMSI-6…52
do, and none becomes a gate MUST until behaviour-proven here.

- **GMSI-54 — Money-path config-layer proof.** (Linktary billing
  gate; confirmed by the TWF Pro gate and the Sovereign Core
  inventory MUST.) Money-path operability is proven at the
  CONFIG layer, not inferred from unauthenticated probes: every
  money batch's probe set includes (a) a secret-name inventory
  of the production worker (names only) against the code's
  required/accepted secret list, and (b) an authenticated
  negative-shape probe (bogus session → provider-shaped error,
  never a config 503). An armed-but-unprovisioned code path is
  a defect class of its own.
- **GMSI-55 — Duplicate-delivery / replay-safety probe.**
  (MyKey billing gate.) Every webhook consumer carries a spec'd
  duplicate-delivery probe: the same verified event delivered
  twice must change state at most once.
- **GMSI-56 — Test/live credential separation invariant.**
  (Sovereign Core billing gate, CRITICAL F-SC-1.) A production
  verifier's accepted-secret set is exactly {its own live
  secret}; test proofs run on separate test deployments, never
  production. GM must be able to prove that separation.
- **GMSI-57 — Cross-product mint probe.** (Sovereign Core
  billing gate.) Issuance handlers must bind the event to the
  product's own price/product (and to completed payment) before
  minting; a spec'd cross-product mint probe belongs in the
  money-batch battery wherever one payment account serves many
  products.
- **GMSI-58 — Buy-entry smoke first.** (TWF Pro billing gate.)
  The Subscribe/checkout route must reach the provider; this
  smoke runs FIRST in every money batch — a dead front door
  makes the deeper battery moot.
- **GMSI-59 — Ack-on-error check.** (TWF Pro billing gate.)
  Every webhook handler is probed so a post-signature failure
  must not ack 2xx.
- **GMSI-60 — Claim-prefill escaped-reflection proof.**
  (codetopo gate.) Any buyer-facing form rendering a
  redirect-carried value must prove escaped-only reflection by
  a live probe, not only by unit test.
- **GMSI-61 — Stale-timestamp webhook delivery probe.**
  (codetopo gate.) A stale-timestamp delivery probe (outside
  the bridge's freshness tolerance) belongs in the standard
  webhook battery for every billing bridge.
- **GMSI-62 — Concurrent-distinct-events send-once probe.**
  (codetopo delta-email gate.) "Sent exactly once" proofs in
  the fleet are sequential; GM should issue a
  concurrent-distinct-events probe for any send-once side
  channel, so the race window is measured, not reasoned about.
- **GMSI-63 — Config-family lint.** (codetopo delta-email
  gate.) Half-configured integration families must fail loudly
  at startup; the residual shape (encryption-off plus
  credentials present) is a mechanical config-lint case for
  every env-configured integration.
- **GMSI-64 — Assertion-message hygiene.** (codetopo
  delta-email gate.) No format-interpolation of
  credential-bearing content in test failure messages, fixtures
  included — a greppable scanner class.
- **GMSI-65 — Stable-egress vantage for rate-bound probes.**
  (Verdict v1.3.0 adjudication.) Rate-bound probes require a
  stable-egress vantage; spec a fixed-egress probe node so
  per-IP counters can be falsified honestly.
- **GMSI-66 — Fleet-controlled redirector.** (Verdict v1.3.0
  adjudication.) A fleet-controlled redirector is recurring
  gate infrastructure (the SRF-REDIRECT battery), not a
  per-product improvisation.
- **GMSI-67 — Health-endpoint methods as declared surface.**
  (Verdict v1.3.0 adjudication, F-V130-1.) Declared-method
  inventories treat health endpoints' methods as declared
  surface in every product contract.
- **GMSI-68 — Mixed-traffic chain proof.** (WO-6 gate, this
  run.) Any work order that adds a new audit-log writer or
  event type must prove the chain under MIXED traffic (existing
  writers + the new writer interleaved on one daemon, verified
  through ReadAuditLog). Single-writer chain state is an
  invariant: two chain-writer instances over one log is a
  defect class of its own (WO-6 F4, fixed in round 2).
- **GMSI-69 — Chain integrity under concurrency.** (WO-6
  post-deploy production proof, this run.) The hash chain must
  verify after CONCURRENT verdict traffic: one 115-request
  burst against v0.8.0 produced 32 consecutive duplicate chain
  hashes and a verification break at position 2, because
  seal() reads and updates the last chain hash under separate
  short locks and concurrent writers interleave on the same
  predecessor. The chain append must be atomic per entry
  (the predecessor read, digest, persist, and predecessor
  update as one critical section) for every writer, verdicts
  and certificate events alike. Production history carries
  burst-race breaks from position 557 (first sealed by
  v0.7.0's THROTTLE bursts). Filed as WO-6.1 (P1, next run,
  ahead of WO-7); a concurrent-burst chain proof is its
  acceptance test.
- **GMSI-70 — Parity differential for fact-products.** (codetopo
  0.6.0 gate, 2026-10-20.) Playbook §7's consistency leg,
  generalised: for products whose output is measurements rather
  than verdicts, Guardian Mesh must be able to prove a standing
  cross-surface equality corpus — the same input presented to
  every surface the product exposes (CLI / HTTP / MCP), with
  byte-equal structured answers — as the analogue of the
  judgment-differential corpus.
- **GMSI-71 — Test-context resolution before a secret can
  block.** (codetopo 0.6.0 gate, 2026-10-20; the gate scanner's
  sixth context miss of this class.) A certification input that
  reports a secret in code must state whether the hit's module
  context was resolved (e.g. inside a `#[cfg(test)]` fixture
  module) before the hit can block issuance; a pattern hit whose
  context was never read is a lead, not a finding.
- **GMSI-72 — Vulnerability-data freshness.** (codetopo 0.6.0
  gate, 2026-10-20.) Both RUSTSEC advisories in that gate
  postdated the product's previous gate by days. Dependency-
  vulnerability data presented at certification must be pulled
  fresh at that gate — never inherited from a prior run's pack —
  and the evidence must state the pull date.
- **GMSI-73 — Owed-probe obligations ride the certificate
  record.** (codetopo 0.6.0 gate, 2026-10-20.) Where a gate
  defers attacker-view probes because the surface is not yet
  deployed, the deferral must be carried as a named owed-probe
  obligation (the routes and the probe set) attached to the
  release record, discharged by a delta gate at deploy — never
  as an unowned NOT RUN line.
- **GMSI-74 — Concurrency proofs must be synchronised or
  graded.** (WO-6.1 gate, 2026-10-20.) An un-synchronized small
  burst passes probabilistically on racy code: Wright's
  16-thread × 8 in-process repro against the pre-fix vault
  failed once (126/128 entries persisted) and passed once
  against the same binary, while the barrier-synchronized
  32-thread version failed deterministically. Any concurrency
  acceptance proof (chain integrity, send-once, rate limits)
  must release its writers simultaneously (barrier or
  equivalent) or be run N times with every run reported — one
  green run of an un-synchronized burst is not evidence.
- **GMSI-75 — Test counts must name their invocation root.**
  (WO-7 gate, 2026-10-21.) A suite run from a crate subdirectory
  and from the workspace root can legitimately differ (the WO-7
  lane ran `cargo test` inside `guardian-meshd/` and got 79 lib
  tests; the workspace-root invocation — CI's, and Wright's
  verification — runs 80). A release record's counts are evidence
  only when they name the invocation; the canonical invocation
  is the one CI uses (workspace root). A lane reporting counts
  from any other root — and especially "correcting" previously
  verified counts from one — is a finding, not an update. Third
  lane count slip of the class (WO-6, WO-6.1 F1, WO-7 F1).
- **GMSI-76 — Pack drift watch.** (DogEar v1.2.0 gate,
  2026-10-22.) Content served from an operator bucket must be
  provably equal to its pinned manifest on a schedule, not only
  at upload: Guardian Mesh must be able to prove per-file hash
  equality between the served bucket objects and the pin of
  record (the pack-hosting route class).
- **GMSI-77 — Price-totality probe.** (DogEar v1.2.0 gate,
  2026-10-22.) A price change must be provably total across
  served bytes: Guardian Mesh must be able to prove that every
  served page's price text equals the configuration constant
  of record, with zero occurrences of a superseded price.
- **GMSI-78 — Seam-activation watch.** (DogEar v1.2.0 gate,
  2026-10-22.) A verification seam that honestly answers
  not-verified while a credential is absent must alert if it
  still answers not-verified after that credential is
  provisioned: Guardian Mesh must be able to prove a seam's
  activation state against its provisioning state.
- **GMSI-79 — Pairing integrity.** (DogEar v1.2.0 gate,
  2026-10-22.) Where a native shell depends on a served
  companion asset, Guardian Mesh must be able to prove the
  served asset's bytes equal the gated bytes of record — the
  pair staying in sync is a standing proof, not a deploy-time
  check.
- **GMSI-80 — Certified-shell identity.** (DogEar v1.4.0
  beta.4 gate, 2026-10-22.) A client-side cache name that
  nothing mechanically bumps is a silent stale-shell channel:
  Guardian Mesh must be able to prove the shell a client runs
  is the shell that was certified (served cache string vs
  certified bundle) as a standing probe, not a release-time
  grep.
- **GMSI-81 — Capability-tier proof.** (DogEar v1.4.0 beta.4
  gate, 2026-10-22.) A capability offered at a tier must be
  provable loadable/runnable on a reference device class for
  that tier: Guardian Mesh must carry the tier matrix as a
  re-runnable proof — offered implies proven, never merely
  listed.
- **GMSI-82 — Unbuilt test infrastructure is not a
  capability.** (WO-8 gate, 2026-10-22.) A fuzz (or any
  test-harness) work order closes only with a build + brief-run
  proof of the harness itself on its home surface, executed by
  the verifying lane: the WO-8 lane's package could not build in
  three independent ways (missing cargo-fuzz package metadata,
  an undeclared crate dependency, a missing trait import), its
  nightly workflow invoked cargo-fuzz from a directory where it
  cannot run, and its proof target's input layout made the real
  verification path unreachable — while reporting the targets as
  delivered. A lane's claim that targets exist is not evidence
  they compile or run.
- **GMSI-83 — A published release-status claim must name
  its status artifact.** (WO-9 gate, 2026-10-23.) The
  release log's per-release status (Released vs Release
  candidate) was inferred from CHANGELOG narrative and was
  wrong for four releases (v0.8.0–v0.8.3 marked "Released"
  while still RELEASE CANDIDATES in soak); the status of
  record lived in the RC register. Guardian Mesh
  certificates and public status surfaces must bind every
  lifecycle/status field to the artifact that is its
  source of truth (register/ledger), name that artifact
  in the record, and treat a status published without a
  named source as a finding — the GMSI-2 discipline (the
  copy presented, not the copy at mint) applied to status
  claims.
- **GMSI-84 — A fix outside the build path is a silent
  no-op ship.** (DogEar v1.2.0 beta.5 gate, 2026-10-24.) A fix
  that lands outside the path the build actually compiles was
  exercised in review and then shipped as bytes that never
  contained it (case F-B5-1). Guardian Mesh must be able to
  prove "the bytes CI built contain the fix the exercise
  exercised" — path + hash attestation of the named fix
  files against the exercise record — as a standing probe.
  A fix claim without a build-path attestation is a finding.
- **GMSI-85 — State divergence after restore must be
  provable.** (DogEar v1.1.0 final gate, 2026-10-24.) After a
  forced process death + restore, the restored surface's
  page / core / session state diverged silently (case
  F-B6-1, carried as an accepted RC risk). Guardian Mesh must
  be able to prove page/core/session agreement after a
  death + restore cycle — or catch the divergence
  mechanically and name the disagreeing layer — as a
  standing probe. A restore that merely resumes is not
  evidence the restored state agrees.
- **GMSI-86 — A scanner candidate's context labels must be
  proven against the source before it can block.** (codetopo
  v0.7.0 gate, 2026-10-25.) The release-gate scanner reported
  a Rust `#[test]` fixture plaintext as a secret candidate
  labelled `in_test: false` and blocked on it — the GMSI-6
  family on a new leg: test-suite detection was taught, but
  secret-candidate context labelling was not. Guardian Mesh
  must be able to prove a scanner's candidate labels
  (in-test / in-fixture / in-example) against the actual
  source context before a candidate blocks a gate; a label
  asserted without a source read is a finding.
- **GMSI-87 — A privacy-doc check must state its scope and
  accept the published policy location.** (codetopo v0.7.0
  gate, 2026-10-25.) The scanner's privacy-policy check
  passes/fails on repo files only, without stating that
  scope, and accepts no evidence of a policy published at a
  site route or a README section — so its verdict reflects
  the filing cabinet, not the product. Guardian Mesh
  certificates must bind a privacy-evidence claim to its
  scope (repo files | published location) and to the
  location checked, and treat an unscoped PASS/FAIL as a
  finding.
- **GMSI-88 — A selling surface's legal pages are a live,
  pre-sale proof.** (Sanity Check legal-pages gate,
  2026-10-25.) That product passed its 2026-10-23 gate with
  no /privacy or /terms pages at all; the gap was caught
  post-release by the daily asset-compliance check. Any
  surface that sells (checkout, licence sale, subscription)
  must present live /privacy and /terms naming the legal
  entity in the body BEFORE first sale — proven on the live
  surface, never from source files. Guardian Mesh must be
  able to issue that proof per selling surface; the gate
  catches it pre-release, compliance only confirms it
  post-release.
- **GMSI-89 — Generated-artifact completeness.** (WO-10
  gate, 2026-10-25.) When a service definition changes,
  EVERY generated artifact must be diffed against it —
  message types AND the client stub — and the proof is a
  clean-tree build (`npm ci` from nothing), never the
  builder's incremental tree. Founding case: WO-10's lane
  hand-updated the message file but not the client file —
  the new RPC was missing from the client and, the new
  method sitting at service index 1, seven existing client
  method indices silently pointed at the wrong RPCs —
  while the lane reported its build green (Wright's clean
  build failed TS2339). Guardian Mesh must be able to
  prove a shipped client stub's method table equals the
  service definition of record.
- **GMSI-90 — A paid deliverable's rendering is part of
  the product.** (Sanity Check report-formats gate,
  2026-10-26.) That gate's flagship deliverable — the
  customer report — had its code paths checked while the
  rendered artifact itself, in every offered format, went
  ungenerated and unread pre-release; the gap was caught
  by the Director reading a customer report, not by any
  automated check. Guardian Mesh certificates must be
  able to bind a deliverable-rendering claim: the flagship
  artifact itself, generated in EVERY format the surface
  offers and read back, with the formats enumerated in
  the evidence — a code-path PASS without the artifact
  read-back is a finding, not a proof.

- **GMSI-91 — A generated file under @ts-nocheck
  defeats the type checker's completeness proof.**
  (Guardian Mesh WO-11 gate, 2026-10-26.) The lane's
  hand-updated generated TS message file carried the
  seven new policy message INTERFACES and the three
  new service methods but NO protobuf-ts MessageType
  classes for them, and AuditProof's MessageType
  lacked its new field — yet the WebUI build and lint
  were green, because the file is @ts-nocheck and
  Rollup treats the undefined class identifiers as
  external globals; the shipped bundle would have
  thrown ReferenceError at module import, and TS
  wire clients silently dropped the new proof field
  on decode. Client-stub completeness must be proven
  BY EXECUTION — import the built module, or drive
  every method of the table — never by a green build
  alone. This is GMSI-89's class, second occurrence.

- **GMSI-92 — Revocation-effect proofs must cover
  the negative space.** (Guardian Mesh WO-12 gate,
  2026-10-27.) A revocation is proven in three
  separate legs: EFFECT — every capability the
  revoked credential had is re-attempted and
  refused (a revoked session's Evaluate denied; a
  revoked key's Handshake refused); NON-EFFECT — an
  unrelated credential is shown still working
  (revocation is surgical, not a outage); and
  DURABILITY — the revocation is shown surviving a
  restart from its persisted record. Any one leg
  alone is not a revocation proof. Founding case:
  the WO-12 wire proof (36/36 through the shipped
  TS client) ran all three legs for sessions and
  keys, and effect + durability for certificates.

- **GMSI-93 — A lane build counts as BUILT only when
  the full test suite compiles and passes from the
  workspace root.** (Guardian Mesh WO-14 gate,
  2026-10-28.) The lane's commit did not compile its
  bin test suite (81 errors: a dropped import used by
  40 test sites; 41 pre-existing initializers never
  updated for the new proto fields), all 16 of its
  new unit tests failed, and its WebUI caller did not
  compile — while its result file reported the work
  order complete. `cargo test` from the workspace
  root (not `cargo build`, not `--lib`) is the
  minimum lane evidence; a commit whose tests do not
  compile or pass is reported NOT BUILT with the
  failing output attached. The work-order checklist
  (UI surface, release-log entry, README/CHANGELOG
  accuracy against the shipped proto) is part of
  "built", and lane result files stay untracked.

- **GMSI-94 — Hand-rolled calendar conversions are
  a defect class: validity-window code must
  round-trip known epoch vectors in both
  directions.** (Guardian Mesh WO-14 gate,
  2026-10-28.) The shipped civil-to-unix conversion
  was ≈93 days off for 2023-11-14; the unit tests
  passed against themselves because the test encoder
  shared the same wrong math's inverse image. Any
  date conversion feeding a security decision
  (certificate validity, token expiry, audit
  timestamps) carries at least one externally-known
  epoch vector per code path, asserted in both
  directions (encode and decode).

- **GMSI-95 — Authenticator proofs separate effect,
  non-target survival, and refusal naming.**
  (Guardian Mesh WO-14 gate, 2026-10-28.) A
  second-factor mechanism is proven in three legs:
  EFFECT — the attested/enrolled path works end to
  end (attested session evaluates; enrolled admin's
  change applies); NON-TARGET SURVIVAL — principals
  and sessions outside the factor behave exactly as
  before it existed; REFUSAL NAMING — every refusal
  states the missing or invalid confirmation
  (BM-11). A happy-path-only proof does not evidence
  a boundary mechanism. This mirrors GMSI-92's
  three-leg rule for revocations.

- **GMSI-96 — A shipped script is evidence only after
  its author lane has executed it end to end.**
  (Guardian Mesh WO-13 gate, 2026-10-29.) A lane's
  deliverable script or tool is NOT RUN until the lane
  itself has run it once, successfully, on the record;
  source that merely reads correctly is a claim, not
  evidence. (Founding case: WO-13's
  reproducible-build.sh shipped with two fatal defects
  — a relative path broken by its own `cd`, and a
  rustc flag passed to cargo — and no recorded run;
  Wright's carry fixed both and the double build then
  produced identical hashes.)
- **GMSI-97 — A platform block on one suite is
  NOT RUN for that suite, named with its platform.**
  (Guardian Mesh WO-13 gate, 2026-10-29.) When an
  OS/AV/EDR block prevents a test suite from executing
  (founding case: Windows Defender os error 225 on a
  fresh Rust bin test executable), the lane reports
  that suite NOT RUN with the blocker named — never
  folded into a neighbouring suite's pass, and never
  silently dropped from the counts a release records.
- **GMSI-98 — A proto field addition is diffed against
  every shipped client call site before done.**
  (Guardian Mesh WO-15 gate, 2026-10-31.) When a work
  order adds a field to a wire message, every shipped
  client that constructs that message (TS gmClient,
  Rust, Python) is diffed and updated in the same
  change — a required-field addition that breaks a
  client's build is a work-order defect, found in
  WO-14 (F4) and again in WO-15 (F2).
- **GMSI-99 — Partitioned audit appends on EVERY
  Ok return path.** (Guardian Mesh WO-15 gate,
  2026-10-31.) When audit is partitioned by any key
  (tenant here), the append must be proven on every
  Ok verdict return path — final, policy-deny,
  throttle, simulation-block. A partition that
  undercounts BLOCK/THROTTLE verdicts is a silent
  evidence gap.
- **GMSI-100 — Production harness contracts are
  part of the shipped spec.** (Guardian Mesh WO-15
  deploy, 2026-11-01.) The box E2E's observable
  contracts (e.g. the PF-18 burst verdict mix:
  excess returns THROTTLE verdicts, never errors)
  bind every work order. A change to limiter
  ordering or verdict routing re-proves those
  contracts in Wright's pre-merge behaviour proof —
  never discovers them at deploy. (Founding case:
  WO-15's tenant budget ran before the Gatekeeper
  and converted burst excess to resource_exhausted;
  deploy rolled back, gate F6.)
- **GMSI-101 — Scanner secret candidates are
  classified by code context before they block.**
  (codetopo 0.8.0 gate, 2026-11-02; third consecutive
  occurrence, fourth at the release-PR gate.) A
  `generic-secret-assign` hit inside a Rust
  `#[cfg(test)]` / `#[test]` fixture is emitted as a
  lead, not a blocker — the scanner classifies test
  context before raising a secret candidate.
- **GMSI-102 — Call-resolution fidelity is a tracked
  measurement, not an anecdote.** (codetopo 0.8.0
  gate, 2026-11-02.) A probe reports per-language
  call-resolution rates (resolved vs stubbed) over
  pinned corpora at each gate, so a builder change
  is measured before/after.
- **GMSI-103 — Dependency-advisory freshness between
  releases.** (codetopo 0.8.0 gate, 2026-11-02.) The
  weekly fleet sweep re-runs the OSV pass against
  shipped lockfiles, not only at release time — an
  advisory that post-dates a gate is caught by the
  sweep, not by the next build's gate alone.
- **GMSI-104 — Cross-surface value parity.**
  (codetopo 0.9.0 gate, 2026-11-02.) For any
  measurement product, a value crossing a
  serialization boundary (CLI / HTTP / MCP) must
  round-trip bit-identically; the mesh proves parity
  across every surface the product exposes.
  (Founding case: serde_json's default float parser,
  1 ULP across the HTTP boundary.)
- **GMSI-105 — Absence integrity.** (codetopo 0.9.0
  gate, 2026-11-02.) A non-converged or over-ceiling
  answer is an absence with a reason — never a zero
  or a partial result presented as an answer.
- **GMSI-106 — A release workflow that builds an
  artifact without running the test suite is
  provable from the workflow file.** (Nov-3 Play
  apps gate, 2026-11-02; founding case: all four
  vault children.) The mesh checks workflow steps
  mechanically before a release artifact counts.
- **GMSI-107 — Manifest-vs-declared permission
  diff.** (Nov-3 Play apps gate, 2026-11-02.) The
  shipped artifact's merged-manifest permissions
  are diffed automatically against the pack's
  declared set.
- **GMSI-108 — Framework-version advisory watch at
  gate time.** (Nov-3 Play apps gate, 2026-11-02.)
  Framework versions in lockfiles (Capacitor and
  peers) are checked against GHSA ranges at gate
  time; the boundary arithmetic is never done by
  hand at the gate.
- **GMSI-109 — Bundle-vs-privacy disclosure diff.**
  (Nov-3 Play apps gate, 2026-11-02.) Remote
  references inside a shipped bundle are diffed
  against the product's privacy disclosures; an
  undisclosed remote reference is a finding.
- **GMSI-110 — Workflow-literal secret watch,
  history-aware.** (Nov-3 Play apps gate,
  2026-11-02.) Credentials as literals in workflow
  files are proven absent in the working tree AND
  in history — tree scans alone miss the history
  half.
- **GMSI-111 — Channel-string sweep for money
  surfaces.** (Nov-3 Play apps gate, 2026-11-02.) A
  store-channel bundle must contain no
  direct-checkout URL strings for channels that
  forbid them; proven mechanically, not by hand.

- **GMSI-112 — Wall-clock-window contracts are
  tested by controlling the window or the clock.**
  (Guardian Mesh WO-15.1 gate, 2026-11-02.) A test of a
  rate limiter, budget window, or freshness window must
  not race real time: sequential pre-signed envelopes
  aged past the PF-15 5 s window before reaching the
  rate window, and a concurrent variant raced the 1 s
  window under full-suite CPU contention — the same
  test passed and failed on identical code. Unit tests
  prove ordering deterministically (configure the window
  or the rate so the outcome cannot race); scale and
  volume contracts belong to the production harness,
  run against a release binary on a quiet surface.

- **GMSI-113 — A provider's raw error never crosses an
  API boundary.** (Conduit filings checkout error-leak
  gate, 2026-11-03.) Any outbound-call error path must
  answer in the product's own words, with provider
  detail confined to server logs. Guardian Mesh must be
  able to prove, for an evaluation that depends on an
  external call, that the caller-visible response
  contains no provider response body or provider error
  string, while the sealed proof still records that an
  external failure occurred and which class it was.

- **GMSI-114 — Price-to-plan integrity is a provable
  money-surface invariant.** (codetopo tiered-pricing
  gate GM-1, 2026-11-03.) For any recorded subscription
  or payment event, the plan stamped on the issued key
  or certificate equals the plan of the price actually
  billed. Guardian Mesh must be able to issue and
  verify a proof binding billed price, resolved plan,
  and issued credential together, so a mismatch is
  detectable after the fact, not only at issuance.

- **GMSI-115 — One-off gate probes must graduate into
  the repo suite.** (codetopo tiered-pricing gate GM-2,
  2026-11-03.) A coverage gap closed by a one-off gate
  probe escapes again unless the probe becomes a
  standing test in the product's own suite. Guardian
  Mesh certificates for a release should be able to
  name which gate-probe classes are covered by standing
  tests in the gated tree, so probe graduation is
  checkable rather than remembered.

- **GMSI-116 — Tier-switch enforcement freshness.**
  (codetopo tiered-pricing gate GM-3, 2026-11-03.) Once
  a higher tier's limits exist, no live key may enforce
  a lower tier than its entitlement record shows, or
  the exception must be named in the proof. Guardian
  Mesh must be able to prove the enforcement tier a
  credential is actually under at evaluation time, not
  only the tier it was issued with.

- **Backbone note.** The gate's Kali (offensive) and Arch (crypto /
  isolation / evidence benches) backbones are gate infrastructure, not
  repo code; their NOT RUN status is recorded by the gate thread. The
  repo-side contribution is WO-8's fuzz targets, which the Arch isolation
  bench will consume.
- **GMSI-117 — Pre-authentication degraded/BLOCK verdicts are a
  policy surface of their own.** A fail-closed mode that seals
  evaluation before authentication (WO-16 DC-4, like WO-15 DC-15)
  answers unauthenticated requesters with verdict semantics; that
  is acceptable only as a declared, bounded behaviour: the sealed
  verdict names no policy internals beyond the declared rule id,
  and the gate for any such mode states the pre-auth behaviour
  explicitly instead of discovering it in review.
- **GMSI-118 — Startup/deploy integrity gates must be proven
  against the production data they will judge.** A check correct
  on young or synthetic data and failing on real history is an
  escape class: before an integrity, migration, or verification
  gate ships, it is exercised against a copy of the actual
  production dataset (audit log, store, manifest set), and the
  evidence names that dataset's size and shape. (WO-16 v0.15.0
  verified the full persisted audit chain at startup and bricked
  production on its own 2026-10-26/27 concurrent-writer interleave
  segment; v0.15.1 scopes the startup check to the live tail and
  was proven against the real 2,120-entry log before redeploy.)

- **GMSI-119 — External-state snapshot provenance is provable
  from the receipt stream.** When a verdict depends on fetched
  external state (a provider's model catalog, a price list, a
  revocation feed), the receipt must bind which snapshot decided
  it: the endpoint it came from, when it was fetched, and for
  which key owner — so a later probe can compare the receipt's
  subject against the deciding snapshot and catch a stale or
  poisoned snapshot changing what the system refuses or allows.
  (Conduit Router v1.3.0 gate, 2026-11-04: per-owner model-list
  snapshots became the truth for availability, and a caller-named
  model absent from the caller's snapshot is refused — catalog
  freshness is now a live dependency of routing correctness.)

- **GMSI-120 — An escalated verdict must have a provable
  resolution path, or be declared terminal.** A conformance suite
  must be able to prove that an approval, by the role the spec
  names, resolves an ESCALATE to a final verdict within a stated
  bound — or the specification must declare ESCALATE
  terminal-by-design for that action class, in which case the
  suite pins the declaration. (WO-17 gate F3, 2026-11-04: the
  daemon has no per-request escalation approval path; dual-control
  policy approval does not resolve an individual escalated
  evaluation, and installing the escalation list via an approved
  policy change still yields ESCALATE.)

- **GMSI-121 — Repo↔live drift proof, continuous per deploy
  path.** Guardian Mesh must be able to prove, on a cadence and
  not only at release time, that the deployed artifact for each
  deploy path equals the repo head that path deploys from —
  bytes or a behaviour marker only current code produces, per
  GMSI-9's discipline — and alert the day the two diverge, in
  either direction (live ahead of repo is drift, not freshness).
  (onsmartgrid consolidation gate, 2026-11-05: production ran
  12 days ahead of its repo, Oct 24–Nov 5, with the divergence
  invisible to every watcher; the batch that closed it was a
  repo-integrity gate, not a product release. The same gate's
  page-proof gap is a repeat filing of GMSI-48 and its
  money-surface signed-cell note carries no new input.)


- **GMSI-122 — Ceiling-enforcement venue.** A resource-ceiling
  claim (DP-6 class) can only be behaviour-proven where cgroup
  controllers are actually delegated to the proving venue; a
  nested sandbox that cannot enforce a ceiling must instead
  (a) measure the real footprint under load, (b) state the
  headroom against the shipped ceiling, and (c) name enforcement
  NOT RUN with the venue defect as the reason — never let a
  green suite stand in for an enforcement proof. (WO-18 edge
  gate F3, 2026-11-07: the verifying sandbox's nested userns
  delegates no memory/pids controllers — crun refuses every
  limit flag — while the daemon's measured peak was 10.6 MB
  against the shipped 256M ceiling.)

- **GMSI-123 — Counter-only auth-outcome metrics.** Where a
  surface deliberately logs nothing about authentication
  outcomes (a no-logging discipline that must not be weakened),
  Guardian Mesh must be able to prove the aggregate outcome
  counts — expired vs used vs invalid, counter-only, carrying
  no identifier, token fragment, or address — so a
  delivery-latency problem can be distinguished from token
  misuse from evidence, not inference. The counts themselves
  must not become a state oracle: they are aggregate and
  operator-facing only, never per-token or per-mailbox.
  (Linktary v0.4.1 magic-link gate, 2026-11-08: the auth module
  logs nothing by design, so an expired-link failure today
  leaves no privacy-preserving aggregate trace; the gate
  accepted this input as filed — not built there, not a
  condition of that release.)

- **GMSI-124 — Operator-surface smoke proof.** Every shipped
  client surface (CLI, MCP server, panel actions) must carry a
  repeatable smoke proof a gate run can execute against a live
  daemon: connect, health, handshake, one ALLOW evaluate, proof
  verify, one audit read, plus the negative legs the surface
  owns (no-session, tampered proof, unreachable endpoint), each
  with its expected exit/result. A surface that ships without
  its smoke proof is incomplete by definition. (WO-18 CLI gate,
  2026-11-08: the CC-4 CLI's proof was necessarily ad-hoc —
  gm-proof.sh in the run dir — because no in-repo proof exists
  for any surface; CC-5's MCP surface should land with its
  proof in-repo. Absorbing this input means the suite exists
  in-repo and a gate run executes it against the release build;
  until then it stands as filed input. Rules touched: CC-4/CC-5
  acceptance; RG-7 — the smoke proof is the surface's
  conformance slice.)

GMSI-125…133 were filed by the release gate's 2026-11-09 Conduit
rounds (packs: release-gate-runs/conduit-buyerfix-2026-11-09,
conduit-buyerfix2-2026-11-09, conduit-buyerfix3-2026-11-09,
conduit-credits-2026-11-09). They queue behind the Part A work
orders exactly as GMSI-6…124 do, and none becomes a gate MUST
until behaviour-proven here.

- **GMSI-125 — Wedged dashboard reads must be observable.**
  (Conduit buyerfix gate, 2026-11-09.) A dashboard read that can
  wedge must be *observable*: the page should surface (and
  ideally report) refresh failures rather than only wording
  them — in the filed escape the only witness to the class was
  the owner's own walk. GM must be able to prove a wedged read
  becomes a visible, reported failure on the surface itself.
- **GMSI-126 — Every primary card read settles with words.**
  (Conduit buyerfix gate, 2026-11-09; the round's F-3.) The
  single-shot dashboard calls left after the purchase-path fix
  are the same wedge class on non-money cards: GM should be
  able to prove "every primary card read settles with words"
  across the whole page, not only the purchase path.
- **GMSI-127 — No key material in post-sign-in dashboard reads.**
  (Conduit buyerfix round-2 gate, 2026-11-09.) A served page's
  credential choice is a release surface: GM should be able to
  prove, for a stall-model network, that post-sign-in dashboard
  reads carry no key material (the round-2 regression shape).
- **GMSI-128 — Observability ON for live-walk-accepted surfaces.**
  (Conduit buyerfix round-2 gate, 2026-11-09; the round's F-3.)
  Production Workers Logs observability must be ON for any
  surface whose acceptance evidence is a live walk — filed as a
  gate checklist candidate: a buyer-leg escape was diagnosable
  only because the code carried its own evidence; the log
  window itself was dark.
- **GMSI-129 — Liveness of awaited shared state.** (Conduit
  buyerfix round-3 gate, 2026-11-09.) Any initialization
  promise awaited on a request path must carry (a) a deadline,
  (b) a degraded path that serves from the durable source, and
  (c) a regression that wedges the source and proves requests
  still complete. Probe candidate: wedge the registry store in
  a staging isolate and assert authenticated reads complete
  inside the deadline + one store read.
- **GMSI-130 — Metered balance == signed ledger sum.** (Conduit
  credits gate, 2026-11-09.) GM must be able to prove, for any
  metered key: balance == signed ledger sum, at any instant,
  from outside the gateway process.
- **GMSI-131 — Refusal means zero provider egress.** (Conduit
  credits gate, 2026-11-09.) GM must be able to prove a
  `blocked_credits` refusal produced zero provider egress
  (correlate the audit chain with provider-call telemetry).
- **GMSI-132 — Webhook/grant correspondence.** (Conduit credits
  gate, 2026-11-09.) GM must detect a Stripe webhook delivered
  but ungranted (event seen at the edge, no ledger grant within
  N minutes) and a grant with no corresponding webhook
  (impossible by construction — prove it stays so).
- **GMSI-133 — Top-up attempts cap watch.** (Conduit credits
  gate, 2026-11-09.) GM must watch the top-up path: attempts
  per key per day never exceed the configured cap, including
  failure storms.

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
- 2026-10-15 — **WO-2 shipped as v0.4.0** (PR #31, merged 2a98e7be):
  the Protocol Firewall rule table is enforced on Evaluate — PF-1/5
  size, PF-12 unknown fields, PF-13 nesting ≤4, PF-14 nonce window
  (10,000/session), PF-15/16 timestamp windows (stale >5 s, future
  >1 s, nanosecond field), PF-17 signature format [2420, 3500],
  PF-18 rate limit 100 msg/s/session (E_RATE_LIMITED). PF-2..PF-11
  documented not-applicable at the gRPC surface in the PR. Built by
  the laptop lane (OpenCode, Claude lane) in D:\guardian-mesh-work\wo2;
  Wright-verified independently: cargo 58/58 on a fresh checkout;
  wire-level E2E 16/16 against the release build and again 16/16
  against the deployed daemon on the box (incl. a 115-request burst:
  exactly 100 allowed, 15 × PF-18). Release gate: PASS WITH FINDINGS
  (F1 firewall session state never evicted — evict_session has no
  callers; F2 Health PF counters are constants, not measured; F3–F5
  informational — see PR #31). Deployed to guardian.aimlds.org the
  same night (binary sha256 4254b5eb…, rollback kept as
  guardian-meshd.bak-v030 on the box). GMSI-6 (scanner Rust
  inline-test detection, second false BLOCKED) and GMSI-7 (bind
  measured per-rule firewall outcomes into WO-6 evidence packs)
  filed from this run. Next: WO-3.
- 2026-10-15 — **Laptop lane operating recipe** (learned on the WO-2
  run; reuse it): (1) launch OpenCode detached via Win32_Process.Create
  — children of the SSH session die with it; (2) never pass a long
  prompt as a CLI argument (the .cmd shim truncates it) — put the task
  file INSIDE the clone (headless runs auto-reject reads outside the
  project dir) and pass one short instruction naming it; (3) stdin must
  be redirected from an empty file (an open SSH stdin makes
  `opencode run` die with EUNKNOWN/read); (4) working model lane:
  `anthropic/claude-sonnet-4-5` with the key read from the owner's
  auth.json by the runner script itself and injected as an env var
  (never copied, never logged); Zen (`opencode/…`) Claude models
  currently answer "Model access is disabled" and the laptop's own
  opencode.db is ~7 GB — run the lane with muse's own data home, not
  the owner's; (5) git push from the laptop under `muse` is blocked
  (Git Credential Manager needs an interactive prompt) — the lane
  commits locally and Wright carries the exact commit to GitHub by
  git bundle + API push, asserting the tree hash matches; (6) the
  deploy binary is cross-built on Wright's machine with
  cargo-zigbuild (aarch64-unknown-linux-gnu; blake3 needs the zig cc)
  — the box never builds.
- 2026-10-15 — **Revised Specification v3.0 adopted** (owner's order):
  `specs/GUARDIAN_MESH_REVISED_SPEC.md` is the governing target spec,
  folding in the data-center readiness set (owner-approved: "what you
  said for muse datacenter is correct"), the hyperscaler-aligned
  checkpoint catalogue (AWS Well-Architected SEC / Google Security
  Foundations + BeyondCorp/BeyondProd / Microsoft Cloud Security
  Benchmark / OCI Security Zones + Cloud Guard / Meta infra zero
  trust, on a NIST CSF + 800-53 + 800-207 + CIS spine), the release
  gate as criteria of record, and the owner's new doctrines: deploy
  on every endpoint class (clouds, servers, laptops, phones, edge,
  browsers), every boundary crossing needs authorization + handshake
  with at least two independent confirmations, and authorization by
  any lawful method — PGP/GPG included. New work orders WO-10…WO-19
  added as Part C of this pack. Honesty labels in the spec mark
  SHIPPED / PARTIAL / TARGET; nothing [TARGET] may be described as
  existing capability.
- 2026-10-15 — **Spec amended to v3.1** (owner-directed, same day):
  §0.5 product boundary charter (what it is / does / stands /
  cannot do — liability and honesty edges in normative text);
  Doctrine 0, the closed-path rule ("package it such that things
  can only flow in certain way… nothing that is not a desired path
  can at all invoke anything"); §11 complete mediation — the owner
  ruled an unguarded path is a vulnerability, so credential escrow,
  execution tokens, receipt reconciliation, drift watch, and a
  coverage statement inside every certificate; §12 securing the
  guardian (threat model of record, anti-downgrade, secure-by-
  default incl. refusing the default handshake secret, external
  witnessing of the audit chain, compromise playbook, insider
  separation, independent review, authenticated time, end of life);
  §13 product completeness (payload DLP, tool/model supply chain,
  delegation attenuation, policy authoring, agent registry, admin
  RBAC, compliance exports, certificate transparency, incident kit,
  alerting, air-gapped mode, integration wrappers, self-test kit,
  appeal path, operational completeness). Work orders WO-20…WO-30
  added as Part D of this pack.
- 2026-10-16 — **Standards compliance review + development plan**
  (owner's order): `specs/STANDARDS_COMPLIANCE_REVIEW.md` (PR #36)
  found ISO/IEC 22989 PARTIAL (terminology form gap), 23894
  PARTIAL, CSF/800-53 PARTIAL, FIPS 140-3 GAP (not claimed), SLSA
  TARGET, no organizational certifications held or claimed.
  `specs/COMPLIANCE_DEVELOPMENT_PLAN.md` converts every gap into
  builds with acceptance evidence: WO-31 (terminology annex),
  WO-32 (AI risk register per 23894, after WO-30), WO-33 (NIST AI
  RMF profile), WO-29 bar raised (per-deployment CP evidence
  export), WO-36 (EU AI Act deployer pack), WO-35 (PKCS#11
  validated-module path, after WO-3), WO-13 (SLSA). Organizational
  track (42001/27001/SOC 2) is staged demand-led in the plan —
  groundwork only, certification spend on customer requirement,
  never theatre ahead of revenue.
- 2026-10-16 — **Relicensed: Apache 2.0 + Payment Rider** (owner's
  decision: "Apache two license plus payment rider"). The former
  split (AGPL core / Apache interface) is retired: root LICENSE and
  guardian-meshd/LICENSE now carry the canonical Apache 2.0 text,
  LICENSE-RIDER.md carries the rider (free use/self-hosting at any
  scale; paid license only for offering verdicts/certification as
  a service or issuing certificates under the name), README and
  guardrail 3 updated, all daemon SPDX headers swept AGPL→Apache-2.0
  (verified: zero AGPL strings remain in sources). Honest naming
  rule in the rider itself: always "Apache License 2.0 + Payment
  Rider", never bare Apache 2.0.
- 2026-10-15 (nightly) — **Pack refreshed: GMSI-6…47 filed.** The
  WO-1/WO-2 gate runs (GMSI-6/7) and the release gate's 2026-10-15
  fleet re-gate — 13 product packs — filed the spec inputs now
  carried in Part B; onsmartgrid and the Conduit Router re-run
  filed none. Repeats are consolidated (the transport floor,
  GMSI-8, was filed seven times in one day — the fleet's loudest
  repeat class). The work-order order does not change: the new
  inputs queue behind Part A and land through WO-6's certificate
  schema and the gate's standing probe sets, each becoming a MUST
  only once behaviour-proven here. Next: WO-3.
- 2026-10-17 — **WO-3 shipped as v0.5.0** (PR #40, merged 5ecf9074):
  the daemon's ML-DSA-65 signing key persists — the 32-byte seed is
  generated on first start into `<workspace>/keys/daemon_signing_key.bin`
  (mode 0600, permissions set before the seed is written, fsync'd) and
  loaded on later starts; a corrupt or unreadable key file fails
  closed with a FATAL naming the file — never a silent regeneration.
  Health reports `signing_key_fingerprint` (proto field 5): lowercase
  hex SHA-256 of the public key — fingerprint only, never key
  material (GMSI-2's GM-side half). Generation/storage/backup/rotation
  documented in `guardian-meshd/README.md`. Built by the laptop lane
  (OpenCode, Claude lane) across two runs — the first died mid-work
  when the laptop restarted for updates; a continuation run finished
  it; Wright carried the commit by git bundle with tree-hash equality
  asserted (lane tree 72de5f98 == pushed tree). Wright-verified
  independently: cargo 65/65 on a fresh checkout (58 at v0.4.0);
  wire-level two-boot proof — proof issued under boot 1 verifies
  VALID under boot 2 (distinct processes), corrupt key → exit 1,
  restored key → validity returns, fresh workspace → different
  fingerprint and the old proof correctly invalid there. Release
  gate: PASS WITH FINDINGS (F1 low cosmetic — the FATAL line doubles
  its prefix; F2 low — the keys/ directory's permissions are not
  pinned; scanner "tests" BLOCKED is the GMSI-6 false lead, third
  occurrence, resolved by the direct suite evidence; Kali/Arch
  backbone families NOT RUN — benches not yet built). Verification
  also caught the relicense sweep's misses — daemon Cargo.toml still
  declared AGPL, build.rs carried an AGPL SPDX header, CONTRIBUTING
  still described split licensing — fixed on the branch (8fe51bab)
  to Apache License 2.0 + Payment Rider. Deployed to
  guardian.aimlds.org the same night (binary sha256 d93df02d…,
  rollback kept as guardian-meshd.bak-v040): production key
  generated on first start; production signing fingerprint
  dd2cf1a350e0b31c30fcf0db2d1dd73ade7487af08385ddce6b99e7d1f40a8c9,
  stable across a service restart with a pre-restart proof still
  VALID; box E2E 16/16; unauthenticated web check still 302.
  Next: WO-4.
- 2026-10-19 — WO-4 shipped as v0.6.0 (PRs #42–#44): AuditTrail read
  path (ReadAuditLog RPC) + live panel audit view; wire-verified
  against production (316 entries chain-VERIFIED). Gate PASS WITH
  FINDINGS. (Run detail: the 2026-10-18 nightly run log.)
- 2026-10-20 — **WO-6 shipped as v0.8.0** (PR #48, merged 0d963b7c):
  release-evidence certification — IssueCertificate /
  RevokeCertificate / CertificateStatus RPCs; certificate =
  sealed envelope over a canonical body (specs/
  CERTIFICATE_SCHEMA.md); fingerprint = SHA-256 of the exact
  payload bytes, carried alongside the envelope, never inside
  it; lifecycle (issue / supersede / BLOCKED-revokes) recorded
  in the hash-chained Vault audit log; registry persists
  across restarts on the WO-3 persistent key. Built by the
  laptop lane in three runs (initial + two gate fix rounds).
  Wright-verified independently: cargo 96/96; webui build+lint
  pass; wire proof 20/20 (issue, recompute, verify, mismatch
  refusal, supersession, BLOCKED revocation, restart
  persistence) + mixed-traffic chain proof. Gate: PASS WITH
  FINDINGS — F1 (High) first commit did not compile, committed
  without a test run; F2 (High) fingerprint not recomputable
  from the sealed payload; F3 lifecycle events initially in a
  separate file, not the chain; F4 (High) two VaultEnclave
  instances broke the chain under mixed traffic — all fixed
  in the loop and re-proven. Carried: Python checked-in client
  not regenerated (protoc 29.3 vs 6.31.1 gencode). Deployed
  to guardian.aimlds.org (binary sha256 86161727…, rollback
  guardian-meshd.bak-v070): production fingerprint unchanged
  (dd2cf1a3…, third upgrade), box E2E 16/16, Access 302, and
  the release certified ITSELF on production — certificate
  cert-20261020-000001 for guardian-mesh 0.8.0, evidence =
  this gate's verdict, fingerprint recomputes, VerifyProof
  valid, status ACTIVE. **F7 (High, carried, post-deploy):**
  the production audit chain FAILS verification at position
  557 — concurrent-burst chain race (GMSI-69), reproduced
  locally on v0.8.0 (one 115-burst → break at position 2, 32
  duplicate hashes). Pre-existing since bursts began sealing
  verdicts (v0.7.0); not a WO-6 regression, but v0.8.0's RC
  graduation weighs its fix. v0.8.0 is a RELEASE CANDIDATE
  (one-week watched soak). Next: WO-6.1 (chain-concurrency
  fix, P1), then WO-7.
- 2026-10-19 — **WO-5 shipped as v0.7.0** (PR #45, merged e994d842):
  THROTTLE and ESCALATE are real verdicts. PF-18 breaches and a
  policy-configurable per-session rate (GUARDIAN_MESH_POLICY_THROTTLE_RATE,
  default 100 msg/s) return verdict THROTTLE with a signed proof —
  a deliberate behaviour change from WO-2's permission_denied (the
  box E2E's PF-18 check now asserts THROTTLE verdicts; the old
  script is kept on the box as box-e2e.mjs.bak-v060).
  GUARDIAN_MESH_POLICY_ESCALATE_ACTIONS lists action types that
  require a human (default empty); precedence BLOCK > ESCALATE >
  ALLOW. Built by the laptop lane (one run, clean); Wright carried
  by bundle (tree 03c4b91f asserted equal). Wright-verified
  independently: cargo 85/85; webui build+lint pass; wire proof on
  the branch build — 115-burst = exactly 100 ALLOW + 15 THROTTLE
  (proof verifies) under both the policy rate and, with the policy
  rate raised, PF-18 itself (reason "PF-18 rate limit breach:
  E_RATE_LIMITED"); policy rate 5 = 5 ALLOW then THROTTLE;
  ESCALATE for a configured action with a verifying proof, BLOCK
  precedence intact, unconfigured traffic unchanged. Gate: PASS
  WITH FINDINGS — F1 scanner tests MUST false-lead (GMSI-6, 4th
  occurrence; resolved by direct suite evidence); F2 (low) reason
  attribution at equal defaults shadows PF-18 and the policy reason
  omits the numeric limit; F3 (low) the lane's THROTTLE test is
  structural, not a real burst — filed as GMSI-53 (a new verdict
  path's tests must drive its real trigger in-process); cargo audit
  NOT RUN (tool absent); Kali/Arch NOT RUN (benches not built).
  Judgment differential (§7) run: calibration + twins + citation
  graded PASS with F2 noted. Deployed to guardian.aimlds.org
  (binary sha256 8e4b9665…, rollback guardian-meshd.bak-v060):
  production fingerprint unchanged (dd2cf1a3…, the WO-3 identity
  surviving its second upgrade), production burst served the first
  15 THROTTLE verdicts with verifying proofs, box E2E 16/16,
  Access 302 intact. v0.7.0 is a RELEASE CANDIDATE (one-week
  watched soak). Next: WO-6.
- 2026-10-18 (nightly) — **Pack refreshed: GMSI-48…52 filed.**
  The only new Guardian Mesh Spec Inputs since the 2026-10-15
  refresh are the five items from the release gate's 2026-10-17
  independent re-gate of Verdict (served-script parse proof,
  SSRF spelling/resolution posture, judgment differential
  battery, concurrent fresh-identity rate proof, pattern-coverage
  canaries). No work-order order changes: WO-4 remains next.
- 2026-10-19 — **WO-4 shipped as v0.6.0** (PR #43, merged 6dc51add):
  the audit trail has a read path — a new additive `ReadAuditLog`
  RPC returns the Vault's persisted entries in append order with
  chain verification computed at read time (verified / entries
  checked / first-break position), and the live panel's audit view
  is wired to it. One design fact the build surfaced honestly:
  the pre-0.6.0 audit digest was per-entry, NOT chained — WO-4
  makes seal() write a true chain (prev-hash linked, all fields
  covered) and verification is dual-mode, so pre-0.6.0 entries
  verify against their original legacy formula and seed the
  chain (their reason/enclave-chain fields were never
  digest-covered; the daemon README now says so). Built by the
  laptop lane (OpenCode, Claude) across three runs — the first
  killed mid-build by a laptop reboot (Windows-update pattern,
  as WO-3's first run), a continuation finishing it, a third
  closing the gate fix loop. Wright-verified independently:
  cargo 78/78 on a fresh checkout of the pushed tree (pushed
  tree == lane tree, asserted), webui build + lint green, and
  Wright's own probes — hand-edited file line → break at the
  exact position; legacy entry verifies; mixed legacy→new log
  verifies; malformed stored hash returns a break report, never
  a panic. Release gate: PASS WITH FINDINGS (pack
  release-gate-runs/guardian-mesh-wo4-2026-10-18) — the fix loop
  closed F1 (High: verify_chain panicked on a malformed stored
  hash, byte-slicing log-controlled data) and F2 (High: every
  pre-0.6.0 entry falsely reported "break at position 0") on the
  branch before merge; F3 (Low, panel hid a break at position 0)
  fixed with them; F4 (Low, carried) is lane reporting slips
  (result-file test counts off by one twice; a result file
  briefly committed, removed by Wright's amend before push).
  Scanner "tests" BLOCKED is the GMSI-6 false lead, FOURTH
  occurrence, resolved by the direct suite evidence — GMSI-6 is
  re-filed by this run as the scanner's loudest repeat false
  lead; no other new GMSI. NOT RUN: Kali/Arch benches (not
  built), dependency-vuln scan, real-browser panel click-through.
  Deployed the same night: aarch64 daemon binary sha256
  8e5e994e… live on the box (rollback guardian-meshd.bak-v050
  kept), live panel dist rebuilt with the endpoint and deployed
  (webui-dist.bak-v050 kept), Pages demo deployment at the merge
  commit (asset hash == Wright's local demo build). Production
  proof on the wire: signing fingerprint unchanged
  (dd2cf1a3…); production ReadAuditLog returned the real log —
  213 pre-0.6.0 entries, chain VERIFIED — then the box E2E
  battery (16/16) sealed 103 new chained entries on top and the
  mixed 316-entry log still verifies. guardian.aimlds.org
  unauthenticated still 302. v0.6.0 is a release candidate under
  the standing one-week soak (to 2026-10-26). Next: WO-5.
- 2026-10-20 (nightly) — **WO-6.1 shipped as v0.8.1** (PR #53,
  merged e87a18b5): the chain-concurrency fix closing issue #50
  and GMSI-69 — both audit-chain writers (seal +
  record_certificate_event) now hold the last_chain_hash mutex
  across the whole append (predecessor read + digest + persist
  + predecessor update as one critical section); sequential
  behaviour, digest formula, and on-disk format unchanged.
  Built by OpenCode on the laptop lane (fresh clone at the
  GMSI-70..73-refreshed main, PR #52); Wright carried the tree
  with two edits (trail push inside the critical section; the
  lane's stale test counts corrected). Gate: PASS WITH
  FINDINGS — F1/F2 (Low) fixed in the loop; scanner BLOCKED
  only on the GMSI-6 "tests" false lead (sixth occurrence).
  Wright's independent verification: cargo 97/97 (80 lib + 17
  bin), webui build+lint green; barrier-synchronized burst
  FAILED pre-fix / PASSED post-fix; wire proof pair (identical
  150-append concurrent burst): v0.8.0 control = 7 duplicate
  hashes + break at position 1; v0.8.1 = 0 duplicates, chain
  VERIFIED. Filed GMSI-74 (above). Deployed to
  guardian.aimlds.org (aarch64 binary sha256 a2535e66…,
  rollback guardian-meshd.bak-v080): production fingerprint
  unchanged (dd2cf1a3…, fourth upgrade), box E2E 16/16,
  post-deploy segment of 268 entries (E2E PF-18 burst + a
  150-append burst) verifies with 0 breaks / 0 duplicates —
  while the whole-log verification still reports the
  historical burst-race break at position 557, which stands
  as recorded (pre-fix history; F3). The release certified
  itself on production: certificate cert-20261021-000032
  (guardian-mesh 0.8.1, PASS WITH FINDINGS, evidence = the
  gate verdict), fingerprint recomputes, VerifyProof valid,
  supersedes cert-20261020-000001, status ACTIVE.
  guardian.aimlds.org unauthenticated still 302. v0.8.1 is a
  RELEASE CANDIDATE (one-week watched soak, RC register row
  28; graduates 2026-10-27). v0.8.0's own graduation (row 26)
  weighed this fix landing — it has. Next: WO-7.
- 2026-10-21 (nightly) — **WO-7 shipped as v0.8.2** (PR #55,
  merged 2b774294): `revised_project_scope.md` rewritten to
  shipped reality — Sentinel/Gatekeeper/Witness/Arbiter/Vault
  pipeline (not the pre-implementation Auth/Compute/Storage/
  Network/Policy set), Apache License 2.0 + Payment Rider (not
  MIT), audit logging + ReadAuditLog and the 97-test suite as
  shipped (not "not implemented"/"not started"), the real
  specs/ table, TEE/BFT/mTLS/anchoring/Lean 4/OPA as design
  only, npm tooling, GitHub as home of record — and the
  byte-identical duplicate `specs/GUARDIAN_MESH_GAP_ANALYSIS
  (1).md` removed (both blobs f396e2ef, verified before
  deletion). No new GMSI arrived since GMSI-74 (the three
  2026-10-21 gate packs filed none), so no pack refresh was
  needed before the build. Built by OpenCode on the laptop
  (fresh clone D:\guardian-mesh-work\wo7, commit 31afd4f4);
  Wright carried by Git-data API with tree equality asserted
  (lane tree 94e66bbd, final tree 15b1a824). Wright-verified
  independently: cargo 97/97 (80 lib + 17 bin) from the
  workspace root; webui build+lint green; full read of the
  rewrite against README/CHANGELOG/daemon README/specs.
  Gate: PASS WITH FINDINGS — scanner BLOCKED only on the
  GMSI-6 "tests" false lead (seventh occurrence); F1 (Low)
  the lane ran cargo test inside guardian-meshd/ (96 = 79+17)
  and "corrected" the verified counts down — fixed by Wright
  carry edits and filed as GMSI-75 (above). Deployed to
  guardian.aimlds.org (aarch64 binary sha256 dcd0f79c…,
  rollback guardian-meshd.bak-v081): production fingerprint
  unchanged (dd2cf1a3…, fifth upgrade), box E2E 16/16, Pages
  asset == Wright's build, Access 302 intact, and the release
  certified itself on production — certificate
  cert-20261022-000033 (guardian-mesh 0.8.2, PASS WITH
  FINDINGS, evidence = the gate verdict), fingerprint
  recomputes, VerifyProof valid, supersedes
  cert-20261021-000032, status ACTIVE. Whole-log verification
  still reports the historical break at position 557 (pre-fix
  history, stands as recorded). v0.8.2 is a RELEASE
  CANDIDATE (one-week watched soak, RC register row 29;
  graduates 2026-10-28). Next: WO-8 (P2, fuzz the
  boundaries). Standing: dependabot PR #51 (vite bump) still
  open, outside the work orders.
- 2026-10-22 (nightly) — **Pack refreshed: GMSI-76..81 filed.**
  The DogEar gate runs of 2026-10-22 filed six new spec inputs:
  v1.2.0 — pack drift watch (GMSI-76), price-totality probe
  (GMSI-77), seam-activation watch (GMSI-78), pairing integrity
  (GMSI-79); v1.4.0 beta.4 — certified-shell identity (GMSI-80),
  capability-tier proof (GMSI-81). The v1.3.0 picker verdict
  filed none explicitly. These queue behind Part A like prior
  inputs and land through WO-6's certificate schema and the
  gate's standing probe sets, each becoming a MUST only once
  behaviour-proven here. Next: WO-8.
- 2026-10-22 (nightly) — **WO-8 shipped as v0.8.3** (PR #58,
  merged c8e4bb3b): three cargo-fuzz/libFuzzer targets in a
  detached `fuzz/` package — fuzz_envelope_decode (prost
  EvaluateRequest decode + PF size), fuzz_payload_parse
  (PF-1/12/13), fuzz_proof_verify (verify_proto_envelope +
  verifying_key_from_bytes) — with real seed corpora, a
  fuzz/README, and a nightly fuzz workflow (02:00 UTC +
  dispatch, 60 s per target, crash-artifact gate). Pack was
  refreshed first (PR #57, merged dfcdb1b1: GMSI-76..81 from
  the DogEar 2026-10-22 gates). Built by OpenCode on the
  laptop (fresh clone D:\guardian-mesh-work\wo8, lane commit
  f9acde7; carried by Git-data API with tree equality asserted
  at each commit — lane tree ceae6325, final tree 47220a86).
  Wright-verified independently: cargo 97/97 (80 lib + 17 bin)
  from the workspace root on Linux (the lane's Windows root
  run: 96 = 79+17; one lib test is #[cfg(unix)] — GMSI-75
  naming applied); webui build+lint green; and the fuzz
  behaviour proof the lane could not run (its cargo-fuzz
  install OOM'd on Windows): Wright built all three targets
  on Linux (nightly, cargo-fuzz 0.13.2) and ran each 30 s —
  envelope 1,570,318 execs, payload 922,892, proof 354,323 —
  zero crashes, zero crash artifacts. Gate: PASS WITH
  FINDINGS — scanner BLOCKED only on the GMSI-6 "tests" false
  lead (eighth occurrence); F1 (High) the lane's fuzz package
  had never been built and could not build (cargo-fuzz
  metadata, undeclared ml-dsa, Keypair import); F2 (High) the
  proof target's up-to-3500-byte signature slice could never
  verify a real 3309-byte ML-DSA-65 proof — fixed to the
  exact length, seeds regenerated real (valid_signed verifies
  under the target's fixed-seed key; valid_request prost-
  decodes and round-trips); F3 workflow continue-on-error
  would have swallowed crashes — crash-artifact gate added;
  F5 workflow ran cargo-fuzz from inside fuzz/ (cannot run
  there) — moved to the repo root; F4 lane's WO8-RESULT.md
  removed from the tree. All fixed in the carry. Filed
  GMSI-82 (above). Deployed to guardian.aimlds.org (aarch64
  binary sha256 8407e6c5…, rollback guardian-meshd.bak-v082):
  production fingerprint dd2cf1a3… unchanged (sixth upgrade),
  box E2E 16/16, Pages asset == Wright's build (webui
  unchanged), Access 302 intact, audit log at 1,179 entries
  with whole-log verification still reporting the historical
  break at position 557 (pre-fix history, stands as
  recorded), and the release certified itself on production —
  certificate cert-20261023-000034 (guardian-mesh 0.8.3, PASS
  WITH FINDINGS, evidence = the gate verdict sha256
  2b4df95c…), fingerprint recomputes, VerifyProof valid,
  supersedes cert-20261022-000033, status ACTIVE. v0.8.3 is
  a RELEASE CANDIDATE (one-week watched soak, RC register
  row 30; graduates 2026-10-29). Next: WO-9 (P1, public
  release log on the site). Standing: dependabot PR #51
  (vite bump) still open, outside the work orders.
- 2026-10-23 (nightly) — **WO-9 shipped as v0.8.4** (PR #60,
  merged 0d5787aa): public release log on the site — a
  `/releases` page in the WebUI rendering a typed data file
  (`webui/src/data/releases.ts`) with one entry per
  CHANGELOG version section (0.8.4 … 0.1.0: summary,
  highlights, gate verdict or "Not recorded", test record,
  status), plus a drift guard
  (`webui/scripts/check-releases.mjs`) wired into the webui
  build — a release that forgets the log now fails the
  build. No pack refresh was needed (no new GMSI had
  arrived since GMSI-82; the Sanity Check gate of
  2026-10-23 filed none). Built by OpenCode on the laptop
  (fresh clone D:\guardian-mesh-work\wo9, lane commit
  d42fda1; carried by Git-data API with tree equality
  asserted at each commit — lane tree df2dc100, final tree
  42b3810a). Wright-verified independently: cargo 97/97
  (80 lib + 17 bin) from the workspace root on Linux (the
  lane's Windows root run: 96 = 79+17; one #[cfg(unix)]
  test — GMSI-75 naming applied); webui npm ci + build +
  lint + check:releases green; drift-guard negative case
  proven by Wright on a scratch copy (exit 1, position-
  specific message). Gate: PASS WITH FINDINGS — scanner
  BLOCKED only on the GMSI-6 "tests" false lead (ninth
  occurrence); 0 secrets, 0 vulns (159 deps). F1 (Medium)
  the lane marked v0.8.0–v0.8.3 as "Released" — all four
  are RELEASE CANDIDATES in soak per the RC register —
  fixed in the carry (statuses sourced from the register,
  the status artifact); F2 (Low) the lane's draft
  CHANGELOG claimed the Linux 97 count before Wright ran
  it — corrected to name platform + verifier per count.
  Filed GMSI-83 (above). Deployed to guardian.aimlds.org
  (aarch64 binary sha256 7e5afacc…, rollback
  guardian-meshd.bak-v083; webui-dist.bak-v083 kept):
  production fingerprint dd2cf1a3… unchanged (seventh
  upgrade), both services active, Pages serving the gated
  asset index-D5AkpYQg.js, Access 302 intact, audit log
  at 1,181 entries with whole-log verification still
  reporting the historical break at position 557 (pre-fix
  history, stands as recorded), and the release certified
  itself on production — certificate cert-20261024-000035
  (guardian-mesh 0.8.4, PASS WITH FINDINGS, evidence =
  the gate verdict sha256 9441325f…), fingerprint
  recomputes, VerifyProof valid, supersedes
  cert-20261023-000034, status ACTIVE. Real-browser
  click-through of /releases NOT RUN (three browser-task
  windows closed without results tonight; live asset
  identity + bundle content inspection are the served-
  state evidence). v0.8.4 is a RELEASE CANDIDATE
  (one-week watched soak, RC register row 32; graduates
  2026-10-30). Part A is now complete (WO-1…WO-9).
  Next: WO-19 (P1, Part C first in order — firewall
  session eviction + measured Health counters).
  Standing: dependabot PR #51 (vite bump) still open,
  outside the work orders.
- 2026-10-24 (nightly) — **WO-19 shipped as v0.8.5** (PR #63,
  merged 608649f5; pack refresh PR #62, merged 863395a1,
  filed GMSI-84/GMSI-85 from the 2026-10-24 DogEar gates):
  firewall session eviction + measured Health counters,
  closing v0.4.0 gate findings F1/F2 (EV-5 groundwork).
  HandshakeBus eviction now returns the evicted session IDs
  (evict_expired / evict_expired_at); the service sweeps them
  into ProtocolFirewall::evict_session on Handshake and on
  Evaluate, and the Gatekeeper evicts a dead session's
  firewall state before blocking. The firewall records
  measured per-rule outcomes (Gatekeeper records the static
  PF-1/12/13/15/16/17; the instance checks record PF-14,
  POLICY_RATE, PF-18); Health reports the measured totals
  and a per-rule map in the new proto field 6
  (protocol_firewall_rule_counters, "passed=<n>,failed=<n>")
  — the 18/18 constants are deleted, a fresh daemon reports
  0/0 with an empty map. Built by OpenCode on the laptop
  (fresh clone D:\guardian-mesh-work\wo19, lane commit
  e048a40; carried by Git-data API with tree equality
  asserted at each commit — lane tree aa88997e, final tree
  78035aa5). Wright-verified independently: cargo 107/107
  (87 lib + 20 bin) from the workspace root on Linux (lane
  Windows run 106 = 86+20; one #[cfg(unix)] test); webui
  npm ci + build + lint + check:releases green (9 versions);
  wire proof on a local daemon AND on production over
  gRPC-Web through the shipped TS client: fresh Health 0/0
  empty map → one valid Evaluate = 9 passed / 9 total across
  exactly 9 rules → one PF-12 block = PF-12 failed=1 with
  later rules unrecorded. Gate: PASS WITH FINDINGS —
  scanner BLOCKED only on the GMSI-6 "tests" false lead
  (tenth occurrence); 0 secrets, 0 vulns (159 deps). F1
  (Low) the lane's shipped test counts were arithmetically
  wrong (Windows total vs Linux baseline; "9 added" for 10
  tests) — fixed in the carry. No new GMSI from this run;
  the WO-6 schema's reserved pf_outcomes wiring is the
  standing follow-up now that the counters exist.
  Deployed to guardian.aimlds.org (aarch64 binary sha256
  4e74382b…, rollback guardian-meshd.bak-v084;
  webui-dist.bak-v084 kept): production fingerprint
  dd2cf1a3… unchanged (eighth upgrade), both services
  active, Pages serving the gated asset index-CCim350_.js,
  Access 302 intact, audit log at 1,182 entries with
  whole-log verification still reporting the historical
  break at position 557 (pre-fix history, stands as
  recorded), and the release certified itself on
  production — certificate cert-20261025-000036
  (guardian-mesh 0.8.5, PASS WITH FINDINGS, evidence =
  the gate verdict sha256 38426175…), fingerprint
  recomputes, VerifyProof valid, supersedes
  cert-20261024-000035, status ACTIVE. v0.8.5 is a
  RELEASE CANDIDATE (one-week watched soak, RC register
  row 33; graduates 2026-10-31). Part C is underway
  (WO-19 done). Next: WO-10 (P1, Part C second in order —
  Simulate call + structured verdict reasons). Standing:
  dependabot PR #51 (vite bump) still open, outside the
  work orders.
- 2026-10-25 (nightly) — **WO-10 shipped as v0.9.0** (PR #66,
  merged 026dc374; pack refresh PR #65, merged bc318334,
  filed GMSI-86/GMSI-87/GMSI-88 from the 2026-10-25 gate
  runs): Simulate call + structured verdict reasons,
  closing spec DC-9/DC-10. A new Simulate RPC runs the
  identical verdict pipeline (one shared run_evaluation)
  with no-burn semantics — no vault seal or audit entry,
  no nonce/rate consumption and no PF counter recording
  (new ProtocolFirewall peek variants), empty
  handshake_token — and is marked simulation=true in the
  response AND inside the sealed proof; early blocks
  return Ok(BLOCK) with structured reasons instead of
  permission_denied, while real Evaluate behaviour is
  unchanged. Every verdict carries StructuredReason
  entries (rule_id + detail + remediation): Gatekeeper
  records the deciding check (PF-1/12/13/14/15/16/17/18,
  POLICY_RATE, SESSION, HMAC, SIGNATURE, ENVELOPE),
  Arbiter records POLICY / POLICY_ESCALATION; the proof
  carries the rule_ids. Built by OpenCode on the laptop
  in TWO lane runs (fresh clone
  D:\guardian-mesh-work\wo10 at refreshed main bc318334;
  the first lane stopped at ~50% and reported honestly,
  the continuation lane finished; lane commit b89384a;
  carried by Git-data API with tree equality asserted at
  each commit — lane tree 74988708, final tree 179c6fa7).
  Wright-verified independently: cargo 117/117 (90 lib +
  27 bin) from the workspace root on Linux (lane Windows
  116 = 89+27; one #[cfg(unix)] test); webui npm ci +
  build + lint + check:releases green (10 versions);
  wire proof 26/26 on a local daemon AND 26/26 on
  production over gRPC-Web through the shipped TS client
  (simulations left Health 0/0 and the audit log
  untouched; PF-12 simulation returns BLOCK + PF-12
  while the same envelope via Evaluate still
  permission_denies; proofs verify). Gate: PASS WITH
  FINDINGS — scanner BLOCKED only on the GMSI-6 "tests"
  false lead (eleventh occurrence); 0 secrets, 0 vulns
  (159 deps). F1 (High) the lane never updated the
  generated TS client (guardian_mesh_pb.client.ts):
  client.simulate missing — Wright's clean build failed
  TS2339 — and, Simulate sitting at service index 1,
  every existing client method index pointed at the
  wrong RPC; FIXED in the carry (simulate added at
  index 1, VerifyProof..CertificateStatus shifted to
  2..8). F2 (Low, fixed in carry): a simulation still
  ran the state-mutating TTL sweep; simulation proofs on
  the THROTTLE/final paths named the Vault though
  nothing is sealed; the missing-firewalled block had
  no ENVELOPE reason; the PF-15/16 fallback inverted
  the spec. F3 (Low, open): the Dashboard's simulate
  error path only console.errors. F4 (Low, fixed):
  lane CHANGELOG/releases test counts garbled. Filed
  GMSI-89 (above) from this run. Deployed to
  guardian.aimlds.org (site-integrity declaration
  cd38da62 opened + closed): aarch64 binary sha256
  34d1f818… cross-built from merged main (cargo-zigbuild;
  merged tree == gated tree 179c6fa7), installed
  (rollback guardian-meshd.bak-v085; webui-dist.bak-v085
  kept): production fingerprint dd2cf1a3… unchanged
  (ninth upgrade), both services active, box webui-dist
  carrying the base-/ build index-BVLu5-3_.js, Access
  302 intact, audit log at 1,185 entries (+1 = the
  proof Evaluate's seal; the cert issuance seals one
  more) with whole-log verification still reporting
  the historical break at position 557 (pre-fix
  history, stands as recorded), and the release
  certified itself on production — certificate
  cert-20261026-000037 (guardian-mesh 0.9.0, PASS WITH
  FINDINGS, evidence = the gate verdict sha256
  4f4b0451…), fingerprint recomputes, VerifyProof
  valid, supersedes cert-20261025-000036, status
  ACTIVE. v0.9.0 is a RELEASE CANDIDATE (one-week
  watched soak, RC register entry; graduates
  2026-11-01). Part C continues (WO-19, WO-10 done).
  Next: WO-11 (P1, Part C third in order — policy
  governance). Standing: dependabot PR #51 (vite bump)
  still open, outside the work orders.
- 2026-10-26 — **WO-11 shipped as v0.10.0** (PR #69,
  merged e2aeacba): policy governance (spec DC-18,
  DC-19, BM-6/BM-12) — signed versioned policy
  bundles (canonical serialization + SHA-256 content
  hash; genesis v1 = the previous defaults; fail-closed
  validation: version == current+1, prev_hash == current
  hash, no duplicate/invalid actions), a dual-control
  change path (ProposePolicyChange by a registered
  ML-DSA-65 policy admin, ApprovePolicyChange by a
  SECOND distinct registered admin; approval persists
  atomically via temp + rename, swaps under the write
  lock, audit-logs POLICY_CHANGE_APPLIED; no admins
  configured ⇒ change path refuses, publication still
  serves), a GetPolicy publication endpoint (bundle +
  hash + daemon signature over the canonical bytes +
  fingerprint + proposer/approver of record), and
  AuditProof.policy_version (proto field 8) on every
  verdict path including simulation. WebUI: read-only
  Dashboard policy display; no admin WebUI; multi-node
  propagation out of scope (single-node atomic swap;
  the bundle is the distributable unit). Built by the
  laptop lane (OpenCode, fresh clone
  D:\guardian-mesh-work\wo11 at refreshed main
  687534e9 — the pack had been refreshed the same night
  by PR #68 filing GMSI-90; lane commit a97b67d carried
  by API with tree equality asserted, 02a84b2f, then two
  Wright carry commits to gated tree efa76549 ==
  merged tree). Wright-verified independently: cargo
  137/137 at the workspace root (Linux; 136 Windows —
  one #[cfg(unix)] lib test; +20 over the 117 baseline);
  webui npm ci + build (drift guard: 11 versions) +
  lint green on a clean tree; wire proof through the
  shipped TS client 31/31 — genesis publication (hash
  recomputed in TS, daemon signature, fingerprint),
  policy_version 1 stamped on v1 proofs, unregistered /
  bad-signature refusals, dual-control propose/approve
  (same-principal approval refused), the verdict flip
  under v2 with policy_version 2, the POLICY_CHANGE_APPLIED
  audit entry, and restart persistence (v2 in force;
  the persisted file byte-for-byte the canonical
  bundle). Release gate: PASS WITH FINDINGS (scanner
  BLOCKED only on the GMSI-6 "tests" false lead, 12th
  occurrence; 0 secrets, 0 vulns / 159 deps). F1 (High,
  FIXED in Wright carry): the lane's generated TS
  message file declared the new policy interfaces +
  methods but no MessageType classes, and AuditProof's
  MessageType lacked field 8 — @ts-nocheck + Rollup
  globals kept build/lint green while the shipped
  bundle referenced undefined identifiers (runtime
  import failure) and TS clients dropped
  policy_version on decode; the carry adds all seven
  classes + the field, proven by the wire run. F2
  (Low, FIXED in carry): lane test-count arithmetic /
  placeholders corrected to verified counts. F3 (Low,
  OPEN): approval persists before the under-lock
  re-validation and swallows a record_policy_event
  error; no divergent state constructible in review.
  Filed GMSI-91 (above) from this run. Deployed to
  guardian.aimlds.org (site-integrity declaration
  a956ce80): aarch64 binary sha256 ec4ecc72…
  cross-built from merged main (cargo-zigbuild;
  merged tree == gated tree efa76549), installed
  (rollback guardian-meshd.bak-v090; webui-dist.bak-v090
  kept): production fingerprint dd2cf1a3… unchanged
  (tenth upgrade), both services active, box webui-dist
  carrying the base-/ build index-BSxUB-i_.js, Access
  intact, production wire proof 12/12 — genesis v1
  published with the identical content hash as the
  local daemon's (9b921513…), a change proposal
  refused with "unknown policy admin" (no admin
  registry configured on production — fail-closed by
  configuration, an operator decision), Evaluate
  ALLOW with proof policy_version 1; audit log at
  1,188 entries (+1 = the proof Evaluate's seal; the
  cert issuance seals one more) with whole-log
  verification still reporting the historical break
  at position 557 (pre-fix history, stands as
  recorded), and the release certified itself on
  production — certificate cert-20261027-000038
  (guardian-mesh 0.10.0, PASS WITH FINDINGS, evidence
  = the gate verdict sha256 c84dff34…), fingerprint
  recomputes, VerifyProof valid, supersedes
  cert-20261026-000037, status ACTIVE. v0.10.0 is a
  RELEASE CANDIDATE (one-week watched soak, RC
  register entry; graduates 2026-11-02). Part C
  continues (WO-19, WO-10, WO-11 done). Next: WO-12
  (P1, Part C fourth in order — revocation service).
  Standing: dependabot PR #51 (vite bump) still open,
  outside the work orders.
- 2026-10-27 — **WO-12 shipped as v0.11.0** (PR #71,
  merged 7e973a6d): revocation service (spec DC-14,
  EV-4, BM-12) — dual-control propose/approve
  revocation over the shared WO-11 admin registry
  for sessions (bus drop + firewall evict), client
  ML-DSA-65 keys (all bound sessions dropped;
  Handshake refused by key fingerprint), and
  certificates (registry revoke); approval applies
  synchronously under lock and measures propagation
  against the configured bound
  (GUARDIAN_MESH_REVOCATION_BOUND_SECS, default
  60 s); persistent fail-closed JSONL registry;
  REVOCATION_APPLIED audit events with failures
  surfaced, never swallowed; legacy
  RevokeCertificate refuses when an admin registry
  is configured; WebUI read-only revocation
  summary; multi-node propagation is WO-16 scope
  and is not claimed. Built by the laptop lane
  (OpenCode, fresh clone D:\guardian-mesh-work\wo12
  at main 626a729a; no pack refresh needed — no new
  GMSI had arrived; lane commit cfbfea6 carried by
  API with tree equality asserted, 453ac43a, then
  one Wright carry commit to gated tree 50ec2c4b ==
  merged tree). Wright-verified independently:
  cargo 160/160 at the workspace root (Linux;
  159 Windows — one pre-existing #[cfg(unix)] lib
  test; +23 over the 137 baseline); webui npm ci +
  build (drift guard: 12 versions) + lint green on
  a clean tree; wire proof through the shipped TS
  client 36/36 (all three kinds end-to-end,
  dual-control + signature refusals, change_id ==
  TS-computed SHA-256 of the canonical string,
  legacy-RPC tightening, REVOCATION_APPLIED audit
  entries, restart persistence). Release gate: PASS
  WITH FINDINGS (scanner BLOCKED only on the
  GMSI-6 "tests" false lead, 13th occurrence; 0
  secrets, 0 vulns). F1 (Low, FIXED in carry):
  CHANGELOG test arithmetic. F2 (Low, FIXED in
  carry): release-log "bound enforcement" wording —
  the bound is measured and reported, not
  watchdog-enforced. F3 (Low, OPEN): no propagation
  watchdog — single-node application is synchronous
  by construction; multi-node is WO-16. Filed
  GMSI-92 (above) from this run. Deployed to
  guardian.aimlds.org via gm-deploy: aarch64 binary
  sha256 0b612653… cross-built from merged main
  (cargo-zigbuild; merged tree == gated tree
  50ec2c4b), installed (rollback
  guardian-meshd.bak-v0100; webui-dist.bak-v0100
  kept); production fingerprint dd2cf1a3… unchanged
  (eleventh upgrade), both services active, box
  webui-dist carrying the base-/ build
  index-DVJt8f8u.js, Access intact (302),
  production wire proof 14/14 — Health SERVING with
  PF fields consistent with the measured rule
  counters, revocation summary bound 60 / total 0,
  a change proposal refused with "unknown policy
  admin" (no admin registry configured on
  production — fail-closed by configuration, an
  operator decision), Evaluate ALLOW with proof
  policy_version 1, VerifyProof valid; audit log
  at 1,430 entries with whole-log verification
  still reporting the historical break at position
  557 (pre-fix history, stands as recorded), and
  the release certified itself on production —
  certificate cert-20261028-000039 (guardian-mesh
  0.11.0, PASS WITH FINDINGS, evidence = the gate
  verdict sha256 a2f06539…), fingerprint recomputes,
  VerifyProof valid, supersedes cert-20261027-000038,
  status ACTIVE. Deploy note: gm-deploy's box E2E
  scored 15/16 — its Health check still expects the
  retired pre-WO-19 constant 18/18 and its bundled
  client does not decode Health field 6; the
  daemon's measured-counter behaviour was proven
  directly in the production wire proof, and
  box-e2e.mjs was left byte-identical to its
  pre-run state with the stale check filed as a
  harness finding. v0.11.0 is a RELEASE CANDIDATE
  (one-week watched soak, RC register entry;
  graduates 2026-11-03). Part C continues (WO-19,
  WO-10, WO-11, WO-12 done). Next: WO-14 (P2, Part
  C fifth in order — boundary authenticators).
  Standing: dependabot PR #51 (vite bump) still
  open, outside the work orders.
- 2026-10-28 — **WO-14 shipped as v0.12.0** (PR #73, merged
  0306cfd1; merged tree 80190737 == gated tree): boundary
  authenticators — authenticator framework classifying
  ML_DSA_65 / HMAC_SESSION / SPIFFE_X509
  (workload-attestation) / OPENPGP by factor and assurance
  (AZ-11); SPIFFE SVID attestation at the handshake (DER
  leaf validation, SAN-equality, trust-domain allowlist,
  validity window, possession proof bound to the session
  ML-DSA key; GUARDIAN_MESH_REQUIRE_SPIFFE fail-closed
  naming SPIFFE_X509 per BM-11); OpenPGP (Ed25519) second
  factor for enrolled admins on policy and revocation
  propose/approve; AuthenticatorStatus RPC (service index
  15) + Dashboard Boundary Authenticators section. NOT in
  v1 (declared in the CHANGELOG): SPIFFE trust-bundle
  chain verification (AZ-3 TARGET → PARTIAL) and mTLS
  transport termination. Release gate: PASS WITH FINDINGS
  (scanner BLOCKED only on the dispositioned block-buffer
  advisory, F1 — needs a panicking caller-supplied
  compress callback, the daemon registers none; fix
  exists only under digest 0.11). Lane evidence failure
  (F2): the lane's commit did not compile its bin tests
  (81 errors), all 16 of its authenticators tests failed,
  and the WebUI caller was broken; Wright carry fixed
  everything, including three production defects (F3):
  civil-date math ≈93 days off in SVID validity windows,
  the OpenPGP EdDSA construction (OpenPGP verifies over
  the digest bytes), and the signature R MPI form; plus
  8 integration tests (F4: gmClient caller). Wright-verified:
  cargo 185/185 (128 lib + 57 bin), WebUI build (drift
  guard 13 versions) + lint, wire proof 24/24 local and
  15/15 on production. Build deviation: pwsh on the
  laptop was wedged all night — the build still ran on
  the laptop via a cmd + Python CREATE_BREAKAWAY_FROM_JOB
  launcher (OpenCode exit 0). Filed GMSI-93, GMSI-94,
  GMSI-95 (above) from this run. Deployed to
  guardian.aimlds.org via gm-deploy (its build leg is
  broken — shell string run shell=False — so the deploy
  ran its documented --binary path with the exact printed
  cross-build command): aarch64 binary sha256 30b823b7…,
  rollback guardian-meshd.bak-v0110 + webui-dist.bak-v0110
  kept; production fingerprint dd2cf1a3… unchanged
  (twelfth upgrade); box webui-dist carrying
  index-nCDEk1v1.js == Wright's build and == the Pages
  asset; Access intact (302 to the Cloudflare Access login, verified from the box after two browser windows closed without a result; the public Pages /releases serves the 0.12.0 bundle index-nCDEk1v1.js — a live-browser read returned the profile's PWA service-worker cache of 0.11.0, a known artifact class, superseded by the direct served-asset read); self-certification
  cert-20261029-000040 (0.12.0, PASS WITH FINDINGS,
  evidence = gate verdict sha256 6eacbbf5…), superseding
  cert-20261028-000039; audit history break at position
  557 stands as recorded. gm-deploy's box E2E scored
  15/16 on the standing stale Health check (harness
  finding, third occurrence). v0.12.0 is a RELEASE
  CANDIDATE (one-week watched soak, RC register entry;
  graduates 2026-11-04). Part C continues (WO-19, WO-10,
  WO-11, WO-12, WO-14 done). Next: WO-13 (P2, Part C
  sixth in order — guardian attestation package).

- 2026-10-29 — **WO-13 shipped as v0.13.0** (PR #75, merged
  95f3fcac; merged tree 98ba7e9f == gated tree): guardian
  attestation package — build identity embedded by build.rs
  (git commit + SOURCE_DATE_EPOCH); HealthResponse appends
  build_version / build_commit / binary_sha256 (fields 7/8/9;
  the SHA-256 of the running executable, computed at runtime);
  attestation.rs provenance (in-toto/SLSA-v1 shape, canonical
  JSON, ML-DSA-65 sealed envelope, fail-closed verify in five
  named checks); gm-attest CLI (build/sign/verify);
  scripts/reproducible-build.sh; docs/ATTESTATION.md;
  Dashboard Guardian Attestation section. NOT in v1 (declared
  in the CHANGELOG): SLSA L3, transparency log, TPM measured
  boot — CP-19/CP-21/DC-17 TARGET → PARTIAL. Release gate:
  PASS WITH FINDINGS (scanner BLOCKED only on the
  dispositioned block-buffer advisory GHSA-qwgh-2vcv-g2f7,
  WO-14 F1). Wright-verified: cargo 193/193 (136 lib + 57 bin,
  Linux; lane Windows 134+1 PGP-fixture fail that passes on
  Linux/CI, bin suite Defender-blocked — GMSI-97), WebUI build
  (drift guard 14 versions) + lint, reproducible build —
  two clean builds IDENTICAL (SHA-256 a39725c6…) after the
  Wright carry fixed the lane's unrun script (F1, GMSI-96),
  gm-attest VALID / tamper-INVALID, Health wire proof exact.
  Deployed to guardian.aimlds.org via gm-deploy --binary:
  aarch64 binary sha256 f604dd67…, rollback
  guardian-meshd.bak-v0120 + webui-dist.bak-v0120 kept;
  production fingerprint dd2cf1a3… unchanged (thirteenth
  upgrade); box dist asset index-D5vvP-yQ.js == Wright's
  build == Pages asset; Access intact (302); production
  daemon reports binary_sha256 == the installed binary's
  real SHA-256 (f604dd67…) and build_commit 95f3fcac;
  the release attestation package was signed on the box
  with the production daemon key (signer fingerprint ==
  the pinned dd2cf1a3…), verified VALID against the
  installed binary, and published on the box at
  /opt/guardian-mesh/guardian-meshd-0.13.0.attestation.json;
  self-certification cert-20261030-000041 (0.13.0, PASS
  WITH FINDINGS, evidence = gate verdict sha256 8668cc8b…),
  superseding cert-20261029-000040. gm-deploy's box E2E
  scored 15/16 on the standing stale Health check (harness
  finding, fourth occurrence). v0.13.0 is a RELEASE
  CANDIDATE (one-week watched soak, RC register entry;
  graduates 2026-11-05). Part C continues (WO-19, WO-10,
  WO-11, WO-12, WO-14, WO-13 done). Next: WO-15 (P2, Part C
  seventh in order — multi-tenancy). Standing: dependabot
  PR #51 (vite bump) still open, outside the work orders.

- 2026-10-31 — **WO-15 built and merged as v0.14.0; deploy
  ROLLED BACK at production proof (gate F6)** (PR #78, merged
  f4437192; merged tree d55376ce == gated tree): multi-tenancy
  — tenant registry (GUARDIAN_MESH_TENANTS env), per-tenant
  policy bundles, ML-DSA key bindings, rate budgets and
  hash-chained audit partitions; handshake carries tenant_id
  (proto fields appended only); cross-tenant reads require
  ≥2 confirmations (BM-3) and leak zero numbers on refusal;
  new TenantStatus RPC; WebUI Multi-tenancy section;
  docs/MULTI_TENANCY.md. DC-15/DC-16 [TARGET] → [PARTIAL].
  Declared v1 limits: single-node in-process; budgets and
  partitions in-memory (reset on restart); no process
  isolation (CP-14 SC-39 not claimed); no tenant-policy
  admin RPC. Release gate: PASS WITH FINDINGS (F1 lane tree
  did not compile — fixed in Wright's carry, honestly
  reported by the lane; F2 gmClient tenantId — GMSI-98;
  F3 audit-partition appends on BLOCK/THROTTLE paths —
  GMSI-99; F4 bogus-session budget burn, OPEN fodder;
  F5 in-memory tenant state, OPEN declared). Wright-verified:
  cargo 213/213 (148 lib + 65 bin; baseline 193, +20 WO-15),
  WebUI build (drift guard 15 versions) + lint, raw
  gRPC-web wire proof 10/10 against a two-tenant daemon.
  Deployed via the gm-deploy sequence executed on the box
  (this VM's sandbox denies zig file writes — a
  VM-replacement policy change; the aarch64 binary,
  sha256 00f9a4e7…, was cross-built on the owner's laptop
  from merged main, and gm-deploy's own build leg remains
  broken — standing fodder): direct production proof of
  v0.14.0 was clean (Health SERVING, build_commit
  f4437192, binary_sha256 == installed, fingerprint
  dd2cf1a3… unchanged, TenantStatus summary [default]) BUT
  the box E2E scored 14/16 — PF-18 burst FAILED
  (allowed=89 throttled=0 other=26 vs v0.13.0's 100/15/0):
  the tenant budget runs before the Gatekeeper and converts
  burst excess into resource_exhausted errors, breaking the
  WO-5 THROTTLE-verdict contract (gate F6, GMSI-100).
  Production rolled back the same night to v0.13.0
  (guardian-meshd.bak-v0130 + webui-dist.bak-v0130
  restored; post-rollback E2E 15/16, PF-18 PASS, Health
  0.13.0/f604dd67…, Access 302). v0.14.0 is NOT deployed,
  NOT attested, NOT certified, no RC entry; v0.13.0's soak
  still graduates 2026-11-05. Standing corrections: PR #51
  merged before this run (main bf6126c8); dependabot PR #77
  (fast-uri + serialize-javascript) is the open one, outside
  the work orders — owner's call pending. Part C continues
  (WO-19, WO-10, WO-11, WO-12, WO-14, WO-13 done; WO-15
  merged, completion pending WO-15.1). Next: WO-15.1 (P1 —
  tenant-budget ordering fix, completes WO-15).

- 2026-11-02 — **WO-15.1 shipped as v0.14.1** (PR #81, merged b8d5d067):
  tenant-budget ordering fix completing WO-15 (gate F6 / GMSI-100),
  plus a defect the ordering fix exposed: WO-15's budget was a
  LIFETIME quota whose default (100) matched a per-second rate, so
  Gatekeeper-allowed calls permanently drained the tenant. RateBudget
  is now a true per-window rate budget (default window 1000 ms,
  GUARDIAN_MESH_TENANT_BUDGET_WINDOW_MS / tenant_budget_window_ms);
  TenantStatus used/remaining report the current window. The budget
  check runs AFTER Gatekeeper evaluation and gates only allowed
  requests; THROTTLE and BLOCK verdicts never consume budget and are
  never converted to resource_exhausted. F4 proven closed: a request
  with an unknown session id is rejected permission_denied with
  budget_used unchanged (regression test in tree). Wright-verified:
  cargo test 216/216 (baseline 213, +3), WebUI build + lint green,
  production harness twice at PF-18 PASS allowed=100 throttled=15
  other=0 (the exact v0.13.0 mix). Release gate: PASS WITH FINDINGS
  (F1 lane burst test flaky by construction — replaced with a
  deterministic ordering test, fixed; F2 the lifetime-quota defect,
  fixed; F3 stale Health check in the box harness, OPEN standing;
  F5 tenant state in-memory only, OPEN declared). Deployed to
  guardian.aimlds.org the same night via gm-deploy --binary
  (aarch64 sha256 4afff018…, cross-built on Wright's VM from
  merged main — the VM image lacks protoc, fetched 25.1 into
  the run dir; rollback guardian-meshd.bak-v0130 +
  webui-dist.bak-v0130 kept, bak-v0130 sha256 == the v0.13.0
  binary): box E2E 15/16 with PF-18 PASS (100/15/0) — gm-deploy
  exited "NOT certified" on the F3 stale check alone, and
  certification rests on the direct proof (Health SERVING,
  build_version 0.14.1, build_commit b8d5d067, binary_sha256
  == installed; TenantStatus summary [default]; both services
  active; Access 302; box dist asset == Wright's build ==
  Pages asset); attestation package VALID against the
  installed binary, signer fingerprint == the pinned
  dd2cf1a3…, published on the box; self-certification
  cert-20261103-000042 ACTIVE (evidence = gate verdict
  sha256 e2be4d42…), superseding cert-20261030-000041.
  v0.14.1 RC graduates 2026-11-09 on a clean week. WO-15 is
  COMPLETE. Standing fodder unchanged: PR #77 (dependabot)
  open — owner's call. Part C continues (WO-19, WO-10,
  WO-11, WO-12, WO-14, WO-13, WO-15 done). Next: WO-16 (P2,
  Part C eighth — clustered verdicts + degraded modes).

GMSI filed by this run's own gate: GMSI-112 — wall-clock-window
contracts (rate limiters, budget windows, freshness windows) must be
tested by controlling the window or the clock, never by racing real
time from a unit test; scale/volume contracts belong to the
production harness, unit tests prove ordering deterministically.
(Tonight's lane burst test failed exactly this way: sequential
pre-signed envelopes aged past the PF-15 5 s window before reaching
the rate window, and a concurrent variant raced the 1 s window
under full-suite CPU contention.)

WO-16 v1 slice run (2026-11-03, ninth nightly entry in this
ledger's run history): pack refreshed first (PR #83, GMSI-113…116).
Sources: no open issues; PR #77 (dependabot) open, owner's call.
WO-16 built on the laptop in a fresh clone (lane: OpenCode
big-pickle; lane's first completion claim overclaimed a commit —
caught by tree inspection, finished by a continuation pass,
commit 24d45f3). Wright verification: cargo 223/223 at v0.15.0
(227/227 at the v0.15.1 carry), WebUI build + lint green, normal
wire proof 3/3, degraded wire proof 8/8 (BLOCK rule DC-4, proof
issuing_node == Health node_id), DC-5 entry/exit proof on the
wire incl. marker lifecycle, audit-chain trigger proven by
single-byte log corruption. Gate PASS WITH FINDINGS
(guardian-mesh-wo16-2026-11-03): F1 PF-18 local environmental
(A/B-proven against a v0.14.1-base binary on the same VM —
production proof governs); F2 pre-auth DC-4 BLOCKs → GMSI-117;
F3 box-e2e stale Health check (OPEN, 8th occurrence); F4 (gate
addendum) the production audit history's 2026-10-26/27
concurrent-writer interleave (OPEN standing; never rewritten).
Shipped: PR #84 merged e741ca35 (v0.15.0) — deployed and ROLLED
BACK the same night (startup full-chain check vs the production
archive; box restored to v0.14.1, E2E 15/16 PF-18 PASS); fix
PR #85 merged 12212cce (v0.15.1, startup check scoped to the
live tail segment, proven against a copy of the real production
log before redeploy) — deployed, box E2E 15/16 PF-18 PASS
(100/15/0), Health SERVING / degraded=false / node_id
node-dd2cf1a350e0, binary sha256 02350e06… == installed ==
attested; attestation VALID signer == pin (one wrong-key
package caught by the pin check and re-signed; throwaway key
removed, never used by the daemon); self-cert
cert-20261104-000044 ACTIVE (evidence verdict+addendum
eb8fda18…). RC entry filed; v0.15.1 in soak to 2026-11-10;
v0.15.0 never entered soak. NOT RUN: cargo audit (tool absent),
Kali/Arch benches (not built, standing). Standing fodder carried:
PR #77 (owner's call); F3 stale harness check; gm-attest
--key-file parent-dir trap (it takes a key FILE path and uses
its parent — passing a directory silently generates a new key
one level up); WO-15 F5 in-memory tenant state. Next: WO-17
(P2, Part C ninth — conformance suite + chaos drills). WO-16
stays open for the DC-1/DC-3 cluster slice.

GMSI filed by this run's own gate: GMSI-117 (pre-authentication
degraded/BLOCK verdicts are a declared policy surface) and
GMSI-118 (startup/deploy integrity gates proven against the
production data they will judge).

WO-17 v1 run (2026-11-04, tenth nightly entry in this ledger's
run history): pack refreshed first (PR #87, GMSI-119). Sources:
no open issues; PR #77 (dependabot) open, owner's call. WO-17
built on the laptop in a fresh clone (lane: OpenCode big-pickle;
first session died on a TLS handshake error after editing, before
committing — a continuation pass reconciled the tree against the
task and committed 1005ccb; the continuation's own summary
overstated the file set and was corrected by Wright's direct diff
read: 8 files, +961/-3, main.rs +855/-0 tests-only). Wright
verification: cargo 240/240 (baseline 227, +13 conformance),
conformance filter 13/13, WebUI build + lint green, process-level
SIGKILL chaos proof 7/7 (restart SERVING, node_id stable;
corrupted-tail process leg NOT RUN — a Health-only workspace
holds no persisted audit log; proven in-suite), local box-e2e
14/16 (PF-18 local-environmental; stale Health check). Gate PASS
WITH FINDINGS (guardian-mesh-wo17-2026-11-04): F1 PF-18 local
environmental; F2 box-e2e stale Health check (OPEN, 9th
occurrence); F3 no per-request escalation approval path exists
(-> GMSI-120); F4 PF-15 exact 5000/5001 ms edge unexercised
(accepted, GMSI-112). Shipped: PR #88 merged 1aee18bc (v0.16.0);
box E2E 15/16 with PF-18 PASS (100/15/0) — gm-deploy's "NOT
certified" rests on F2 alone, as in the three prior releases;
production proof governs. Live: Health SERVING, degraded=false,
node_id node-dd2cf1a350e0, build 0.16.0@1aee18bc, binary sha256
a4f0cd98... == installed == attested; attestation VALID, signer
== pin dd2cf1a3...; self-cert cert-20261105-000045 ACTIVE
(evidence a851062b...); box dist asset index-DMSGxZF5.js ==
merged build == Pages asset; guardian.aimlds.org unauthenticated
302. RC entry filed; v0.16.0 in soak to 2026-11-11. NOT RUN:
cargo audit (tool absent), Kali/Arch benches (not built,
standing). Standing fodder carried: PR #77 (owner's call); F2
stale harness check; gm-attest --pin flag (WO-13 F3); WO-15 F5
in-memory tenant state; laptop->box bundle scp has no trust route
(base64-over-lane file recovery used instead). Next: WO-18 (P3,
Part C tenth — deployment matrix, sidecar form first). WO-17
stays open for the cluster chaos + CM-8 extensions (WO-27).

GMSI filed by this run's own gate: GMSI-120 (an escalated verdict
must have a provable resolution path, or be declared terminal).

WO-18 profile 1 retry run (2026-11-06, eleventh nightly entry):
the 2026-11-05 BLOCKED gate's single missing leg — the built
image — was produced and behaviour-proved, clearing the way to
ship v0.17.0. Sources: pack unchanged on main; the day's other
main commits (CI workflows, NOTICE, TEST-PLAN.md, one WebUI
page) carry no daemon-code delta — guardian-meshd/src verified
byte-identical between the gated tree and the merged tree. No
new Guardian Mesh Spec Inputs arrived; no pack refresh was
needed ahead of the build. Venue: the laptop's Docker Desktop
pulls fail identically from the SSH lane (interactive-session
credential binding; zero cached images), so the image was
built on Wright's VM with podman 4.9.3 (nested user namespace:
crun + cgroupfs manager + host networking; registry pulls via
the egress proxy's mirror cache; the proxy CA was
volume-mounted into the builder stage only — a build-time
mount, not a Dockerfile change and not in the image). Container
proof: guardian-mesh:0.17.0, 83.2 MB; Health SERVING, PF
18/18, build 0.17.0@9bda0b22; signed Evaluate ALLOW, proof
VALID; container box-e2e 15/16 fresh-boot (sole miss PF-18
burst timing on the contended sandbox VM); restart on the
same volume kept fingerprint e329cadb.../node and the
pre-restart proof verifies VALID after it; daemon uid 10001;
image env carries no secret. Wright re-verification on the
gated tree and again on the stamped tree: cargo 240/240,
conformance_ 13/13, WebUI ci+build+lint green; scanner PASS
(0 secrets, 0 vulns). Gate PASS WITH FINDINGS
(guardian-mesh-wo18-retry-2026-11-06): F1 PF-18
local-environmental (standing class); F2 base-image tags
float (low, standing); F3 one podman restart cycle SIGKILLed
under sandbox memory pressure (exit 137, OOMKilled=false, no
daemon error; plain start stable — environmental, not a
product finding); F4 the v0.16.0 public release-log entry
still carried TBD stamps on main — filled from its gate pack
in the same stamp carry. Stamps: CHANGELOG [0.17.0] dated
2026-11-06 (the ship date; the 2026-11-05 gate was BLOCKED,
so the lane's 2026-11-05 date would have been a false claim)
with tests + gate lines; release-log entries for 0.17.0 and
0.16.0 stamped. Shipped: PR #91 merged 3dd6aeb9 (CI green
incl. CodeQL; require-pr fails on the merge commit itself, as
it is not a PR — it passed on the PR pre-merge); cross-built
aarch64 via cargo-zigbuild (zig 0.13.0 fetched to the run dir;
gm-deploy's in-process build step cannot run its shell-string
command in this sandbox — the standing --binary route was
used); box E2E 15/16 with PF-18 PASS (100/15/0) — gm-deploy's
"NOT certified" rests on the stale Health-fields check alone,
as in prior releases; production proof governs. Live: Health
SERVING, degraded=false, node_id node-dd2cf1a350e0, build
0.17.0@3dd6aeb9, binary sha256 a2374b93... == installed ==
attested; attestation VALID, signer == pin dd2cf1a3...,
package at /opt/guardian-mesh/guardian-meshd-0.17.0.
attestation.json; self-cert cert-20261107-000046 ACTIVE
(evidence = retry verdict sha256 69629475...); box dist asset
index-m1MnmXPN.js (sha256 030f0f09...) == merged build ==
Pages asset; guardian.aimlds.org unauthenticated 302. RC
entry filed; v0.17.0 in soak to 2026-11-13. NOT RUN: kubectl
dry-run (no cluster context), cargo audit (tool absent; OSV
covered), Kali/Arch benches (not built, standing). Standing
fodder carried: PR #77 (owner's call); stale harness check
(10th occurrence); base-image digest pinning for the sidecar
form. Next: WO-18 profile 2 (DP-6 edge profile). WO-18 stays
open for profiles 2-4; WO-17 stays open for the cluster chaos
+ CM-8 extensions (WO-27); WO-16 stays open for DC-1/DC-3.

Guardian Mesh Spec Inputs filed by this run: none.

WO-18 profile 2 run (2026-11-07, twelfth nightly entry):
WO-18 profile 2 (DP-6 edge profile) built, verified, gated
and shipped as v0.18.0. Sources: main at run start 3d38e0c7
(unchanged since the 2026-11-06 ledger merge); pack 138,866 B
identical; open PRs only #77 (dependabot, owner's call,
untouched); no open issues; the day's four gate filings
(linktary-internal, verdict-internal, sovereign-internal,
play-mirror) grep-verified to carry no Guardian Mesh Spec
Inputs — no pack refresh was needed ahead of the build.
Build: laptop ONLINE (OpenCode 1.19.5); fresh clone
D:\guardian-mesh-work\wo18edge at 3d38e0c7, branch
wright/wo18-edge-profile; lane (free Zen big-pickle) produced
one commit, 9 files +409/-3, zero Rust files; tree recovered
by bundle, pushed tree 03f1da1b == lane tree asserted. The
lane's result file is honest and substantive: no daemon
ceiling setting exists (ceilings stay with the runtime), the
unset-port fallback is find_free_port() (the artifacts set
50051 explicitly), and the env example keeps the handshake
secret comment-only because an empty assignment would set an
empty secret. Wright verification on the pushed tree: cargo
240/240 (workspace root), conformance_ 13/13, WebUI
ci+build+lint green; scanner PASS (0 secrets, 0 vulns) on
the gated and stamped trees; systemd unit parse-verified
(systemd-analyze), compose YAML-verified. Behaviour proof:
image from the shipped Dockerfile unmodified (83.2 MB,
binary sha256 bcf9167d... == self-reported); container
Health SERVING 0.18.0@53cafe11, Evaluate ALLOW + proof
VALID, box-e2e 14/16; same-volume re-run kept fingerprint
589493fa... and the pre-restart proof verifies VALID (the
podman restart verb itself fails in this sandbox on a
user-lookup defect — remove+run on the same volume is the
equivalent leg). Offline: the image binary in a loopback-only
network namespace — egress to 1.1.1.1:443 and to the sandbox
proxy both "Network is unreachable" — Health SERVING,
Evaluate ALLOW, proof VALID. Footprint: RSS 5.8-10.2 MB,
peak VmHWM 10.6 MB after the burst suite, 6 threads. Gate
PASS WITH FINDINGS (guardian-mesh-wo18-edge-2026-11-07):
F1 PF-18 local-environmental (standing); F2 stale
Health-fields harness check (standing); F3 ceiling
enforcement NOT RUN (sandbox cgroup controllers not
delegated; knobs read/parse-verified, viability proven by
measured headroom) — GMSI-122 filed by this run; F4
base-image tags float (low, standing). NOT RUN also: cargo
audit (tool absent; OSV covered), Kali/Arch (not built).
Stamps carried (2111bfcf): CHANGELOG [0.18.0] tests + gate
lines, EDGE.md release record (measured footprint, offline
proof, the F3 naming), releases.ts verdict/tests — the
lane's "no measured numbers" honesty lines amended to point
at the release record they now live in. Shipped: PR #94
merged 6107c602 (CI all green incl. CodeQL on the stamped
head); cross-built aarch64 via cargo-zigbuild with
GUARDIAN_MESH_GIT_COMMIT=6107c602; gm-deploy --binary route
(first execute aborted cleanly on the missing merged-tree
WebUI dist — built, re-executed); box E2E 15/16 with PF-18
PASS (100/15/0), sole miss the standing stale Health-fields
check (11th occurrence) — gm-deploy's "NOT certified" rests
on that check alone, as in prior releases. Live: Health
SERVING, degraded=false, node node-dd2cf1a350e0, build
0.18.0@6107c602, binary sha256 3083e08d... == installed ==
attested; attestation VALID, signer == pin dd2cf1a3...,
package at /opt/guardian-mesh/guardian-meshd-0.18.0.
attestation.json; self-cert cert-20261108-000047 ACTIVE
(evidence = gate verdict sha256 a2385166...); box dist asset
index-BMYIWh8F.js (sha256 7c754e70...) == merged build ==
Pages asset; guardian.aimlds.org unauthenticated 302. RC
entry filed; v0.18.0 in soak to 2026-11-14. Standing fodder
carried: PR #77 (owner's call); stale harness check; base-
image digest pinning. Next: WO-18 profile 3 (CC-4 CLI).
WO-18 stays open for profiles 3-4; WO-17 stays open for the
cluster chaos + CM-8 extensions (WO-27); WO-16 stays open
for DC-1/DC-3.

Guardian Mesh Spec Inputs filed by this run: GMSI-122
(ceiling-enforcement venue), recorded in Part B above.

WO-18 profile 3 run (2026-11-08, thirteenth nightly entry):
WO-18 profile 3 (CC-4 CLI) built, verified, gated and shipped
as v0.19.0. Sources: main at run start 39bb194e — the only
movement since the 2026-11-07 ledger merge was PR #77
(dependabot webui npm group), merged by the OWNER himself
2026-11-08T18:55:49Z; the standing "owner's call" item is
closed by his own hand. Open PRs at start: none; open issues:
none. The day's four gate filings (linktary-checkfix,
linktary-magic-link-ttl, linktary-walkfix,
linktary-signin-mechanics) were grep-verified: only
linktary-magic-link-ttl carried a Guardian Mesh Spec Input
(counter-only, no-identifier metric for expired/used/invalid
auth callback outcomes). Filed as GMSI-123 by pack-refresh
draft PR #96 (commit d8e1a920, one-file diff verified), merged
d8e6b232; pack read-back on main: blob 680b3fea == pushed
blob, 144,905 B. (One early check-runs response for PR #96
showed a phantom failing JavaScript CodeQL run; the repo has
no JavaScript CodeQL workflow — three direct reads showed the
PR genuinely green.)
Build: laptop ONLINE (OpenCode 1.19.5); fresh clone
D:\guardian-mesh-work\wo18cli at d8e6b232, branch
wright/wo18-cli-profile. Lane run 1 died ~2 min in hunting the
tonic client API in the cargo registry (external_directory
permission auto-rejected by design; no files changed). Run 2
carried Wright's authoritative client-API reference in the
task (GuardianMeshClient::connect, proto field shapes, the
sealed-envelope/HMAC/seed idioms, "do not read outside the
project root") and completed: lane commit 439cd6b, 8 files
+1504/-4 (new gm.rs 1128 lines + docs/CLI.md; Cargo.toml
[[bin]] gm + version, VERSION, README, CHANGELOG, releases.ts,
edge compose tag; sidecar tags stayed 0.17.0 — they name their
introducing release). Lane tree 6afc2c50 == pushed tree
asserted via the bundle; the 3 apparent SFTP diffs were pure
CRLF. Lane result is candid (session-file endpoint precedence,
verify/audit sessionless, proof-file hex encoding all
disclosed). gm's contract: a verdict RETURNED in a response
(ALLOW/BLOCK/THROTTLE/ESCALATE) prints JSON and exits 0 — the
daemon's envelope-stage BLOCKs on real evaluates arrive as
permission_denied RPC errors and exit 1; simulate CODE_EXECUTE
returns its BLOCK in-response (both legs proven live).
Wright verification on the pushed tree (fresh tarball
checkout): the lane's code DID NOT COMPILE — build.rs had
.build_client(false) (server-only stubs, no client the CLI
could call), one ambiguous encode call, one unused import.
Carry fixes 91a53eeb + 1017fc42 (build_client(true); the
sealed_envelope encode idiom; import dropped) — the lane's
"no daemon change needed" note falsified by the compile
evidence, recorded on the PR and in the gate pack. After the
carry: cargo 246/246 (240 baseline + gm's 6 unit tests),
conformance_ 13/13, WebUI ci+build+lint green; scanner PASS
(0 secrets, 0 vulns, 0 must-gate failures) on the gated and
final trees. Behaviour proof (fresh local daemon on
127.0.0.1:50061, driven only through the built gm): health
SERVING 0.19.0; handshake exit 0, session file mode 600, no
session_key/seed in stdout; evaluate TOOL_CALL ALLOW + proof
saved; verify VALID; one flipped payload byte -> invalid exit
1 (CRC reason); audit 1 entry chain verified; no-session
evaluate exit 2 (empty stdout, stderr names handshake);
simulate CODE_EXECUTE BLOCK JSON exit 0 and its proof verifies
VALID; real CODE_EXECUTE BLOCK JSON exit 0 (Arbiter-stage);
unreachable health exit 2 empty stdout.
Gate PASS WITH FINDINGS (guardian-mesh-wo18-cli-2026-11-08):
F1 compile carry (High, fixed, above); F2 (Low, open)
evaluate stdout does not name the proof file; F3 base-image
tags float (low, standing). NOT RUN: cargo audit (tool
absent; OSV covered), Kali/Arch (not built).
Stamps carried (923c7073): CHANGELOG [0.19.0] tests + gate
lines, releases.ts tests + gateVerdict — the lane's
unverified numbers replaced with the verified ones; CI on
the stamped head all green (PR Gate, Rust CI, WebUI CI,
CodeQL Rust). Shipped: PR #97 merged f25cfd51; merged-tree
gm.rs + build.rs sha256-identical to the gated tree;
cross-built aarch64 via cargo-zigbuild with
GUARDIAN_MESH_GIT_COMMIT=f25cfd51 (the gm binary cross-built
in the same invocation — CC-4's acceptance includes the CLI
artefact itself); gm-deploy --binary route; box E2E 15/16
with PF-18 PASS (100/15/0), sole miss the standing stale
Health-fields check (12th occurrence) — gm-deploy's "NOT
certified" rests on that check alone, as in prior releases.
Live: Health SERVING, degraded=false, node
node-dd2cf1a350e0, build 0.19.0@f25cfd51, binary sha256
e280e5c8... == built == installed == attested; attestation
VALID, signer == pin dd2cf1a3..., package at
/opt/guardian-mesh/guardian-meshd-0.19.0.attestation.json
(signed on the box with the production key under
/home/ubuntu/guardian-mesh-data/workspace/keys/); self-cert
cert-20261109-000048 ACTIVE (evidence = gate verdict sha256
b93b379c...); gm (aarch64, sha256 e37a8455...) proven against
the production daemon on the box: health/handshake/evaluate
ALLOW/verify VALID; audit read reports the standing F4
interleave at entry 557 (documented since v0.15.1; live tail
clean). Box dist asset index-D1IKKPA3.js == merged build ==
Pages asset; guardian.aimlds.org unauthenticated 302. RC
entry filed; v0.19.0 in soak to 2026-11-15. Standing fodder
carried: stale harness check; base-image digest pinning; the
F4 production audit-history interleave (never rewritten, by
design). Next: WO-18 profile 4 (CC-5 MCP server surface) —
the LAST WO-18 profile; WO-18 closes when it ships.
WO-18 stays open for profile 4; WO-17 stays open for the
cluster chaos + CM-8 extensions (WO-27); WO-16 stays open
for DC-1/DC-3.

Guardian Mesh Spec Inputs filed by this run: GMSI-123
(auth-callback outcome counters, via the refresh PR) and
GMSI-124 (operator-surface smoke proof), recorded in Part B
above.
