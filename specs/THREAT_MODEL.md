<!-- Copyright (c) 2026 Nrupal Akolkar -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Guardian Mesh — Threat Model of Record

**Requirement:** SG-1 (`specs/GUARDIAN_MESH_REVISED_SPEC.md` §12).
**Status:** Live document, first issued with v0.22.0 (2026-11-10).
**Maintenance rule:** this model is reviewed at every release gate run;
the review (changed / unchanged, and why) is recorded in that release's
gate verdict. A release whose behaviour changes a threat, an asset, or
a countermeasure status and does not update this file is non-conforming
with SG-1. The AI risk register (WO-32, `specs/RISK_REGISTER.md`, per
ISO/IEC 23894) builds on this file and may not contradict it.

**Honesty rule (applies to every row below):** a countermeasure is
marked **[SHIPPED]** only when the behaviour exists in the shipped
daemon and is covered by tests or a gate behaviour proof; **[PARTIAL]**
when a named slice ships and a named slice does not; **[TARGET]** when
it is specified but not built. A threat whose countermeasures are
TARGET-only is an **open risk**, stated as such — never described as
covered. Statuses cite the revised specification's own labels and the
release record; where the specification's status label lags a shipped
release, this file says so explicitly.

License: Apache License 2.0 + Payment Rider (see `LICENSE` and
`LICENSE-RIDER.md`). This document describes the shipped single-node
daemon and its shipped client surfaces. It claims nothing for the
designed-not-built set (TEE attestation, multi-node/BFT consensus,
external anchoring, Lean 4 verification).

---

## 1. System in one page

Guardian Mesh is a verdict service: a caller asks *before* acting, the
daemon answers ALLOW / BLOCK / THROTTLE / ESCALATE, and every answer
carries a sealed, independently verifiable proof.

- **Daemon (`guardian-meshd`, Rust):** five internal stages — Sentinel
  (Protocol Firewall PF-1…PF-18), Gatekeeper (policy evaluation),
  Witness (proof sealing, ML-DSA-65), Arbiter (verdict composition),
  Vault (append-only hash-chained audit). gRPC API plus gRPC-web for
  the panel. Single-node today (DC-1/DC-3 clustering is [TARGET]).
- **Clients:** the WebUI panel (browser), the `gm` operator CLI
  (CC-4, v0.19.0), the `gm-mcp` MCP server surface (CC-5, v0.20.0) —
  all ordinary clients of the same API, none holding policy authority.
- **Evidence:** sealed proofs (EV-1), release-evidence certificates
  (WO-6 schema, `specs/CERTIFICATE_SCHEMA.md`), the audit hash chain,
  per-release signed build attestations (WO-13).
- **Deployment of record:** one daemon on a Linux host, panel served
  behind an authenticated proxy; the daemon's gRPC port is a local /
  tunneled surface, not a public internet surface.

## 2. Assets

| ID | Asset | Why it matters |
|----|-------|----------------|
| A-1 | Daemon signing key (ML-DSA-65) | Whoever holds it can mint proofs and certificates that verify as Guardian Mesh. The single highest-value secret in the system. |
| A-2 | Verdict integrity — the meaning of ALLOW | If an ALLOW can be produced without the Gatekeeper's decision, the product is void. |
| A-3 | Policy bundles (signed, versioned) | The rules everyone is judged by; a silent policy change is a silent verdict change. |
| A-4 | Audit trail (hash-chained) | The evidence history; rewriting it rewrites what the product claims happened. |
| A-5 | Proofs and certificates in circulation | Strangers rely on them offline (EV-1); a forgery that verifies destroys that reliance. |
| A-6 | Session keys + caller signing keys | Session keys are bearer <redacted> for a live session; caller ML-DSA-65 keys bind requests to callers. |
| A-7 | Tenant evidence and state | One tenant's policies, budgets, audit partition and certificates must never leak to or be damaged by another tenant. |
| A-8 | Action payloads in transit and at rest | Payloads can carry a caller's secrets or personal data; the guardian sees them by design and must not become a leak. |
| A-9 | Release artifacts + attestation chain | The binary a customer runs must be the binary the gate judged (BM-8). |
| A-10 | Verdict-path availability | A guardian too slow or too down to call gets bypassed (Doctrine 7); availability is a security property, bounded by the fail-closed rule. |
| A-11 | Guardian host and configuration | The host holds A-1 as a file; its compromise is the daemon's compromise (see TM-17). |
| A-12 | Time | Timestamps order proofs, bound certificate validity, and drive PF-15/PF-16; a moved clock moves all three. |

## 3. Adversaries

SG-1 names the first five; ADV-6 and ADV-7 are recorded because the
specification's own requirements (PC-2, SG-5/SG-7) already assume them.

| ID | Adversary | Capability assumed |
|----|-----------|--------------------|
| ADV-1 | **Malicious agent** — a guarded caller acting in bad faith | Holds a legitimate session; can send arbitrary envelopes, replay, flood, probe boundaries, and ignore verdicts it dislikes. |
| ADV-2 | **Compromised tenant** — one tenant's callers/keys taken over | Everything ADV-1 can do inside one tenant, plus attempts to cross BM-3 into other tenants' evidence, budgets, and policy. |
| ADV-3 | **Rogue administrator** — a legitimate admin (or stolen admin credentials) acting against the deployment | Can reach admin surfaces and policy workflows; attempts unilateral policy change, evidence suppression, or audit alteration. |
| ADV-4 | **Supply-chain attacker** — compromises a dependency, a build input, or a guarded tool/model | Ships code or tool behaviour the release process did not intend to judge; includes a guarded tool that changes after approval (rug-pull). |
| ADV-5 | **Network attacker** — on the path between caller, daemon, panel, or verifier | Can observe, delay, replay, and attempt to modify traffic; can probe any listening surface; cannot break ML-DSA-65 or the hash chain's cryptography. |
| ADV-6 | **Hostile guarded resource / tool** — the thing behind the verdict misbehaves | Executes more or other than the judged action, lies about execution, or is itself compromised. |
| ADV-7 | **Coercive or careless operator** — whoever runs the deployment host | Full host access (can read A-1, replace the binary, edit files); may be malicious, coerced, or simply mistaken. The model treats operator power as a threat to *evidence*, answered by detection, not by trust. |

Out of scope as adversaries: attackers with a break of ML-DSA-65 /
SHA-256 / CRC32C's *non-cryptographic* role (CRC32C is an integrity
check inside a signed envelope, never a security control on its own);
physical attackers with unsupervised hardware access beyond ADV-7's
host access; nation-state endpoint implants on the *caller's* machine
(the caller's own key custody is the caller's deployment decision —
see TM-18's residual risk).

## 4. Trust boundaries

The boundary map of §4 of the revised specification applies unchanged
(BM-1 caller → guardian, BM-2 guardian → guarded resource, BM-3
tenant → tenant, BM-4 node → node, BM-5 guardian → external verifier,
BM-6 administrator → policy, BM-7 edge → core, BM-8 build →
deployment). Two boundaries exist in shipped form today (BM-1, BM-3,
BM-5, BM-6, BM-8 in the slices named in the register); BM-4 does not
exist (no cluster — DC-1 [TARGET]); BM-2 is mediated by verdict only,
not by execution control (CM-2/CM-3 [TARGET], TM-04/TM-05); BM-7 ships
as the edge *deployment form* (DP-6, v0.18.0) with no edge → core
sync (BM-7 sync is design, recorded in `docs/EDGE.md`).

## 5. Threat register

Reading key: **Countermeasures** cite requirement IDs in
`specs/GUARDIAN_MESH_REVISED_SPEC.md` (and PF-xx in the formal
specification) with their honest status. **Residual risk** names what
remains true after the shipped countermeasures. **Closed by** names
the work order or gate item that retires the residual risk, where one
exists.

### Malicious agent (ADV-1)

#### TM-01 — Forged or tampered Evaluate envelope
The agent fabricates an envelope, or alters one in flight, hoping the
Gatekeeper judges bytes the caller never signed.
- **Countermeasures:** envelope CRC32C integrity (PF-6) [SHIPPED];
  ML-DSA-65 request-signature verification against the key bound at
  handshake (AZ-1, WO-1) [SHIPPED v0.3.0]; HMAC session proof (AZ-2)
  [SHIPPED]; the two together are BM-1's two confirmations (BM-9)
  [PARTIAL — shipped for BM-1; other boundaries are TARGET].
- **Residual risk:** a caller whose own signing key is stolen is
  indistinguishable from the caller until revocation (TM-17).

#### TM-02 — Replay of a captured envelope
A valid envelope is re-sent to re-issue a verdict or re-run an action.
- **Countermeasures:** PF-14 per-session nonce window (reuse →
  reject) [SHIPPED]; PF-15/PF-16 timestamp windows (stale > 5 s,
  future > 1 s) [SHIPPED]; session TTL ≤ 300 s default (CP-03)
  [SHIPPED].
- **Residual risk:** within the timestamp window and nonce rules,
  replay protection is per-session; a *new* session re-presenting an
  old action is a fresh judgement of that action, which is the
  product's intended behaviour, not a bypass.

#### TM-03 — Malformed-input attack on the verdict path
Oversized, deeply nested, or unknown-field payloads probe the parser
for a crash, a hang, or a lenient parse.
- **Countermeasures:** PF-1/PF-5 size bounds, PF-12 unknown-field
  rejection, PF-13 nesting depth ≤ 4 [SHIPPED v0.4.0]; fuzz targets
  for envelope decoding, payload parsing, proof verification (WO-8)
  [SHIPPED]; every rejection is audit-logged with step + error code
  (formal spec §1.4) [SHIPPED].
- **Residual risk:** fuzzing runs briefly per CI night, not
  continuously; a parser defect outside the three fuzzed boundaries
  is found by the gate's deep review or not at all.

#### TM-04 — Say-one-do-another execution
The agent obtains ALLOW for a benign action, then executes a
different one at the resource.
- **Countermeasures:** the sealed proof binds the exact action
  descriptor (EV-1) [SHIPPED] — a verifier can prove the executed
  action was never judged, after the fact. Execution tokens bound to
  the sealed action hash with a tool-side checker (CM-2) **[TARGET]**.
- **Residual risk — OPEN, high:** today nothing at the resource
  *prevents* the swap; detection is forensic (proof vs. what the
  resource did), and only where someone compares. **Closed by:**
  WO-20 (complete-mediation core).

#### TM-05 — Guardian bypass (direct resource access)
The agent simply never calls the guardian and talks to the tool,
API, or model directly.
- **Countermeasures:** none in the shipped daemon — Guardian Mesh is
  a verdict service a caller must actually call. Resource-side
  lockdown (CM-3), forced routing (CM-4), receipt reconciliation
  (CM-5), and coverage inventory with bypass alarms (CM-6) are all
  **[TARGET]** (WO-20, WO-21); the non-catalogued-invocation probe
  suite (CM-8) is **[TARGET]** (WO-27, extends WO-17).
- **Residual risk — OPEN, high, and structural:** a deployment that
  has not forced routing has an advisory guardian. Every public
  surface must keep saying so (honesty boundary); certificates carry
  no coverage statement until CM-7 ships (WO-21), so a certificate
  must never be read as "all paths are guarded".

#### TM-06 — Flood / resource exhaustion against the guardian
The agent (or many agents) saturates the verdict path so legitimate
callers time out — or route around the guardian (A-10).
- **Countermeasures:** PF-18 per-session rate limit, 100 msg/s →
  THROTTLE-grade reject [SHIPPED]; PF-1/PF-5 size bounds [SHIPPED];
  per-tenant per-window rate budgets (DC-15 slice, WO-15.1)
  [SHIPPED]; cheap-checks-first ordering on the Evaluate path
  (DC-8) [PARTIAL — shipped v0.4.0; line-rate proof is TARGET].
- **Residual risk:** the pre-handshake surface (TM-15) and raw
  network flooding are bounded by the deployment (host firewall,
  proxy), not by the daemon; per-deployment resource ceilings are
  enforced by systemd / the container runtime in the edge form, and
  ceiling *enforcement proof* is an open gate item (GMSI-122).

#### TM-07 — Payload-borne exfiltration
The agent encodes secrets or personal data into action payloads,
hoping the guardian's evidence (proofs, audit, certificates) becomes
the leak, or that an ALLOW launders the exfiltration.
- **Countermeasures:** proofs carry hashes and verdict data, not
  payload contents by default (CP-08) [PARTIAL — true of proofs;
  payload handling in audit is PC-1's subject]; payload secret/PII
  detection, audit redaction by default, and exfiltration block
  rules (PC-1) **[TARGET]** (WO-24).
- **Residual risk — OPEN:** payloads are visible to the daemon by
  design (A-8) and no shipped control inspects them for secrets.
  Deployments must treat the daemon host as in-scope for whatever
  data their agents carry.

#### TM-08 — Policy probing via simulation
The agent uses Simulate to map the policy exhaustively, then crafts
the one action that slips through.
- **Countermeasures:** Simulate runs the identical verdict logic and
  issues no execution rights; its proofs are marked as simulation
  (DC-9) [SHIPPED, WO-10]; probing is itself audited like any other
  request [SHIPPED].
- **Residual risk:** policy is *publishable to judged agents by
  design* (DC-19) [SHIPPED, WO-11] — the model assumes the judged can
  read the rules; security rests on the rules being right, not on
  their secrecy. A policy that is only safe while secret is a policy
  defect, filed as such when found.

### Compromised tenant (ADV-2)

#### TM-09 — Cross-tenant evidence or state access
The compromised tenant reads or alters another tenant's audit
partition, certificates, or policy (BM-3 crossing).
- **Countermeasures:** tenant-scoped policy, keys, budgets, and
  audit partitions (DC-15) [PARTIAL — shipped WO-15/WO-15.1
  v0.14.1; process isolation and cross-node isolation remain
  TARGET]; tenant isolation behaviour-proven in tests and in the
  conformance suite (DC-16) [PARTIAL — same slice]; tenant key
  binding at handshake (a session's key binds to its tenant)
  [SHIPPED].
- **Residual risk:** all tenants share one daemon process; a memory-
  safety or logic defect in the daemon is a BM-3 event. Rust, the
  fuzz targets (TM-03), and the conformance suite are the shipped
  mitigations; process-per-tenant isolation is not built.

#### TM-10 — Cross-tenant resource starvation
One tenant burns the shared budgets so other tenants' callers are
throttled or refused.
- **Countermeasures:** per-tenant per-window rate budgets that gate
  only Gatekeeper-allowed requests, so THROTTLE verdicts are never
  converted into budget errors for other tenants (WO-15.1, gate F6
  fix) [SHIPPED v0.14.1]; PF-18 per-session limits [SHIPPED].
- **Residual risk:** budgets meter *requests*, not CPU or memory; a
  tenant whose requests are individually expensive is bounded by
  deployment ceilings (TM-06), not by the budget.

### Rogue administrator (ADV-3)

#### TM-11 — Unilateral policy change
An admin swaps the policy bundle so future verdicts come out as the
admin wishes.
- **Countermeasures:** policy distributed as signed, versioned
  bundles; the bundle version is named in subsequent verdicts;
  changes are audit-logged (DC-18) [SHIPPED, WO-11]; policy readable
  by the judged (DC-19) [SHIPPED, WO-11], so a change is visible to
  its subjects. OpenPGP administrator authorization (AZ-4) [PARTIAL —
  v1 shipped WO-14 v0.12.0: Ed25519-only keys, SHA-256/SHA-512
  digests; when a PGP admin key directory is configured, the
  policy and revocation RPCs refuse operations whose signature is
  missing or invalid]. Dual control — a second principal on the BM-6
  crossing (BM-12) — is specified as additionally required for
  privileged crossings **[TARGET]** in the specification's label;
  the shipped dual-control change path is the WO-11 slice, and
  full BM-12 coverage of every privileged crossing (policy,
  revocation, release promotion) is not claimed.
- **Residual risk:** an admin who can also suppress the audit trail
  (TM-13) can hide a change; the controls compose, and SG-7
  (TM-13) is the open half.

#### TM-12 — Revocation abuse or refusal
An admin revokes a rival's sessions/keys/certificates — or refuses
to revoke a compromised one.
- **Countermeasures:** revocation of sessions, keys, and
  certificates with a propagation bound (default ≤ 60 s) (DC-14)
  [SHIPPED, WO-12 — single-node: propagation is immediate in-process;
  the bound matters when a cluster exists]; revocation events are
  audit entries [SHIPPED].
- **Residual risk:** the *decision* to revoke is an operator
  decision; no shipped control compels it (the compromise playbook,
  SG-6, is [TARGET] — TM-17).

#### TM-13 — Insider evidence suppression
One person both administers policy and handles evidence, and makes
an inconvenient verdict disappear.
- **Countermeasures:** the audit trail is append-only and
  hash-chained, so removal breaks the chain and is detectable on
  verification (CP-15, WO-4) [SHIPPED]; insider separation — no
  single administrator may both change policy and alter or suppress
  the audit trail (SG-7) **[TARGET]**; admin-plane RBAC (PC-6)
  **[TARGET]** (WO-26).
- **Residual risk — OPEN:** role separation is procedural today
  (deployment practice), not enforced by the daemon's own surfaces.

### Operator-level attacks on history (ADV-7)

#### TM-14 — Audit-history rewrite by the operator
The operator edits the audit files and re-computes the chain so
history says what the operator wants.
- **Countermeasures:** the hash chain makes any edit that does *not*
  recompute the whole tail detectable by the public read path's
  chain verification (CP-15) [SHIPPED]; per-release, the production
  daemon's self-certification seals the gate-evidence hash and the
  daemon's measured state (Health counters, EV-5) into a certificate
  whose fingerprint is recorded outside the host (release record)
  [SHIPPED as process, RG-3].
  Periodic external witnessing of the chain head (SG-5) is
  **[TARGET]** (WO-23).
- **Residual risk — OPEN, named plainly:** an operator who rewrites
  *and* re-chains the full history, before any head was recorded
  externally, produces a chain that verifies. The shipped defence is
  that heads are in fact recorded externally at every release and
  every certificate issuance seals measured state (EV-5, shipped
  v0.21.0); between those recordings, rewriting is detectable only
  against the last recorded head. The production audit history
  already carries one documented interleave segment (first break at
  entry 557, recorded since v0.15.1; the live tail is clean by
  design and history is never rewritten to hide it) — this model
  treats that record as the correct pattern: breaks are documented,
  never repaired away.

### Supply chain (ADV-4)

#### TM-15 — Malicious or vulnerable dependency ships in the daemon
A crate in the tree (or a build input) carries a defect or a
backdoor into the release.
- **Countermeasures:** the Release Gate on every release — machine
  scan (secrets, known vulnerabilities) + deep review incl. the
  dependency family (RG-1, RG-4, CP-20) [SHIPPED as process];
  signed, reproducible builds with published provenance (CP-19,
  DC-17) [PARTIAL — WO-13 v1 shipped; a second-party reproduction
  is the standing proof route]; fuzz + conformance suites in CI
  (RG-7) [PARTIAL — v1 shipped WO-17].
- **Residual risk:** base-image tags for the container forms float
  (standing gate finding, low); the scanner's vulnerability data is
  only as current as its OSV feed; `cargo audit` is NOT RUN in the
  reference gate environment (tool absent — recorded per RG-4 in
  every gate pack since v0.20.0).

#### TM-16 — Build → deployment substitution (BM-8)
The artifact deployed is not the artifact the gate judged.
- **Countermeasures:** per-release attestation — statement signed on
  the deployment host with the production key, verified against a
  pinned signing fingerprint before the release is called live
  (CP-21, DC-17) [PARTIAL — WO-13 v1]; the deployed binary's SHA-256
  is compared to the built binary's in every release proof
  [SHIPPED as process]; Health reports build identity (version +
  commit) [SHIPPED].
- **Residual risk:** measured boot / remote attestation of the
  *running* daemon (as opposed to the installed file) is [TARGET]
  (DC-17's remaining slice); an operator (ADV-7) can swap a binary
  after attestation — the swap is detectable at the next release
  proof or Health identity check, not prevented.

#### TM-17 — Guarded tool / model rug-pull
A tool the guardian judges changes its description, schema, or
behaviour after approval; or a model file is swapped before a
MODEL_LOAD the guardian allowed.
- **Countermeasures:** none shipped. Tool-manifest pinning with
  change detection and signed MODEL_LOAD provenance (PC-2) are
  **[TARGET]** (WO-25).
- **Residual risk — OPEN:** today the guardian judges the action as
  described at evaluation time; what the tool has become since is
  outside the verdict. Callers must not treat an ALLOW as a
  continuing warranty of the tool (liability boundary).

### Network attacker (ADV-5)

#### TM-18 — Traffic observation / manipulation between caller and guardian
The attacker reads payloads (A-8) or attempts a man-in-the-middle
against the gRPC / gRPC-web path.
- **Countermeasures:** verdict-path *integrity* does not depend on
  the transport: envelopes are signed (AZ-1), session-bound (AZ-2),
  and proofs verify offline (EV-1) [SHIPPED]. Transport encryption
  (CP-07: TLS 1.3 everywhere) is **[PARTIAL]** — terminated by the
  deployment (the production panel path is HTTPS through the
  hosting proxy; the daemon's gRPC listener itself is plaintext on
  its local/tunneled interface); workload mTLS (AZ-3) is
  **[TARGET]** — WO-14's shipped slice is a second-factor framework,
  not transport mTLS: SPIFFE SVID leaf structure + key possession
  are verified, the certificate chain to a trust bundle is NOT
  verified in v1, and no mTLS is terminated.
- **Residual risk — OPEN for confidentiality:** on any hop a
  deployment leaves unencrypted, payloads and verdicts are readable
  (verdicts are not secret; payloads may be — TM-07). A deployment
  MUST terminate TLS at or before the daemon; this model does not
  claim the daemon enforces it. Anti-downgrade negotiation rules
  (SG-2) are [TARGET]; with only AZ-1/AZ-2 shipped and both
  required, there is no weaker shipped method to downgrade *to* on
  BM-1 today — that changes the day AZ-3…AZ-9 land, and SG-2 must
  land with them.

#### TM-19 — Pre-handshake surface abuse
Before any session exists, the attacker probes whatever answers —
for information, for a crash, or to reach internal capabilities.
- **Countermeasures:** the pre-handshake surface is Health only, by
  design (SG-3) [PARTIAL — Health only today, as the specification
  records]; the handshake is a strict state machine admitting one
  shape per step (Doctrine 0) [SHIPPED]; a crossing that cannot
  produce its confirmations fails closed and is logged with the
  missing confirmation named (BM-11) [PARTIAL].
- **Residual risk:** Health answers unauthenticated by design (it
  is the liveness surface) and necessarily reveals version, build
  commit, node identity, and measured PF counters — deployments
  must treat those as public or restrict Health's reach; the
  machine-checked handshake proof (SG-11) is [TARGET].

#### TM-20 — Clock manipulation
The attacker (or a careless operator) moves the host clock to
stretch timestamp windows, resurrect expired sessions, or
back-date proofs.
- **Countermeasures:** PF-15/PF-16 windows bound how much a moved
  clock buys on the envelope path [SHIPPED]; certificate validity
  windows are sealed into the certificate and checked at
  verification (EV-3) [PARTIAL — schema shipped WO-6; lifecycle
  EV-4 remains TARGET in part]. Authenticated time (SG-10) is
  **[TARGET]**.
- **Residual risk — OPEN:** the daemon trusts the host clock within
  the PF windows; a host-level attacker (ADV-7) owns the clock.
  Deployments should run a disciplined time source; detection of
  manipulation is not shipped.

### The guardian itself

#### TM-21 — Signing-key compromise (A-1)
The daemon's ML-DSA-65 private key is read from its file (host
compromise, backup leak, insider) and used to mint proofs and
certificates elsewhere.
- **Countermeasures:** the key persists with 0600 permissions in
  the daemon workspace (DC-13 floor) [SHIPPED, WO-3]; Health
  publishes the key's *fingerprint* (hash, never material), and
  the production fingerprint is pinned in the release record — a
  substituted key changes the fingerprint and is visible to any
  verifier who checks the pin [SHIPPED]; revocation machinery
  (DC-14) [SHIPPED, WO-12] covers sessions/keys/certificates in
  the registry sense. HSM/KMS custody (DC-13 upper ladder) is
  [TARGET] (WO-35 validated-module path); the compromise playbook
  — canary keys, issuance-anomaly alarms, containment bound,
  disclosure timeline (SG-6) — is **[TARGET]**.
- **Residual risk — OPEN, highest severity in this model:** the key
  is a file on the host; ADV-7 (or any host compromise) has it.
  What limits the damage today: proofs issued before a compromise
  remain distinguishable *only if* their fingerprints/heads were
  recorded externally (TM-14's mitigation) — SG-5 (WO-23) is the
  structural fix, and until it ships this risk is carried, named,
  at every gate.

#### TM-22 — Guardian killed or wedged mid-verdict
The daemon dies (crash, OOM, operator kill) between evaluation and
sealing, or enters a state where it answers nothing.
- **Countermeasures:** fail-closed doctrine — no answer means
  BLOCK, on every client surface including `gm-mcp`'s explicit
  isError contract (Doctrine 4) [SHIPPED]; declared degraded modes
  with audited entry/exit (DC-4, DC-5) [SHIPPED v1, WO-16 v0.15.1 —
  the specification's [TARGET] label for DC-4/DC-5 lags this
  release]; in-process chaos legs: restart-fails-closed,
  corrupt-log detection, revoked-session stop (RG-8) [SHIPPED v1,
  WO-17].
- **Residual risk:** one daemon is one point of failure for
  *availability* (never for safety — it fails closed). Clustered
  verdicts (DC-1), per-node keys (DC-2), and threshold issuance
  (DC-3) are [TARGET]; multi-node chaos is untestable until a
  cluster exists (WO-16 remains open for DC-1/DC-3).

#### TM-23 — Forged certificate presented to a third party (BM-5)
Someone fabricates a certificate, or replays a real one outside its
scope, to claim Guardian Mesh certified something it did not.
- **Countermeasures:** certificates bind serial + issuer, the exact
  subject (item, commit SHA, artifact hash), policy bundle version,
  verdict + evidence-trail hash, validity window (EV-3) [PARTIAL —
  schema and issuance shipped WO-6 + WO-19 completion (measured
  pf_outcomes, EV-5, v0.21.0); lifecycle EV-4 completes with
  WO-21's coverage statement]; the sealed body is ML-DSA-65 signed
  and its fingerprint is the SHA-256 of the exact payload — any
  field change invalidates it (EV-2) [SHIPPED]; the liability
  boundary is printed on the product's surfaces: a certificate
  warrants only the exact item tested, against the policy named,
  on the date stamped.
- **Residual risk:** there is no public transparency log of
  issuance (PC-8 [TARGET]) — a stranger cannot yet enumerate what
  the guardian has issued; and scope confusion (`working-tree` vs
  `full-history`, EV-4) is a reading risk the schema names but a
  careless reader can still get wrong.

#### TM-24 — Escalation rubber-stamping
ESCALATE routes hard actions to a human who approves without
reading, converting the human factor into a rubber stamp.
- **Countermeasures:** the ESCALATE verdict machinery exists and
  carries the reason (WO-5) [SHIPPED]; approval-integrity controls
  — full context, anomaly flags on approval patterns, cooling-off
  on high-risk actions (SG-9) — are **[TARGET]**; the escalation
  queue with response-time commitments (DC-20) is **[TARGET]**.
- **Residual risk — OPEN:** today escalation is a verdict, not a
  staffed queue; a deployment that does not staff it has a dead
  end where the specification intends a human (PC-14 appeal path,
  [TARGET]).

#### TM-25 — End-of-life and tenant-exit residue
A decommissioned deployment or an exited tenant leaves keys,
evidence, or backups readable after the relationship ends.
- **Countermeasures:** owner-held data doctrine — evidence is the
  owner's property, exportable and deletable in full (Doctrine 6)
  [SHIPPED as doctrine]; verifiable destruction of keys/evidence
  and tenant-exit proof of deletion (SG-12) are **[TARGET]**.
- **Residual risk — OPEN:** no shipped mechanism *proves* deletion;
  exit is an operator procedure today.

## 6. Open risks at a glance

The threats whose deciding countermeasure is not shipped — the
honest centre of this model. Each is carried openly at the gate
until its closing work order ships.

| Threat | Open because | Closed by |
|--------|--------------|-----------|
| TM-04 say-one-do-another | CM-2 execution tokens not built | WO-20 |
| TM-05 guardian bypass | CM-3/CM-4/CM-5/CM-6 not built | WO-20, WO-21, WO-27 |
| TM-07 payload exfiltration | PC-1 not built | WO-24 |
| TM-13 insider evidence suppression | SG-7, PC-6 not built | WO-26 |
| TM-14 history rewrite (pre-head) | SG-5 external witnessing not built | WO-23 |
| TM-17 tool/model rug-pull | PC-2 not built | WO-25 |
| TM-18 payload confidentiality on unencrypted hops | CP-07 daemon-side, AZ-3 mTLS not built | WO-14 follow-on / deployment rule |
| TM-20 clock manipulation | SG-10 authenticated time not built | (unscheduled) |
| TM-21 signing-key compromise impact | SG-5, SG-6, HSM ladder not built | WO-23, WO-35 |
| TM-22 single-node availability | DC-1/DC-3 cluster not built | WO-16 (open) |
| TM-24 escalation rubber-stamping | SG-9, DC-20 not built | (unscheduled) |
| TM-25 exit residue proof | SG-12 not built | (unscheduled) |

## 7. What this model is not

- It is not a claim that any [TARGET] countermeasure exists. The
  labels are part of the model; softening one without shipping the
  behaviour is a specification violation (§10 of the revised
  specification, applied here).
- It is not a penetration test and not a cryptographic review; SG-8
  (independent eyes: external crypto review + third-party pentest
  before enterprise claims) remains [TARGET] and is the named gate
  for any enterprise claim.
- It does not model the *caller's* internal security (an agent
  framework that leaks its own signing key is TM-01/TM-21's residual
  risk, owned by that deployment).
- It does not cover the hosted website / marketing surfaces; those
  are ordinary web properties under the fleet release gate, not
  verdict surfaces.

## 8. Review log

| Date | Release | Review |
|------|---------|--------|
| 2026-11-10 | v0.22.0 | First issue (WO-30). Register TM-01…TM-25 against the shipped system at v0.21.0 + this release's SG-1 status change. Several of the revised specification's status labels lag shipped releases (among them DP-3, CC-4, CC-5, DC-4/DC-5, DC-9, DC-14, DC-18/DC-19); this model follows the release record and notes the lag where a row depends on it (e.g. TM-22). Spec-label reconciliation is a documentation follow-up, not a behaviour gap. |
