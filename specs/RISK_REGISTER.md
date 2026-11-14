<!-- Copyright (c) 2026 Nrupal Akolkar -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Guardian Mesh — AI Risk Register

**Standard:** ISO/IEC 23894:2023 (AI risk management guidance).
**Work order:** WO-32 (`docs/nightly/OPENCODE-INSTRUCTIONS.md`).
**Status:** Live document, first issued with v0.27.0 (2026-11-14).
**Source of record for identification:** `specs/THREAT_MODEL.md`
(SG-1). This register builds on the threat model and may not
contradict it: every register entry is one threat-model entry,
scored, owned, and given a treatment. Where this file and the
threat model disagree, the threat model governs and the register
is corrected at the next gate review.

**Maintenance rule:** this register is reviewed at every release
gate run; the review (entries opened, mitigated, re-scored,
consciously accepted, or unchanged — and why) is recorded in that
release's gate verdict. A release whose behaviour changes a
threat, a countermeasure status, or a residual risk and does not
update this register is non-conforming with WO-32, exactly as the
same omission is non-conforming with SG-1 for the threat model.

**Honesty rule (applies to every row below):** a score may be
lowered only by a shipped countermeasure or by a recorded,
owned acceptance — never by re-wording. A countermeasure marked
[TARGET] in the threat model contributes nothing to a residual
score. No entry in this register claims a control that the threat
model does not claim.

License: Apache License 2.0 + Payment Rider (see `LICENSE` and
`LICENSE-RIDER.md`). ISO/IEC 23894 is guidance, not a certifiable
standard; this register claims alignment with its process, never
certification to it. Scope is the shipped single-node daemon and
its shipped client surfaces, exactly the threat model's scope.
The designed-not-built set (TEE attestation, multi-node/BFT
consensus, external anchoring, Lean 4 verification) is out of
scope and carries no entries.

---

## 1. The risk process (ISO/IEC 23894)

The register is operated as a cycle, not written as a monument:

1. **Establish context.** The system, its assets (threat model
   §2, A-1…A-12), its adversaries (§3, ADV-1…ADV-7), and its
   trust boundaries (§4, BM-1…BM-8) are defined by the threat
   model. Risk criteria are the scales and acceptance rule in
   §2 of this file; they change only by a recorded amendment to
   this file, reviewed at a gate run.
2. **Identify.** The threat model is the identification source of
   record: a threat that reaches the model gets a register entry
   in the same release. New identification also arrives as
   release-gate findings (Guardian Mesh Spec Inputs) and as
   gate-run NOT RUN items; an input that names a new risk class
   opens a threat-model entry first, then a register entry.
3. **Analyse.** Each entry is scored inherent (no countermeasure
   beyond a baseline host/OS) and residual (with the shipped
   countermeasures at the current release), on the §2 scales.
   The analysis basis is the threat model's own countermeasure
   and residual-risk text — the register adds scores, owners, and
   treatment decisions, never new technical claims.
4. **Evaluate.** Residual scores are compared against the §2
   acceptance rule at every gate review. The gate verdict records
   the evaluation outcome for every entry at High or Critical
   residual, and for every entry that changed.
5. **Treat.** Each entry carries one treatment, chosen from:
   *mitigate* (a named closing work order ships the deciding
   countermeasure), *accept* (the residual is consciously carried
   — §2 rule), *avoid* (the feature or claim is not offered —
   e.g. no enterprise claim is made while SG-8 is [TARGET]), or
   *transfer* (never claimed in this register: no insurance or
   contractual instrument is in place, and none is implied).
6. **Monitor and review.** The gate review is the monitoring
   point: scores, statuses, and treatments are re-examined
   against the release that carries the review. Event-driven
   review triggers are named per entry in the register table.
7. **Communicate and record.** This file is the record; its
   change log (§5) is the history. Gate verdicts cite the review;
   the CHANGELOG cites the verdict. A deployer reading this file
   sees the same scores the gate saw — there is no internal
   register with different numbers.

**Owners** are accountable roles, one per entry:

| Role | Owns |
|------|------|
| Product owner (AIMLDS) | Risk acceptance decisions; the claims made for the product |
| Guardian Mesh engineering | Daemon, client, and protocol countermeasures |
| Release Gate operator | The gate process, its benches, and the evidence packs |
| Deployment operator | Host, configuration, time source, and deployment-form controls |
| Policy administrator | Policy bundles, revocation decisions, escalation staffing |

---

## 2. Scales and acceptance rule

**Likelihood** (of the threat being realised in a year of
ordinary deployment):

| L | Anchor |
|---|--------|
| 1 | Rare — requires an unusual conjunction; no known instance |
| 2 | Unlikely — a determined actor or an uncommon failure |
| 3 | Possible — a capable actor with access, or a plausible failure |
| 4 | Likely — a routine actor with access, or an expected failure |
| 5 | Almost certain — available to any actor, or continuous |

**Impact** (worst credible outcome for verdict integrity,
evidence, or the deployer):

| I | Anchor |
|---|--------|
| 1 | Negligible — cosmetic; no verdict or evidence effect |
| 2 | Minor — limited, recoverable; no reliance harmed |
| 3 | Moderate — a deployment degraded or a control weakened |
| 4 | Major — evidence or verdicts for a deployment are unreliable |
| 5 | Severe — forged verdicts/certificates verify, or the signing key is compromised: the product's core claim fails |

**Score** = L × I. **Bands:** Low 1–4 · Medium 5–9 · High 10–16 ·
Critical 17–25.

**Acceptance rule.**
- A **Critical** residual blocks a release unless the product
  owner consciously accepts it, in the gate verdict, with the
  treatment and the closing work order named.
- A **High** residual must be named in the gate verdict with its
  treatment at every release until it falls below High.
- **Medium** and **Low** residuals are carried by their owners
  and reviewed on the standing cadence.
- Acceptance is per release cycle, never perpetual: an accepted
  Critical or High entry is re-accepted, mitigated, or escalated
  at the next gate review.

---

## 3. Register

Reading key: **Inherent** = L × I with no Guardian Mesh
countermeasure. **Treatment / mitigations** = the threat model's
countermeasures with their honest status, and the work order that
closes the residual where one exists. **Residual** = L × I with
the countermeasures shipped at v0.26.0. **Review trigger** is in
addition to the standing per-release gate review.

| ID | Risk (threat-model source) | Inherent | Treatment / mitigations | Residual | Owner | Review trigger |
|----|----------------------------|----------|-------------------------|----------|-------|----------------|
| RR-01 | Forged or tampered Evaluate envelope is judged as genuine (TM-01) | 3×5 = 15 High | Mitigate — shipped: CRC32C integrity (PF-6), ML-DSA-65 request-signature verification (AZ-1, WO-1), HMAC session proof (AZ-2). Residual is the stolen-caller-key case, scored at RR-21's custody problem, not here | 1×5 = 5 Medium | Guardian Mesh engineering | Any AZ-family change |
| RR-02 | Captured envelope is replayed to re-issue a verdict or re-run an action (TM-02) | 4×3 = 12 High | Mitigate — shipped: PF-14 nonce window, PF-15/PF-16 timestamp windows, session TTL ≤ 300 s (CP-03) | 2×3 = 6 Medium | Guardian Mesh engineering | Any PF-14…PF-16 change |
| RR-03 | Malformed input crashes, hangs, or leniently parses on the verdict path (TM-03) | 4×4 = 16 High | Mitigate — shipped: PF size/field/depth bounds, fuzz targets (WO-8). Residual: fuzzing is per-CI-night, not continuous; an unfuzzed boundary is found by gate review or not at all | 2×4 = 8 Medium | Guardian Mesh engineering | New parser or payload class |
| RR-04 | Agent obtains ALLOW for a benign action and executes a different one (TM-04) | 4×5 = 20 Critical | Mitigate — CM-2 execution tokens [SHIPPED] v0.26.0 (WO-20): a resource embedding the `ExecutionChecker` refuses a mismatched action. Residual: a resource that does not embed the checker cannot be prevented, only detected forensically. **Closes on WO-27** (deployment conformance) | 3×5 = 15 High | Guardian Mesh engineering | WO-27 conformance results |
| RR-05 | Agent bypasses the guardian entirely and calls the resource directly (TM-05) | 5×5 = 25 Critical | Mitigate + accept — CM-3 [PARTIAL] v0.26.0 (checker hook); CM-4 forced routing, CM-5 receipt reconciliation, CM-6 coverage inventory are [TARGET] (**WO-21**); conformance probes CM-8 (**WO-27**). Until routing is forced the guardian is advisory — every public surface must keep saying so, and no certificate carries a coverage statement until CM-7 (WO-21) | 4×5 = 20 Critical | Product owner (AIMLDS) | WO-21 / WO-27 progress; any coverage claim |
| RR-06 | Flood or exhaustion makes the guardian too slow or too down to call (TM-06) | 4×4 = 16 High | Mitigate — shipped: PF-18 per-session limits, size bounds, per-tenant budgets (DC-15 slice). Residual: pre-handshake and raw-network flooding are deployment-bounded; ceiling-enforcement proof is open gate item GMSI-122 | 3×3 = 9 Medium | Deployment operator | GMSI-122 proof; any ceiling change |
| RR-07 | Secrets or personal data ride action payloads into the guardian's evidence (TM-07) | 4×5 = 20 Critical | Mitigate — PC-1 payload detection, audit redaction, exfiltration rules are [TARGET] (**WO-24**). Shipped today: proofs carry hashes and verdict data, not payload contents (CP-08, partial). Deployments must treat the daemon host as in-scope for whatever data their agents carry | 4×4 = 16 High | Guardian Mesh engineering | WO-24 progress; any payload-handling change |
| RR-08 | Simulation probing maps the policy, then the one slipping action is crafted (TM-08) | 4×2 = 8 Medium | Accept by design — Simulate issues no execution rights, its proofs are marked simulation (DC-9), probing is audited, and policy is publishable to the judged (DC-19): security rests on the rules being right, not secret. A policy only safe while secret is filed as a policy defect | 4×1 = 4 Low | Policy administrator | Any policy-defect finding |
| RR-09 | Compromised tenant crosses into another tenant's evidence, budgets, or policy (TM-09) | 3×5 = 15 High | Mitigate — DC-15 tenant scoping [PARTIAL] (WO-15/WO-15.1), DC-16 isolation behaviour-proven for the shipped slice, tenant key binding at handshake [SHIPPED]. Residual: all tenants share one daemon process; process-per-tenant isolation is not built | 2×5 = 10 High | Guardian Mesh engineering | Any DC-15/DC-16 change; cluster work (WO-16) |
| RR-10 | One tenant starves the shared budgets so other tenants are refused (TM-10) | 3×3 = 9 Medium | Mitigate — shipped: per-tenant per-window budgets that gate only Gatekeeper-allowed requests (WO-15.1); PF-18. Residual: budgets meter requests, not CPU or memory | 2×3 = 6 Medium | Guardian Mesh engineering | Any budget-semantics change |
| RR-11 | Rogue administrator changes policy unilaterally and future verdicts follow (TM-11) | 3×5 = 15 High | Mitigate — shipped: signed, versioned bundles named in verdicts and audit-logged (DC-18); policy readable by the judged (DC-19); OpenPGP admin authorization [PARTIAL] (AZ-4, WO-14). Residual: full dual control (BM-12) over every privileged crossing is [TARGET]; composes with RR-13 | 2×5 = 10 High | Policy administrator | Any BM-6 surface change |
| RR-12 | Revocation is abused against a rival, or refused for a compromised key (TM-12) | 3×4 = 12 High | Mitigate — shipped: revocation with propagation bound (DC-14, WO-12), revocation events audited. Residual: the *decision* to revoke is an operator decision no shipped control compels (compromise playbook SG-6 is [TARGET], RR-21) | 3×3 = 9 Medium | Policy administrator | Any revocation incident |
| RR-13 | Insider suppresses inconvenient evidence — one person holds policy and evidence (TM-13) | 3×5 = 15 High | Mitigate — shipped: append-only hash-chained audit (CP-15) makes removal detectable. SG-7 insider separation and PC-6 admin RBAC are [TARGET] (**WO-26**). Residual: role separation is procedural today, not daemon-enforced | 3×4 = 12 High | Product owner (AIMLDS) | WO-26 progress |
| RR-14 | Operator rewrites audit history and re-chains it before any head is recorded externally (TM-14) | 2×5 = 10 High | Mitigate — shipped: hash chain + per-release external recording of chain heads and sealed measured state (EV-5, RG-3 process). SG-5 periodic external witnessing is [TARGET] (**WO-23**). History breaks are documented, never repaired away (the entry-557 segment is the standing example) | 2×4 = 8 Medium | Release Gate operator | WO-23 progress; any chain-break record |
| RR-15 | Malicious or vulnerable dependency or build input ships in the daemon (TM-15) | 3×5 = 15 High | Mitigate — shipped as process: release gate on every release (RG-1, RG-4, CP-20), signed reproducible builds [PARTIAL] (CP-19/DC-17, WO-13), fuzz + conformance in CI [PARTIAL] (RG-7). Residual: container base-image tags float (standing Low gate finding); scanner data is only as current as its OSV feed | 2×5 = 10 High | Release Gate operator | Any dependency-family gate finding |
| RR-16 | The artifact deployed is not the artifact the gate judged (TM-16) | 3×5 = 15 High | Mitigate — per-release attestation signed on the deployment host and verified against the pinned fingerprint before the release is called live (CP-21/DC-17, [PARTIAL], WO-13); deployed-vs-built SHA-256 compared in every release proof; Health reports build identity. Residual: measured boot of the *running* daemon is [TARGET]; a post-attestation swap is detectable, not prevented | 2×4 = 8 Medium | Release Gate operator | Any attestation-chain change |
| RR-17 | Guarded tool or model changes after approval (rug-pull) and the ALLOW is read as a continuing warranty (TM-17) | 4×4 = 16 High | Mitigate — PC-2 tool-manifest pinning, change detection, and signed MODEL_LOAD provenance are [TARGET] (**WO-25**); nothing is shipped. The liability boundary is the interim control: an ALLOW judges the action as described at evaluation time | 4×4 = 16 High | Guardian Mesh engineering | WO-25 progress |
| RR-18 | Payloads and verdicts are read or altered on an unencrypted caller↔guardian hop (TM-18) | 4×4 = 16 High | Mitigate — verdict integrity does not depend on transport (AZ-1, AZ-2, EV-1 shipped). Transport encryption CP-07 is [PARTIAL] (deployment-terminated); workload mTLS AZ-3 is [TARGET]. Residual: confidentiality on any hop a deployment leaves unencrypted; a deployment MUST terminate TLS at or before the daemon — the daemon does not enforce it | 3×4 = 12 High | Deployment operator | Any AZ-3 / CP-07 change; new deployment form |
| RR-19 | Pre-handshake surface is probed for information, a crash, or internal reach (TM-19) | 4×3 = 12 High | Mitigate — Health-only pre-handshake surface (SG-3, [PARTIAL]: Health only today), strict handshake state machine, fail-closed crossings (BM-11, [PARTIAL]). Residual: Health necessarily reveals version, build commit, node identity, and PF counters — deployments treat those as public or restrict Health's reach | 3×2 = 6 Medium | Guardian Mesh engineering | Any pre-handshake surface change |
| RR-20 | Host clock is moved to stretch windows, resurrect sessions, or back-date proofs (TM-20) | 2×4 = 8 Medium | Mitigate — shipped: PF-15/PF-16 windows bound what a moved clock buys; certificate validity windows are sealed and checked (EV-3, [PARTIAL]). SG-10 authenticated time is [TARGET] (unscheduled). Residual: the daemon trusts the host clock within the PF windows; a disciplined time source is a deployment duty | 2×4 = 8 Medium | Deployment operator | Any time-source incident |
| RR-21 | Daemon signing key (A-1) is compromised and used to mint proofs and certificates (TM-21) | 3×5 = 15 High | Mitigate + accept — shipped: 0600 key file (DC-13 floor), fingerprint pinning in the release record, revocation machinery (DC-14). The deciding treatments are [TARGET]: SG-5 external witnessing (**WO-23**), the SG-6 compromise playbook, HSM/KMS custody (**WO-35**). The threat model's highest carried risk: the key is a file on the host, and host compromise is key compromise until those ship | 3×5 = 15 High | Product owner (AIMLDS) | WO-23 / WO-35 progress; any host incident |
| RR-22 | Guardian dies or wedges mid-verdict, or answers nothing (TM-22) | 3×4 = 12 High | Mitigate — shipped: fail-closed doctrine on every client surface, declared degraded modes (DC-4/DC-5, WO-16 v1), in-process chaos legs (RG-8, WO-17). Residual: one daemon is one point of failure for availability — never for safety; clustering (DC-1/DC-3) is [TARGET], WO-16 stays open | 3×3 = 9 Medium | Guardian Mesh engineering | Cluster work (WO-16); any availability incident |
| RR-23 | Forged or out-of-scope certificate is presented to a third party as Guardian Mesh certification (TM-23) | 3×5 = 15 High | Mitigate — shipped: certificates bind serial, subject, policy version, verdict, evidence hash, and validity (EV-3, [PARTIAL]); sealed ML-DSA-65 body whose fingerprint is the payload hash (EV-2); liability boundary printed on the surfaces. Residual: no public issuance transparency log (PC-8 [TARGET]); scope confusion remains a reader risk the schema names | 1×5 = 5 Medium | Product owner (AIMLDS) | Any certificate-schema change (WO-21) |
| RR-24 | ESCALATE is rubber-stamped by a human who approves without reading (TM-24) | 4×3 = 12 High | Mitigate — ESCALATE machinery with reasons is shipped (WO-5). Approval-integrity controls SG-9 and the staffed escalation queue DC-20 are [TARGET] (unscheduled). Residual: today escalation is a verdict, not a staffed queue; a deployment that does not staff it has a dead end where the specification intends a human | 4×3 = 12 High | Policy administrator | Any escalation-surface change; staffing decision |
| RR-25 | Decommissioned deployment or exited tenant leaves keys, evidence, or backups readable (TM-25) | 3×4 = 12 High | Mitigate — owner-held data doctrine (evidence exportable and deletable in full) is [SHIPPED as doctrine]. SG-12 verifiable destruction and tenant-exit proof of deletion are [TARGET] (unscheduled). Residual: no shipped mechanism *proves* deletion; exit is an operator procedure today | 3×3 = 9 Medium | Deployment operator | Any tenant exit or decommission |

---

## 4. Residual risk at a glance

The entries the §2 acceptance rule keeps in front of the gate,
highest first. Every entry here is named in each gate verdict
until it falls below its band.

| ID | Residual | State |
|----|----------|-------|
| RR-05 guardian bypass | 20 Critical | Open — treatment WO-21 + WO-27; consciously accepted per cycle (§5) |
| RR-07 payload exfiltration | 16 High | Open — treatment WO-24 |
| RR-17 tool/model rug-pull | 16 High | Open — treatment WO-25 |
| RR-04 say-one-do-another | 15 High | Mitigated v0.26.0 (CM-2); closes on WO-27 conformance |
| RR-21 signing-key compromise | 15 High | Open — treatments WO-23 + WO-35; consciously accepted per cycle (§5); the threat model's highest carried risk |
| RR-13 insider evidence suppression | 12 High | Open — treatment WO-26 |
| RR-18 payload confidentiality on unencrypted hops | 12 High | Open — deployment rule + AZ-3 target |
| RR-24 escalation rubber-stamping | 12 High | Open — SG-9 / DC-20 unscheduled |
| RR-09 cross-tenant access | 10 High | Partially mitigated — shared-process residual |
| RR-11 unilateral policy change | 10 High | Partially mitigated — BM-12 full coverage target |
| RR-15 dependency / build input | 10 High | Process-mitigated — standing gate family |

All other entries sit at Medium or Low residual and are carried
by their owners on the standing cadence.

---

## 5. Change log — the review history

An entry is added at every gate review that opens, mitigates,
re-scores, accepts, or closes an entry — and a review that
changes nothing still adds its line (that is what makes the
cadence auditable).

| Date | Release | Review |
|------|---------|--------|
| 2026-11-14 | v0.27.0 | First issue (WO-32). Register RR-01…RR-25 issued 1:1 against TM-01…TM-25 at the shipped state of v0.26.0; inherent and residual scores as tabled in §3. **RR-04 recorded MITIGATED in the v0.26.0 cycle** (CM-2 shipped, WO-20: residual 20 Critical inherent → 15 High; not closed — closes on WO-27 deployment conformance). **RR-05 (residual 20 Critical) and RR-21 (residual 15 High) CONSCIOUSLY ACCEPTED for this cycle** by the product owner via this release's gate verdict, treatments named (WO-21/WO-27; WO-23/WO-35), re-acceptance due at the next gate review. SG-1 threat-model maintenance review performed in the same verdict: no threat, asset, or countermeasure status changes — the register consumes the model as issued. This review is the acceptance evidence named by compliance plan item 1.3 (register reviewed in the gate record, with entries mitigated and consciously accepted). |
