# Guardian Mesh — Compliance Development Plan
## Building the missing compliances as evidence-producing machinery

**Date:** 2026-10-16
**Owner's directive:** "Build the compliances that are missing — write
them as a development plan for the Guardian Mesh."
**Source of the gaps:** `specs/STANDARDS_COMPLIANCE_REVIEW.md`
(2026-10-16), whose statuses this plan takes as its register.
**Governing rule:** compliance here is built the way the product is
built — a compliance claim exists only when machinery produces the
evidence for it, behaviour-proven (RG-10). Documents that describe
controls we do not run are not compliance; they are liabilities.

## How to read this plan

Each item names: the gap (with the review's status), the standard it
answers, the build, the **acceptance evidence** that closes it, its
dependencies, and its work order in the nightly pack
(`docs/nightly/OPENCODE-INSTRUCTIONS.md`). Items marked ORG are
organizational (AIMLDS the company) — they are planned here so the
whole picture is visible, but they are **not** nightly-build work and
never ride the OpenCode lane.

## Phase 1 — Language and risk (rides the current queue)

| # | Gap → build | Standard | Acceptance evidence | WO |
|---|-------------|----------|---------------------|----|
| 1.1 | **Terminology annex.** The repo uses ISO/IEC 22989's concepts without citing them (review: PARTIAL). Build: annex to the revised specification adopting 22989 terms — AI agent, AI system, human oversight, verification vs validation, trustworthiness characteristics — with every Guardian Mesh product term defined against them; 22989 + SC 42 family added to the §3 spine. | ISO/IEC 22989 | Annex merged; a term spot-check across README/specs finds no product term used against its 22989 meaning; review §1 status can move to ALIGNED. | WO-31 |
| 1.2 | **Threat model of record.** Named adversaries, assets, countermeasure mapping (prerequisite for risk work). | ISO/IEC 23894 (input), SG-1 | `specs/THREAT_MODEL.md` merged and referenced by a release gate run. | WO-30 |
| 1.3 | **AI risk register + process.** No formal risk register exists (review: 23894 PARTIAL). Build: `specs/RISK_REGISTER.md` — risks scored, owned, tied to threat-model entries and to the mitigations (shipped or WO) that answer them; the register is reviewed at every release gate run and the review is recorded in the gate verdict. | ISO/IEC 23894 | Register merged; one full release cycle shows the register reviewed in its gate record with at least one entry opened, mitigated, or consciously accepted. | WO-32 |

## Phase 2 — Attestation machinery (make compliance an export, not an essay)

| # | Gap → build | Standard | Acceptance evidence | WO |
|---|-------------|----------|---------------------|----|
| 2.1 | **Control evidence exporter.** The CP catalogue maps NIST families but no deployment can *produce* its control evidence (review: CSF/800-53 PARTIAL). Build: every CP checkpoint emits a machine-readable result per deployment (PASS / FAIL / N/A / NOT RUN + evidence pointer), exportable as an auditor pack mapped to NIST CSF 2.0 functions and SP 800-53 families, plus ISO/IEC 27001 Annex A themes. | NIST CSF 2.0, SP 800-53, ISO/IEC 27001 (support) | A live deployment exports a pack; a checker confirms every CP-01…CP-24 has a result and no result lacks an evidence pointer. | WO-29 (bar set here) |
| 2.2 | **NIST AI RMF profile.** No published profile (review: PARTIAL). Build: a profile document mapping Govern/Map/Measure/Manage to Guardian Mesh mechanisms (gate = Measure/Manage evidence; risk register = Map; policy governance = Govern) — documentation over machinery that exists or is Phase-1 built, no new claims. | NIST AI RMF 1.0 | Profile merged; every mapped function points at a real mechanism or an open WO — zero aspirational mappings. | WO-33 |
| 2.3 | **EU AI Act deployer pack.** The Act mapping lives in architecture prose (review: enabling control). Build: a customer-facing mapping from Guardian Mesh evidence outputs to deployer obligations — Art. 9 (risk management), Art. 12 (record-keeping), Art. 14 (human oversight), Art. 15 (robustness/cybersecurity) — generated from the same evidence exporter as 2.1. | EU AI Act | Pack produced from a real export (2.1), not hand-written; legal framing reviewed as "supports deployer obligations", never "compliant product". | WO-36 |

## Phase 3 — Cryptographic and supply-chain standing

| # | Gap → build | Standard | Acceptance evidence | WO |
|---|-------------|----------|---------------------|----|
| 3.1 | **Validated-module path (FIPS 140-3 GAP).** Our crypto is open-source crates, not a validated module — and never claimed otherwise. Build: a cryptographic provider boundary in the daemon (keys and signing behind a provider interface), a PKCS#11 provider so deployments can put keys in an HSM/KMS, and a documented *validated-module deployment profile* stating exactly which component carries the validation (the module vendor's certificate — cited, never implied to be ours). | FIPS 140-3 (via module), FIPS 203/204 (already implemented) | Daemon runs end-to-end with signing keys held in an external PKCS#11 token (software token in test); profile document merged; review §3 FIPS row can move to "GAP closed by deployment profile; module validation is the vendor's". | WO-35 (after WO-3) |
| 3.2 | **SLSA provenance.** Builds are reproducible by route but carry no published provenance (review: TARGET). Build: signed, reproducible release builds with provenance attestations published per release and public verification instructions. | SLSA L2+ | A stranger follows the published instructions and verifies one release's provenance from public artifacts alone. | WO-13 |

## Organizational track (AIMLDS — planned, staged, demand-led)

These are company certifications, not product features. They are
sequenced by the owner's worth doctrine: groundwork now, certification
spend only when a customer or contract actually requires it — never
certification theatre ahead of revenue.

| # | Item | Standard | Staging |
|---|------|----------|---------|
| O-1 | **AIMS groundwork.** AI policy, roles, and the risk process of Phase 1 operated as AIMLDS's management system in substance. | ISO/IEC 42001 | Operate the Phase-1/2 machinery as the system for two release cycles; gap-assess against the standard; certification decision only on customer demand. |
| O-2 | **ISMS groundwork.** Asset inventory, access review cadence, incident process — documented from practices already operated (gate records, access discipline). | ISO/IEC 27001 | Documentation pass after O-1 stabilizes; certification decision only on customer demand. |
| O-3 | **SOC 2 readiness.** Control evidence from the exporter (2.1) doubles as readiness evidence. | SOC 2 (CC6/CC7) | Deferred by design until a named customer requires a report; the exporter keeps the option cheap to exercise. |

## Continuous upkeep

- The compliance review is refreshed at each release (RG-3); a status
  may move only on the acceptance evidence named in this plan.
- The conformance suite (WO-17/WO-27) gains a compliance drift check:
  any public claim in README/site copy that outruns a review status
  fails the suite. Claims drift is treated as a defect, like code drift.
- This plan is complete when every row's acceptance evidence exists —
  at which point the review's headline reads: terminology ALIGNED,
  risk process OPERATING, attestation EXPORTED, crypto path DOCUMENTED
  AND RUNNING, provenance VERIFIABLE BY STRANGERS. Until then, the
  statuses in the review are the truth, in public, on purpose.
