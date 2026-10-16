# Guardian Mesh — Standards Compliance Review
## ISO/IEC 22989 and the cybersecurity standards family

**Date:** 2026-10-16
**Scope:** The `nrupala/guardian-mesh` repository at main `2e6a35d`
(specifications, documentation, shipped behaviour through v0.4.0).
**Nature of this review — read first:** this is an **alignment review**,
not a certification. Guardian Mesh and AIMLDS hold no ISO, SOC 2, or FIPS
certification, and nothing in this document claims one. Where a standard
is a *product* standard, the status describes the product; where it is an
*organizational* standard (ISO/IEC 27001, ISO/IEC 42001, SOC 2), the
status describes what the product does to **support a deployer's**
compliance — the deployer's certification remains the deployer's.
ISO/IEC texts are licensed documents; this review is assessed against
their published structure, scope, and terminology.

Status key: **ALIGNED** (substance in place, evidence in repo) ·
**PARTIAL** (substance in part; named gap) · **TARGET** (in the revised
specification, not yet built) · **GAP** (no coverage yet) · **N/A**
(not applicable at this layer).

---

## 1. ISO/IEC 22989:2022 — AI concepts and terminology

22989 is the JTC 1/SC 42 vocabulary standard: it defines the terms the
rest of the AI standards family uses (AI agent, AI system, autonomy,
trustworthiness and its characteristics, human oversight, verification
vs validation) so that standards, regulators, and builders mean the
same thing by the same words. Conformance here is **terminology
conformance of our documents**, and the verdict is:

**Status: PARTIAL — substance aligned, form undocumented.**

Guardian Mesh's working concepts sit squarely inside the standard's
frame — it governs *AI agents* (entities that sense, decide, and act),
it is a control in the *AI system* lifecycle (deployment/operation
stage), and its product claims are trustworthiness claims. But the repo
contains **no terminology annex and no normative reference to 22989**;
our key terms are used consistently yet defined only by our own specs.

### 1.1 Terminology mapping (repo term → 22989 concept → finding)

| Guardian Mesh term | ISO/IEC 22989 concept | Finding |
|---|---|---|
| Agent / caller | **AI agent** — an automated entity that senses and responds to its environment and takes actions to achieve its goals | Aligned. Our guarded caller is exactly this when it is an AI agent; the spec should say so and note callers may also be non-AI actors (the standard's term does not cover those). |
| The guarded system | **AI system** — an engineered system generating outputs (content, forecasts, recommendations, decisions) for human-defined objectives | Aligned. Guardian Mesh stands in the operation stage of the AI system lifecycle. |
| Verdict (ALLOW/BLOCK/…) | No direct term — closest: a **control** decision in operation; ESCALATE maps to **human oversight** (incl. human-on-the-loop / human-in-command patterns) | Aligned with a naming note: our escalation is the standard's human-oversight concept and should be documented as such. |
| Proof verification | **Verification** — confirmation that specified requirements have been fulfilled | Aligned, and usefully precise: proof-checking is verification. What we sometimes loosely call "validation" of a deployment is, in 22989 terms, validation (fulfilment of intended use) — docs must not blur the two. |
| Verifiability / proof-carrying verdicts | **Trustworthiness** characteristics: transparency, accountability, controllability, robustness, resilience | Aligned in substance. Our doctrine "verifiability is the product" is a trustworthiness claim and inherits the duty to evidence each characteristic claimed. |
| Policy | Related to the objectives/constraints set by the **AI system's stakeholders** (deployer/owner roles in the lifecycle) | Aligned; role names in our specs (owner, deployer, caller, verifier) should be pinned to the standard's role vocabulary. |

### 1.2 Actions (22989)

1. Add a **terminology annex** to the revised specification adopting
   22989 terms for agent, AI system, oversight, verification/validation,
   and the trustworthiness characteristics, with our product terms
   defined against them. (New work order WO-31.)
2. Reference 22989 normatively in the revised specification's standards
   spine (§3), alongside the SC 42 family below.

## 2. The SC 42 family around 22989

| Standard | What it is | Status | Evidence / gap |
|---|---|---|---|
| ISO/IEC 23894:2023 | AI risk management guidance | **PARTIAL** | Risk thinking exists (revised spec §12, gate practice); no formal risk register or risk process per the standard. WO-30 (threat model of record) is the first artifact; a risk register follows it. |
| ISO/IEC 42001:2023 | AI management systems (organizational, certifiable) | **N/A as certification; product supports deployers** | AIMLDS operates no AIMS today. Guardian Mesh is positioned as a control a deployer's AIMS can cite (monitoring, record-keeping, human oversight). |
| ISO/IEC 24028:2020 | Trustworthiness in AI — overview | **ALIGNED (approach)** | GM's trustworthiness characteristics (transparency of verdicts, accountability via sealed proofs, controllability via policy + escalation) follow its framing. |
| ISO/IEC 23053:2022 | Framework for AI systems using ML | **ALIGNED (positioning)** | GM is deliberately model-agnostic: it guards the action boundary of an AI system whatever its ML framework — consistent with the standard's component view. |
| ISO/IEC 5259 series | Data quality for analytics & ML | **N/A (product layer)** | GM does not train on data. Payload handling quality is PC-1/WO-24 territory, tracked there. |
| NIST AI RMF 1.0 | US AI risk framework (Govern/Map/Measure/Manage) | **PARTIAL** | The release gate performs Measure/Manage-like functions for our own releases; no formal AI RMF profile published. Companion to 23894 in the roadmap. |

## 3. Cybersecurity standards

| Standard | Status | Evidence / gap |
|---|---|---|
| NIST CSF 2.0 | **PARTIAL** (spine of spec §3) | The revised specification's checkpoint catalogue (CP-01…CP-24) is organized on CSF functions for the product; the organizational functions (Govern, Identify) remain the deployer's. |
| NIST SP 800-53 Rev. 5 | **PARTIAL** | CP catalogue cites control families (IA, AC, SC, AU, CM, IR, RA, SI). No control-by-control attestation exists; PC-7 (compliance exports) is the mechanism that will produce it per deployment. |
| NIST SP 800-207 (Zero Trust) | **ALIGNED (architecture) / TARGET (implementation)** | Doctrine 0 + the boundary map (§4) are zero-trust by construction: per-request authentication + authorization, no network-location trust. Clustered/attested implementation is DC-family target work. |
| ISO/IEC 27001:2022 | **Not certified; product supports deployer controls** | GM supports Annex A themes A.5.15 (access control), A.8.2 (privileged access), A.8.15 (logging), A.8.16 (monitoring), A.8.13 (backup — PC-15). AIMLDS holds no ISMS certification and claims none. |
| CIS Controls v8.1 | **PARTIAL** | Mapped in spec §3 (Controls 3, 5, 6, 8, 13 cited at checkpoints). Full safeguard-level mapping is a PC-7 export artifact, not yet produced. |
| FIPS 203 (ML-KEM) / FIPS 204 (ML-DSA) | **ALIGNED — implemented** | ML-DSA-65 signatures are shipped (v0.3.0+); ML-KEM-768 is the formal spec's key-encapsulation default. Post-quantum by design, not by roadmap. |
| FIPS 140-3 (cryptographic modules) | **GAP — not claimed** | Our cryptography comes from open-source Rust crates, not a FIPS 140-3 validated module. Any deployment requiring validated modules must supply them (HSM/KMS custody, DC-13) — stated here so it is never implied otherwise. |
| OWASP ASVS / Agentic AI risks | **PARTIAL** | Protocol Firewall = input-validation family at the verdict path (shipped). Agentic-specific risks map to §11/§13 (tool poisoning PC-2, delegation PC-3) — TARGET. |
| SLSA (supply chain) | **TARGET L2+** | WO-13 (signed reproducible builds + provenance). Not yet true; never described as true. |
| SOC 2 (AICPA TSC) | **Not attested; product supports deployer criteria** | GM evidence (proofs, audit chain) supports a deployer's CC6/CC7 evidence. No SOC 2 report exists for AIMLDS. |
| EU AI Act | **Enabling control (deployer obligations)** | Architecture v2 already maps human oversight (Art. 14) to the Arbiter/escalation design; GM's sealed logs support Art. 12 record-keeping and verdict governance supports Art. 9/15 programmes of deployers. GM is a component in a deployer's compliance, never a compliance claim of its own. |

## 4. Headline findings

1. **22989 (the ask): PARTIAL.** The product's concepts are the
   standard's concepts, but the repo never says so. One annex (WO-31)
   closes the form gap; the substance gap is near zero.
2. **Strongest ground:** cryptography (FIPS 203/204 implemented, in
   production, behaviour-verified) and zero-trust architecture
   (800-207-aligned by construction at the single-node layer).
3. **Honest gaps, by name:** FIPS 140-3 validated modules (not claimed),
   SLSA provenance (target), formal AI risk register per ISO/IEC 23894
   (starts with WO-30), any organizational certification — ISO/IEC
   27001, 42001, SOC 2 — **none held, none claimed**.
4. **The pattern:** Guardian Mesh is strongest exactly where it can
   issue proof, and the compliance story inherits the product doctrine —
   every status above is checkable against the repo, and TARGET never
   reads as done.

## 5. Maintenance

This review is refreshed at each release alongside the gate record
(RG-3) and re-issued when a status changes. Terminology upkeep rides
WO-31; risk-register upkeep rides WO-30.
