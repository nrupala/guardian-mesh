# Guardian Mesh Revised Specification
## Deployable Security Tooling for Every Endpoint — Protocol, Boundaries, Evidence

**Version:** 3.0
**Date:** 2026-10-15
**Classification:** Public — Engineering Specification
**Status:** Governing target specification. Supersedes the scope and
architecture direction of *Guardian Mesh Architecture v2.0* (2026-05-14)
and extends *Guardian Mesh Formal Specification v1.0-draft* (2026-05-14),
which remains the wire-protocol law for the sealed envelope and the
Protocol Firewall (PF-1…PF-18) until a section here says otherwise.
**Inputs folded in:** the original specifications; the owner's direction of
2026-10-15 (universal deployment; boundary mapping with at least two
confirmations; authorization by any lawful method, PGP/GPG included);
the data-center readiness review of 2026-10-14; the Release Gate and its
security-testing criteria (gate skill `local-release-gate`, including all
Guardian Mesh Spec Inputs filed to date); and the published security
best-practice frameworks of the hyperscalers (§3).

---

## 0. Conventions and honesty labels

- **MUST**, **MUST NOT**, **SHALL**, **SHOULD**, **MAY** follow RFC 2119.
- Every requirement carries an ID and a status label:
  - **[SHIPPED]** — implemented and behaviour-verified in a released version.
  - **[PARTIAL]** — implemented in part; the gap is named.
  - **[TARGET]** — specified, not yet built. No surface, document, or person
    may describe a [TARGET] item as existing capability.
- Where this specification and the shipped code disagree, the code and its
  tests are the record of the present, this document is the record of the
  target, and the discrepancy is filed in the gap analysis — never silently
  papered over.
- Cryptographic defaults inherit the formal specification: ML-DSA-65
  (FIPS 204) signatures, ML-KEM-768 (FIPS 203) key encapsulation,
  Blake3-256 hashing unless a section names otherwise.
- System-level implementation only: the daemon and every
  performance/security-critical component are Rust (POSIX-class system
  languages: Rust, C, C++). No interpreted language ships as a product
  component (owner's doctrine, 2026-10-14).

## 1. Product definition — deployable security tooling

Guardian Mesh is a **deployable security tool**: a guardian that stands in
front of an actor's actions, evaluates each action against policy before it
executes, and returns a deterministic verdict with sealed, portable proof.
It is built to be deployed anywhere actions need guarding, and to be used
by every kind of caller.

### 1.1 Deployment classes (DP)

| ID | Requirement | Status |
|----|-------------|--------|
| DP-1 | The daemon MUST run on cloud instances of every major cloud (AWS, Azure, Google Cloud, Oracle Cloud) and on provider-neutral Linux servers, with no cloud-vendor lock-in in the core. | [PARTIAL] — Linux x86_64 + aarch64 builds shipped; per-cloud packaging is target |
| DP-2 | The daemon MUST run on bare metal and inside KVM-class virtual machines; demo and prototype systems that must scale are kept as Linux VMs, not containers (fleet platform rule, 2026-10-15). | [PARTIAL] |
| DP-3 | A container/sidecar form SHOULD be provided for orchestrated workloads (Kubernetes sidecar beside the guarded workload). | [TARGET] |
| DP-4 | An endpoint profile MUST run on laptops and desktops (Windows, macOS, Linux) guarding local agents and tools. | [TARGET] |
| DP-5 | A mobile profile SHOULD run on phones (Android first), guarding on-device agents within the platform sandbox. | [TARGET] |
| DP-6 | An edge profile MUST run on resource-capped edge and server-class endpoints (small ARM/x86 gateways, industrial PCs) with configurable memory/CPU ceilings and offline verdict operation. | [TARGET] |
| DP-7 | A browser-resident client (the WebUI/PWA) MUST remain a first-class surface wherever a full daemon cannot run. | [SHIPPED] |
| DP-8 | All profiles MUST speak the same verdict protocol and produce interchangeable proofs; a proof issued by any profile verifies on every other. | [PARTIAL] — one daemon + web client today |

### 1.2 Caller classes (fully configurable, every interface friendly)

| ID | Requirement | Status |
|----|-------------|--------|
| CC-1 | **Agents** MUST be able to handshake, evaluate, verify proofs, simulate (§6.4), and read their own budgets/state (§6.5) programmatically. | [PARTIAL] |
| CC-2 | **Humans** MUST have a graphical surface (web panel) presenting verdicts, policy, and evidence in plain words, jargon one layer down. | [SHIPPED] |
| CC-3 | An **API** (gRPC + gRPC-web) MUST expose every capability; no capability may exist only in a UI. | [PARTIAL] |
| CC-4 | A **CLI** MUST provide handshake/evaluate/verify/audit operations for operators and scripts. | [TARGET] |
| CC-5 | **Software** integrators MUST get client libraries and an MCP server surface, so agent frameworks consume Guardian Mesh as a tool. | [TARGET] |
| CC-6 | **Systems** MUST integrate through machine exports: webhooks, SIEM/GRC feeds, `/.well-known` discovery, signed JSON evidence. | [PARTIAL] — discovery + signed JSON on the public site; feeds target |
| CC-7 | Every deployment MUST be **fully configurable**: policy, rate budgets, assurance requirements (§5), endpoints, and evidence retention are configuration, never code changes. | [PARTIAL] |

## 2. Doctrine

1. **Judge before execution.** No guarded action executes on an ALLOW that
   has not been issued for that exact action.
2. **Verifiability is the product.** Every verdict carries sealed proof a
   stranger can check without trusting the guardian (§8).
3. **The tool calculates, the user decides.** Policy belongs to the
   deploying owner; Guardian Mesh enforces and evidences it.
4. **Fail closed.** Any check that cannot complete denies the action.
   Degraded operation (§6.2) narrows what is allowed; it never widens it.
5. **Liability is bounded by the certificate.** A certificate warrants only
   the exact item tested and the exact test recorded — never the deployer's
   subsequent choices.
6. **Local-first, owner-held data.** Evidence is the owner's property,
   exportable in full, deletable in full.
7. **Speed is a security property.** The verdict path is budgeted (§6.3);
   a guardian too slow to call is a guardian that gets bypassed.

## 3. Control framework alignment — endpoints and checkpoints

Guardian Mesh checkpoints are aligned to the security specification
best practice published across the industry. The **spine** is framework
neutral: NIST CSF 2.0 (Govern/Identify/Protect/Detect/Respond/Recover),
NIST SP 800-53 Rev. 5 control families, NIST SP 800-207 (zero trust),
CIS Controls v8.1, ISO/IEC 27001:2022, OWASP ASVS, and SLSA for supply
chain. The **hyperscaler mappings** adopt the published frameworks of the
clouds Guardian Mesh deploys to:

- **AWS** — Well-Architected Framework, Security Pillar (SEC01–SEC10) and
  the Foundational Security Best Practices; checkpoint analogues: IAM,
  KMS, CloudTrail, GuardDuty, Security Hub, Verified Access.
- **Google Cloud** — Security Foundations blueprint and the BeyondCorp /
  BeyondProd zero-trust programmes; analogues: Cloud KMS/HSM, Security
  Command Center, Assured Workloads.
- **Microsoft Azure** — Microsoft Cloud Security Benchmark (MCSB v1) and
  the Azure Well-Architected security guidance; analogues: Entra workload
  identities, Azure Policy, Defender.
- **Meta** — infrastructure zero-trust migration and platform integrity
  engineering as publicly documented (ubiquitous TLS, certificate
  transparency, large-scale automated analysis in the delivery pipeline).
- **Oracle Cloud (OCI)** — OCI Security Guide, Cloud Guard, and Security
  Zones (maximum-security-zone policies enforced preventively).

A **checkpoint** is a control evaluated at an **endpoint** (a surface where
Guardian Mesh attaches). Each checkpoint names: the control, its framework
sources, the endpoint, the evaluation, and the evidence emitted. The
catalogue below is normative; implementations report each checkpoint as
PASS / FAIL / NOT APPLICABLE / NOT RUN in the evidence pack (§8), never
silently omitted.

### 3.1 Identity and access checkpoints

| ID | Control (sources) | Endpoint | Evaluation → evidence |
|----|-------------------|----------|-----------------------|
| CP-01 | Unique workload identity for every caller; no shared identities (800-53 IA-2, CIS 5/6, AWS SEC02, MCSB IM) | Handshake | Caller presents a verifiable identity (§5); proof binds identity + session |
| CP-02 | Phishing-resistant authentication for human administrators (IA-2, CIS 6, MCSB IM) | Admin surfaces | WebAuthn/FIDO2 or PGP/GPG-signed admin actions (§5); auth method recorded in proof |
| CP-03 | Least-privilege, short-lived sessions (AC-6, CIS 6, AWS SEC03) | Handshake/session | Session TTL ≤ 300 s default; scope recorded; expiry enforced |
| CP-04 | No standing privilege: privileged operations need step-up authorization (AC-6, BeyondCorp) | Policy/admin endpoints | §4 two-confirmation rule on privileged crossings |

### 3.2 Cryptography and key management checkpoints

| ID | Control (sources) | Endpoint | Evaluation → evidence |
|----|-------------------|----------|-----------------------|
| CP-05 | Approved cryptography only; PQC for signatures (SC-13, FIPS 140-3, FIPS 204/203) | All verdict paths | ML-DSA-65 / ML-KEM-768 defaults; algorithm IDs in every proof |
| CP-06 | Keys in managed custody; rotation and revocation that propagates (SC-12, AWS SEC09/KMS practice, MCSB DP) | Daemon key store | §6.6 custody ladder; revocation events in audit trail |
| CP-07 | Encryption in transit everywhere, TLS 1.3 (SC-8, CIS 3, AWS SEC09) | Every network surface | Transport policy check at startup; downgrade attempts denied + logged |
| CP-08 | Secrets never in code, logs, or proofs (CIS 3, gate leakage family) | Build + runtime | Release-gate secret scan per release; proofs carry hashes, never payloads by default |

### 3.3 Network and boundary checkpoints

| ID | Control (sources) | Endpoint | Evaluation → evidence |
|----|-------------------|----------|-----------------------|
| CP-09 | Zero-trust access: every request authenticated + authorized, network location grants nothing (SP 800-207, BeyondCorp, AWS SEC03) | All endpoints | §4 boundary rule on every crossing |
| CP-10 | Protocol validation at the boundary (SI-10, ASVS) | Evaluate path | PF-1…PF-18 [SHIPPED v0.4.0] |
| CP-11 | Rate and abuse controls per caller and per tenant (SC-7, CIS 3) | Evaluate path | PF-18 + tenant budgets (§6.3) |
| CP-12 | Egress control for guarded agents: destinations are policy, not defaults (SC-7, CIS 3/13) | Action evaluation | NETWORK_REQUEST verdicts name the destination; proof binds it |

### 3.4 Data protection checkpoints

| ID | Control (sources) | Endpoint | Evaluation → evidence |
|----|-------------------|----------|-----------------------|
| CP-13 | Data classification drives handling (MP/SC families, MCSB DP, OCI Data Safe practice) | Policy engine | Actions carry classification; policy rules per class |
| CP-14 | Tenant isolation: no tenant sees, slows, or starves another (SC-39 process isolation, CIS 3) | Multi-tenant daemon | §6.7 partitions; isolation tests in the conformance suite (§7.3) |
| CP-15 | Evidence integrity: append-only, hash-chained audit (AU-9 protection of audit information) | Vault | Hash chain verification is a public, offline operation |

### 3.5 Logging, monitoring, and evidence checkpoints

| ID | Control (sources) | Endpoint | Evaluation → evidence |
|----|-------------------|----------|-----------------------|
| CP-16 | Every verdict logged with rule IDs and reasons (AU-2/AU-3, CIS 8) | Vault / audit read path | §6.5 legibility + WO-4 read path |
| CP-17 | Tamper-evident, independently re-verifiable evidence (AU-9, SLSA provenance thinking) | Certificates | Tampered proof verifies NOT VALID (§8) |
| CP-18 | Security events exportable to the owner's SIEM/GRC (AU-6, CIS 8/13) | Export endpoints | Signed JSON/webhook feeds (CC-6) |

### 3.6 Supply-chain and build checkpoints

| ID | Control (sources) | Endpoint | Evaluation → evidence |
|----|-------------------|----------|-----------------------|
| CP-19 | Signed, reproducible builds with provenance (SLSA L2+ target, SI-7, AWS SEC08) | Release pipeline | §6.8 attestation package per release |
| CP-20 | Dependency vulnerability management (RA-5, CIS 2/7) | Release gate | Gate scan + stack-native audits per release (§7) |
| CP-21 | The guardian itself is attested before it is trusted (SI-7, BeyondProd service identity/integrity) | Deployment | Measured/attested binary identity published; tenants verify before first handshake (§6.8) |

### 3.7 Resilience and governance checkpoints

| ID | Control (sources) | Endpoint | Evaluation → evidence |
|----|-------------------|----------|-----------------------|
| CP-22 | No single point of failure or coercion in the verdict path (SC-39, CP-10 contingency) | Clustered deployment | §6.1–6.2 |
| CP-23 | Policy change is governed: signed, versioned, dual-controlled (CM-3, CIS 4) | Policy endpoint | §6.9 |
| CP-24 | Incident-ready: escalation paths have owners and response-time commitments (IR family, CIS 10/11) | Escalation queue | §6.10 |


## 4. Trust boundaries — mapping and the two-confirmation rule (BM)

Every Guardian Mesh deployment MUST carry an explicit **boundary map**:
the enumerated trust boundaries of the system and the rule for crossing
each. An unmapped boundary is treated as hostile by default.

### 4.1 Boundary classes

| ID | Boundary | Examples |
|----|----------|----------|
| BM-1 | Caller → guardian | Agent, human, or system presenting an action for evaluation |
| BM-2 | Guardian → guarded resource | The tool, API, file, network destination, or model behind the verdict |
| BM-3 | Tenant → tenant | One customer's callers, policies, keys, and evidence vs another's |
| BM-4 | Node → node | Guardian cluster members exchanging verdicts, policy, or audit segments |
| BM-5 | Guardian → external verifier | Certificates and proofs leaving the deployment to strangers |
| BM-6 | Administrator → policy | Humans changing the rules everyone is judged by |
| BM-7 | Edge → core | Offline/edge profiles syncing verdicts and evidence upstream |
| BM-8 | Build → deployment | Release artifacts crossing into production |

### 4.2 The two-confirmation rule

| ID | Requirement | Status |
|----|-------------|--------|
| BM-9 | Crossing any mapped boundary MUST require **authorization plus a handshake carrying at least two independent confirmations** — two proofs from different factors (§5.2), such that compromising any single one does not open the boundary. | [PARTIAL] — BM-1 ships with two (HMAC session proof + ML-DSA-65 request signature, v0.3.0) |
| BM-10 | Confirmations MUST be independent: different keys, different mechanisms, no shared secret whose theft satisfies both. | [PARTIAL] |
| BM-11 | A boundary crossing that cannot produce its two confirmations MUST fail closed, and the attempt MUST be logged with the missing confirmation named. | [PARTIAL] |
| BM-12 | Privileged crossings (BM-6 policy change, BM-8 release promotion, revocation) MUST additionally require a second *principal* — dual control; no single administrator, however authenticated, crosses alone. | [TARGET] |
| BM-13 | Boundary rules are configuration (§1.2 CC-7): policy names, per boundary, which confirmation combinations satisfy it. Weakening a boundary below two confirmations MUST be impossible by configuration; it requires a build change, so the weakening is itself a BM-8 event. | [TARGET] |

## 5. Authorization — any lawful method, one verdict interface (AZ)

Authorization is pluggable. Any lawful, verifiable method MAY serve as a
confirmation factor; Guardian Mesh evaluates combinations, not brands.

### 5.1 Authenticator catalogue

| ID | Method | Typical principal | Status |
|----|--------|-------------------|--------|
| AZ-1 | ML-DSA-65 signatures (FIPS 204) | Agents, services, nodes | [SHIPPED] |
| AZ-2 | HMAC session proof (handshake-issued session key) | Any caller | [SHIPPED] |
| AZ-3 | X.509 mutual TLS, incl. SPIFFE/SVID workload identity | Services, nodes, fleets | [TARGET] |
| AZ-4 | **PGP/GPG signatures** (OpenPGP) | Humans, administrators, release signers | [TARGET] |
| AZ-5 | WebAuthn / FIDO2 | Human administrators | [TARGET] |
| AZ-6 | OAuth 2.0 / OpenID Connect tokens | Humans, delegated software | [TARGET] |
| AZ-7 | Cloud IAM signatures (AWS SigV4, Azure Managed Identity, Google service accounts, OCI instance principals) | Cloud workloads | [TARGET] |
| AZ-8 | SSH keys / agent forwarding attestations | Operators, automation | [TARGET] |
| AZ-9 | Hardware-backed keys (TPM, HSM, secure enclave) as the store behind AZ-1/AZ-3/AZ-4 | Any | [TARGET] |
| AZ-10 | API keys / bearer secrets | — | Permitted ONLY as a first factor, NEVER sufficient alone for a boundary crossing (BM-9) |

### 5.2 Assurance and factors

| ID | Requirement | Status |
|----|-------------|--------|
| AZ-11 | Every authenticator is classified by factor type (possession / knowledge / inherence / workload-attestation) and assurance strength; the handshake records which factors were presented. | [TARGET] |
| AZ-12 | Policy MAY require named methods for named boundaries (e.g. BM-6 requires AZ-5 or AZ-4 plus a second principal, BM-12). | [TARGET] |
| AZ-13 | A method whose standard is withdrawn or whose implementation fails the conformance suite MUST be removable by configuration without a rebuild of callers. | [TARGET] |
| AZ-14 | Authorization decisions are evidence: the proof of a verdict names the methods that authorized the caller (by type and key fingerprint, never by secret). | [PARTIAL] — session + signature identity bound today |

## 6. Data-center readiness (DC)

The data-center profile is Guardian Mesh operated as shared
infrastructure: many tenants, many callers, no tolerance for a guardian
that is itself the risk. (Owner-approved 2026-10-15; source: the
2026-10-14 data-center review.)

### 6.1 No single guardian

| ID | Requirement | Status |
|----|-------------|--------|
| DC-1 | Verdicts MUST be issuable by a cluster: no single daemon instance is a point of failure or of coercion. Cluster consensus follows the architecture v2 design (BFT levels by assurance tier). | [TARGET] |
| DC-2 | Each node holds its own signing key; a verdict names its issuing node, and a proof remains verifiable when that node is gone. | [TARGET] |
| DC-3 | Compromise of one node MUST NOT let an attacker mint ALLOWs the honest majority would deny; threshold issuance applies at the highest assurance tier. | [TARGET] |

### 6.2 Degraded operation

| ID | Requirement | Status |
|----|-------------|--------|
| DC-4 | Every deployment MUST define its degraded mode in advance: on loss of cluster quorum, policy service, or time source, the guardian narrows to a pre-declared safe subset (fail closed) — it never fails open and never fails everything by accident. | [TARGET] |
| DC-5 | Entry into and exit from degraded mode are themselves logged, alerted, and proof-carrying events. | [TARGET] |

### 6.3 Latency and throughput budgets

| ID | Requirement | Status |
|----|-------------|--------|
| DC-6 | The verdict path MUST publish budgets per deployment class (indicative: p99 ≤ 5 ms in-process/sidecar evaluation excluding policy-defined external checks; ≥ 1,000 evaluations/s per node sustained) and MUST report measured performance against them (see F2/GMSI-7: measured, never constant). | [TARGET] |
| DC-7 | Repeat identical actions MAY be answered from a verdict cache ONLY when the cached verdict is bound to the exact sealed hash of the action; similarity-based caching is prohibited. | [TARGET] |
| DC-8 | The Protocol Firewall MUST operate at the front of the path at line rate for the deployment class; expensive checks are ordered after cheap rejections. | [PARTIAL] — cheap-first ordering shipped v0.4.0 |

### 6.4 The simulate call

| ID | Requirement | Status |
|----|-------------|--------|
| DC-9 | Callers MUST be able to ask "would this be allowed?" — a simulate/dry-run evaluation running the identical verdict logic, issuing no execution rights and clearly marked as simulation in its proof. Agents must never need to burn real attempts to learn the rules. | [TARGET] |

### 6.5 Legibility and visible state

| ID | Requirement | Status |
|----|-------------|--------|
| DC-10 | Every verdict MUST carry machine-readable reasons: the rule IDs that fired (PF-xx, policy section, CP-xx) and, for denials, what would have to change. Prose-only reasons are a defect. | [PARTIAL] — PF reasons name rules today; policy reasons and structured fields are target |
| DC-11 | Callers MUST be able to read their own state: rate budget remaining, session health, escalation status. A caller plans around the guardian instead of colliding with it. | [TARGET] |
| DC-12 | Silent drops are prohibited: every request receives a verdict or a named error. | [SHIPPED] in substance |

### 6.6 Key custody ladder

| ID | Requirement | Status |
|----|-------------|--------|
| DC-13 | Signing keys MUST persist across restarts (floor), SHOULD be HSM/KMS-backed at data-center tier, and MUST support rotation without invalidating outstanding proofs. | [PARTIAL] — persistence is WO-3; HSM/KMS target |
| DC-14 | Revocation of sessions, keys, and certificates MUST exist and MUST propagate within a policy-set bound (default ≤ 60 s across a cluster); a revoked credential that still works is a critical defect. | [TARGET] |

### 6.7 Multi-tenancy

| ID | Requirement | Status |
|----|-------------|--------|
| DC-15 | Policies, keys, rate budgets, and audit partitions MUST be tenant-scoped; cross-tenant access is a BM-3 crossing under the two-confirmation rule. | [TARGET] |
| DC-16 | Tenant isolation MUST be behaviour-proven (conformance suite, §7.3): no tenant can read another's evidence, exhaust another's budget, or time another's traffic into information. | [TARGET] |

### 6.8 Attestation of the guardian

| ID | Requirement | Status |
|----|-------------|--------|
| DC-17 | Releases MUST be signed and reproducible, with published provenance (CP-19); a tenant MUST be able to verify the running daemon is the attested build (measured boot / remote attestation where the platform offers it) before trusting its first verdict. "Who guards the guardian" is answered with evidence, not branding. | [TARGET] |

### 6.9 Policy governance

| ID | Requirement | Status |
|----|-------------|--------|
| DC-18 | Policy is distributed as signed, versioned bundles; every change is a BM-6 crossing (dual control, BM-12), is itself audit-logged and proof-carrying, and takes effect atomically per node with the bundle version named in subsequent verdicts. | [TARGET] |
| DC-19 | The current policy MUST be readable by the agents it judges (publication endpoint), so compliance can be by construction rather than by collision. Secrets embedded in policy, if any, are redacted by the publisher, never by omission of the rule. | [TARGET] |

### 6.10 Escalation and break-glass

| ID | Requirement | Status |
|----|-------------|--------|
| DC-20 | ESCALATE MUST route to a human queue with a policy-set response-time commitment; an escalation nobody answers is a defect, not a verdict. Queue state is visible to the caller (DC-11). | [TARGET] (verdict machinery itself: WO-5) |
| DC-21 | Break-glass overrides MUST be possible, MUST require dual control (BM-12), MUST expire, and the override itself MUST become a sealed proof reviewed after the fact. | [TARGET] |


## 7. Release gate and security testing — criteria of record (RG)

No Guardian Mesh release ships without the Release Gate. The gate is
part of this specification: a release that bypasses it is non-conforming
by definition, whatever its tests say. (Owner's order, 2026-10-14:
"run every time".)

### 7.1 Gate composition

| ID | Requirement | Status |
|----|-------------|--------|
| RG-1 | Every release MUST pass: (a) the machine scan (secrets, known vulnerabilities, MUST checklist), (b) the deep review across four families — dependency vulnerabilities, data leakage, authentication gaps, user-protection gaps — and (c) behaviour proof on the live surface for anything a user or caller touches (for web UIs: the served page in a real browser, primary flow clicked through). | [SHIPPED] as process |
| RG-2 | The extended test families MUST each be evidenced, marked not-applicable with a reason, or marked NOT RUN with a reason: software testing · network vulnerability · user security · data protection · connection protection · encryption · zero-knowledge · zero trust · UAT · proof of concept · security hardening · data isolation · user isolation · boundaries · key generation · key management. A silent pass is a gate failure. | [SHIPPED] as process |
| RG-3 | The verdict (PASS / PASS WITH FINDINGS / BLOCKED) MUST be recorded in the release record (PR + CHANGELOG + the product's public release log, with the testing record published alongside the changes). | [SHIPPED] as process |
| RG-4 | Scanner results are leads, not verdicts: every lead is resolved REAL or FALSE in the deep review with a one-line reason. A check that cannot run is NOT RUN, never PASS. | [SHIPPED] as process |

### 7.2 Test backbones

| ID | Requirement | Status |
|----|-------------|--------|
| RG-5 | Offensive testing runs on the **Kali bench** (network/vulnerability scanning, web exposure, TLS/connection posture, authentication attacks against own test accounts, password-strength proof). Defensive/crypto/isolation benches run on **Arch-based microVM benches** (reproducible, one clean instance per run). | [PARTIAL] — benches specified; stand-up is gate-thread infrastructure work |
| RG-6 | Benches are Linux VMs (Kali: full KVM VM; Arch: microVMs) built from pinned golden images, cloned per run, evidence extracted, clone destroyed (fleet platform rule, 2026-10-15). Authorized surfaces only; every run recorded. | [PARTIAL] |

### 7.3 Conformance suite

| ID | Requirement | Status |
|----|-------------|--------|
| RG-7 | This specification and the formal specification MUST be executable as tests: a conformance suite that runs the PF table, the boundary rules (§4), the authorization combinations (§5), tenant isolation (DC-16), and tamper behaviour (§8) as law, in CI, on every change. | [TARGET] |
| RG-8 | Chaos drills MUST be part of the suite: kill an enclave or node mid-verdict — the system fails closed, every time; corrupt a proof — it verifies NOT VALID; revoke a credential — it stops working within the DC-14 bound. | [TARGET] |

### 7.4 The GMSI loop

| ID | Requirement | Status |
|----|-------------|--------|
| RG-9 | Every gate run MUST emit Guardian Mesh Spec Inputs (GMSI): escapes, NOT RUN checks, new attack/failure classes, thin-evidence families — each stating the evaluation input, the ALLOW/BLOCK rule, the sealed-proof fields, the tamper behaviour, and the certificate-lifecycle impact. "None" is stated explicitly when there are none. | [SHIPPED] as process |
| RG-10 | A Guardian Mesh capability becomes a gate MUST only after it is behaviour-proven. The gate never requires a proof the machinery cannot yet issue, and no surface claims a proof that does not exist. | [SHIPPED] as doctrine |

## 8. Evidence and certificates (EV)

| ID | Requirement | Status |
|----|-------------|--------|
| EV-1 | Every verdict issues a sealed proof (ML-DSA-65 over the verdict, reasons, and evidence references) that verifies **offline and independently** — no callback to the issuing daemon may be required (GMSI-3). | [SHIPPED] — proofs self-contained since v0.2.0 |
| EV-2 | A tampered proof MUST verify NOT VALID — any field, any byte. | [SHIPPED] behaviour-proven |
| EV-3 | Certificates bind: serial + issuer, the exact subject (item/repo, commit SHA, artifact/config hash), policy bundle version, verdict + evidence trail hash, validity window, and verification status. Liability is bounded to that subject and that test (§2.5). | [PARTIAL] — schema is WO-6 |
| EV-4 | Certificate lifecycle: issuance → verification → expiry → re-verification → revocation, with revocation propagating per DC-14. Certificates carry a `scope` field (`working-tree` / `full-history`, GMSI-5). | [TARGET] |
| EV-5 | Evidence packs MUST bind **measured** state: per-rule firewall outcomes, budgets consumed, policy version — measured values, never constants (GMSI-7; closes gate finding F2 of v0.4.0). | [TARGET] |
| EV-6 | Certificate transfer, exhibition, and education are free; the build (evaluation + certification work) is what is charged (owner's model, 2026-10-05). Pricing is not declared in this specification. | Doctrine |

## 9. Implementation map

This specification is executed through the nightly work-order pack
(`docs/nightly/OPENCODE-INSTRUCTIONS.md`). Existing orders WO-3…WO-9
stand. This revision adds:

| Work order | Scope (spec sections) |
|------------|-----------------------|
| WO-10 | Simulate RPC + structured machine-readable verdict reasons everywhere (DC-9, DC-10) |
| WO-11 | Policy governance: signed versioned bundles, dual-control change, judged-readable publication (DC-18, DC-19, BM-6/BM-12) |
| WO-12 | Revocation service for sessions/keys/certificates with propagation bound (DC-14) |
| WO-13 | Guardian attestation package: signed reproducible builds + provenance published per release (CP-19, CP-21, DC-17) |
| WO-14 | Boundary authenticators: SPIFFE/mTLS workload identity (AZ-3) + PGP/GPG admin authorization (AZ-4) as second-factor framework (BM-9) |
| WO-15 | Multi-tenancy: tenant-scoped policy/keys/budgets/audit + isolation proofs (DC-15, DC-16, CP-14) |
| WO-16 | Clustered verdicts + declared degraded modes (DC-1…DC-5) |
| WO-17 | Conformance suite + chaos drills in CI (RG-7, RG-8) |
| WO-18 | Deployment matrix: sidecar form (DP-3), edge profile (DP-6), CLI (CC-4), MCP surface (CC-5) |
| WO-19 | Firewall session-state eviction + measured Health counters (closes v0.4.0 gate findings F1/F2; EV-5 groundwork) |

## 10. What this specification is not

- It is not a claim that the [TARGET] items exist. The honesty labels are
  part of the specification; removing or softening one without shipping
  the behaviour is a specification violation.
- It is not a pricing, packaging, or go-to-market document.
- It does not replace the formal specification's protocol law; where the
  two ever conflict on wire behaviour, the conflict is filed as a gap and
  resolved explicitly, never by silent preference.

*— End of Revised Specification v3.0 —*
