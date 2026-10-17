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

### WO-16 (P2) Clustered verdicts + degraded modes
Multi-node verdict issuance per architecture v2 consensus levels;
declared fail-closed degraded modes (spec DC-1…DC-5).

### WO-17 (P2) Conformance suite + chaos drills
Spec-as-tests in CI: PF table, boundary rules, authorization
combinations, tenant isolation, tamper behaviour; kill-mid-verdict
chaos cases (spec RG-7, RG-8).

### WO-18 (P3) Deployment matrix
Sidecar form (DP-3), edge profile (DP-6), CLI (CC-4), MCP server
surface (CC-5) — one profile per run, in that order.

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
