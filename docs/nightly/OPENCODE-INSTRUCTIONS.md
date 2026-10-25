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
