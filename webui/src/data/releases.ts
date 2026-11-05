// Copyright (c) 2026 Nrupal Akolkar
// SPDX-License-Identifier: Apache-2.0

export interface Release {
  version: string
  date: string
  summary: string
  highlights: string[]
  gateVerdict: string
  tests: string
  status: string
}

export const RELEASES: Release[] = [
  {
    version: "0.16.0",
    date: "2026-11-04",
    summary: "WO-17 v1 conformance suite: named tests for protocol-firewall rules (RG-7), boundary edges, session authorization combinations, tenant isolation (DC-16), proof tamper behaviour (EV-2), and in-process chaos drills (RG-8), runnable with the full suite or alone via `cargo test conformance_`.",
    highlights: [
      "RG-7 PF table exercises PF-1, PF-12, PF-13, PF-14, PF-15, PF-16, PF-17, PF-18 and POLICY_RATE through the service surface, asserting the verdict and the rule_id in both the structured reason and the proof",
      "RG-7 boundary cases cover the enforced 64 KiB payload limit and the ML-DSA-65 signature-length budget at each edge and one byte past it; the PF-16 future window is exercised at its exact edge, while the PF-15 5000 ms stale edge is named unexercised because the check samples the wall clock internally (GMSI-112)",
      "RG-7 authorization table covers no session, bogus session, valid session, and escalation with and without the codebase's only approval scaffolding (dual-control policy change)",
      "RG-7 tenant isolation proves an exhausted budget, a tenant policy deny, and tenant audit partitions do not leak across tenants",
      "RG-7 / EV-2 tamper cases reject mutated verdict, rule ids, timestamp, issuing node and signature bytes, plus truncated and garbage envelopes, without panicking",
      "RG-8 chaos drills: restart fails closed while the persisted audit chain still verifies and pre-restart proofs still verify, a corrupted audit log is detected and degrades the next startup, and a revoked session can no longer evaluate",
      "HONESTY BOUNDARY: multi-node chaos (killing a node of a cluster) is NOT in this release — no cluster exists yet (WO-16 DC-1/DC-3 open); CM-8 non-catalogued/direct-access probes are WO-27, not WO-17"
    ],
    gateVerdict: "TBD",
    tests: "Tests: TBD by Wright verification.",
    status: "Release candidate"
  },
  {
    version: "0.15.1",
    date: "2026-11-03",
    summary: "Fix for the v0.15.0 deploy defect: the degraded-mode startup trigger now verifies the live tail segment of the audit log instead of the entire history, so a daemon with a historical chain interleave (production, 2026-10-26/27) starts normally while tampering with the current segment still fails closed.",
    highlights: [
      "verify_startup_chain: newest non-empty audit file, chained from the previous file's last stored digest; same entry check as the strict verifier",
      "Full-history verification remains on ReadAuditLog, which keeps reporting the historical interleave as a finding — the audit trail is never rewritten",
      "Proven against a copy of the actual production audit log before deploy: clean start SERVING; one corrupted tail byte starts DEGRADED"
    ],
    gateVerdict: "PASS WITH FINDINGS — WO-16 gate addendum 2026-11-03",
    tests: "227/227 cargo (Wright-verified); WebUI build + lint green; production-log proof: clean copy starts SERVING, one corrupted tail byte starts DEGRADED",
    status: "Release candidate"
  },
  {
    version: "0.15.0",
    date: "2026-11-03",
    summary: "Declared degraded modes (DC-4/DC-5) and issuing-node identity in proofs (DC-2): a daemon can be started in a fail-closed degraded mode that permits only a pre-declared safe action subset, with entry/exit audit events and a persisted marker, while every AuditProof names the node that issued it.",
    highlights: [
      "Degraded mode triggers: operator declaration (GUARDIAN_MESH_DEGRADED=1/true) or a completed audit-chain verification that reports an invalid chain",
      "Safe subset configured with GUARDIAN_MESH_DEGRADED_SAFE_ACTIONS; while degraded every action outside the exact-match subset returns a sealed BLOCK with rule DC-4 before tenant policy",
      "Degraded BLOCKs never consume tenant budget and append to the tenant audit partition exactly like the existing DC-15 BLOCK path",
      "Entry/exit lifecycle events (DEGRADED_MODE_ENTERED / DEGRADED_MODE_EXITED) are written to the hash-chained audit log; a degraded.marker in the workspace records the trigger and is removed on clean exit",
      "node_id resolves from GUARDIAN_MESH_NODE_ID or defaults to node-<first 12 hex of the signing-key fingerprint>; Health reports it alongside degraded status, trigger, safe actions, and since timestamp",
      "AuditProof gains issuing_node so a proof names the daemon that issued it; sealed proofs continue to verify via VerifyProof",
      "HONESTY BOUNDARY: multi-node consensus (DC-1) and threshold issuance (DC-3) are NOT in this release and remain target; v1 degraded mode is single-node and operator-declared"
    ],
    gateVerdict: "PASS WITH FINDINGS — Release Gate 2026-11-03 (guardian-mesh-wo16-2026-11-03)",
    tests: "223/223 cargo (Wright-verified); WebUI build + lint green; degraded wire proof 8/8",
    status: "Rolled back — deployed 2026-11-03 and rolled back the same night: the startup full-chain check degraded the daemon on the production audit history (see 0.15.1). Superseded by 0.15.1."
  },
  {
    version: "0.14.1",
    date: "2026-11-02",
    summary: "Tenant-budget ordering fix (gate F6 / GMSI-100): the per-tenant rate budget now gates only requests the Gatekeeper allowed, so bursts return THROTTLE verdicts instead of resource_exhausted errors. First deployed multi-tenancy release (0.14.0 was rolled back).",
    highlights: [
      "Budget consumption moved after the Sentinel/Gatekeeper pipeline and after the THROTTLE and BLOCK return paths",
      "THROTTLE and BLOCK verdicts never consume tenant budget and are never converted to budget errors",
      "Existing wo15_tenant_budget_exhaustion_throttles test unchanged; new burst regression test asserts zero errors",
      "F4: an unknown/bogus session is denied before the budget point, with a regression test asserting budget_used is unchanged"
    ],
    gateVerdict: "PASS WITH FINDINGS — Release Gate 2026-11-03 (guardian-mesh-wo16-2026-11-03)",
    tests: "223/223 cargo (Wright-verified); WebUI build + lint green; degraded wire proof 8/8",
    status: "Release candidate"
  },
  {
    version: "0.14.0",
    date: "2026-10-31",
    summary: "Multi-tenancy: tenant-scoped policy, keys, rate budgets, and audit partitions. Closes specs DC-15 (PARTIAL), DC-16 (PARTIAL), CP-14 (PARTIAL).",
    highlights: [
      "Tenant registry with per-tenant policy bundles, ML-DSA key bindings, rate budgets, and audit partitions",
      "Handshake tenant_id field binds sessions to tenants; cross-tenant key access is permission_denied",
      "Tenant policy decisions evaluated before global policy; deny verdicts return BLOCK with DC-15 structured reason",
      "Rate budgets are per-tenant and isolated: exhausting one tenant's budget does not affect others",
      "Audit partitions are per-tenant with independent hash chains; TenantStatus RPC enforces BM-3 two-confirmation cross-tenant reads",
      "TenantStatus RPC and WebUI Multi-tenancy section showing registered tenants, default tenant budget, and audit entry counts",
      "HONESTY BOUNDARY: v1 is single-node in-process; budgets and audit are in-memory (reset on restart); no process isolation (CP-14 SC-39), no cross-node tenancy, no admin RPC for tenant policies (library/test surface only)"
    ],
    gateVerdict: "PASS WITH FINDINGS — Release Gate 2026-10-31",
    tests: "213 Rust tests passing (148 library + 65 binary) · WebUI build + lint · TenantStatus wire proof 10/10",
    status: "Release candidate"
  },
  {
    version: "0.13.0",
    date: "2026-10-29",
    summary: "Guardian attestation package: signed reproducible builds with provenance published per release. Closes specs CP-19, CP-21, DC-17 (PARTIAL).",
    highlights: [
      "Health carries build identity: build_version, build_commit, binary_sha256 fields for tenant verification before first verdict",
      "gm-attest CLI for building provenance statements, signing attestation packages, and verifying binary-to-attestation correspondence",
      "Reproducible build script (scripts/reproducible-build.sh) performing two independent builds with SOURCE_DATE_EPOCH and path remapping",
      "docs/ATTESTATION.md public verification instructions a stranger can follow from public artifacts alone",
      "Provenance statement following in-toto/SLSA v1 structure signed with ML-DSA-65 in a sealed envelope",
      "WebUI Guardian Attestation section displaying version, build commit (short), and running binary SHA-256 with attestation reminder",
      "HONESTY BOUNDARY: SLSA L2-style builder-signed provenance, no SLSA L3 hermetic builder, no transparency log, no TPM measured boot in v1"
    ],
    gateVerdict: "PASS WITH FINDINGS — Release Gate 2026-10-29",
    tests: "193 Rust tests passing (136 library + 57 binary) · WebUI build + lint · reproducible builds identical · gm-attest VALID/tamper-INVALID · Health build-identity wire proof",
    status: "Release candidate"
  },
  {
    version: "0.12.0",
    date: "2026-10-28",
    summary: "Boundary authenticators: SPIFFE SVID workload attestation at the handshake and OpenPGP administrator second factor on policy and revocation crossings. Second-factor framework for BM-9 (spec AZ-3, AZ-4, AZ-11, AZ-14).",
    highlights: [
      "Authenticator framework with factor classification for ML-DSA-65, HMAC session, SPIFFE/X.509, and OpenPGP methods",
      "SPIFFE SVID attestation at handshake: DER validation, trust-domain allowlist, validity window, possession proof bound to the session ML-DSA key",
      "Required-SPIFFE mode fails closed and names the missing confirmation (BM-11)",
      "OpenPGP (Ed25519) second factor enforced for enrolled admins on policy and revocation propose/approve",
      "AuthenticatorStatus RPC and WebUI Boundary Authenticators summary",
      "Not in v1: SPIFFE trust-bundle chain verification and mTLS transport termination"
    ],
    gateVerdict: "PASS WITH FINDINGS — Release Gate 2026-10-28",
    tests: "185 Rust tests passing (128 library + 57 binary) · WebUI build + lint · wire proof 24/24",
    status: "Release candidate"
  },
  {
    version: "0.11.0",
    date: "2026-10-27",
    summary: "Dual-control revocation service for sessions, keys, and certificates with DC-14 propagation bound. Closes specs DC-14, EV-4, BM-12.",
    highlights: [
      "ProposeRevocation and ApproveRevocation RPCs implementing dual-control revocation (BM-12)",
      "Revocation of sessions, ML-DSA-65 client keys, and certificates with per-kind validation",
      "Synchronous propagation, measured at approval against the DC-14 bound",
      "RevocationStatus RPC for querying individual targets or registry summary",
      "Persistent revocation registry (revocations.jsonl) with restart durability",
      "Legacy RevokeCertificate tightened: refuses when admin registry is configured",
      "Handshake refuses revoked client keys; key revocation drops all bound sessions",
      "Audit events for all applied revocations with proposer/approver principals",
      "WebUI revocation summary showing total count and DC-14 propagation bound"
    ],
    gateVerdict: "PASS WITH FINDINGS",
    tests: "Cargo 160/160 Linux (111 lib + 49 bin) / 159/159 Windows, Wright-verified from the workspace root; WebUI npm ci + build (drift guard: 12 versions) + lint green; wire proof through the shipped TS client 36/36 (session, key, and certificate revocation end-to-end incl. dual-control refusals, legacy-RPC tightening, audit entries, and restart persistence).",
    status: "Release candidate"
  },
  {
    version: "0.10.0",
    date: "2026-10-26",
    summary: "Policy governance with signed versioned bundles, dual-control approval, publication endpoint, and policy version in all verdicts. Closes v0.4.0 gate specs DC-18, DC-19, BM-6/BM-12.",
    highlights: [
      "PolicyBundle: signed, versioned bundles with canonical deterministic serialization and SHA-256 content hashes",
      "Dual-control policy changes: ProposePolicyChange and ApprovePolicyChange RPCs requiring two distinct admin principals (BM-12)",
      "GetPolicy publication endpoint for judged agents to read current policy (DC-19)",
      "Policy persistence in canonical format with atomic temp file + rename",
      "Every AuditProof now carries policy_version field naming the bundle version at evaluation time (DC-18)",
      "Admin registry from ML-DSA-65 verifying keys in policy_admin_keys_dir",
      "VaultEnclave::record_policy_event for hash-chained audit logging of policy changes",
      "WebUI Current Policy section displaying bundle version, rules table, proposer/approver principals"
    ],
    gateVerdict: "PASS WITH FINDINGS",
    tests: "137 tests (100 lib + 37 bin) from the workspace root on Linux, Wright-verified (136 on Windows; one #[cfg(unix)] lib test is Linux-only); 20 tests added over the v0.9.0 baseline (10 policy.rs, 10 main.rs); webui build + lint passing; wire proof 31/31 through the shipped TS client (dual-control propose/approve, verdict flip under v2, policy_version in proofs, audit event, restart persistence)",
    status: "Release candidate"
  },
  {
    version: "0.9.0",
    date: "2026-10-25",
    summary: "Simulate dry-run RPC and structured verdict reasons. Closes v0.4.0 gate findings DC-9/DC-10. Agents can now ask 'would this be allowed?' without burning real attempts, and every verdict carries machine-readable rule IDs and remediation strings.",
    highlights: [
      "New Simulate RPC running identical verdict logic with no state mutation or execution rights",
      "Firewall peek variants (check_nonce_uniqueness_peek, check_rate_limit_peek, check_policy_rate_peek) for simulation mode",
      "Structured reasons in every response: StructuredReason message with rule_id, detail, remediation fields",
      "Gatekeeper and Arbiter populate structured reasons for all Block/Throttle/Escalate/Allow verdicts",
      "WebUI Simulate button with distinct rendering for simulation outcomes showing structured reasons"
    ],
    gateVerdict: "PASS WITH FINDINGS",
    tests: "117 tests (90 lib + 27 bin) from the workspace root on Linux, Wright-verified (116 on Windows; one #[cfg(unix)] lib test is Linux-only); 10 tests added over the v0.8.5 baseline (7 main.rs, 2 protocol_firewall.rs, 1 gatekeeper.rs); webui build + lint passing; wire proof 26/26 through the shipped TS client",
    status: "Release candidate"
  },
  {
    version: "0.8.5",
    date: "2026-10-24",
    summary: "Firewall session eviction wired and Health reports measured per-rule pass/fail counts. Closes v0.4.0 gate findings F1/F2.",
    highlights: [
      "ProtocolFirewall now records measured outcomes per rule (RuleCounter with passed/failed counts)",
      "Gatekeeper records all static checks (PF-1, PF-12, PF-13, PF-15, PF-16, PF-17) and evicts firewall state for dead sessions",
      "HandshakeBus eviction returns evicted session IDs; TTL sweep wired in handshake() and evaluate()",
      "Health proto field 6 (protocol_firewall_rule_counters map) carries measured per-rule counts",
      "WebUI Protocol Firewall card shows per-rule counters and corrected total label (checks run, not named rules)"
    ],
    gateVerdict: "PASS WITH FINDINGS",
    tests: "107 tests (87 lib + 20 bin) Wright-verified on Linux from the workspace root; 106 (86 lib + 20 bin) on the lane's Windows run (one #[cfg(unix)] test absent there); 10 tests added over the 97 baseline; wire proof: fresh Health 0/0 with empty counters map, one valid Evaluate → 9 passed / 9 total across exactly 9 rules, one PF-12 block → PF-12 failed=1",
    status: "Release candidate"
  },
  {
    version: "0.8.4",
    date: "2026-10-23",
    summary: "Public release log page added to the WebUI, fed from CHANGELOG and gate records. A drift guard script now ensures the release log stays current with every release.",
    highlights: [
      "New /releases page displaying all Guardian Mesh releases with their changes and testing records",
      "Drift guard script (check-releases.mjs) wired into the build to detect when the release log falls out of sync with the CHANGELOG",
      "Release data file (releases.ts) containing structured release information for all versions"
    ],
    gateVerdict: "PASS WITH FINDINGS",
    tests: "97/97 (80 lib + 17 bin) from the workspace root, Wright-verified on Linux (lane Windows run 96 — one #[cfg(unix)] test); webui build + lint + check:releases passing; drift-guard negative case proven (exit 1 on a mismatched version)",
    status: "Release candidate"
  },
  {
    version: "0.8.3",
    date: "2026-10-22",
    summary: "Three libFuzzer-based fuzz targets added for boundary-facing APIs (envelope decode, payload parse, proof verify). Nightly CI workflow runs fuzz targets for 60 seconds each.",
    highlights: [
      "Fuzz targets for envelope decoding (protobuf malformation), payload parsing (JSON structure and firewall rules), and proof verification (ML-DSA-65 signatures)",
      "Detached fuzz package with seed corpora containing real valid inputs and their variants",
      "Nightly CI workflow running fuzz targets with documented crash-to-P0-work-order discipline"
    ],
    gateVerdict: "PASS WITH FINDINGS",
    tests: "97/97 tests (80 lib + 17 bin) Wright-verified from workspace root on Linux; fuzz targets built and ran against seed corpus with zero crashes",
    status: "Release candidate"
  },
  {
    version: "0.8.2",
    date: "2026-10-21",
    summary: "Scope documentation reconciled with shipped reality. The revised_project_scope.md now accurately describes the implemented Sentinel/Gatekeeper/Witness/Arbiter/Vault pipeline and Apache License 2.0 + Payment Rider licensing.",
    highlights: [
      "Corrected project scope documentation to reflect the actual shipped system",
      "Updated licensing description from MIT to Apache License 2.0 + Payment Rider",
      "Removed duplicate gap analysis file",
      "Documentation-only release with no code changes"
    ],
    gateVerdict: "PASS WITH FINDINGS",
    tests: "97 tests green (80 lib + 17 bin) Wright-verified from workspace root; WebUI build + lint passing",
    status: "Release candidate"
  },
  {
    version: "0.8.1",
    date: "2026-10-20",
    summary: "Fixed race condition in audit chain where concurrent writers could produce duplicate chain hashes and break verification. Chain appends now hold the lock for the entire critical section.",
    highlights: [
      "Fixed chain-concurrency defect where concurrent seal() and record_certificate_event() calls could interleave on the same predecessor hash",
      "New concurrency regression test with 160 appends across multiple threads verifying chain integrity",
      "Sequential behavior unchanged; logs written before the fix verify after it"
    ],
    gateVerdict: "PASS WITH FINDINGS",
    tests: "97 tests green (80 lib + 17 bin) after Wright's independent verification; wire proof showed v0.8.0 produced 7 duplicate hashes while v0.8.1 produced 0 duplicates with chain VERIFIED",
    status: "Release candidate"
  },
  {
    version: "0.8.0",
    date: "2026-10-19",
    summary: "Release-evidence certification capability added. Guardian Mesh can now issue certificates that bind a gate verdict to an evidence pack under the daemon's cryptographic signature.",
    highlights: [
      "Certificate schema v1 with IssueCertificate, RevokeCertificate, and CertificateStatus RPCs",
      "Lifecycle management: ACTIVE, SUPERSEDED, REVOKED, UNKNOWN states with audit trail",
      "Evidence hash verification at issuance (10 MB cap) and fingerprint field for GMSI-2 compliance",
      "Self-contained sealed envelopes verifiable by any Guardian Mesh daemon via VerifyProof",
      "Honest clauses: certificate vouches only for the binding (evidence hash, verdict, issuer, time), never for deployment choices"
    ],
    gateVerdict: "PASS WITH FINDINGS",
    tests: "96 tests green (79 lib + 17 bin) independently re-run by Wright; 11 certificate-path test cases including lifecycle, tamper proofs, and mixed audit traffic",
    status: "Release candidate"
  },
  {
    version: "0.7.0",
    date: "2026-10-19",
    summary: "Real THROTTLE and ESCALATE verdicts implemented. Both verdicts now exist as actual code paths with signed proofs and are rendered distinctly in the control panel.",
    highlights: [
      "THROTTLE verdict emitted on PF-18 rate breaches (100 msg/s) and policy-configurable per-session rates",
      "ESCALATE verdict for policy-configured action types requiring human decision",
      "Behavior change: PF-18 now returns THROTTLE verdict with proof instead of bare gRPC error",
      "Panel renders THROTTLE (orange/amber) and ESCALATE (orange/amber) with plain-language descriptions"
    ],
    gateVerdict: "Not recorded",
    tests: "84 tests (68 unit + 16 integration) all green; integration tests verify THROTTLE/ESCALATE verdicts have proper proof structure and precedence rules",
    status: "Released"
  },
  {
    version: "0.6.0",
    date: "2026-10-19",
    summary: "Audit trail read RPC (ReadAuditLog) returns the Vault's hash-chained audit log with chain verification computed at read time. Live panel audit view wired to the new RPC.",
    highlights: [
      "ReadAuditLog RPC returns all audit entries in append order with chain verification status",
      "Chain verification re-walks from genesis hash and reports breaks with position",
      "Live panel displays audit entries and chain status in plain words",
      "Mixed logs (pre-0.6.0 legacy + 0.6.0+ fully-chained) verify correctly"
    ],
    gateVerdict: "PASS WITH FINDINGS",
    tests: "78 tests green (cargo); webui build + lint passing; tamper/legacy/malformed-hash/mixed-chain probes all passing",
    status: "Released"
  },
  {
    version: "0.1.0",
    date: "2026-08-30",
    summary: "Initial release with Rust gRPC daemon featuring ML-DSA-65, CRC32C, and HMAC handshake bus. React + Vite + PWA control panel and CI/CD workflows for Rust, WebUI, and APK builds.",
    highlights: [
      "Rust gRPC daemon with five-enclave enforcement pipeline",
      "ML-DSA-65 post-quantum signatures, CRC32C integrity checks, HMAC handshake authentication",
      "React control panel with 2FA login and demonstration dashboards",
      "CI/CD workflows for automated builds and releases"
    ],
    gateVerdict: "Not recorded",
    tests: "Not recorded",
    status: "Released"
  }
]
