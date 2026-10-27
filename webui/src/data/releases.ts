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
