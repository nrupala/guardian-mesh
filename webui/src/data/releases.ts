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
    version: "0.8.4",
    date: "2026-10-23",
    summary: "Public release log page added to the WebUI, fed from CHANGELOG and gate records. A drift guard script now ensures the release log stays current with every release.",
    highlights: [
      "New /releases page displaying all Guardian Mesh releases with their changes and testing records",
      "Drift guard script (check-releases.mjs) wired into the build to detect when the release log falls out of sync with the CHANGELOG",
      "Release data file (releases.ts) containing structured release information for all versions"
    ],
    gateVerdict: "Gate verdict: recorded by Wright after the independent release-gate run.",
    tests: "cargo test: 97 (80 lib + 17 bin) from workspace root; webui build + lint + check:releases all passing",
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
    status: "Released"
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
    status: "Released"
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
    status: "Released"
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
    status: "Released"
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
