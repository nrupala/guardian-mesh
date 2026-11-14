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
    version: "0.27.0",
    date: "2026-11-14",
    summary: "WO-32: AI risk register + process (ISO/IEC 23894) - specs/RISK_REGISTER.md scores and owns RR-01..RR-25, tied 1:1 to the threat model of record and its mitigations, and is reviewed at every release gate run with the review recorded in the gate verdict.",
    highlights: [
      "specs/RISK_REGISTER.md (new): the 23894-shaped process (context, identification from the threat model, 5x5 analysis, evaluation bands and acceptance rule, treatment, per-gate monitoring and review, communication and recording), owner roles, and the register itself - RR-01..RR-25, each with inherent and residual scores, the shipped mitigations with their honest statuses, the closing work order, an accountable owner role, and a review trigger",
      "Residual risk at a glance: RR-05 guardian bypass remains the sole Critical residual (20) until forced routing and reconciliation ship (WO-21/WO-27); RR-21 signing-key compromise (15 High) is the threat model's highest carried risk, treated by WO-23 external witnessing and WO-35 HSM custody",
      "This gate cycle's review (recorded in the register change log): RR-04 recorded MITIGATED in the v0.26.0 cycle (CM-2 shipped, residual 15 High, closes on WO-27); RR-05 and RR-21 CONSCIOUSLY ACCEPTED for this cycle by the product owner via the gate verdict, re-acceptance due next cycle - the acceptance evidence named by compliance plan item 1.3",
      "specs/THREAT_MODEL.md: header notes the register is issued; review log gains the v0.27.0 row (reviewed, no threat or status changes). specs/STANDARDS_COMPLIANCE_REVIEW.md: the ISO/IEC 23894 row moves PARTIAL -> ALIGNED on the shipped register (guidance alignment, never certification)",
      "HONESTY BOUNDARY: this release is documentation plus the version bump - no daemon code, no proto, no verdict behaviour changes; no score in the register is lowered by anything but a shipped countermeasure or a recorded acceptance, and no TARGET countermeasure contributes to a residual score"
    ],
    gateVerdict: "Wright verification pending",
    tests: "Wright verification pending",
    status: "Current release"
  },
  {
    version: "0.26.0",
    date: "2026-11-13",
    summary: "WO-20: complete-mediation core (CM-2 + CM-1 escrow mode + CM-3 checker hook) - every real ALLOW now issues a one-time, ML-DSA-signed execution token bound to the sealed action hash, a resource-side ExecutionChecker refuses execution without a matching token, and escrow mode refuses agent-presented credentials daemon-side.",
    highlights: [
      "guardian-meshd/src/execution_token.rs (new): the CM-2 token format (GMET1 payload, canonical length-prefixed action hash, 120 s TTL, u32-BE length-prefixed wire form signed with the daemon ML-DSA-65 key), issue_token(), TokenClaims, and the resource-side ExecutionChecker with check() and check_and_release() plus an in-memory escrow store that never prints credential bytes",
      "guardian-meshd/src/config.rs adds escrow_mode parsed from GUARDIAN_MESH_ESCROW_MODE (1/true, case-insensitive) and is_credential_metadata_key() matching credential-named metadata keys case-insensitively, with unit tests",
      "guardian-meshd/src/main.rs issues the execution token only on a real (non-simulation) ALLOW in EvaluateResponse field 5; all other responses keep the field empty. With escrow mode on, an action carrying a credential-named metadata key is blocked with rule CM-1 before the Sentinel pipeline, naming the key only, never its value",
      "guardian-meshd/proto/guardian_mesh.proto: field 5 comment now documents the CM-2 execution token; name, type and number unchanged",
      "specs/GUARDIAN_MESH_REVISED_SPEC.md: CM-2 [TARGET] -> [SHIPPED] for the v0.26.0 scope, CM-1 -> [PARTIAL] (escrow mode + checker release; daemon-side vault injection remains), CM-3 -> [PARTIAL] (checker as resource-side identity hook; mTLS/network lockdown remains deployment-side). specs/THREAT_MODEL.md: TM-04 countermeasure names CM-2 [SHIPPED] v0.26.0, TM-05 stays open with CM-3 [PARTIAL]",
      "docs/MEDIATION.md (new) documents the token format and semantics, checker API, both sides of escrow mode, a resource-integration sketch, and an explicit not-claimed list",
      "HONESTY BOUNDARY: this release adds token issuance, escrow-mode refusal and the resource-side checker plus docs/spec/version surfaces - no new dependencies, no new RPCs, no CLI commands, and no changes to verdict logic, policy, firewall, handshake, certificate, revocation, tenant or degraded behaviour beyond the CM-1 escrow BLOCK"
    ],
    gateVerdict: "PASS WITH FINDINGS - release gate 2026-11-12 (WO-20, rebase addendum 2026-11-13): scanner PASS 0 secrets / 0 vulns / 0 must-gate failures; cargo audit clean (174 deps); F1 lane code needed one Wright compile fix (E0502); F2 token-id RNG failure ignored, fail-closed, noted; GMSI-152 filed (self-contained lane tasks)",
    tests: "Wright independent verification on the rebased tree (over WO-DCR v0.25.0): cargo test 298/298 (188 lib + 93 bin + 11 gm-mcp + 6 gm = 280 v0.25.0 suite + 18 new WO-20 tests); WebUI ci/build/lint + check:releases green (28 versions); Wright behaviour proof re-run 8/8 (exact-action + escrow release, replay, action mismatch, tampers, expiry boundary, wrong-target escrow)",
    status: "Release candidate"
  },  {
    version: "0.25.0",
    date: "2026-11-12",
    summary: "WO-DCR (Gap 5 behaviour-proof build): the DCR-REDIRECT-FRAGMENT content rule - an evaluation whose payload is an OAuth client-registration request carrying a redirect URI with a fragment component is BLOCKED at evaluation time, and the sealed proof records the rule that blocked it (gate case 2026-10-15, Conduit DCR).",
    highlights: [
      "guardian-meshd/src/policy.rs adds PolicyEngine::check_content_rules and the DCR_REDIRECT_FRAGMENT_RULE constant: registration-shaped context payloads (redirect_uris and/or redirect_uri fields) with a fragment ('#') in any redirect URI return a blocking reason citing RFC 6749 \u00a73.1.2 and RFC 7591 \u00a72; the reason names the field (e.g. redirect_uris[0]), never the URI value",
      "guardian-meshd/src/enclave/arbiter.rs applies the content rule with WO-5 precedence - below a type-level policy BLOCK, above ESCALATE/ALLOW - and the rule rides the existing structured-reasons path into EvaluateResponse.reasons and the sealed AuditProof.rule_ids",
      "guardian-meshd/src/main.rs adds full-path integration tests: fragment registration BLOCKs with the rule inside the sealed proof (VerifyProof VALID); a clean registration ALLOWs with a valid proof",
      "HONESTY BOUNDARY: no proto changes, no new dependencies, and no verdict-path change for any existing payload class; content rules inspect the context payload only (metadata-carried registration payloads are a follow-up), and sibling DCR validations (http downgrade, embedded credentials in redirect URIs) are follow-up spec inputs, not in this release"
    ],
    gateVerdict: "PASS WITH FINDINGS \u2014 Release Gate 2026-11-12 (guardian-mesh-dcr-behaviour-proof-2026-11-12): machine scanner PASS (0 must-gate failures, 0 secrets, 0 known vulns); cargo audit clean (174 dependencies, 1490 advisories); F1 content rules inspect the context payload only; F2 sibling DCR validations are follow-up spec inputs",
    tests: "Wright, independent, fresh checkout of PR #112 head: cargo test 280/280 (268 baseline + exactly the 12 new tests: 6 policy unit, 4 arbiter unit, 2 full-path); WebUI ci+build+lint clean, check:releases green; live wire rehearsal on this tree 4/4 legs (fragment BLOCK with rule named + proof VALID, tampered proof NOT VALID, clean ALLOW + valid proof, dead endpoint fails closed). PRODUCTION behaviour proof on the shipped build against live Conduit: 4/4 legs PASS (fragment BLOCK naming DCR-REDIRECT-FRAGMENT with the rule sealed in the proof, VerifyProof VALID; tampered proof NOT VALID; clean registration ALLOW + Conduit 201; no-answer BLOCK); self-cert cert-20261113-000054; evidence in the gate pack (guardian-mesh-dcr-behaviour-proof-2026-11-12).",
    status: "Release candidate"
  },
  {
    version: "0.23.0",
    date: "2026-11-11",
    summary: "WO-22: secure by default (SG-4) - production posture (the default) refuses to start with the built-in default handshake secret, and the new gm doctor scans the configuration environment and names every insecure setting.",
    highlights: [
      "guardian-meshd/src/config.rs adds the Posture enum (production, demo; unset means production), the public DEFAULT_HANDSHAKE_SECRET constant, default-secret detection, PostureFinding and Config::validate_posture(), with unit tests covering parsing, default detection, blocking and demo warnings",
      "guardian-meshd/src/main.rs refuses to start in production posture when the built-in default handshake secret is in use, printing FATAL: posture check failed: <setting>: <message> to stderr and exiting 1 before creating directories",
      "guardian-meshd/src/bin/gm.rs adds the doctor subcommand: it reads the local environment, contacts no daemon, prints posture and one line per finding (BLOCKING or warning), and exits 2 when any blocking finding is present",
      "specs/GUARDIAN_MESH_REVISED_SPEC.md: SG-4 [TARGET] -> [SHIPPED] for the v0.23.0 refusal plus doctor scope; docs/CLI.md documents gm doctor; deploy/edge/guardian-mesh.env.example documents GUARDIAN_MESH_POSTURE and the production refusal",
      "HONESTY BOUNDARY: this release is config/startup/CLI plus docs and the version bump only - no new dependencies, no proto changes, no verdict-path, firewall, handshake-session or signing-key handling changes"
    ],
    gateVerdict: "PASS WITH FINDINGS — Release Gate 2026-11-11 (guardian-mesh-wo22-2026-11-11): scanner PASS (0/0/0); F1 doctor SPIFFE-not-required warning on the current production config (shipped deliberate posture, named by design); F2 standing GMSI-143 status lag outside this WO; GMSI-145 filed (negative-start proof)",
    tests: "Wright, independent, fresh checkout of PR #109 head (tree == lane tree): cargo test 268/268 (conformance 13/13); WebUI ci+build+lint clean, check:releases green (26 versions); behaviour proof 9/9 legs — production+default refused (exit 1, FATAL names the setting), production+literal refused, invalid posture refused, demo+default serves, production+custom serves, gm doctor exit 2/0/0 across production-default / production-custom / demo-default",
    status: "Release candidate"
  },
  {
    version: "0.22.0",
    date: "2026-11-10",
    summary: "WO-30: threat model of record (SG-1) - specs/THREAT_MODEL.md names the system's adversaries, assets and trust boundaries, and maps 25 threats (TM-01..TM-25) to their countermeasures by requirement ID with honest shipped/partial/target status and residual risk.",
    highlights: [
      "specs/THREAT_MODEL.md (new): assets A-1..A-12, adversaries ADV-1..ADV-7 (the five SG-1 adversaries plus hostile guarded resource and coercive/careless operator), the BM-1..BM-8 boundary map as it exists in shipped form, and a 25-threat register grouped by adversary",
      "Every countermeasure cites revised-spec requirement IDs (PF, AZ, BM, DC, SG, CM, PC, EV, CP, RG) with [SHIPPED]/[PARTIAL]/[TARGET] status; threats whose deciding countermeasure is not built are listed as open risks in one table with the work order that closes each (WO-20, WO-21, WO-23, WO-24, WO-25, WO-26, WO-27, WO-35)",
      "Highest open risk named plainly: TM-21 - the daemon signing key is a file on the host, so host compromise is key compromise until SG-5 external witnessing (WO-23) and the HSM custody ladder (WO-35) ship",
      "specs/GUARDIAN_MESH_REVISED_SPEC.md: SG-1 status [TARGET] -> [SHIPPED] (model issued with this release, maintained per release); no other status changed - TARGET countermeasures inside the model stay TARGET",
      "HONESTY BOUNDARY: this release adds the threat-model document and the version bump only - no daemon code, no proto, no verdict behaviour changes; the model claims no countermeasure that is not shipped"
    ],
    gateVerdict: "PASS WITH FINDINGS — Release Gate 2026-11-10 (guardian-mesh-wo30-2026-11-10): F1 = GMSI-143 (revised-spec status labels lag shipped releases in at least seven places; the threat model follows the release record and notes the lag). Standing NOT RUN: cargo audit, benches, ceiling enforcement (GMSI-122), panel click-through (GMSI-134).",
    tests: "cargo test 261/261 + conformance_ 13/13 (identical count to the v0.21.0 baseline — docs-only change), WebUI ci/build/lint green, check:releases green (25 versions); mechanical acceptance: 84 requirement IDs cited in THREAT_MODEL.md, 0 missing from the specs; TM-01..TM-25 each exactly once — Wright-verified 2026-11-10",
    status: "Release candidate"
  },
  {
    version: "0.21.0",
    date: "2026-11-10",
    summary: "WO-19 completion: GMSI-7 pf_outcomes wiring - certificates now carry the daemon's measured per-rule Protocol Firewall pass/fail counts at issuance time, never constants.",
    highlights: [
      "guardian-meshd/src/protocol_firewall.rs adds pf_outcomes_string() returning measured counters in canonical format (RULE:passed=<n>,failed=<n> joined by ;) or None when empty",
      "guardian-meshd/src/certificate.rs issue_certificate gains pf_outcomes parameter (after policy, before signing_key); used in both CertificateBodyForSealing and stored Certificate",
      "guardian-meshd/src/main.rs issue_certificate gRPC handler computes pf_outcomes = self.firewall.pf_outcomes_string() and passes it to certificate issuance",
      "specs/CERTIFICATE_SCHEMA.md updated: pf_outcomes now populated at issuance time with measured outcomes in canonical format; null when no outcomes measured; schema version stays 1 (populating a reserved field)",
      "HONESTY BOUNDARY: certificates now carry measured PF outcomes of the issuing daemon at issuance time; null when nothing measured; never constants; this does not change what a certificate certifies (the binding of verdict to evidence)"
    ],
    gateVerdict: "PASS WITH FINDINGS — Release Gate 2026-11-10 (guardian-mesh-wo19-pf-2026-11-10): F1 = GMSI-135 (repo-root Python client stubs stale). Standing NOT RUN: cargo audit, benches, ceiling enforcement (GMSI-122).",
    tests: "cargo test 261/261 + conformance_ 13/13, WebUI ci/build/lint green, wire proof 18/18 (unmeasured cert omits pf_outcomes; measured cert's sealed pf_outcomes == Health counters) — Wright-verified 2026-11-10",
    status: "Release candidate"
  },
  {
    version: "0.20.0",
    date: "2026-11-09",
    summary: "WO-18 profile 4: CC-5 MCP server surface - the new gm-mcp binary is a stdio MCP server that is an ordinary client of the existing single-node daemon, exposing health, evaluate/simulate, proof verification and audit as four MCP tools with in-memory sessions and fail-closed evaluate behaviour.",
    highlights: [
      "guardian-meshd/src/bin/gm-mcp.rs adds gm-mcp, a newline-delimited JSON-RPC 2.0 stdio MCP server with initialize version negotiation, notifications, ping, tools/list and tools/call; stdout carries protocol messages only and diagnostics go to stderr",
      "Four tools: guardian_health (the gm health field set), guardian_evaluate (required action_type/context/target, optional metadata and simulate; returns the gm evaluate output plus a proof_envelope in the exact proof-file JSON shape), guardian_verify (rebuilds the proto envelope and calls VerifyProof) and guardian_audit (ReadAuditLog; limit truncates the printed entries client-side only)",
      "Sessions are lazy and in-memory only: the first evaluate opens a handshake as gm-mcp, the session id/key/seed/TTL are cached, an expired session is re-handshaked before the call, and a session error triggers one re-handshake and one retry; the session key and seed are never written to stdout, stderr, a file or a tool result",
      "guardian_evaluate fails closed: an unreachable daemon or transport failure returns isError=true stating that NO verdict was issued and the caller MUST treat the action as BLOCK, and the server keeps answering later requests (a following ping still returns a result)",
      "Unit tests in gm-mcp.rs need no daemon and cover initialize negotiation, the exact four-tool catalogue with schemas, JSON-RPC -32601/-32700/-32600 errors, missing action_type and bad proof hex as tool errors naming the field, and proof-envelope round-trips",
      "docs/MCP.md documents what gm-mcp is and is not, build/run, GM_ENDPOINT/GM_TENANT configuration, a generic MCP stdio client entry, the tool catalogue and result shapes, session handling, fail-closed behaviour, the GMSI-124 smoke proof and explicit non-claims",
      "scripts/smoke.sh and scripts/smoke_mcp.py (GMSI-124, test scaffolding only) prove the operator surfaces: nine smoke legs including gm health/handshake/evaluate/verify/audit, a tampered-proof verify, an unreachable-endpoint exit code, live MCP tool calls and the MCP fail-closed legs",
      "HONESTY BOUNDARY: this is a client surface of the existing daemon - no new verdict capability, no daemon changes, no clustering (WO-16 DC-1/DC-3 remain open), no TEE attestation and no external anchoring (designed, not built), and NOT forced routing (CM-4): an agent framework must choose to call the tools",
      "Also NOT in this release: no new dependencies, no clustering and no daemon behaviour change; client access remains the existing proto/gRPC API and the gm CLI"
    ],
    gateVerdict: "PASS WITH FINDINGS — Release Gate 2026-11-09 (guardian-mesh-wo18-mcp-2026-11-09): F1 lane push carried by Wright (process, fixed in-run); F2 base-image tags float (standing). GMSI-134 filed.",
    tests: "cargo test 257/257 + conformance_ 13/13, WebUI ci/build/lint green, in-repo smoke 9/9 + direct stdio protocol negatives — Wright-verified 2026-11-09",
    status: "Release candidate"
  },
  {
    version: "0.19.0",
    date: "2026-11-08",
    summary: "WO-18 profile 3: operator CLI (CC-4) - the gm binary is an operator client of the existing single-node daemon, with handshake, evaluate/simulate, verify and audit subcommands over gRPC, plus honest documentation of its session and proof files, exit codes and non-claims.",
    highlights: [
      "guardian-meshd/src/bin/gm.rs adds gm with hand-rolled argument parsing (no clap, no new dependencies): health, handshake, evaluate (real or --simulate), verify and audit, all JSON on stdout and errors on stderr",
      "handshake generates a 32-byte seed, derives the ML-DSA-65 session keypair, opens the session as gm-cli and writes a session file (0600 on Unix) holding the hex session key and signing seed as bearer secrets; the default path is $HOME/.guardian-mesh/gm-session.json",
      "evaluate seals the exact camelCase ActionDescriptor payload, HMACs it with the session key, calls Evaluate or Simulate, prints verdict/reasons/proof summary and saves the proof envelope as hex-encoded JSON beside the session file",
      "verify rebuilds the proto envelope from the proof file and calls VerifyProof (exit 0 valid, 1 invalid, 2 transport/usage); audit calls ReadAuditLog and its --limit truncates the printed entries client-side only",
      "Exit-code contract: 0 for a successful operation or any verdict returned in a response (BLOCK is success; scripts read the verdict from JSON), 1 for an invalid proof or unhealthy daemon, 2 for usage/session/transport/gRPC errors with no partial JSON on stdout",
      "docs/CLI.md documents what the CLI is, build/install, each subcommand with worked examples and JSON shapes, the session file and TTL/expiry, the proof file and evaluate->verify flow, scripting notes, and explicit non-claims",
      "HONESTY BOUNDARY: this is a client of the existing single-node daemon - it adds no new verdict capability, no clustering, no daemon-logic changes, and the CLI holds no policy authority; it asks the daemon like any other client",
      "Also NOT in this release: CC-5 MCP surface remains target; no TEE attestation or external anchoring (designed, not built); no forced routing (CM-4)"
    ],
    gateVerdict: "PASS WITH FINDINGS — Release Gate 2026-11-08 (guardian-mesh-wo18-cli-2026-11-08)",
    tests: "246/246 cargo (Wright-verified 2026-11-08) + conformance_ 13/13; WebUI ci+build+lint green; behaviour proof through the shipped gm binary against a local daemon: health SERVING, handshake (session file 0600, no secret in stdout), evaluate ALLOW + proof saved, verify VALID, tampered proof invalid (exit 1), audit chain verified, no-session and unreachable-endpoint legs exit 2 with empty stdout, simulate and real BLOCK verdicts in JSON (exit 0)",
    status: "Release candidate"
  },
  {
    version: "0.18.0",
    date: "2026-11-07",
    summary: "WO-18 profile 2: edge profile (DP-6) - a resource-capped, offline deployment form of the existing single-node daemon for small ARM/x86 gateways and industrial PCs, with systemd and Docker Compose forms and honest deployment documentation.",
    highlights: [
      "deploy/edge/guardian-meshd.service runs the daemon as a dedicated non-root guardian user under systemd-level ceilings (MemoryMax=256M, CPUQuota=50%, TasksMax=64), with hardening and a loopback bind default",
      "deploy/edge/guardian-mesh.env.example lists every real GUARDIAN_MESH_* runtime variable an edge deployment may set; the handshake secret has no value, not even a placeholder",
      "deploy/edge/docker-compose.yaml provides the container form with mem_limit 256m and cpus 0.5, a loopback-only published port, a named guardian-data volume and the handshake secret passed through from the shell with no literal value",
      "docs/EDGE.md documents the profile, when to use each form, the honest statement that ceilings are enforced by systemd or the container runtime rather than a daemon setting, fully local offline verdict operation, persistence and proof continuity (WO-3), the real configuration table, the workload's fail-closed duty, and explicit non-claims",
      "HONESTY BOUNDARY: this is packaging and configuration of the existing single-node daemon - no new verdict capability, no clustering (WO-16 DC-1/DC-3 open), no edge-to-core sync (BM-7 is design, not shipped), not forced routing (CM-4), and the listed values are ceilings - measured footprint lives in docs/EDGE.md",
      "Also NOT in this release: CC-4 CLI and CC-5 MCP surface remain target; no TEE attestation or external anchoring (designed, not built); no daemon behaviour change"
    ],
    gateVerdict: "PASS WITH FINDINGS — Release Gate 2026-11-07 (guardian-mesh-wo18-edge-2026-11-07)",
    tests: "cargo test (workspace root) 240/240, conformance_ 13/13, WebUI ci+build+lint green (Wright-verified, 2026-11-07); container proof: Health SERVING at 0.18.0@53cafe11, Evaluate ALLOW + proof VALID, restart persistence on the same volume, fully offline verdict operation proven in a loopback-only namespace; measured footprint 5.8-10.2 MB RSS (peak 10.6 MB) vs the 256M ceiling",
    status: "Release candidate"
  },
  {
    version: "0.17.0",
    date: "2026-11-06",
    summary: "WO-18 profile 1: sidecar form (DP-3) - a multi-stage container image of the existing single-node daemon, Kubernetes and Docker Compose sidecar examples, and honest deployment documentation.",
    highlights: [
      "Multi-stage Dockerfile builds the guardian-meshd release binary on rust:1-bookworm and ships it on debian:bookworm-slim as non-root uid/gid 10001",
      "Runtime image defaults the workspace to /data/workspace, output to /data/output, bind address to 0.0.0.0 and port to 50051; the handshake secret is injected at run time and is never baked into the image",
      "deploy/sidecar/kubernetes.yaml defines a pod-local guardian sidecar beside a placeholder workload, a Secret example, and a PersistentVolumeClaim for the signing key and hash-chained audit log",
      "deploy/sidecar/docker-compose.yaml provides the local analogue: the workload shares the guardian's network namespace and reaches it at 127.0.0.1:50051",
      "docs/SIDECAR.md documents build, run, compose, Kubernetes, every real GUARDIAN_MESH_* variable, the workload's fail-closed duty, and the explicit non-claims",
      "HONESTY BOUNDARY: this is packaging of the existing single-node daemon - no new verdict capability, no clustering (WO-16 DC-1/DC-3 open), and NOT forced routing (CM-4): nothing captures the workload's traffic, so omitting the call to the guardian is still possible",
      "Also NOT in this release: DP-6 edge profile, CC-4 CLI and CC-5 MCP surface remain target; no TEE attestation or external anchoring (designed, not built)"
    ],
    gateVerdict: "PASS WITH FINDINGS — Release Gate 2026-11-06 (guardian-mesh-wo18-retry-2026-11-06)",
    tests: "240/240 cargo (Wright-verified 2026-11-06) + conformance_ 13/13; WebUI build + lint green; container proof: image built from the shipped Dockerfile, Health SERVING (PF 18/18), signed Evaluate ALLOW + proof VALID, restart on the same volume kept fingerprint/node_id and the pre-restart proof verifies VALID, uid 10001, no secret in image env; container box-e2e 15/16 (PF-18 local-environmental)",
    status: "Release candidate"
  },
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
    gateVerdict: "PASS WITH FINDINGS — Release Gate 2026-11-04 (guardian-mesh-wo17-2026-11-04)",
    tests: "240/240 cargo (Wright-verified) + conformance_ 13/13; WebUI build + lint green; process-level chaos proof 7/7; box E2E 15/16 (PF-18 PASS on the box)",
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
