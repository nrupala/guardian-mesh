# Conformance Suite (WO-17 v1)

This document is the map of the named conformance suite added in WO-17 v1. The
suite lives in the test module of `guardian-meshd/src/main.rs`; every test name is
prefixed `conformance_` and the tests are grouped under a `WO-17 conformance suite`
section comment.

## Running it

```sh
# Full suite (the conformance cases run with everything else)
cargo test

# Conformance suite alone
cargo test conformance_
```

CI runs the suite as its own identifiable step:
`Conformance suite (WO-17 / RG-7, RG-8)` → `cargo test conformance_`.

## Suite map

| Test | Requirement | What it proves |
|------|-------------|----------------|
| `conformance_rg7_pf_table_blocks_each_implemented_rule` | RG-7 §1 (PF table) | Each implemented protocol-firewall rule blocks through the service surface: PF-1, PF-12, PF-13, PF-14, PF-15, PF-16, PF-17. The verdict is `BLOCK` and the `rule_id` appears in both the structured reason and the proof. |
| `conformance_rg7_pf18_rate_limit_returns_throttle_with_rule_id` | RG-7 §1 (PF table) | PF-18 returns `THROTTLE` with `PF-18` in the reason and proof after the existing per-session limiter is primed to its ceiling. |
| `conformance_rg7_policy_rate_returns_throttle_with_rule_id` | RG-7 §1 (PF table) | POLICY_RATE returns `THROTTLE` with `POLICY_RATE` in the reason and proof when the policy-configured rate is primed. |
| `conformance_rg7_boundary_payload_size_and_signature_length` | RG-7 §2 (boundaries) | The 64 KiB payload limit accepts exactly 65536 bytes (valid JSON with trailing whitespace) and rejects 65537 with PF-1. The ML-DSA-65 signature budget accepts 2420 and 3500 bytes (they then fail signature verification, not PF-17) and rejects 2419 and 3501 with PF-17. |
| `conformance_rg7_boundary_timestamp_windows` | RG-7 §2 (boundaries) | The PF-16 future window at its exact edge: +1000 ms is processed, +2000 ms is rejected with PF-16. The PF-15 stale window uses the existing margin pattern: 4 s old is processed, 6 s old is rejected with PF-15. The literal 5000/5001 ms PF-15 edge is not deterministically reachable through the daemon (the check samples the wall clock internally) and is not faked. |
| `conformance_rg7_authorization_session_state_matrix` | RG-7 §3 (authorization) | Normal and escalation actions across session states: no session → denied; bogus session id → denied; valid session normal action → `ALLOW`; valid session escalation action without approval → `ESCALATE`; valid session escalation action after the codebase's only approval scaffolding (dual-control policy change) → still `ESCALATE`. |
| `conformance_rg7_tenant_budget_does_not_leak_across_tenants` | RG-7 §4 (DC-16) | Tenant A exhausting its budget does not block tenant B. |
| `conformance_rg7_tenant_policy_does_not_leak_across_tenants` | RG-7 §4 (DC-16) | Tenant A's policy deny returns `BLOCK` with `DC-15`; the same action under tenant B is `ALLOW`. |
| `conformance_rg7_tenant_audit_partitions_are_isolated` | RG-7 §4 (DC-16) | Evaluations land in their own tenant audit partition; TenantStatus reports A=2, B=1 for two A and one B evaluation. |
| `conformance_rg7_ev2_tampered_proofs_are_invalid` | RG-7 / EV-2 §5 (tamper) | A real proof with mutated verdict, rule ids, timestamp, issuing node, or signature bytes fails VerifyProof; truncated and garbage-bytes envelopes fail VerifyProof without panicking. |
| `conformance_chaos_restart_fails_closed` | RG-8 §6 (chaos) | After dropping and recreating the service on the same workspace: the old session is denied, the persisted audit chain still verifies, and the pre-restart proof still verifies offline. |
| `conformance_chaos_corrupt_audit_log_detected` | RG-8 §6 (chaos) | A single flipped byte in the persisted audit log makes the strict verification path report invalid and degrades the next startup with trigger `audit-chain-verification-failed`. |
| `conformance_chaos_revoked_session_stops` | RG-8 §6 (chaos) | A session revoked through the existing dual-control revocation path is denied on the next Evaluate. |

## Rules and boundaries not exercised

- **PF-2 … PF-11** are not implemented by the daemon as separately enforceable
  rules id, so there is nothing to trigger through the service surface.
- **PF-5** shares the PF-1 size check and emits the `PF-1` rule id; it has no
  distinct case (the check is exercised by the PF-1 cases).
- **PF-19 and later** are not implemented by the daemon.
- **PF-15 exact 5000/5001 ms edge** is not deterministically testable through
  the service surface: `check_timestamp_windows` samples the wall clock inside
  the check, so an envelope prepared at exactly the threshold is already older
  than the threshold by evaluation time. The suite uses the existing margin
  pattern (4 s in, 6 s out) and does not encode a wall-clock race (GMSI-112).

## Explicit non-claims

- **Multi-node chaos is NOT covered.** Killing a node of a cluster is not in
  this release because no cluster exists yet (WO-16 DC-1/DC-3 remain open).
  The RG-8 drills are the in-process provable slice only.
- **CM-8 non-catalogued/direct-access probes are WO-27**, not WO-17.
- The suite proves behaviour through the in-process service surface. The
  process-level chaos proof against the release binary (SIGKILL mid-burst,
  restart, chain state) is Wright's independent verification, not this suite.
- No test results are claimed by the authoring lane; Wright runs the suite and
  stamps the results.
