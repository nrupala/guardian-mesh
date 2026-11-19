<!-- Copyright (c) 2026 Nrupal Akolkar -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Guardian Mesh — Touchpoint Coverage Register (WO-37)

**Work order:** WO-37 (T1 wired v0.28.0; T2 wired v0.29.0; T3 wired v0.30.0; T4 wired v0.31.0; T5 wired v0.32.0).
**Owner's directive:** 2026-10-16 — Guardian Mesh connected at every touchpoint.

The map of record is the goal file `touchpoint-wiring-map.md`, which names eight
touchpoints: T1 release gate, T2 publishing pipeline, T3 Conduit, T4 fleet
repos, T5 nightly lane, T6 oc-bridge, T7 MyMilo loop, and T8 GM's own surfaces.
One touchpoint is wired per nightly run, in map order.

A touchpoint counts as **wired** only when BOTH halves exist: a verdict recorded
before the action and a proof after it, AND the proof verifies offline
(`VerifyProof` against a second instance or a separate client — CM-6/CM-7
discipline applied to our own fleet). A touchpoint is not wired because a client
can call the daemon, because a document names it, or because a proof exists that
only its issuer can check.

## Coverage

| Touchpoint | What flows there | Connection | Status |
|---|---|---|---|
| T1 Release gate | The gate's verdict and evidence pack; the proof is the sealed certificate issued after the action | `gm certificate issue` / `status` / `verify` / `revoke` over the certificate RPCs (IssueCertificate, CertificateStatus, RevokeCertificate, VerifyProof), against the production daemon | WIRED (v0.28.0) |
| T2 Publishing pipeline | Public content in the owner's name (AIMLDS blog/papers pipeline) | `gm publish check` before posting (real Evaluate, action_type PUBLISH) + the sealed proof and receipt after it; `gm publish verify` re-checks proof and content hash | WIRED (v0.29.0) |
| T3 Conduit | Conduit fleet traffic and its verdicts | `gm conduit check` before dispatch (real Evaluate, action_type TOOL_CALL, per-tenant context) + the sealed proof and receipt after it; `gm conduit verify` re-checks proof and args hash | WIRED (v0.30.0) |
| T4 Fleet repos | Per-repository release evidence and certificates | `gm repo check` before a repo merge/release (real Evaluate, action_type REPO_RELEASE, per-repo context) + the sealed proof and receipt after it; `gm repo verify` re-checks proof and evidence hash | WIRED (v0.31.0) |
| T5 Nightly lane | Nightly build-lane verdicts and the proofs after each action | `gm nightly check` before a build/merge action (real Evaluate, action_type NIGHTLY_BUILD, per-work-order context) + sealed proof and receipt after it; `gm nightly verify` re-checks proof and evidence hash | WIRED (v0.32.0) |
| T6 oc-bridge | Internal bridge actions and their verdicts | Internal; rides after T3 | NAMED, NOT WIRED (internal, rides after T3) |
| T7 MyMilo loop | Internal loop actions and their verdicts | Internal | NAMED, NOT WIRED (internal) |
| T8 GM's own surfaces | Guardian Mesh's own panel and release-record surfaces | Panel live; release log is WO-9 | PARTIAL (panel live; release log WO-9) |

### T1 release gate — what is wired, and what this does not add

At T1 the gate's verdict is recorded in, and enforced by, certificate issuance:
the daemon refuses a BLOCKED verdict, revokes any ACTIVE certificate for that
product+version, and recomputes the evidence hash daemon-side. The proof after
the action is the sealed certificate issued via `gm certificate issue` and
verified via `gm certificate verify` / `VerifyProof` on a second instance.

This does NOT add an `Evaluate` call against the release action itself. The
"verdict before the action" at T1 is the release gate's own verdict, which
issuance binds and enforces.

### T2 publishing pipeline — what is wired, and what this does not add

The verdict before the action is a real Evaluate of a PUBLISH action whose metadata carries the CLI-computed SHA-256 of the exact content file; the daemon seals the verdict into its hash-chained audit trail and returns a sealed proof; the receipt the CLI writes pairs that proof with the content hash, destination and channel. This does NOT post anything - the posting step stays the publisher's own, gated on exit 0. The daemon's proof binds the action type, verdict, timestamp and policy version; the pairing of the proof to this content hash is asserted by the receipt (the same presenter-declaration class as release certificates) and is checked by recomputation - `gm publish verify --content-file` recomputes the hash of the artifact presented and compares it to the receipt, so a swapped artifact fails verification. A publish blocked before proof sealing (Sentinel/Gatekeeper/Witness) returns no proof and the CLI writes no receipt: exit 2, nothing posted. Simulation is never a publish check.

### T3 Conduit - what is wired, and what this does not add

The verdict before the action is a real Evaluate of a TOOL_CALL action whose
metadata carries the CLI-computed SHA-256 of the exact args file, the tenant and
the tool; the daemon seals the verdict into its hash-chained audit trail and
returns a sealed proof; the receipt pairs that proof with the args hash, tenant
and tool. Raw args never enter the receipt or any log - only their hash. This
does NOT route Conduit's live service traffic: the Conduit service's own dispatch
path calling this check (or Evaluate directly) before dispatch is follow-on
integration work in Conduit's own repo, named here as NOT WIRED. The daemon's
proof binds action type, verdict, timestamp and policy version; the pairing of
the proof to this args hash is asserted by the receipt (presenter-declaration
class, GMSI-182) and checked by recomputation - `gm conduit verify --args-file`
recomputes the hash of the args presented and compares it to the receipt, so
swapped args fail verification. A call blocked before proof sealing returns no
proof and the CLI writes no receipt: exit 2, nothing dispatched. Simulation is
never a conduit check.

### T4 Fleet repos - what is wired, and what this does not add

The verdict before the action is a real Evaluate of a REPO_RELEASE action whose
metadata carries the CLI-computed SHA-256 of the exact evidence file, the repo
and the exact commit; the daemon seals the verdict into its hash-chained audit
trail and returns a sealed proof; the receipt pairs that proof with the evidence
hash, repo and commit. This does NOT install GitHub webhooks, required status
checks, or CI integration in fleet repos, and does NOT certify the fleet's
repositories - rolling this check into each repo's own CI/release path is
follow-on work repo by repo, named here as NOT WIRED. Per-repo coverage
statements in certificates remain WO-21's remainder, not this WO. The daemon's
proof binds action type, verdict, timestamp and policy version; the pairing of
the proof to this evidence hash and commit is asserted by the receipt
(presenter-declaration class, GMSI-182) and checked by recomputation -
`gm repo verify --evidence-file` recomputes the hash of the evidence presented
and compares it to the receipt, so swapped evidence fails verification. A release
blocked before proof sealing returns no proof and the CLI writes no receipt:
exit 2, nothing merged or released. Simulation is never a repo check.

### T5 Nightly lane - what is wired, and what this does not add

The verdict before the action is a real Evaluate of a NIGHTLY_BUILD action whose
metadata carries the CLI-computed SHA-256 of the exact evidence file, the work
order and the run when given; the daemon seals the verdict into its hash-chained
audit trail and returns a sealed proof; the receipt pairs that proof with the
evidence hash, work order and run. This wires the GM-side check + protocol the
nightly operator runs before a build dispatch and before a merge. It does NOT
automate the scheduler/cron invocation itself - mechanically wiring the cron/CI
to call `gm nightly check` is follow-on work; the operator runs the check per
protocol. It does NOT evaluate the lane's intermediate steps: one check per
build/merge action, not per command. The daemon's proof binds action type,
verdict, timestamp and policy version; the pairing of the proof to the
work-order/run/evidence hash is receipt-asserted (presenter-declaration class,
GMSI-182) and checked by recomputation - `gm nightly verify --evidence-file`
recomputes the hash of the evidence presented and compares it to the receipt, so
swapped evidence fails verification. An action blocked before proof sealing
returns no proof and the CLI writes no receipt: exit 2, nothing dispatched or
merged. Simulation is never a nightly check.

## Rules

- Coverage is the metric: each touchpoint is wired, named-unwired, or
  out-of-scope, reviewed at each release.
- Internal first; customer-facing on evidence.
- Each wiring ships through the nightly program, gate-verified, one touchpoint
  per run, in map order.

## Change log

### v0.32.0

- T5 wired. `gm nightly check` records a real Evaluate verdict for action_type NIGHTLY_BUILD (with the CLI-computed evidence SHA-256 in metadata, alongside the work order and optional run) and, on a verdict response, saves the sealed proof and a receipt pairing it to the evidence hash, work order and run; `gm nightly verify` re-checks the proof and the evidence hash by recomputation. This wires the operator-run check before a build dispatch or merge only: cron/CI scheduling of the check, and evaluation of intermediate lane steps, are explicitly not wired (follow-on work, named here as NOT WIRED).

### v0.31.0

- T4 wired. `gm repo check` records a real Evaluate verdict for action_type REPO_RELEASE (with the CLI-computed evidence SHA-256 in metadata, alongside the repo and commit) and, on a verdict response, saves the sealed proof and a receipt pairing it to the evidence hash, repo and commit; `gm repo verify` re-checks the proof and the evidence hash by recomputation. GitHub-side integration (webhooks, required status checks, CI) and WO-21 per-repo coverage statements are explicitly not wired (follow-on work in each repo, named here as NOT WIRED). Evidence: this release's own repo check receipt cited in the release record (CHANGELOG [0.31.0]).

### v0.30.0

- T3 wired. `gm conduit check` records a real Evaluate verdict for action_type TOOL_CALL (with the CLI-computed args SHA-256 in metadata, alongside the tenant and tool) and, on a verdict response, saves the sealed proof and a receipt pairing it to the args hash, tenant and tool; `gm conduit verify` re-checks the proof and the args hash by recomputation. Conduit-service internal routing is explicitly not wired (Conduit-side follow-on work). Evidence: this release's own conduit check receipt cited in the release record (CHANGELOG [0.30.0]).

### v0.29.0

- T2 wired. `gm publish check` records a real Evaluate verdict for action_type PUBLISH (with the CLI-computed content SHA-256 in metadata) and, on a verdict response, saves the sealed proof and a receipt pairing it to the content hash, destination and channel; `gm publish verify` re-checks the proof and the content hash by recomputation. Evidence: this release's own publish check receipt for the public release-log publish, cited in the release record (CHANGELOG [0.29.0]).

### v0.28.0

- T1 wired. The release gate's verdict is bound and enforced by certificate
  issuance, and the certificate issued through `gm certificate issue` verifies
  offline via `gm certificate verify` / `VerifyProof` on a second instance.
  Evidence: this release's own gate certificate, serial cited in the release
  record — see CHANGELOG [0.28.0].
