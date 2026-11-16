<!-- Copyright (c) 2026 Nrupal Akolkar -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Guardian Mesh - Touchpoint Coverage Register (WO-37)

**Work order:** WO-37 (T1 wired v0.28.0; T2 wired v0.29.0).
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
| T3 Conduit | Conduit fleet traffic and its verdicts | Flagship integration; rides after T1/T2 | NAMED, NOT WIRED (flagship integration, after T1/T2) |
| T4 Fleet repos | Per-repository release evidence and certificates | Per-repo coverage statements are WO-21's remainder, not this WO | PARTIAL (certificates exist per WO-6; per-repo coverage statements are WO-21's remainder, not this WO) |
| T5 Nightly lane | Nightly run verdicts and the proofs after each action | Process live and gated | PARTIAL (process live and gated; proof formalization is the remaining build) |
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

### T2 publishing pipeline - what is wired, and what this does not add

The verdict before the action is a real Evaluate of a PUBLISH action whose metadata carries the CLI-computed SHA-256 of the exact content file; the daemon seals the verdict into its hash-chained audit trail and returns a sealed proof; the receipt the CLI writes pairs that proof with the content hash, destination and channel. This does NOT post anything - the posting step stays the publisher's own, gated on exit 0. The daemon's proof binds the action type, verdict, timestamp and policy version; the pairing of the proof to this content hash is asserted by the receipt (the same presenter-declaration class as release certificates) and is checked by recomputation - `gm publish verify --content-file` recomputes the hash of the artifact presented and compares it to the receipt, so a swapped artifact fails verification. A publish blocked before proof sealing (Sentinel/Gatekeeper/Witness) returns no proof and the CLI writes no receipt: exit 2, nothing posted. Simulation is never a publish check.

## Rules

- Coverage is the metric: each touchpoint is wired, named-unwired, or
  out-of-scope, reviewed at each release.
- Internal first; customer-facing on evidence.
- Each wiring ships through the nightly program, gate-verified, one touchpoint
  per run, in map order.

## Change log

### v0.29.0

- T2 wired. `gm publish check` records a real Evaluate verdict for action_type PUBLISH (with the CLI-computed content SHA-256 in metadata) and, on a verdict response, saves the sealed proof and a receipt pairing it to the content hash, destination and channel; `gm publish verify` re-checks the proof and the content hash by recomputation. Evidence: this release's own publish check receipt for the public release-log publish, cited in the release record (CHANGELOG [0.29.0]).

### v0.28.0

- T1 wired. The release gate's verdict is bound and enforced by certificate
  issuance, and the certificate issued through `gm certificate issue` verifies
  offline via `gm certificate verify` / `VerifyProof` on a second instance.
  Evidence: this release's own gate certificate, serial cited in the release
  record — see CHANGELOG [0.28.0].
