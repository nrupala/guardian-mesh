<!-- Copyright (c) 2026 Nrupal Akolkar -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Guardian Mesh — Touchpoint Coverage Register (WO-37)

**Work order:** WO-37 (T1), v0.28.0.
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
| T2 Publishing pipeline | Public content in the owner's name (AIMLDS blog/papers pipeline) | Manual publisher step; no wired call from the pipeline yet | NAMED, NOT WIRED (manual publisher step) |
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

## Rules

- Coverage is the metric: each touchpoint is wired, named-unwired, or
  out-of-scope, reviewed at each release.
- Internal first; customer-facing on evidence.
- Each wiring ships through the nightly program, gate-verified, one touchpoint
  per run, in map order.

## Change log

### v0.28.0

- T1 wired. The release gate's verdict is bound and enforced by certificate
  issuance, and the certificate issued through `gm certificate issue` verifies
  offline via `gm certificate verify` / `VerifyProof` on a second instance.
  Evidence: this release's own gate certificate, serial cited in the release
  record — see CHANGELOG [0.28.0].
