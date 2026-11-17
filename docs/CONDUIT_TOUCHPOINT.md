<!-- Copyright (c) 2026 Nrupal Akolkar -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Conduit Touchpoint (WO-37 / T3) - Operator Protocol

Guardian Mesh v0.30.0 wires T3, the Conduit touchpoint, through `gm conduit`. This
document is the protocol an operator follows around a Conduit tool call. The CLI
surface is in [CLI](CLI.md) and the touchpoint register in
[TOUCHPOINTS](../specs/TOUCHPOINTS.md).

## Purpose

Record a guardian verdict for a specific Conduit tool call before it is
dispatched, and keep a verifiable receipt that pairs the sealed proof to the
exact args hash, tenant and tool. This does not dispatch anything - the dispatch
step stays the caller's own and is gated on exit 0.

## Steps

1. **Handshake for a session.** Open a session with `gm handshake` (or reuse a
   fresh, unexpired session). `gm conduit check` requires a session.
2. **Check the tool call before dispatch.** Run `gm conduit check` on the exact
   args file to be presented, naming the tool and tenant:

   ```bash
   gm conduit check --tool <name> --tenant <id> --args-file <path>
   ```

   The CLI computes the args SHA-256 itself and calls a real `Evaluate` (never
   `Simulate`) for action_type `TOOL_CALL` with per-tenant context, the tool as
   target and the hash, tenant and tool in metadata. On a verdict response it
   saves the sealed proof and a receipt pairing the proof with the args hash,
   tenant and tool. Raw args are never printed and never enter the receipt.
3. **Dispatch ONLY on exit 0.** Exit 0 means the verdict is `ALLOW` and the
   receipt is written - the caller may dispatch the tool call. Exit 1 means the
   daemon refused or escalated this call (the receipt is still written, naming
   the verdict); exit 2 means no verdict was obtained (transport, session, usage
   or a pre-proof block - no proof and no receipt are written). **Both exit 1 and
   exit 2 mean do not dispatch.** Exit 0 is the only outcome under which the
   caller may dispatch; `gm conduit check` does not dispatch anything itself.
4. **After dispatch, verify.** Run `gm conduit verify` with `--args-file`
   pointing at the args that were actually presented:

   ```bash
   gm conduit verify --args-file <path>
   ```

   This re-checks the daemon proof and recomputes the args hash against the
   receipt, so swapped args fail verification.
5. **Cite the receipt and proof in the call record.** Record the receipt file
   and proof file alongside the Conduit call record so the check is auditable.

## Fail closed

At every step, absence of a verdict or a receipt means no "guardian-checked"
claim. No receipt, or a non-zero exit, is never treated as approval. A call
blocked before proof sealing returns no proof, writes no receipt, exits 2 and
dispatches nothing.

## Honesty limits

- The hash is the only binding to the args: raw args never enter the receipt or
  any log, only the CLI-computed SHA-256 of the exact args file.
- The receipt-asserted pairing of proof to that hash (presenter-declaration
  class, GMSI-182) is checked by recomputation: `gm conduit verify --args-file`
  compares the hash of the presented args to the receipt, so swapped args fail
  verification. The daemon's proof binds action type, verdict, timestamp and
  policy version.
- This wires the check around a Conduit call: it does not dispatch the call, does
  not prove the tool's output, and does not by itself route Conduit's live
  service traffic. That integration is Conduit-side follow-on work and is NOT
  WIRED.
- Simulation is never a conduit check; the check is a real `Evaluate`.
