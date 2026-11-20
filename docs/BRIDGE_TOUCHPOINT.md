<!-- Copyright (c) 2026 Nrupal Akolkar -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Bridge Touchpoint (WO-37 / T6) - Operator Protocol

Guardian Mesh v0.33.0 wires T6, the oc-bridge touchpoint, through `gm bridge`.
This document is the protocol an operator follows before the bridge executes an
action. The CLI surface is in [CLI](CLI.md) and the touchpoint register in
[TOUCHPOINTS](../specs/TOUCHPOINTS.md).

## Purpose

Record a guardian verdict for a specific internal bridge action carried for a
seat - a letter, a task or a mailbox action - before the bridge executes it, and
keep a verifiable receipt that pairs the sealed proof to the exact action hash,
seat and action id. This does not execute the action or dispatch it through the
bridge: those steps stay the operator's or bridge caller's own and are gated on
exit 0.

## Steps

1. **Handshake for a session.** Open a session with `gm handshake` (or reuse a
   fresh, unexpired session). `gm bridge check` requires a session.
2. **Check the bridge action before it executes.** Run `gm bridge check` on the
   exact action file, naming the seat and, when available, the action id:

   ```bash
   gm bridge check --seat <seat> --action-file ./bridge-action.json --action-id <action-id>
   ```

   The CLI computes the action SHA-256 itself and calls a real `Evaluate` for
   action_type `BRIDGE_ACTION` with context `bridge:<seat>` and the seat as
   target. On a verdict response it saves the sealed proof and a receipt pairing
   the proof with the action hash, seat and action id.
3. **One check per bridge action.** Repeat the check for each bridge action the
   bridge is about to execute. One check covers one bridge action, not every
   tool call inside it.
4. **Proceed ONLY on exit 0.** Exit 0 means the verdict is `ALLOW` and the
   receipt is written - the operator may let the bridge execute that action.
   Exit 1 means the daemon refused or escalated the action (the receipt is still
   written, naming the verdict); exit 2 means no verdict was obtained (transport,
   session, usage, or a pre-proof block - no proof and no receipt are written).
   **Both exit 1 and exit 2 mean do not proceed.** Exit 0 is the only outcome
   under which the operator may proceed.
5. **After the action, verify.** Run `gm bridge verify` with `--action-file`
   pointing at the retained action file, so the hash is recomputed over the
   action presented:

   ```bash
   gm bridge verify --action-file ./bridge-action.json
   ```

   This re-checks the daemon proof and recomputes the action hash against the
   receipt.
6. **Cite the receipt and proof in the bridge record.** Record the receipt file
   and proof file alongside the action record so the check is auditable.

## Fail closed

Exit 0 means the verdict was `ALLOW` and the receipt and proof were written. Exit
1 means a verdict response arrived but the verdict was not `ALLOW`: the receipt
names that verdict, and the action must not proceed. Exit 2 means usage, session,
transport or RPC error (including a pre-proof block delivered as
`permission_denied`): nothing is written and the action must not proceed.
Absence of a verdict or a receipt is never treated as approval. Verification
exits 0 only when the proof is valid and `action_hash_matches` is not false;
exit 1 means invalid proof or action hash mismatch, and exit 2 means usage,
transport, missing or malformed receipt or proof.

## Honesty limits

- The verdict before the action is a real `Evaluate` of a `BRIDGE_ACTION` action
  whose metadata carries the CLI-computed SHA-256 of the exact action file, the
  seat, the action bytes and the action id when given; the daemon seals the
  verdict into its hash-chained audit trail and returns a sealed proof.
- The receipt pairs that proof with the action hash, seat and action id. The
  daemon's proof binds the action type, verdict, timestamp and policy version;
  the pairing of the proof to the seat, action id and action hash is
  receipt-asserted (presenter-declaration class, GMSI-182) and checked by
  recomputation. `gm bridge verify --action-file` recomputes the hash of the
  presented action file and compares it to the receipt, so a swapped action
  fails verification.
- Simulation is never a bridge check. An action blocked before proof sealing
  returns no proof and the CLI writes no receipt: exit 2, nothing executed.
- This wires the GM-side check + protocol; it does NOT integrate the oc-bridge
  service itself. The bridge service does not call this yet - the operator (or a
  bridge-side caller) does, per protocol. Mechanically wiring the bridge's
  dispatch path to call `gm bridge check`, and evaluating individual tool calls
  inside a checked bridge action, are follow-on work named here as NOT WIRED.

## Licence

Apache License 2.0 + Payment Rider.
