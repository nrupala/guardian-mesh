<!-- Copyright (c) 2026 Nrupal Akolkar -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Nightly Touchpoint (WO-37 / T5) - Operator Protocol

Guardian Mesh v0.32.0 wires T5, the nightly build lane, through `gm nightly`.
This document is the protocol a nightly operator follows. The CLI surface is in
[CLI](CLI.md) and the touchpoint register in
[TOUCHPOINTS](../specs/TOUCHPOINTS.md).

## Purpose

Record a guardian verdict for a specific nightly build-lane action - a build
dispatch or a merge step in the nightly program - before it proceeds, and keep a
verifiable receipt that pairs the sealed proof to the exact evidence hash, work
order and run. This does not dispatch the build or perform the merge: those steps
stay the operator's own and are gated on exit 0.

## Steps

1. **Handshake for a session.** Open a session with `gm handshake` (or reuse a
   fresh, unexpired session). `gm nightly check` requires a session.
2. **Check the build dispatch before dispatching.** Run `gm nightly check` on the
   exact evidence file, naming the work order and, when available, the run:

   ```bash
   gm nightly check --work-order <work-order-id> --evidence-file ./run-plan.json --run <run-id>
   ```

   The CLI computes the evidence SHA-256 itself and calls a real `Evaluate` for
   action_type `NIGHTLY_BUILD` with context `nightly:<work-order>` and the work
   order as target. On a verdict response it saves the sealed proof and a receipt
   pairing the proof with the evidence hash, work order and run.
3. **Check the merge step before merging.** Repeat the check with the merge
   step's own evidence file and the same work order (and run) before that action
   proceeds. One check covers one build/merge action, not a whole command stream.
4. **Proceed ONLY on exit 0.** Exit 0 means the verdict is `ALLOW` and the receipt
   is written - the operator may proceed with that build dispatch or merge. Exit
   1 means the daemon refused or escalated the action (the receipt is still
   written, naming the verdict); exit 2 means no verdict was obtained (transport,
   session, usage, or a pre-proof block - no proof and no receipt are written).
   **Both exit 1 and exit 2 mean do not proceed.** Exit 0 is the only outcome
   under which the operator may proceed.
5. **After the action, verify.** Run `gm nightly verify` with `--evidence-file`
   pointing at the retained evidence file, so the hash is recomputed over the
   evidence presented:

   ```bash
   gm nightly verify --evidence-file ./run-plan.json
   ```

   This re-checks the daemon proof and recomputes the evidence hash against the
   receipt.
6. **Cite the receipt and proof in the nightly record.** Record the receipt file
   and proof file alongside the nightly record so the check is auditable.

## Fail closed

Exit 0 means the verdict was `ALLOW` and the receipt and proof were written. Exit
1 means a verdict response arrived but the verdict was not `ALLOW`: the receipt
names that verdict, and the action must not proceed. Exit 2 means usage, session,
transport or RPC error (including a pre-proof block delivered as
`permission_denied`): nothing is written and the action must not proceed.
Absence of a verdict or a receipt is never treated as approval. Verification
exits 0 only when the proof is valid and `evidence_hash_matches` is not false;
exit 1 means invalid proof or evidence mismatch, and exit 2 means usage,
transport, missing or malformed receipt or proof.

## Honesty limits

- The verdict before the action is a real `Evaluate` of a `NIGHTLY_BUILD` action
  whose metadata carries the CLI-computed SHA-256 of the exact evidence file, the
  work order and the run when given; the daemon seals the verdict into its
  hash-chained audit trail and returns a sealed proof.
- The receipt pairs that proof with the evidence hash, work order and run. The
  daemon's proof binds the action type, verdict, timestamp and policy version;
  the pairing of the proof to the work order, run and evidence hash is
  receipt-asserted (presenter-declaration class, GMSI-182) and checked by
  recomputation. `gm nightly verify --evidence-file` recomputes the hash of the
  presented evidence and compares it to the receipt, so swapped evidence fails
  verification.
- Simulation is never a nightly check. An action blocked before proof sealing
  returns no proof and the CLI writes no receipt: exit 2, nothing dispatched or
  merged.
- This wires the GM-side check + protocol; it does NOT automate the
  scheduler/cron invocation itself. The cron does not call this yet - the
  operator does, per protocol. Mechanically wiring cron/CI to call
  `gm nightly check`, and evaluating the lane's intermediate steps, are
  follow-on work named here as NOT WIRED.

## Licence

Apache License 2.0 + Payment Rider.
