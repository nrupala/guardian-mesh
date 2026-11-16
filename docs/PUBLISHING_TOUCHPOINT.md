<!-- Copyright (c) 2026 Nrupal Akolkar -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Publishing Touchpoint (WO-37 / T2) - Operator Protocol

Guardian Mesh v0.29.0 wires T2, the publishing pipeline, through `gm publish`. This
document is the protocol a publisher follows. The CLI surface is in [CLI](CLI.md)
and the touchpoint register in [TOUCHPOINTS](../specs/TOUCHPOINTS.md).

## Purpose

Record a guardian verdict for a specific piece of public content before it is
posted, and keep a verifiable receipt that pairs the sealed proof to the exact
content hash, destination and channel. This does not post anything - the posting
step stays the publisher's own and is gated on exit 0.

## Steps

1. **Handshake for a session.** Open a session with `gm handshake` (or reuse a
   fresh, unexpired session). `gm publish check` requires a session.
2. **Check the publish before posting.** Run `gm publish check` on the exact file
   to be posted, naming its destination (and channel if not `blog`):

   ```bash
   gm publish check --content-file ./post.md --destination https://example.test/post
   ```

   The CLI computes the content SHA-256 itself and calls a real `Evaluate` for
   action_type `PUBLISH`. On a verdict response it saves the sealed proof and a
   receipt pairing the proof with the content hash, destination and channel.
3. **Post ONLY on exit 0.** Exit 0 means the verdict is `ALLOW` and the receipt
   is written - the publisher may post. Exit 1 means the daemon refused or
   escalated this publish (the receipt is still written, naming the verdict);
   exit 2 means no verdict was obtained (transport, session, usage, or a pre-proof
   block - no proof and no receipt are written). **Both exit 1 and exit 2 mean do
   not post.** Exit 0 is the only outcome under which the publisher may post.
4. **After posting, verify.** Run `gm publish verify` with `--content-file`
   pointing at the posted artifact where the destination serves its bytes back
   (so the hash is recomputed over what was actually served), or at the retained
   local copy where the destination does not serve the bytes back. This re-checks
   the daemon proof and recomputes the content hash against the receipt.
5. **Cite the receipt and proof in the publish record.** Record the receipt file
   and proof file alongside the publish record so the check is auditable.

## Fail closed

At every step, absence of a verdict or a receipt means no "guardian-checked"
claim. No receipt, or a non-zero exit, is never treated as approval.

## Honesty limits

- The verdict before the action is a real `Evaluate` of a `PUBLISH` action whose
  metadata carries the CLI-computed SHA-256 of the exact content file; the daemon
  seals the verdict into its hash-chained audit trail and returns a sealed proof.
- The receipt pairs that proof with the content hash, destination and channel.
  The daemon's proof binds the action type, verdict, timestamp and policy
  version; the pairing of the proof to this content hash is asserted by the
  receipt (the same presenter-declaration class as release certificates) and is
  checked by recomputation. `gm publish verify --content-file` recomputes the
  hash of the presented artifact and compares it to the receipt, so a swapped
  artifact fails verification.
- A publish blocked before proof sealing (Sentinel/Gatekeeper/Witness) returns no
  proof and the CLI writes no receipt: exit 2, nothing posted. Simulation is
  never a publish check.
- This wires the check around publishing; it does not post content and does not
  prove the truth or quality of the content. The receipt certifies the binding of
  the proof to the declared content hash, not the truth of its other fields.
