<!-- Copyright (c) 2026 Nrupal Akolkar -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Repo Touchpoint (WO-37 / T4) - Operator Protocol

Guardian Mesh v0.31.0 wires T4, fleet repos, through `gm repo`. This
document is the protocol a repository operator follows. The CLI surface is in
[CLI](CLI.md) and the touchpoint register in [TOUCHPOINTS](../specs/TOUCHPOINTS.md).

## Purpose

Record a guardian verdict for a specific fleet-repo release (a merge/release of
the named repo at the named commit) before it proceeds, and keep a verifiable
receipt that pairs the sealed proof to the exact evidence hash, repo and commit.
This does not merge, push or release anything - the merge/release step stays the
operator's own and is gated on exit 0.

## Steps

1. **Handshake for a session.** Open a session with `gm handshake` (or reuse a
   fresh, unexpired session). `gm repo check` requires a session.
2. **Check the release before merging/releasing.** Run `gm repo check` on the
   exact evidence file, naming the repository and the exact commit:

   ```bash
   gm repo check --repo example-owner/example-repo --commit 0000000000000000000000000000000000000000 --evidence-file ./evidence.json
   ```

   The CLI computes the evidence SHA-256 itself and calls a real `Evaluate` for
   action_type `REPO_RELEASE` with context `repo:<repo>` and the repo as target.
   On a verdict response it saves the sealed proof and a receipt pairing the
   proof with the evidence hash, repo and commit.
3. **Proceed ONLY on exit 0.** Exit 0 means the verdict is `ALLOW` and the receipt
   is written - the operator may proceed with the merge/release. Exit 1 means the
   daemon refused or escalated this release (the receipt is still written, naming
   the verdict); exit 2 means no verdict was obtained (transport, session, usage,
   or a pre-proof block - no proof and no receipt are written). **Both exit 1 and
   exit 2 mean do not proceed.** Exit 0 is the only outcome under which the
   operator may proceed with the merge/release.
4. **After the merge/release, verify.** Run `gm repo verify` with
   `--evidence-file` pointing at the retained evidence file, so the hash is
   recomputed over the evidence presented:

   ```bash
   gm repo verify --evidence-file ./evidence.json
   ```

   This re-checks the daemon proof and recomputes the evidence hash against the
   receipt.
5. **Cite the receipt and proof in the release record.** Record the receipt file
   and proof file alongside the release record so the check is auditable.

## Fail closed

At every step, absence of a verdict or a receipt means no "guardian-checked"
claim. No receipt, or a non-zero exit, is never treated as approval.

## Honesty limits

- The verdict before the action is a real `Evaluate` of a `REPO_RELEASE` action
  whose metadata carries the CLI-computed SHA-256 of the exact evidence file, the
  repo and the exact commit; the daemon seals the verdict into its hash-chained
  audit trail and returns a sealed proof.
- The receipt pairs that proof with the evidence hash, repo and commit. The
  daemon's proof binds the action type, verdict, timestamp and policy version;
  the pairing of the proof to the repo, commit and evidence hash is asserted by
  the receipt (presenter-declaration class, GMSI-182) and checked by
  recomputation. `gm repo verify --evidence-file` recomputes the hash of the
  presented evidence and compares it to the receipt, so swapped evidence fails
  verification.
- A release blocked before proof sealing returns no proof and the CLI writes no
  receipt: exit 2, nothing merged or released. Simulation is never a repo check.
- This wires the check around a repo release; it does not merge, push or release
  anything, does not prove the code in the commit is good, and does not by itself
  integrate Guardian Mesh into any repo's CI (that integration is follow-on work
  in each repo).
