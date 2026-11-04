# Declared Degraded Modes (WO-16 / v0.15.0)

Guardian Mesh v0.15.0 adds a declared degraded mode. When the daemon is degraded it
fails closed: every action outside a pre-declared safe subset is refused with a
sealed `BLOCK` before tenant policy runs. The mode is explicit, observable in
`Health`, recorded in the hash-chained audit log, and marked on disk so an operator
can see when the daemon entered and left it.

This is the v1 slice of WO-16 (DC-4/DC-5). Proofs also now name the issuing node
(DC-2). Multi-node consensus (DC-1) and threshold issuance (DC-3) are **not** part
of this release and remain target.

## Configuration

### Environment Variables

- `GUARDIAN_MESH_NODE_ID`: Node identity used in `Health.node_id` and in every
  `AuditProof.issuing_node`. When unset or empty, the daemon derives
  `node-<first 12 hex chars of the signing-key fingerprint>`.
- `GUARDIAN_MESH_DEGRADED`: Set to `1` or `true` (case-insensitive `true`) to
  declare degraded mode at startup. Any other value leaves it off.
- `GUARDIAN_MESH_DEGRADED_SAFE_ACTIONS`: Comma-separated list of action types that
  remain permitted while degraded. Entries are trimmed and empty entries dropped.
  Matching is exact and case-sensitive.

Example:

```bash
export GUARDIAN_MESH_NODE_ID="edge-node-01"
export GUARDIAN_MESH_DEGRADED=1
export GUARDIAN_MESH_DEGRADED_SAFE_ACTIONS="HEALTH_CHECK,READ_STATUS"
./guardian-meshd
```

An empty safe subset means degraded mode permits **no** actions.

## Triggers

The daemon resolves its degraded state at startup, after creating the vault and
before serving requests. There are two triggers:

1. **`operator-declared`** — `GUARDIAN_MESH_DEGRADED` is set to `1` or `true`.
   This takes precedence over the audit-chain trigger.
2. **`audit-chain-verification-failed`** — the persisted audit log was read and a
   completed chain verification reported an invalid chain.

A failed read of the audit log (for example a fresh or empty workspace) does **not**
trigger degraded mode. Only a completed verification that reports an invalid chain
does. This keeps a new installation from starting degraded merely because there is
no audit history yet.

## Fail-Closed Behaviour

While degraded:

- `DegradedState::allows(action_type)` returns true only when the action type is in
  the pre-declared safe subset by exact match.
- `Evaluate` and `Simulate` for any other action return verdict `BLOCK` with
  structured rule id `DC-4`. The reason names the trigger and the refused action;
  the remediation tells the operator to restore normal operation or pre-declare the
  action in `GUARDIAN_MESH_DEGRADED_SAFE_ACTIONS`.
- The `DC-4` check runs immediately after tenant and action resolution and **before**
  the tenant-policy decision.
- A degraded `BLOCK` never consumes tenant budget. Real evaluations still append the
  block to the tenant audit partition, matching the existing DC-15 BLOCK path;
  simulations do not append.
- The blocked verdict still carries a sealed `AuditProof` and proof envelope.

Actions in the safe subset continue through the normal pipeline and may still be
blocked by other rules. Being in the safe subset is a permission to be evaluated,
not a guarantee of `ALLOW`.

## Health

`Health` reports:

- `status = DEGRADED` when degraded, otherwise `SERVING`
- `node_id`
- `degraded`
- `degraded_trigger` (empty when not degraded)
- `degraded_safe_actions`
- `degraded_since_unix` (0 when not degraded)

## Entry and Exit Audit Events

The audit log uses the usual hash-chained entry shape:

- `action_id` = hex of the literal `DEGRADED_MODE`
- `verdict` = `DEGRADED_MODE_ENTERED` or `DEGRADED_MODE_EXITED`
- `reason` = `trigger=<trigger>`

On entering degraded mode the daemon records `DEGRADED_MODE_ENTERED` and writes the
marker file:

```
<workspace_dir>/degraded.marker
```

The marker contains the trigger text. If recording the audit event or writing the
marker fails, the daemon logs a warning to stderr and continues starting; a failed
marker write does not fail startup.

On a clean startup where the daemon is **not** degraded and the marker exists, it
reads the previous trigger (or `unknown` if the marker is empty/unreadable), records
`DEGRADED_MODE_EXITED` with that trigger, and removes the marker.

## Exit Procedure

For an operator-declared mode:

1. Remove the trigger: unset `GUARDIAN_MESH_DEGRADED` (or set it to a non-true value).
2. Restart the daemon.
3. Confirm `Health` reports `SERVING` and `degraded = false`, and that
   `degraded.marker` is gone.

For an audit-chain failure, removing the environment trigger is not enough: the
daemon re-verifies the chain on every startup. Repair or restore the audit log to a
verifiable state, then restart. Until then it will re-enter degraded mode with
`audit-chain-verification-failed`.

The marker is bookkeeping, not the source of truth. Deleting it manually does not
exit degraded mode; the next startup re-evaluates the configured trigger and the
audit chain.

## Explicit Non-Claims

- **No cluster consensus (DC-1).** v1 degraded mode is single-node. Nodes do not
  vote, elect a leader, or coordinate degraded state.
- **No threshold issuance (DC-3).** v1 does not split or threshold the signing key
  or require multiple issuers for a proof.
- **No automatic promotion or failover.** There is no automatic exit, no quorum
  recovery, and no distributed degraded-state convergence.
- **No automatic audit repair.** A broken chain keeps the daemon degraded until an
  operator repairs or restores it.
- **No new networking.** This release adds no cluster networking or cross-node
  transport.
