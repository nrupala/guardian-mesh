# Complete Mediation (WO-20 / CM-1, CM-2, CM-3)

Guardian Mesh v0.24.0 adds the first slice of complete mediation: execution
tokens bound to the sealed action hash with a resource-side checker (CM-2), an
escrow mode that refuses agent-presented credentials daemon-side (CM-1), and the
checker as the resource-side identity hook (CM-3). This document describes what
shipped and, just as importantly, what did not.

## What shipped

- **Execution tokens (CM-2).** A real (non-simulation) `ALLOW` now carries a
  signed, one-time, short-lived token in `EvaluateResponse.handshake_token`
  (field 5). Every other response - BLOCK, THROTTLE, ESCALATE, any simulation,
  and every early return - carries the field empty.
- **Escrow mode, daemon side (CM-1).** With `GUARDIAN_MESH_ESCROW_MODE=1` (or
  `true`), an action whose metadata contains a credential-named key is blocked
  with rule `CM-1` before the Sentinel pipeline. The reason names the offending
  key only, never its value.
- **Resource-side checker and escrow (CM-1 / CM-3).** `ExecutionChecker` is the
  resource-side half: an embedder gives it the daemon's verifying key, escrows
  the credentials it holds, and refuses execution without a valid token that
  matches the presented action. Resources that accept only checker-validated
  work accept only guardian-issued work.

The daemon service does not use `ExecutionChecker`; it is for resource-side
embedders and tests.

## Token format and semantics

The token lives in `EvaluateResponse.handshake_token` (proto field 5, type
`bytes`, number unchanged for wire compatibility).

**Payload.** The ASCII header `GMET1` followed by these fields, each encoded as
a 32-bit big-endian length prefix plus the field bytes, in order:

1. `token_id` - 16 random bytes, lowercase hex
2. `action_hash` - lowercase hex SHA-256 of the canonical action encoding
3. `session_id`
4. `tenant_id`
5. `issued_at` - decimal Unix seconds
6. `expires_at` - decimal Unix seconds

**Action hash.** SHA-256 over the canonical length-prefixed encoding of the
action descriptor: `action_type`, `context`, `target` in that order, then each
metadata entry sorted by key, each field as a 32-bit big-endian length prefix
plus bytes (a metadata entry is key length + key + value length + value). The
metadata map's iteration order therefore cannot change the hash.

**Signature.** The payload is signed with the daemon's ML-DSA-65 signing key -
the same persistent key that seals audit proofs. The signature covers the
payload bytes.

**Wire form.** `u32-BE payload length || payload bytes || ML-DSA-65 signature
bytes`. The checker splits on the length prefix and verifies the signature over
the payload, exactly as proof verification does.

**TTL.** `TOKEN_TTL_SECS` is 120 seconds. A token is valid while
`now <= expires_at`; at `now > expires_at` the checker refuses it.

**One-time.** The checker records each consumed `token_id` in an in-memory set
and refuses a second presentation with `execution token already used`. The set
is per checker instance (per resource-side process); a deployment that needs a
shared one-time guarantee across processes must run one checker or share its
state. The daemon itself keeps no token state.

## Checker API

`guardian_meshd::execution_token::ExecutionChecker`:

- `ExecutionChecker::new(verifying_key)` - build with the daemon's ML-DSA-65
  verifying key.
- `with_escrow(target, credential)` / `add_escrow(target, credential)` - put a
  credential in the in-memory escrow store for a target. Credential bytes are
  never printed: the manual `Debug` implementation reports counts only.
- `check(token, action, now_unix) -> Result<TokenClaims, String>` - verify and
  consume a token. Order: structural parse, signature verify, claims parse,
  expiry, action-hash compare, replay consume. The token id is recorded only
  after every check passes.
- `check_and_release(token, action, now_unix) -> Result<Option<Vec<u8>>, String>`
  - run `check`; on success return a clone of the credential escrowed for
  `action.target` (`None` when none is escrowed). A refusal releases nothing.

The consuming methods take `&mut self` because the used-token set and escrow
store are owned maps.

Refusals use a distinct message per class:

| Class | Message |
|-------|---------|
| Empty token | `missing execution token` |
| Short / malformed buffer or payload | `malformed execution token` |
| Signature does not verify | `execution token signature invalid` |
| Token was issued for another action | `execution token action mismatch: token was issued for a different action` |
| Past `expires_at` | `execution token expired` |
| Token id already consumed | `execution token already used` |

## Escrow mode, both sides

**Daemon side (CM-1).** `GUARDIAN_MESH_ESCROW_MODE` accepts `1` or `true`
(case-insensitive); anything else or unset is off. When on, an action with any
metadata key matching (case-insensitive, exact) `credential`, `credentials`,
`password`, `passwd`, `api_key`, `apikey`, `secret`, `token`, `access_key` or
`private_key` is blocked with rule `CM-1`, a reason naming the key, and the
remediation to remove credentials from the action. `token_id` and `monkey` are
not credential keys. The block applies to Evaluate and Simulate exactly like the
other early returns; only a real Evaluate appends to the tenant audit partition.

**Resource side (CM-1 / CM-3).** The resource process keeps the real credential
in its own checker (`with_escrow` / `add_escrow`) and releases it only after
`check_and_release` accepts a token for the exact action. The agent never holds
the credential and the daemon never carries it.

## Resource integration sketch

This is a sketch of the contract, not a CLI or a shipped integration:

```
# resource side, once
checker = ExecutionChecker::new(daemon_verifying_key)
checker.add_escrow(target, real_credential)

# per requested action
action = the exact ActionDescriptor the caller presented
if request has no token:
    refuse "missing execution token"
match checker.check_and_release(token, action, now):
    Ok(Some(credential)):
        execute action with credential
    Ok(None):
        execute action without an escrowed credential
    Err(reason):
        refuse execution; do not execute, do not release
```

A resource that only ever executes after `Ok` is a resource that accepts only
guardian-issued work for the action that was judged.

## Not claimed

- **No network or mTLS lockdown.** CM-3 here is the application-level checker
  hook. Forced routing (CM-4), mTLS identity and network policy remain
  deployment-side and are not built by this release.
- **No daemon-side credential vault.** The daemon does not store, inject or
  custody credentials. Escrow mode refuses agent-presented credentials; the
  credential itself lives with the resource-side checker. Daemon-side vault
  injection is the remainder of CM-1.
- **No receipts or reconciliation.** Signed execution receipts and continuous
  reconciliation against verdicts (CM-5) are WO-21.
- **No conformance probes.** Direct-access and non-catalogued-invocation probes
  (CM-8) are WO-27.
- **No shared one-time state across processes.** The used-token set is in-memory
  per checker instance.
- **No new RPCs, dependencies or CLI commands.** The token rides in the existing
  `EvaluateResponse` field 5; verification uses the existing ML-DSA-65 helpers.
