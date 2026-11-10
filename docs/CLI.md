# CLI (WO-18 profile 3 / CC-4)

Guardian Mesh v0.19.0 adds WO-18 profile 3: the `gm` operator CLI. It is a
client of the existing single-node daemon for operators and scripts, covering
the handshake, evaluate, verify and audit operations named by CC-4.

This document covers WO-18 profile 3 (CC-4), shipped in v0.19.0. The MCP surface
(CC-5) shipped in v0.20.0 as the separate `gm-mcp` binary; see
[MCP](MCP.md).

## What the CLI is

`gm` is an ordinary client of a running `guardian-meshd`. It opens a handshake
session, seals an `ActionDescriptor`, calls `Evaluate` or `Simulate`, checks
saved proofs with `VerifyProof`, and reads the audit trail with `ReadAuditLog`.
It adds no new verdict capability, no daemon behaviour, and no clustering.

The CLI holds no policy authority. It asks the daemon like any other client;
the daemon decides, seals the proof and owns the audit chain. Nothing in the
CLI intercepts or redirects workload traffic.

`gm-attest` is a different tool: it is the offline attestation utility that
never talks to a running daemon. `gm` is the live operator client.

## Build and install

Build from the repository root; the workspace produces all three binaries:

```bash
cargo build --release
```

The binaries are `target/release/guardian-meshd`, `target/release/gm-attest`
and `target/release/gm`. `gm` uses the dependencies the crate already has
(tokio, tonic, serde_json, hmac, sha2, ml-dsa, rand) and adds none. Argument
parsing is hand-rolled like `gm-attest`; there is no clap.

Install it wherever the operator's `PATH` points, for example
`/usr/local/bin/gm`.

## Connecting to the daemon

Every subcommand accepts `--endpoint <url>`. The resolution order is:

1. the `--endpoint` flag;
2. the `GM_ENDPOINT` environment variable;
3. for `evaluate`, `verify` and `audit`, the endpoint recorded in the session
   file (when the file exists);
4. `http://127.0.0.1:50051`.

`handshake` has no session file yet, so it uses the flag, `GM_ENDPOINT`, then
the default.

## `gm health`

Calls `Health`. Prints the full health response as one JSON object: `status` as
its enum name (`UNKNOWN`, `SERVING`, `NOT_SERVING` or `DEGRADED`), build
identity (`build_version`, `build_commit`, `binary_sha256`), the daemon's
`signing_key_fingerprint`, `node_id`, the degraded fields, enclave health and
the protocol-firewall counters.

```bash
gm health
```

```json
{
  "status": "SERVING",
  "build_version": "0.19.0",
  "build_commit": "unknown",
  "binary_sha256": "...",
  "signing_key_fingerprint": "...",
  "node_id": "node-...",
  "degraded": false,
  "degraded_trigger": "",
  "degraded_safe_actions": [],
  "degraded_since_unix": 0,
  "enclave_health": { "sentinel": "ok", "gatekeeper": "ok", "witness": "ok", "arbiter": "ok", "vault": "ok" },
  "protocol_firewall_rules_passed": 0,
  "protocol_firewall_rules_total": 0,
  "protocol_firewall_rule_counters": {}
}
```

Exits 0 when the status is `SERVING` or `DEGRADED`, 1 otherwise (including on a
daemon that is reachable but not serving). A connection failure is a transport
error: exit 2.

## `gm handshake`

Generates a fresh 32-byte seed, derives the ML-DSA-65 keypair from it, and calls
`Handshake` with `source_enclave` `gm-cli`. The caller's encoded verifying key is
bound to the new session. The seed is persisted so the same signing key can be
rebuilt for later `evaluate` calls.

```bash
gm handshake
gm handshake --tenant acme --session-file ./ops/gm-session.json
```

It prints only the non-secret session facts, never the session key or seed:

```json
{
  "session_id": "...",
  "ttl_seconds": 300,
  "tenant_id": "default",
  "session_file": "C:\\Users\\operator\\.guardian-mesh\\gm-session.json"
}
```

The session file is created (and its parent directory created if needed) with
mode 0600 on Unix. See [Session file](#session-file).

## `gm evaluate`

Loads the session file, rebuilds the signing key from the seed, builds the exact
`ActionDescriptor` JSON payload (`actionType`, `context`, `target`, `metadata` -
camelCase, no other fields), seals it with `SealedEnvelope::new`, computes
`HMAC-SHA256(session_key, payload)`, and calls `Evaluate`. With `--simulate` it
calls `Simulate` instead.

```bash
gm evaluate --action-type TOOL_CALL --context chat --target shell \
  --metadata source=script --metadata run=42

gm evaluate --action-type CODE_EXECUTE --context build --target compile \
  --simulate --proof-out ./ops/last-proof.json
```

It prints the verdict and a proof summary as JSON:

```json
{
  "verdict": "ALLOW",
  "reason": "...",
  "containment_stage": "NORMAL",
  "simulation": false,
  "reasons": [
    { "rule_id": "...", "detail": "...", "remediation": "..." }
  ],
  "proof": {
    "action_id": "TOOL_CALL",
    "verdict": "ALLOW",
    "timestamp": 1790000000,
    "policy_version": 1,
    "issuing_node": "node-..."
  }
}
```

The returned `proof_envelope` is saved to the proof file (default
`gm-proof.json` beside the session file, overridable with `--proof-out`). See
[Proof file](#proof-file-and-evaluate---verify).

Exit 0 for any verdict that arrives in a response, including `BLOCK` and
`THROTTLE`; the verdict is in the JSON, not the exit code. A `BLOCK` from a
later enforcement stage is still a successful CLI operation.

One daemon detail matters to scripts: a real `Evaluate` block raised before a
proof is sealed (Sentinel, Gatekeeper or Witness) is delivered by the daemon as
a gRPC `permission-denied` error. The CLI treats that as an RPC error: exit 2,
message on stderr, no JSON. Use `gm evaluate --simulate` when you want such a
block as a `BLOCK` verdict in JSON without executing the action.

Exit 2 also covers a missing session file, an expired session, an unreachable
daemon, and any other gRPC/transport error.

## `gm verify`

Loads a proof file, rebuilds the proto `SealedEnvelope`, and calls `VerifyProof`.

```bash
gm verify
gm verify --proof-file ./ops/last-proof.json
```

```json
{
  "valid": true,
  "reason": "ML-DSA-65 signature verified",
  "proof": null
}
```

Exit 0 iff the daemon reports the proof valid, 1 iff it reports it invalid, and
2 on usage, proof-file or transport errors. A tampered proof file (for example
one flipped payload or signature byte) is an invalid proof, not a crash and not
a transport error: exit 1.

## `gm audit`

Calls `ReadAuditLog` and prints the entries plus the chain verification status.

```bash
gm audit
gm audit --limit 20
```

```json
{
  "entries": [
    {
      "sequence": 0,
      "timestamp": 1790000000,
      "action_id": "...",
      "verdict": "ALLOW",
      "enclave_chain": "...",
      "chain_hash": "...",
      "reason": "..."
    }
  ],
  "verification": {
    "verified": true,
    "entries_checked": 1,
    "first_break_position": 0,
    "status_message": "..."
  }
}
```

`--limit <n>` truncates the **printed** entries client-side after the daemon has
returned and verified the full log. It does not ask the daemon to limit the
audit read; `verification.entries_checked` still describes the daemon's full
check. Exit 0 on success, 2 on usage/transport errors.

## Session file

The default session file is `$HOME/.guardian-mesh/gm-session.json`.
`--session-file` overrides it for `handshake`, `evaluate`, `verify` and `audit`.
The directory is created by `handshake` if needed.

It is JSON with these fields:

| Field | Meaning |
|---|---|
| `endpoint` | Daemon endpoint used for the handshake. |
| `session_id` | Handshake session id. |
| `session_key` | Hex-encoded HMAC-SHA256 session key. |
| `signing_seed` | Hex-encoded 32-byte ML-DSA-65 seed. |
| `tenant_id` | Session tenant (the daemon's default when none was requested). |
| `created_unix` | Unix seconds when the session was created. |
| `ttl_seconds` | Session lifetime reported by the daemon (300 seconds today). |

The `session_key` and `signing_seed` are **bearer secrets**. Anyone who can read
the file can produce valid requests on that session and can recreate the
signing key. The file is written with mode 0600 on Unix; protect it on any other
platform with the equivalent file permissions. The CLI never prints either
secret. Output names only the session-file path.

Sessions expire after the daemon's TTL. An expired session means re-running
`gm handshake`; there is no refresh call. `evaluate` checks the recorded
`created_unix + ttl_seconds` before connecting and fails with exit 2 and a clear
message telling the operator to re-run `handshake`.

## Proof file and evaluate -> verify

`evaluate` saves the daemon-issued `proof_envelope` as JSON. The default path is
`gm-proof.json` beside the session file; `--proof-out` and `--proof-file` choose
another path. All fields are hex-encoded:

| Field | Encoding |
|---|---|
| `payload` | Hex bytes. |
| `payload_type` | Hex bytes. |
| `crc32c` | 8 lowercase hex digits of the `u32` CRC32C value. |
| `ml_dsa_65_signature` | Hex bytes. |
| `timestamp` | 16 lowercase hex digits of the `u64` envelope timestamp. |
| `nonce` | Hex bytes (32-byte nonce). |

The normal flow is:

```bash
gm handshake
gm evaluate --action-type TOOL_CALL --context chat --target shell \
  --metadata source=script
gm verify
```

`evaluate` seals and saves the proof; `verify` rebuilds exactly that envelope
and asks the daemon to re-check the CRC32C and ML-DSA-65 signature. The proof
file contains no session secret and may be kept as evidence; the session file
must not be shared.

## Exit code contract

| Code | Meaning |
|---|---|
| `0` | Successful operation, or any verdict returned in a response (including `BLOCK`, `THROTTLE` and `ESCALATE`). |
| `1` | `verify`: the daemon reports the proof invalid. `health`: the daemon is reachable but not `SERVING`/`DEGRADED`. |
| `2` | Usage, session, proof-file, transport, connection or gRPC error. Error on stderr; no partial JSON on stdout. |

The **BLOCK-is-success** rule is deliberate: a `BLOCK` verdict is a successful
CLI operation, and scripts read the verdict from the JSON. Do not treat exit 0
as permission to act; read `verdict`.

## Scripting notes

- JSON goes to stdout, and only on success. Errors go to stderr. Exit 2 means
  stdout is empty.
- Parse `verdict` for `evaluate`. Treat any missing answer - connection refused,
  timeout, transport error, invalid proof - as do-not-act. The CLI reports those
  as errors, but the enforcement discipline remains the caller's.
- Never print or log the session file's `session_key` or `signing_seed`. Do not
  pass the session file to shared hosts or commit it.
- Re-run `gm handshake` when `evaluate` reports an expired session.

## Explicit non-claims

- **Client, not new capability.** `gm` is a client of the existing single-node
  daemon. It adds no verdict capability, no daemon logic and no clustering
  (WO-16 DC-1/DC-3 remain open).
- **CC-5 MCP is a separate binary.** The MCP surface shipped in 0.20.0 as the
  separate `gm-mcp` binary (see [MCP](MCP.md)); this CLI is not an MCP server.
- **No policy authority.** The CLI does not decide, override or amend policy. It
  asks the daemon like any other client.
- **No TEE attestation and no external anchoring.** Both are designed, not
  built.
- **Not forced routing.** Nothing captures the workload's traffic (CM-4 is not
  built); omitting the call to the guardian is still possible.
- **No new dependencies.** The CLI uses the crate's existing dependencies and a
  hand-rolled argument parser.
- **License.** Apache License 2.0 plus the Payment Rider. It is never
  "unmodified Apache 2.0"; see `LICENSE` and `LICENSE-RIDER.md`.

## Verification status

This document does not assert test or build results. The build lane ran no
`cargo`, `npm`, `docker` or `podman` commands; Wright verifies the daemon
behaviour independently. The unit tests in `gm.rs` need no daemon and cover only
payload construction, session/proof file round-trips and argument errors;
daemon-behaviour proof is Wright's leg.
