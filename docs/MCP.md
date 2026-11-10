# MCP (WO-18 profile 4 / CC-5)

Guardian Mesh v0.20.0 adds WO-18 profile 4: the `gm-mcp` stdio MCP server. It
exposes the existing single-node daemon's health, evaluate/simulate, proof
verification and audit log as MCP tools for agent frameworks. It is an ordinary
client of a running daemon, exactly like the `gm` CLI, and holds no policy
authority.

This release claims only WO-18 profile 4 (CC-5). Client access remains the
existing proto/gRPC API and the `gm` CLI. The MCP surface is an additional client
form, not a replacement for either.

## What `gm-mcp` is

`gm-mcp` is a long-lived stdio MCP server. It speaks newline-delimited JSON-RPC
2.0 on stdin/stdout, advertises four tools, and answers each `tools/call` by
asking the running `guardian-meshd` over gRPC. It opens a handshake session
lazily, seals an `ActionDescriptor`, calls `Evaluate` or `Simulate`, verifies
proof envelopes with `VerifyProof`, and reads the audit trail with
`ReadAuditLog`.

The daemon still decides. `gm-mcp` does not evaluate policy, override a verdict,
amend a proof, or write the audit chain. It is a client surface of the existing
daemon and adds no new verdict capability.

stdout carries protocol messages only. Every diagnostic goes to stderr, so an
MCP client can parse stdout as a pure JSON-RPC stream.

## What `gm-mcp` is not

- It is not a new verdict engine or policy authority.
- It is not a cluster. Multi-node consensus and threshold issuance (WO-16
  DC-1/DC-3) remain target.
- It is not TEE attestation and it does not anchor proofs externally. Both are
  designed, not built.
- It is not forced routing (CM-4). An agent framework must choose to call the
  tools; nothing captures or redirects the workload's traffic.
- It is not an MCP client library or an integration wrapper for a specific
  vendor. It is the stdio server surface itself.

`gm-attest` remains the separate offline attestation utility. `gm` remains the
operator CLI. `gm-mcp` is the MCP server.

## Build and run

Build from the repository root; the workspace produces all four binaries:

```bash
cargo build --release
```

The binaries are `target/release/guardian-meshd`, `target/release/gm-attest`,
`target/release/gm` and `target/release/gm-mcp`. `gm-mcp` uses only the crate's
existing dependencies (tokio, tonic, serde_json, hmac, sha2, ml-dsa, rand) and
adds none.

Start the daemon first, then point an MCP client at the server. There are no
command-line flags: configuration comes from the environment.

```bash
GM_ENDPOINT=http://127.0.0.1:50051 GM_TENANT=default target/release/gm-mcp
```

A client normally launches the process itself as a stdio server entry. An
operator can also run it directly and speak JSON-RPC on stdin/stdout.

## Configuration

| Variable | Meaning | Default |
|---|---|---|
| `GM_ENDPOINT` | Daemon gRPC endpoint. | `http://127.0.0.1:50051` |
| `GM_TENANT` | Tenant id requested at handshake. | Empty (daemon default tenant). |

Both are read once at startup. An empty `GM_ENDPOINT` falls back to the default.
The process never writes a session file, key, seed or proof to disk.

## Generic MCP client configuration

Any MCP client that supports a stdio server can launch `gm-mcp`. The shape below
is generic; consult the client's own documentation for its exact configuration
file location and key names.

```json
{
  "mcpServers": {
    "guardian-mesh": {
      "command": "/usr/local/bin/gm-mcp",
      "env": {
        "GM_ENDPOINT": "http://127.0.0.1:50051",
        "GM_TENANT": "default"
      }
    }
  }
}
```

The daemon must already be running at `GM_ENDPOINT`. `gm-mcp` does not start the
daemon.

## Protocol and tool catalogue

The server implements the MCP stdio transport as newline-delimited JSON-RPC 2.0.
Supported protocol versions are `2024-11-05`, `2025-03-26` and `2025-06-18`;
`initialize` echoes the client's version when it is one of those, otherwise it
answers `2024-11-05`. Notifications (messages without an `id`) get no response.
`ping` returns `{}`. `tools/list` returns the four tools below. Unknown methods
return JSON-RPC error `-32601`; a malformed line returns `-32700` and the server
continues serving later lines; a request without a `method` returns `-32600`.

Every successful or daemon-failed `tools/call` returns the MCP tool result shape:

```json
{
  "content": [{ "type": "text", "text": "<JSON string>" }],
  "isError": false
}
```

The `text` field is a JSON string carrying the tool's own result object.
Argument-validation failures are tool results with `isError: true` whose text
names the bad or missing field; they do not crash the process and do not become
JSON-RPC protocol errors.

### `guardian_health`

No arguments. Calls `Health`. The text JSON is the same field set `gm health`
prints: `status` as its enum name (`UNKNOWN`, `SERVING`, `NOT_SERVING` or
`DEGRADED`), build identity, signing-key fingerprint, `node_id`, degraded fields,
enclave health and protocol-firewall counters.

```json
{
  "status": "SERVING",
  "build_version": "0.20.0",
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

### `guardian_evaluate`

Arguments:

| Field | Type | Required | Meaning |
|---|---|---|---|
| `action_type` | string | yes | Action type, for example `TOOL_CALL`. |
| `context` | string | yes | Action context. |
| `target` | string | yes | Action target. |
| `metadata` | object of string values | no | Metadata map. |
| `simulate` | boolean | no (default `false`) | Call `Simulate` instead of `Evaluate`. |

The server ensures a session, seals the exact `ActionDescriptor` payload,
computes the session HMAC and calls `Evaluate` (or `Simulate`). The text JSON
mirrors `gm evaluate`'s output plus a `proof_envelope` field:

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
  },
  "proof_envelope": {
    "payload": "<hex>",
    "payload_type": "<hex>",
    "crc32c": "<8 hex digits>",
    "ml_dsa_65_signature": "<hex>",
    "timestamp": "<16 hex digits>",
    "nonce": "<hex>"
  }
}
```

`proof_envelope` is exactly the proof-file JSON shape used by `gm evaluate` and
`gm verify`, so it can be passed straight to `guardian_verify`.

One daemon detail carries over from the CLI: a real `Evaluate` block raised
before a proof is sealed (Sentinel, Gatekeeper or Witness) is delivered by the
daemon as a gRPC `permission-denied` error. The MCP call therefore returns a
tool result with `isError: true` and the fail-closed text; it is not a verdict
object. Use `simulate: true` when such a block should arrive as a `BLOCK` verdict
in JSON without executing the action.

### `guardian_verify`

Arguments:

| Field | Type | Required | Meaning |
|---|---|---|---|
| `proof` | object | yes | Proof envelope in the proof-file shape (the six hex fields shown above). |

The server rebuilds the proto envelope and calls `VerifyProof`. Malformed hex in
any field returns `isError: true` whose text names the field. The text JSON
mirrors `gm verify`'s output:

```json
{
  "valid": true,
  "reason": "ML-DSA-65 signature verified",
  "proof": null
}
```

### `guardian_audit`

Arguments:

| Field | Type | Required | Meaning |
|---|---|---|---|
| `limit` | integer | no | Print at most this many entries. |

Calls `ReadAuditLog` and returns entries plus the daemon's chain verification
status. `limit` truncates the printed entries client-side only, exactly as
`gm audit --limit` does; the daemon still returns and verifies the full log.

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

## Fail-closed behaviour

`guardian_evaluate` fails closed. When the daemon is unreachable or a call fails
at transport level, the tool result has `isError: true` and its text says that
no verdict was issued and the caller MUST treat the action as BLOCK. The result
also carries `fail_closed: true` and `must_treat_as: "BLOCK"`.

The server process does not exit on a daemon error. It keeps answering
subsequent requests; a `ping` after a failed evaluate still returns `{}`. A
missing answer is never permission to act: the caller's enforcement discipline
remains to treat any absent or errored evaluate as do-not-act.

## Session handling

Sessions are in-memory only.

- The first `guardian_evaluate` opens a session lazily with a fresh 32-byte seed,
  derives the ML-DSA-65 keypair from that seed, and calls `Handshake` with
  `source_enclave` `gm-mcp` and the configured tenant.
- The server caches the session id, session key, signing seed, creation time and
  daemon TTL in memory. There is no session file.
- A session past `created + ttl_seconds` is re-handshaked before the next
  evaluate.
- If an evaluate/simulate call returns a session error (unauthenticated, or
  permission-denied naming the session), the server re-handshakes once and
  retries the call once.
- The session key and signing seed are bearer secrets. They are never written to
  stdout, stderr, a file, or any tool result.

## Smoke proof (GMSI-124)

`scripts/smoke.sh` is the in-repo operator-surface smoke proof. It is test
scaffolding, not shipped runtime.

```bash
scripts/smoke.sh                          # default endpoint
scripts/smoke.sh http://127.0.0.1:50051   # explicit endpoint
```

The script assumes `guardian-meshd` is already running at the endpoint and that
`gm` and `gm-mcp` are built (it prefers `target/release`, then
`target/debug`). It uses a temporary directory for the CLI's session and proof
files, runs one `PASS <leg>` or `FAIL <leg>` line per leg, and exits non-zero if
any leg fails.

The legs are:

1. `gm health`.
2. `gm handshake`.
3. `gm evaluate` of `TOOL_CALL`, parsed as verdict `ALLOW`.
4. `gm verify`, parsed as valid.
5. `gm verify` with one hex character of the proof payload flipped (exit 1); the
   flipped byte is written to a copy, never the original proof file.
6. `gm audit`.
7. `gm health` against an unreachable endpoint (exit 2).
8. The MCP legs through `scripts/smoke_mcp.py` against the live daemon.
9. The MCP fail-closed legs through a second `gm-mcp` instance pointed at the
   unreachable endpoint: evaluate returns `isError: true` and a following `ping`
   still answers.

`scripts/smoke_mcp.py` is a Python 3 standard-library driver. It spawns
`gm-mcp`, speaks newline-delimited JSON-RPC, and asserts on parsed fields:
`initialize`, `notifications/initialized`, `tools/list` (the four tool names),
`guardian_health`, `guardian_evaluate` (`TOOL_CALL` -> `ALLOW`, capturing
`proof_envelope`), `guardian_verify` (valid), and `guardian_audit`. Its
`--unreachable` mode asserts that evaluate is `isError: true` and that a
following ping still returns a result. It exits non-zero on any failure.

A gate run executes `scripts/smoke.sh` against a live daemon after the Rust test
suite. The Python driver is scaffolding under `scripts/`; it is never a product
component.

## Explicit non-claims

- **No new verdict capability.** `gm-mcp` asks the existing daemon like any
  other client. It adds no daemon logic, no policy authority and no new decision
  path.
- **No clustering.** Multi-node consensus and threshold issuance (WO-16
  DC-1/DC-3) remain target.
- **No TEE attestation.** Designed, not built.
- **No external anchoring.** Designed, not built.
- **NOT forced routing (CM-4).** Nothing captures the workload's traffic. An
  agent framework must choose to call the tools, and omitting the call is still
  possible.
- **CC-5 scope.** This release ships the MCP server surface. Client access
  remains the existing proto/gRPC API and the `gm` CLI.
- **No new dependencies.** `gm-mcp` uses the crate's existing dependencies.
- **License.** Apache License 2.0 plus the Payment Rider. It is never
  "unmodified Apache 2.0"; see `LICENSE` and `LICENSE-RIDER.md`.

## Verification status

This document does not assert test or build results. The build lane ran no
`cargo`, `npm`, `docker` or `podman` commands; Wright verifies the daemon and MCP
behaviour independently. The unit tests in `gm-mcp.rs` need no daemon and cover
protocol negotiation, the tool catalogue, JSON-RPC error codes, argument
validation and proof-envelope round-trips; the live smoke legs are Wright's
behaviour proof.
