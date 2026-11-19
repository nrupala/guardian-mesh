# CLI (WO-18 profile 3 / CC-4)

Guardian Mesh v0.19.0 adds WO-18 profile 3: the `gm` operator CLI. It is a
client of the existing single-node daemon for operators and scripts, covering
the handshake, evaluate, verify and audit operations named by CC-4.

This document covers WO-18 profile 3 (CC-4), shipped in v0.19.0. The MCP surface
(CC-5) shipped in v0.20.0 as the separate `gm-mcp` binary; see
[MCP](MCP.md). v0.23.0 adds `gm doctor` (WO-22, SG-4), a local configuration
scan that names insecure settings and contacts no daemon. v0.28.0 adds
`gm certificate` (WO-37, T1): issue, inspect, verify and revoke
release-evidence certificates through the daemon's certificate RPCs. v0.29.0 adds
`gm publish` (WO-37, T2): check a publish action before posting and verify its
receipt through real Evaluate and VerifyProof. v0.30.0 adds
`gm conduit` (WO-37, T3): check a Conduit tool call before dispatch and verify
its receipt through real Evaluate and VerifyProof. v0.31.0 adds
`gm repo` (WO-37, T4): check a fleet-repo release before merge/release and verify
its receipt through real Evaluate and VerifyProof. v0.32.0 adds
`gm nightly` (WO-37, T5): check a nightly build-lane action before it proceeds
and verify its receipt through real Evaluate and VerifyProof.

## What the CLI is

`gm` is an ordinary client of a running `guardian-meshd`. It opens a handshake
session, seals an `ActionDescriptor`, calls `Evaluate` or `Simulate`, checks
saved proofs with `VerifyProof`, reads the audit trail with `ReadAuditLog`, and
issues, inspects, verifies or revokes release-evidence certificates with the
certificate RPCs. It adds no new verdict capability, no daemon behaviour, and no
clustering.

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
the default. The `certificate` actions need no session and no handshake; they
use the flag, `GM_ENDPOINT`, then the default.

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

## `gm doctor`

Scans the local configuration environment and names every insecure setting. It
reads the same `GUARDIAN_MESH_*` environment variables the daemon reads at
startup, builds the configuration in-process, and contacts no daemon.
`--endpoint` is accepted and ignored.

```bash
GUARDIAN_MESH_POSTURE=production gm doctor
```

Output is plain lines, not JSON:

```text
posture: production
BLOCKING GUARDIAN_MESH_HANDSHAKE_SECRET: the daemon is using the built-in default handshake secret, which is public in the source code; set GUARDIAN_MESH_HANDSHAKE_SECRET to a deployment-specific value (demo posture permits the default for local demonstration only)
warning GUARDIAN_MESH_REQUIRE_SPIFFE: SPIFFE attestation is not required in production posture; set GUARDIAN_MESH_REQUIRE_SPIFFE=1 to require SVID attestation at handshake
doctor: FAIL — 1 blocking finding(s)
```

Each finding is one of:

- `BLOCKING` - the daemon refuses to start in this posture.
- `warning` - insecure or notable, but startup is not refused.

`GUARDIAN_MESH_POSTURE` defaults to `production`. Production posture refuses the
built-in default handshake secret at startup. `demo` is for local demonstration
only: it allows the default secret, and the doctor still names it as a warning.
An invalid posture value is a blocking finding in every posture.

Exit 0 when there are no blocking findings, 2 when any blocking finding is
present (a normal result, not a usage error).

## `gm certificate`

Issues and manages release-evidence certificates (WO-37, v0.28.0). The four
actions call `IssueCertificate`, `CertificateStatus`, `VerifyProof` and
`RevokeCertificate`; none needs a session or a handshake. The schema and
lifecycle are in
[CERTIFICATE_SCHEMA](../specs/CERTIFICATE_SCHEMA.md); the release-gate operator
protocol is in
[RELEASE_GATE_TOUCHPOINT](RELEASE_GATE_TOUCHPOINT.md).

Endpoint resolution for all four actions is `--endpoint`, then `GM_ENDPOINT`,
then `http://127.0.0.1:50051`; no session file is read.

```bash
gm certificate issue --product guardian-mesh --version 0.28.0 \
  --verdict "PASS WITH FINDINGS" --evidence-file ./gate-pack.json \
  --evidence-scope full-history --tests-passed 85 --tests-failed 0 \
  --policy gate-v1.0.0 --cert-out ./ops/gm-certificate.json

gm certificate status --serial cert-20261115-000001
gm certificate verify --cert-file ./ops/gm-certificate.json --endpoint <second-daemon>
gm certificate revoke --serial cert-20261115-000001 --reason "verdict withdrawn"
```

### `gm certificate issue`

Required: `--product`, `--version`, `--verdict`, `--evidence-file`,
`--evidence-scope` (`working-tree` or `full-history`), `--tests-passed`,
`--tests-failed`, `--policy`. Optional: `--cert-out` (default
`gm-certificate.json` in the current directory) and `--endpoint`.

The CLI reads the evidence file and computes its SHA-256 itself; the operator
never types a hash. The test total sent to the daemon is `passed + failed`.

On issuance it writes the returned sealed envelope to the cert file and prints:

```json
{
  "issued": true,
  "serial": "cert-20261115-000001",
  "fingerprint": "...",
  "product": "guardian-mesh",
  "version": "0.28.0",
  "verdict": "PASS WITH FINDINGS",
  "evidence_hash": "...",
  "cert_file": "./ops/gm-certificate.json"
}
```

Exit 0. On refusal it prints `{"issued": false, "reason": "<refusal reason>"}`
to stdout, does not write or overwrite the cert file, and exits 1. A BLOCKED
verdict is refused this way, and the daemon also revokes any ACTIVE certificate
for that product+version. A missing or unreadable evidence file, a missing
certificate envelope in an `issued` response, and any gRPC/transport error are
runtime errors: exit 2.

### `gm certificate status`

Required: `--serial`. Prints the queried serial, the lifecycle status enum name
and the stored body:

```json
{
  "serial": "cert-20261115-000001",
  "status": "ACTIVE",
  "body": {
    "schema": "guardian-mesh/certificate",
    "schema_version": 1,
    "serial": "cert-20261115-000001",
    "issuer": "...",
    "product": "guardian-mesh",
    "version": "0.28.0",
    "verdict": "PASS WITH FINDINGS",
    "evidence_hash": "...",
    "evidence_scope": "full-history",
    "tests": { "passed": 85, "failed": 0, "total": 85 },
    "policy": "gate-v1.0.0",
    "pf_outcomes": null,
    "issued_at": 1790000000,
    "supersedes": null,
    "fingerprint": "..."
  }
}
```

`status` is `UNKNOWN`, `ACTIVE`, `SUPERSEDED` or `REVOKED`; an out-of-range
enum value prints `UNKNOWN`. `body` is `null` when the daemon has no stored body
and `tests` is `null` when absent. Exit 0 whenever the daemon answered —
`UNKNOWN` is an answer. Exit 2 on usage/transport errors.

### `gm certificate verify`

Optional: `--cert-file` (default `gm-certificate.json` in the current
directory), `--endpoint`. Loads the file as a proof file, rebuilds the envelope
and calls `VerifyProof`; no client-side signature check is performed.

```json
{ "valid": true, "reason": "ML-DSA-65 signature verified" }
```

Exit 0 iff the daemon reports the certificate valid, 1 iff it reports it
invalid, 2 on usage, cert-file or transport errors. A malformed or tampered cert
file is an invalid proof (exit 1), never a crash. Verify against a second daemon
instance or a separate client — never only the issuer.

### `gm certificate revoke`

Required: `--serial`, `--reason`. Prints:

```json
{
  "revoked": true,
  "message": "...",
  "serial": "cert-20261115-000001"
}
```

Exit 0 iff `revoked` is true, 1 iff the daemon answered `revoked` false, 2 on
usage/transport errors.

### Certificate file and honesty note

The certificate file has the same `ProofFile` JSON shape as `gm verify` reads:
hex-encoded `payload`, `payload_type`, `crc32c`, `ml_dsa_65_signature`,
`timestamp` and `nonce`. It is a sealed envelope, so
`gm verify --proof-file <cert-out>` also verifies it. The default cert-file path
is `gm-certificate.json` in the current directory.

The certificate binds the presenter's declarations (product, version, verdict,
test counts, policy and scope) to the evidence hash under the daemon's
signature. It certifies the binding, not the truth of the declarations, and is
not a warranty of quality or security. The hash is computed from the evidence
file, and a BLOCKED verdict refuses issuance and revokes daemon-side; no
certificate means no "certified" claim.

## `gm publish`

Publishing-pipeline touchpoint (WO-37, v0.29.0). Checks a publish action before
posting and writes a sealed-proof receipt; verifies the proof and the receipt's
content hash. `check` needs a handshake session and calls a real `Evaluate`
(never `Simulate`); `verify` needs no session.

### `gm publish check`

```bash
gm publish check --content-file <path> --destination <dest> \
  [--channel <name>] [--session-file <path>] \
  [--proof-out <path>] [--receipt-out <path>] [--endpoint <url>]
```

Required: `--content-file`, `--destination`. Optional: `--channel` (default
`blog`), `--session-file` (default `$HOME/.guardian-mesh/gm-session.json`),
`--proof-out` (default `gm-publish-proof.json` beside the session file),
`--receipt-out` (default `gm-publish-receipt.json` in the current directory),
`--endpoint`.

The CLI reads the content file and computes its SHA-256 and byte length itself;
the operator never types a hash. It calls a real `Evaluate` with `action_type`
`PUBLISH`, `context` `publishing:<channel>`, `target` `<destination>`, and
metadata `channel`, `content_bytes` (decimal string), `content_sha256`, and
`kind` = `publish`.

On a verdict response the sealed proof is saved and a receipt (not private) is
written pairing the proof with the content hash, destination and channel. The
printed JSON is the receipt with an added `receipt_file` field:

```json
{
  "receipt_version": 1,
  "kind": "publish",
  "content_sha256": "...",
  "content_bytes": 1234,
  "destination": "https://example.test/post",
  "channel": "blog",
  "verdict": "ALLOW",
  "reason": "...",
  "simulation": false,
  "proof": {
    "action_id": "PUBLISH",
    "verdict": "ALLOW",
    "timestamp": 1790000000,
    "policy_version": 1,
    "issuing_node": "node-..."
  },
  "proof_file": ".../gm-publish-proof.json",
  "receipt_file": "gm-publish-receipt.json"
}
```

**Exit codes:** `0` iff the verdict is `ALLOW` (the publisher may post). `1` iff
a verdict response arrived and the verdict is not `ALLOW` (`BLOCK`, `THROTTLE`,
`ESCALATE`) - the receipt is still written naming the verdict, so a refused
publish leaves its own record; do not post. `2` on usage, session, transport or
RPC error, including a pre-proof block delivered as a gRPC `permission_denied`
error - nothing is written (no proof, no receipt, existing files at those paths
are not overwritten); do not post. **Exit 0 is the only outcome under which the
publisher may post; exit 1 and exit 2 both mean do not post.**

### `gm publish verify`

```bash
gm publish verify [--receipt-file <path>] [--proof-file <path>] \
  [--content-file <path>] [--endpoint <url>]
```

Reads the receipt (default `gm-publish-receipt.json`) and proof (default: the
receipt's `proof_file`, or `--proof-file`), calls `VerifyProof`, and, when
`--content-file` is given, recomputes its SHA-256 and compares it to the
receipt's `content_sha256` (`content_hash_matches`: `true`/`false`, or `null`
when no file is given). Needs no session.

```json
{
  "valid": true,
  "reason": "ML-DSA-65 signature verified",
  "verdict": "ALLOW",
  "content_hash_matches": true,
  "content_sha256": "..."
}
```

**Exit codes:** `0` iff `valid` is true and `content_hash_matches` is not
`false`. `1` iff the daemon reports the proof invalid or the content hash
mismatches. `2` on usage, transport, or missing/malformed receipt or proof.

### Honesty notes

`check` is a real `Evaluate` only; simulation is never a publish check. A
publish blocked before proof sealing (Sentinel/Gatekeeper/Witness) arrives as an
RPC error, so `check` exits 2 and writes no receipt. The daemon's proof binds
the action type, verdict, timestamp and policy version; the pairing of the proof
to the content hash is asserted by the receipt (presenter-declaration class) and
checked by recomputation - `verify --content-file` recomputes the hash of the
presented artifact and compares it to the receipt. The receipt certifies that
binding, not the truth of its other fields, and is not a warranty of quality or
safety.

## `gm conduit`

Conduit tool-call touchpoint (WO-37, v0.30.0). Checks a Conduit tool call before
dispatch and writes a sealed-proof receipt; verifies the proof and the receipt's
args hash. `check` needs a handshake session and calls a real `Evaluate` (never
`Simulate`); `verify` needs no session. This command does not dispatch anything.

### `gm conduit check`

```bash
gm conduit check --tool <name> --tenant <id> --args-file <path> \
  [--provider <name>] [--session-file <path>] \
  [--proof-out <path>] [--receipt-out <path>] [--endpoint <url>]
```

Required: `--tool`, `--tenant`, `--args-file`. Optional: `--provider`,
`--session-file` (default `$HOME/.guardian-mesh/gm-session.json`), `--proof-out`
(default `gm-conduit-proof.json` beside the session file), `--receipt-out`
(default `gm-conduit-receipt.json` in the current directory), `--endpoint`.

```bash
gm conduit check --tool shell --tenant acme-example --args-file ./args.json
```

The CLI reads the args file and computes its SHA-256 and byte length itself; the
operator never types a hash. The raw args are never printed and never enter the
receipt. It calls a real `Evaluate` with `action_type` `TOOL_CALL`, `context`
`conduit:<tenant>`, `target` `<tool>`, and metadata `kind` = `conduit`, `tenant`,
`tool`, `args_sha256` (hex string), `args_bytes` (decimal string) and
`provider` when given.

On a verdict response the sealed proof is saved and a receipt (not private) is
written pairing the proof with the args hash, tenant and tool. The printed JSON
is the receipt with an added `receipt_file` field:

```json
{
  "receipt_version": 1,
  "kind": "conduit",
  "tenant": "acme-example",
  "tool": "shell",
  "provider": null,
  "args_sha256": "...",
  "args_bytes": 1234,
  "verdict": "ALLOW",
  "reason": "...",
  "simulation": false,
  "proof": {
    "action_id": "TOOL_CALL",
    "verdict": "ALLOW",
    "timestamp": 1790000000,
    "policy_version": 1,
    "issuing_node": "node-..."
  },
  "proof_file": ".../gm-conduit-proof.json",
  "receipt_file": "gm-conduit-receipt.json"
}
```

**Exit codes:** `0` iff the verdict is `ALLOW` (the caller may dispatch the tool
call). `1` iff a verdict response arrived and the verdict is not `ALLOW`
(`BLOCK`, `THROTTLE`, `ESCALATE`) - the receipt is still written naming the
verdict; do not dispatch. `2` on usage, session, transport or RPC error,
including a pre-proof block delivered as a gRPC `permission_denied` error -
nothing is written (no proof, no receipt, existing files at those paths are not
overwritten); do not dispatch. **Exit 0 is the only outcome under which the
caller may dispatch the tool call; exit 1 and exit 2 both mean do not dispatch.**

### `gm conduit verify`

```bash
gm conduit verify [--receipt-file <path>] [--proof-file <path>] \
  [--args-file <path>] [--endpoint <url>]
```

Reads the receipt (default `gm-conduit-receipt.json`) and proof (default: the
receipt's `proof_file`, or `--proof-file`), calls `VerifyProof`, and, when
`--args-file` is given, recomputes its SHA-256 and compares it to the receipt's
`args_sha256` (`args_hash_matches`: `true`/`false`, or `null` when no file is
given). Needs no session.

```bash
gm conduit verify --args-file ./args.json
```

```json
{
  "valid": true,
  "reason": "ML-DSA-65 signature verified",
  "verdict": "ALLOW",
  "args_hash_matches": true,
  "args_sha256": "..."
}
```

**Exit codes:** `0` iff `valid` is true and `args_hash_matches` is not `false`.
`1` iff the daemon reports the proof invalid or the args hash mismatches. `2` on
usage, transport, or missing/malformed receipt or proof.

### Honesty notes

`check` is a real `Evaluate` only; simulation is never a conduit check. A call
blocked before proof sealing arrives as an RPC error, so `check` exits 2 and
writes no receipt. The daemon's proof binds the action type, verdict, timestamp
and policy version; the pairing of the proof to the args hash is asserted by the
receipt (presenter-declaration class, GMSI-182) and checked by recomputation -
`verify --args-file` recomputes the hash of the presented args and compares it to
the receipt, so swapped args fail verification. Raw args never enter the receipt
or any log. This wires the check around a Conduit call: it does not dispatch the
call, does not prove the tool's output, and does not by itself route Conduit's
live service traffic (Conduit-side follow-on work).

## `gm repo`

Fleet-repo touchpoint (WO-37, v0.31.0). Checks a fleet-repo release - a
merge/release of the named repo at the named commit - before it proceeds and
writes a sealed-proof receipt; verifies the proof and the receipt's evidence
hash. `check` needs a handshake session and calls a real `Evaluate` (never
`Simulate`); `verify` needs no session. This command does not merge, push or
release anything.

### `gm repo check`

```bash
gm repo check --repo <owner/name> --commit <sha> --evidence-file <path> \
  [--branch <name>] [--session-file <path>] \
  [--proof-out <path>] [--receipt-out <path>] [--endpoint <url>]
```

Required: `--repo`, `--commit`, `--evidence-file`. Optional: `--branch`,
`--session-file` (default `$HOME/.guardian-mesh/gm-session.json`), `--proof-out`
(default `gm-repo-proof.json` beside the session file), `--receipt-out`
(default `gm-repo-receipt.json` in the current directory), `--endpoint`.

```bash
gm repo check --repo example-owner/example-repo --commit 0000000000000000000000000000000000000000 --evidence-file ./evidence.json
```

The CLI reads the evidence file and computes its SHA-256 and byte length itself;
the operator never types a hash. It calls a real `Evaluate` with `action_type`
`REPO_RELEASE`, `context` `repo:<repo>`, `target` `<repo>`, and metadata `kind` =
`repo`, `repo`, `commit`, `evidence_sha256` (hex string), `evidence_bytes`
(decimal string) and `branch` when given.

On a verdict response the sealed proof is saved and a receipt (not private) is
written pairing the proof with the evidence hash, repo and commit. The printed
JSON is the receipt with an added `receipt_file` field:

```json
{
  "receipt_version": 1,
  "kind": "repo",
  "repo": "example-owner/example-repo",
  "commit": "0000000000000000000000000000000000000000",
  "branch": null,
  "evidence_sha256": "...",
  "evidence_bytes": 1234,
  "verdict": "ALLOW",
  "reason": "...",
  "simulation": false,
  "proof": {
    "action_id": "REPO_RELEASE",
    "verdict": "ALLOW",
    "timestamp": 1790000000,
    "policy_version": 1,
    "issuing_node": "node-..."
  },
  "proof_file": ".../gm-repo-proof.json",
  "receipt_file": "gm-repo-receipt.json"
}
```

**Exit codes:** `0` iff the verdict is `ALLOW` (the caller may proceed with the
merge/release). `1` iff a verdict response arrived and the verdict is not
`ALLOW` (`BLOCK`, `THROTTLE`, `ESCALATE`) - the receipt is still written naming
the verdict; do not proceed. `2` on usage, session, transport or RPC error,
including a pre-proof block delivered as a gRPC `permission_denied` error -
nothing is written (no proof, no receipt, existing files at those paths are not
overwritten); do not proceed. **Exit 0 is the only outcome under which the
caller may proceed with the merge/release; exit 1 and exit 2 both mean do not
proceed.**

### `gm repo verify`

```bash
gm repo verify [--receipt-file <path>] [--proof-file <path>] \
  [--evidence-file <path>] [--endpoint <url>]
```

Reads the receipt (default `gm-repo-receipt.json`) and proof (default: the
receipt's `proof_file`, or `--proof-file`), calls `VerifyProof`, and, when
`--evidence-file` is given, recomputes its SHA-256 and compares it to the
receipt's `evidence_sha256` (`evidence_hash_matches`: `true`/`false`, or `null`
when no file is given). Needs no session.

```bash
gm repo verify --evidence-file ./evidence.json
```

```json
{
  "valid": true,
  "reason": "ML-DSA-65 signature verified",
  "verdict": "ALLOW",
  "evidence_hash_matches": true,
  "evidence_sha256": "..."
}
```

**Exit codes:** `0` iff `valid` is true and `evidence_hash_matches` is not
`false`. `1` iff the daemon reports the proof invalid or the evidence hash
mismatches. `2` on usage, transport, or missing/malformed receipt or proof.

### Honesty notes

`check` is a real `Evaluate` only; simulation is never a repo check. A release
blocked before proof sealing arrives as an RPC error, so `check` exits 2 and
writes no receipt. The daemon's proof binds the action type, verdict, timestamp
and policy version; the pairing of the proof to the evidence hash, repo and
commit is asserted by the receipt (presenter-declaration class, GMSI-182) and
checked by recomputation - `verify --evidence-file` recomputes the hash of the
presented evidence and compares it to the receipt, so swapped evidence fails
verification. This wires the check around a repo release: it does not merge,
push or release anything, does not prove the code in the commit is good, and
does not by itself integrate Guardian Mesh into any repo's CI (follow-on work in
each repo).

## `gm nightly`

Nightly build-lane touchpoint (WO-37, v0.32.0). Checks a build dispatch or a
merge step in the nightly program before it proceeds and writes a sealed-proof
receipt; verifies the proof and the receipt's evidence hash. `check` needs a
handshake session and calls a real `Evaluate` (never `Simulate`); `verify` needs
no session. This command does not dispatch builds, perform merges, or call the
nightly scheduler.

### `gm nightly check`

```bash
gm nightly check --work-order <id> --evidence-file <path> [--run <run-id>] \
  [--session-file <path>] [--proof-out <path>] \
  [--receipt-out <path>] [--endpoint <url>]
```

Required: `--work-order`, `--evidence-file`. Optional: `--run`, `--session-file`
(default `$HOME/.guardian-mesh/gm-session.json`), `--proof-out` (default
`gm-nightly-proof.json` beside the session file), `--receipt-out` (default
`gm-nightly-receipt.json` in the current directory), `--endpoint`.

```bash
gm nightly check --work-order <work-order-id> --evidence-file ./run-plan.json --run <run-id>
```

The CLI reads the evidence file and computes its SHA-256 and byte length itself;
the operator never types a hash. It calls a real `Evaluate` with `action_type`
`NIGHTLY_BUILD`, `context` `nightly:<work-order>`, `target` `<work-order>`, and
metadata `kind` = `nightly`, `work_order`, `evidence_sha256` (hex string),
`evidence_bytes` (decimal string) and `run` when given.

On a verdict response the sealed proof is saved and a receipt (not private) is
written pairing the proof with the evidence hash, work order and run. The printed
JSON is the receipt with an added `receipt_file` field:

```json
{
  "receipt_version": 1,
  "kind": "nightly",
  "work_order": "<work-order-id>",
  "run": "<run-id>",
  "evidence_sha256": "0000000000000000000000000000000000000000000000000000000000000000",
  "evidence_bytes": 0,
  "verdict": "ALLOW",
  "reason": "...",
  "simulation": false,
  "proof": {
    "action_id": "NIGHTLY_BUILD",
    "verdict": "ALLOW",
    "timestamp": 1790000000,
    "policy_version": 1,
    "issuing_node": "node-..."
  },
  "proof_file": ".../gm-nightly-proof.json",
  "receipt_file": "gm-nightly-receipt.json"
}
```

`run` is `null` in the receipt when `--run` is absent.

**Exit codes:** `0` iff the verdict is `ALLOW` (the caller may proceed with that
build dispatch or merge). `1` iff a verdict response arrived and the verdict is
not `ALLOW` (`BLOCK`, `THROTTLE`, `ESCALATE`) - the receipt is still written naming
the verdict; do not proceed. `2` on usage, session, transport or RPC error,
including a pre-proof block delivered as a gRPC `permission_denied` error -
nothing is written (no proof, no receipt, existing files at those paths are not
overwritten); do not proceed. **Exit 0 is the only outcome under which the caller
may proceed with the action; exit 1 and exit 2 both mean do not proceed.**

### `gm nightly verify`

```bash
gm nightly verify [--receipt-file <path>] [--proof-file <path>] \
  [--evidence-file <path>] [--endpoint <url>]
```

Reads the receipt (default `gm-nightly-receipt.json`) and proof (default: the
receipt's `proof_file`, or `--proof-file`), calls `VerifyProof`, and, when
`--evidence-file` is given, recomputes its SHA-256 and compares it to the
receipt's `evidence_sha256` (`evidence_hash_matches`: `true`/`false`, or `null`
when no file is given). Needs no session.

```bash
gm nightly verify --evidence-file ./run-plan.json
```

```json
{
  "valid": true,
  "reason": "ML-DSA-65 signature verified",
  "verdict": "ALLOW",
  "evidence_hash_matches": true,
  "evidence_sha256": "0000000000000000000000000000000000000000000000000000000000000000"
}
```

**Exit codes:** `0` iff `valid` is true and `evidence_hash_matches` is not
`false`. `1` iff the daemon reports the proof invalid or the evidence hash
mismatches. `2` on usage, transport, or missing/malformed receipt or proof.

### Honesty notes

`check` is a real `Evaluate` only; simulation is never a nightly check. An action
blocked before proof sealing arrives as an RPC error, so `check` exits 2 and
writes no receipt. The daemon's proof binds the action type, verdict, timestamp
and policy version; the pairing of the proof to the work order, run and evidence
hash is receipt-asserted (presenter-declaration class, GMSI-182) and checked by
recomputation - `verify --evidence-file` recomputes the hash of the presented
evidence and compares it to the receipt, so swapped evidence fails verification.
This wires the operator-run check before a build dispatch or a merge: it does
not dispatch builds or merge anything, does not evaluate intermediate lane steps
(one check per build/merge action), and does not wire cron/CI to call the check
(follow-on work). See [Nightly Touchpoint](NIGHTLY_TOUCHPOINT.md).

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
| `1` | `verify` / `certificate verify`: the daemon reports the proof or certificate invalid. `health`: the daemon is reachable but not `SERVING`/`DEGRADED`. `certificate issue`: the daemon refused issuance. `certificate revoke`: the daemon answered `revoked` false. |
| `2` | Usage, session, proof-file, transport, connection or gRPC error (error on stderr; no partial JSON on stdout), or `doctor`: one or more blocking findings (a normal result, printed on stdout). |

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
payload construction, session/proof/certificate file round-trips, argument
errors, the evidence-hash helper and certificate status-name mapping;
daemon-behaviour proof is Wright's leg.
