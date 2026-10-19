# guardian-meshd — Guardian Mesh Daemon

The **enforcement engine** of Guardian Mesh. A Rust gRPC service that evaluates
every agent action through a 5-enclave pipeline and returns an audited,
cryptographically-signed verdict.

## What it does

Every action an agent attempts is passed through a fixed chain of enclaves.
Each enclave sees only the information its role requires, and produces a
verdict. Any enclave can block; **no single enclave can both observe and
enforce**.

```
Request ─▶ SENTINEL ─▶ GATEKEEPER ─▶ WITNESS ─▶ ARBITER ─▶ VAULT ─▶ Response
            PF-01..18   HMAC session  ML-DSA-65    Policy       Audit log
```

| Enclave | Role | Can see | Cannot |
|---------|------|---------|--------|
| **Sentinel** | Protocol Firewall validation | envelope structure, sizes, targets | policy, secrets |
| **Gatekeeper** | HMAC handshake session auth | session, HMAC tag | secrets, audit |
| **Witness** | Signs the verdict digest | hashed proof only | block, read behavior |
| **Arbiter** | Policy-engine decision | action_type, policy | enforce, audit |
| **Vault** | Seals + persists audit | nothing external | export raw keys |

## Cryptographic building blocks

| Concern | Mechanism |
|---------|-----------|
| Payload integrity | **CRC32C** digest over payload |
| Signatures / keypair | **ML-DSA-65** (FIPS 204, post-quantum) |
| Session authentication | **HMAC-SHA256** over handshake session key |
| Audit digests | **SHA-256** |

`src/sealed_envelope.rs` implements a `SealedEnvelope` (payload + CRC32C +
ML-DSA-65 signature + timestamp + nonce) that can be serialized and verified —
this is the unit of trust exchanged with the daemon.

## Persistent Signing Key

The daemon's ML-DSA-65 signing key persists across restarts, so proofs issued
by different instances of the same daemon verify against the same public key.

### Key Storage

On first start, the daemon generates a fresh ML-DSA-65 keypair and stores the
seed (32 bytes) to:

```
{GUARDIAN_MESH_WORKSPACE}/keys/daemon_signing_key.bin
```

The file is created with **restrictive permissions** (0600 on Unix; on other
platforms the file system's default for user-only files applies). Operators
should ensure the workspace directory itself is protected from unauthorized
access.

On subsequent starts, the daemon loads the existing seed and reconstructs the
same keypair. Proofs issued across restarts verify against the same public key.

### Fingerprint

The **Health RPC** reports the signing-key fingerprint in the
`signing_key_fingerprint` field: the lowercase hex-encoded SHA-256 hash of the
daemon's ML-DSA-65 public key (1952 bytes). This fingerprint allows operators
and clients to identify the daemon's signing identity without exposing key
material.

### Fail-Closed Behavior

If the stored key file exists but is **corrupt** or the **wrong length**, the
daemon fails closed: it exits with a clear **FATAL** log naming the problem and
does NOT silently regenerate the key. Silently changing the signing identity
would invalidate all outstanding proofs and must be an operator decision, not a
default behavior.

### Backup

To back up the signing key, copy the key file:

```bash
cp {GUARDIAN_MESH_WORKSPACE}/keys/daemon_signing_key.bin /secure/backup/location/
```

### Rotation

To rotate the signing key:

1. **Stop the daemon.**
2. **Move the old key aside** (do NOT delete it immediately — keep it in case
   old proofs need verification):
   ```bash
   mv {GUARDIAN_MESH_WORKSPACE}/keys/daemon_signing_key.bin \
      {GUARDIAN_MESH_WORKSPACE}/keys/daemon_signing_key.bin.old
   ```
3. **Start the daemon.** It will generate a fresh keypair.

**Note:** Proofs issued under the old key will stop verifying against the new
fingerprint. This is expected behavior. Clients must obtain fresh proofs from
the daemon after rotation.

## Protocol

`proto/guardian_mesh.proto` defines five RPCs:

```proto
rpc Evaluate      (EvaluateRequest)      returns (EvaluateResponse)
rpc VerifyProof   (VerifyProofRequest)   returns (VerifyProofResponse)
rpc Health        (HealthRequest)        returns (HealthResponse)
rpc Handshake     (HandshakeRequest)     returns (HandshakeResponse)
rpc ReadAuditLog  (ReadAuditLogRequest)  returns (ReadAuditLogResponse)
```

- **Evaluate** runs the full pipeline and returns `ALLOW | BLOCK | THROTTLE | ESCALATE`
  plus the current `containment_stage` and an `AuditProof` carrying the
  Witness's ML-DSA-65 signature.
- **VerifyProof** validates a sealed envelope (CRC32C + signature) against the
  daemon's verifying key.
- **Health** reports `SERVING` plus per-enclave status and protocol-firewall
  rule pass/total counters.
- **Handshake** opens a session and binds the caller's ML-DSA-65 public key to it.
  Returns session ID and HMAC key for subsequent `Evaluate` calls.
- **ReadAuditLog** returns the Vault's hash-chained audit trail in append order
  plus chain verification status.

## Audit Trail Read Path

The Vault appends every evaluation to a hash-chained audit log stored on disk
(`{GUARDIAN_MESH_WORKSPACE}/audit/audit_<day>.jsonl`). The `ReadAuditLog` RPC
exposes a read-only view of this log.

### What it returns

- **Audit entries** in append order, each carrying:
  - `sequence` — position in the log (0-indexed)
  - `timestamp` — Unix seconds when the entry was sealed
  - `action_id` — hex-encoded action type
  - `verdict` — the Arbiter's decision (`ALLOW`, `BLOCK`, etc.)
  - `enclave_chain` — the full enclave chain that processed this action
  - `chain_hash` — the stored hash for this entry (SHA-256 of prev_hash ||
    timestamp || action_id || verdict || enclave_chain || reason)
  - `reason` — the verdict reason or error detail

- **Chain verification status** computed by re-walking the chain at read time:
  - `verified` — `true` if the chain is intact, `false` if any entry breaks it
  - `entries_checked` — how many entries were verified
  - `first_break_position` — if not verified, the 0-indexed position of the
    first broken entry (0 if verified)
  - `status_message` — human-readable summary

### What chain verification proves

Chain verification **proves** that the log has not been altered since the daemon
wrote it:

- Each entry's stored `chain_hash` is re-computed from the entry's own data plus
  the previous entry's hash, starting from a known genesis hash (64 zeros).
- If every computed hash matches its stored value, the chain is intact — no
  entry was inserted, deleted, or modified.
- If any computed hash does not match, verification reports the **first** broken
  position, not a generic failure.

Chain verification **does not prove**:

- That the daemon itself was not compromised when it wrote the log (a
  compromised daemon could write a valid but dishonest chain).
- That the log file was not replaced wholesale (chain verification checks
  internal consistency, not authenticity of the log's origin).
- That entries represent real evaluations (the RPC reads what the Vault wrote;
  it does not re-evaluate actions).

### What to do when verification reports a break

A broken chain means the log file was edited after the daemon wrote it. This is
a **security incident**:

1. **Do not trust the log contents.** Any entry could have been altered,
   inserted, or deleted.
2. **Preserve the log file** for forensic analysis (copy it to a secure
   location; do not modify or delete it).
3. **Investigate** who had write access to `{GUARDIAN_MESH_WORKSPACE}/audit/`
   and when the modification occurred.
4. **Check backups** (if any) for an intact log prior to the break.
5. **Rotate the daemon's workspace** (move the current workspace aside, start
   fresh) if the integrity of the entire workspace is suspect.

The `first_break_position` tells you where to start looking: the entry at that
position is the first one that does not match its expected chain hash. The
break could be at that entry itself or earlier (if an earlier entry was edited,
all subsequent hashes would also fail).

### Read-only guarantee

The `ReadAuditLog` RPC and the live panel's audit view **do not mutate** the
log, the chain, or any daemon state. They are read-only operations. If the log
file is missing or unreadable, the RPC returns a clear error distinguishing
"log exists and is empty" from "log file is unreadable."

## Protocol Firewall (18 rules)

`src/protocol_firewall.rs` defines **18 rules** (PF-01..PF-18) governing
envelope structure, CRC32C, signature, timestamp drift, nonce replay, session
existence, HMAC match, action recognition, context length, path traversal,
blocklist, rate limit, deny-list, chain state, containment stage, and audit
transaction. **Currently 4 are enforced live** (PF-01, PF-04, PF-10, PF-11);
the remainder are scaffolded. See `specs/GUARDIAN_MESH_GAP_ANALYSIS.md`.

## Configuration

All via environment variables (`src/config.rs`):

| Variable | Default | Purpose |
|----------|---------|---------|
| `GUARDIAN_MESH_BIND_ADDR` | `127.0.0.1` | Bind address |
| `GUARDIAN_MESH_PORT` | `50051` | gRPC port |
| `GUARDIAN_MESH_WORKSPACE` | `guardian-mesh-data/workspace` | Runtime data (audit/sessions/keys) |
| `GUARDIAN_MESH_OUTPUT` | `guardian-mesh-data/output` | Generated output |
| `GUARDIAN_MESH_HANDSHAKE_SECRET` | embedded fallback | HMAC master secret |

## Build & test

```bash
cargo build --release            # release binary
cargo clippy --all-targets -- -D warnings   # must be clean
cargo test                        # 64 unit tests, all green
```

Requires `protoc` on `PATH` (protobuf codegen runs in `build.rs`).

## Security notes

- `GUARDIAN_MESH_HANDSHAKE_SECRET` should be set to a strong random value in any
  deployment; the embedded value is a dev fallback only.
- The gRPC server currently serves **plaintext**. For production, terminate TLS
  / mTLS in front of the daemon.
- Policy `overrides` (`src/policy.rs`) are in-memory only and reset on restart.

## See also

- `AGENT_HANDOVER.md` — maintenance notes for a future developer.
- `../specs/GUARDIAN_MESH_FORMAL_SPEC.md` — formal specification.
- `../README.md` — whole-project overview.