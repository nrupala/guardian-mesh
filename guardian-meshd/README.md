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

`proto/guardian_mesh.proto` defines three RPCs:

```proto
rpc Evaluate    (EvaluateRequest)    returns (EvaluateResponse)
rpc VerifyProof (VerifyProofRequest) returns (VerifyProofResponse)
rpc Health      (HealthRequest)      returns (HealthResponse)
```

- **Evaluate** runs the full pipeline and returns `ALLOW | BLOCK | THROTTLE | ESCALATE`
  plus the current `containment_stage` and an `AuditProof` carrying the
  Witness's ML-DSA-65 signature.
- **VerifyProof** validates a sealed envelope (CRC32C + signature) against the
  daemon's verifying key.
- **Health** reports `SERVING` plus per-enclave status and protocol-firewall
  rule pass/total counters.

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