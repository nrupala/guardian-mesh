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
cargo test                        # 31 unit tests, all green
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