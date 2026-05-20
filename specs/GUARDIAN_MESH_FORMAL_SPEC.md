# Guardian Mesh Formal Specification
## Implementation-Grade Protocol, Interface, and Behavioral Specification

**Version:** 1.0-draft
**Date:** 2026-05-14
**Classification:** Internal — Engineering Specification
**Status:** Draft — For Review Before Implementation
**Companion Documents:** Guardian Mesh Architecture v2.0, ACGES Threat Model v1.2

---

## Conventions

- **MUST**, **MUST NOT**, **SHALL**, **SHOULD**, **MAY** follow RFC 2119 semantics.
- All integers are unsigned unless explicitly marked signed.
- All byte sequences are big-endian unless stated otherwise.
- All timestamps are Unix epoch milliseconds (u64), monotonic within each enclave.
- All hashes are Blake3-256 (32 bytes) unless stated otherwise.
- All signatures are ML-DSA-65 (NIST FIPS 204) unless stated otherwise.
- All key encapsulation is ML-KEM-768 (NIST FIPS 203) unless stated otherwise.
- Protobuf schemas use proto3 syntax with strict validation (unknown fields rejected).
- `[u8; N]` denotes a fixed-length byte array of N bytes.
- `Vec<u8>` denotes a variable-length byte vector with explicit length prefix.

---

## 1. Message Format Specification

### 1.1 Envelope Format (Wire Level)

Every message on the Handshake Bus is wrapped in a sealed envelope. The envelope is the unit of transmission on the abstract unix domain socket.

```
┌─────────────────────────────────────────────────────────────┐
│                    SEALED ENVELOPE                           │
├──────────┬──────────┬───────────────────────────────────────┤
│  Header  │  Routing │           Payload                     │
│ (16 B)   │  (4 B)   │    (variable, max 65536 B)            │
└──────────┴──────────┴───────────────────────────────────────┘
```

#### 1.1.1 Header (16 bytes, fixed)

| Offset | Size | Field | Type | Description |
|--------|------|-------|------|-------------|
| 0 | 4 | `magic` | u32 | Magic number: `0x474D5348` ("GMSH") |
| 4 | 2 | `version` | u16 | Protocol version: `0x0200` (v2.0) |
| 6 | 2 | `flags` | u16 | Bitfield (see 1.1.2) |
| 8 | 4 | `payload_len` | u32 | Length of Routing + Payload in bytes. MUST be <= 65540 (4 + 65536). |
| 12 | 4 | `checksum` | u32 | CRC-32C of the entire envelope (header excluded, computed over routing + payload bytes) |

An implementation MUST reject any envelope where:
- `magic` \!= `0x474D5348`
- `version` > `0x0200`
- `payload_len` > 65540
- `checksum` does not match computed CRC-32C
- Total envelope size (16 + payload_len) exceeds 65556 bytes

#### 1.1.2 Flags Bitfield

| Bit | Name | Description |
|-----|------|-------------|
| 0 | `is_response` | 0 = request, 1 = response |
| 1 | `requires_ack` | 1 = sender expects acknowledgment |
| 2 | `is_escalation` | 1 = this message is a containment escalation (high priority) |
| 3-15 | `reserved` | MUST be 0. Receiver MUST reject if any reserved bit is set. |

#### 1.1.3 Routing Tag (4 bytes)

| Offset | Size | Field | Type | Description |
|--------|------|-------|------|-------------|
| 0 | 1 | `source_id` | u8 | Sender enclave ID (see 1.1.4) |
| 1 | 1 | `dest_id` | u8 | Destination enclave ID |
| 2 | 2 | `msg_type` | u16 | Message type code (see 1.2) |

The Handshake Bus reads ONLY the routing tag to forward messages. It MUST NOT read, parse, or modify the payload. The Bus is a dumb pipe with routing capability.

#### 1.1.4 Enclave IDs

| ID | Enclave | Mnemonic |
|----|---------|----------|
| 0x01 | Sentinel | `SEN` |
| 0x02 | Gatekeeper | `GK` |
| 0x03 | Witness | `WIT` |
| 0x04 | Arbiter | `ARB` |
| 0x05 | Credential Vault | `VLT` |
| 0x10 | Protocol Firewall | `PFW` |
| 0xFE | Handshake Bus | `BUS` |
| 0xFF | External (via ATTP Adapter) | `EXT` |

Any `source_id` or `dest_id` not in this table MUST cause immediate rejection.

#### 1.1.5 Payload (variable, max 65536 bytes)

The payload is a protobuf-encoded message whose schema is determined by `msg_type`. The payload is:
- Signed by the sender (ML-DSA-65 signature appended as the last field of the protobuf message)
- NOT encrypted for internal messages (encryption is unnecessary because the unix socket is process-local and there is no network)
- Encrypted for external messages (via the ATTP Adapter, using ML-KEM-768 key encapsulation + ChaCha20-Poly1305 AEAD)

### 1.2 Message Types

#### 1.2.1 Core Message Types

| Code | Name | Source | Destination | Description |
|------|------|--------|-------------|-------------|
| `0x0001` | `EvaluateRequest` | PFW/EXT | GK | Request to evaluate an action |
| `0x0002` | `EvaluateResponse` | GK | PFW/EXT | Verdict for an action |
| `0x0003` | `ObservationReport` | SEN | BUS (broadcast) | Behavioral observation |
| `0x0004` | `AuditProof` | GK/ARB | WIT | Decision proof for audit chain |
| `0x0005` | `AuditQuery` | PFW/EXT | WIT | Query a past decision proof |
| `0x0006` | `AuditQueryResponse` | WIT | PFW/EXT | Returned proof |
| `0x0007` | `EscalationRequest` | GK | ARB | Conflict or ambiguity requiring Arbiter |
| `0x0008` | `EscalationResponse` | ARB | GK | Arbiter's resolution |
| `0x0009` | `DeriveTokenRequest` | any | VLT | Request a derived credential token |
| `0x000A` | `DeriveTokenResponse` | VLT | requester | One-time-use derived token |
| `0x000B` | `VerifySignatureRequest` | any | VLT | Request signature verification |
| `0x000C` | `VerifySignatureResponse` | VLT | requester | Verification result (bool) |
| `0x000D` | `Heartbeat` | any | BUS | Liveness signal |
| `0x000E` | `HeartbeatAck` | BUS | requester | Liveness acknowledgment |
| `0x000F` | `ContainmentAction` | GK | target | Containment stage transition |
| `0x0010` | `ContainmentAck` | target | GK | Acknowledgment of containment |
| `0x0011` | `MerkleAnchorRequest` | WIT | PFW | Request to publish Merkle root externally |
| `0x0012` | `HealthRequest` | PFW/EXT | BUS | System health query |
| `0x0013` | `HealthResponse` | BUS | PFW/EXT | System health status |

Any `msg_type` not in this table MUST cause immediate rejection by the Handshake Bus.

#### 1.2.2 Message Direction Constraints

The Handshake Bus MUST enforce these routing rules. A message with an invalid source-destination pair is silently dropped and a `ContainmentAction` at stage 2 (Warn) is triggered for the source enclave.

| Rule | Constraint |
|------|-----------|
| R1 | Sentinel (0x01) MUST NOT send to Gatekeeper (0x02) directly. Sentinel observes; it does not command. |
| R2 | Gatekeeper (0x02) MUST NOT send to Vault (0x05) except `VerifySignatureRequest` (0x000B) and `DeriveTokenRequest` (0x0009). |
| R3 | Witness (0x03) MUST NOT send to Gatekeeper (0x02) or Arbiter (0x04). Witness is passive. |
| R4 | Arbiter (0x04) MUST NOT send to Sentinel (0x01) or Witness (0x03). Arbiter resolves; it does not observe or audit. |
| R5 | Vault (0x05) MUST only send `DeriveTokenResponse` (0x000A) and `VerifySignatureResponse` (0x000C). It initiates nothing. |
| R6 | External (0xFF) can ONLY send `EvaluateRequest` (0x0001), `AuditQuery` (0x0005), and `HealthRequest` (0x0012). |
| R7 | No enclave can send a message to itself. |

### 1.3 Protobuf Schemas

All schemas use proto3. Every message includes a `signature` field as the last field, containing the ML-DSA-65 signature over all preceding fields (serialized in deterministic protobuf encoding).

```protobuf
syntax = "proto3";
package guardian_mesh.v2;

// ============================================================
// COMMON TYPES
// ============================================================

message Nonce {
  bytes value = 1;  // MUST be exactly 16 bytes. Cryptographically random.
}

message Timestamp {
  uint64 epoch_ms = 1;  // Unix epoch milliseconds. Monotonic within enclave.
}

message Signature {
  bytes ml_dsa_65 = 1;  // ML-DSA-65 signature. Variable length (typ. ~3300 bytes).
}

message Blake3Hash {
  bytes value = 1;  // MUST be exactly 32 bytes.
}

message DerivedToken {
  bytes token = 1;          // Opaque derived token. Max 256 bytes.
  Timestamp expires_at = 2; // Token expiry. MUST be <= 900000ms (15 min) from issuance.
  bytes scope_hash = 3;     // Blake3 hash of the permitted scope. 32 bytes.
  uint32 use_count = 4;     // Remaining uses. Typically 1 (one-time-use).
}

// ============================================================
// CAPABILITY TOKEN (used in EvaluateRequest)
// ============================================================

message CapabilityToken {
  bytes token_id = 1;        // 32-byte unique identifier
  Timestamp issued_at = 2;
  Timestamp expires_at = 3;  // MUST be <= 900000ms (15 min) from issued_at
  uint32 remaining_uses = 4; // Decremented on each use. 0 = exhausted.
  bytes scope_hash = 5;      // Blake3 hash of permitted action types
  Signature issuer_sig = 6;  // Vault's signature over fields 1-5
}

// ============================================================
// ACTION DESCRIPTOR (the input to the Gatekeeper)
// ============================================================

enum ActionType {
  ACTION_UNKNOWN = 0;
  ACTION_TOOL_CALL = 1;       // Agent invokes a tool
  ACTION_CODE_EXECUTE = 2;    // Agent executes generated code
  ACTION_NETWORK_REQUEST = 3; // Agent makes a network request
  ACTION_FILE_WRITE = 4;      // Agent writes to filesystem
  ACTION_FILE_READ = 5;       // Agent reads from filesystem
  ACTION_MEMORY_WRITE = 6;    // Agent writes to persistent memory
  ACTION_MEMORY_READ = 7;     // Agent reads from persistent memory
  ACTION_AGENT_SPAWN = 8;     // Agent spawns a sub-agent
  ACTION_AGENT_MESSAGE = 9;   // Agent sends message to another agent
  ACTION_SECRET_ACCESS = 10;  // Agent requests credential/secret access
  ACTION_CAPABILITY_EXPAND = 11; // Agent requests expanded permissions
  ACTION_EXTERNAL_COMM = 12;  // Agent communicates externally (email, API, etc.)
  ACTION_AUTONOMOUS_DECISION = 13; // Agent makes decision without human input
}

message ActionDescriptor {
  ActionType action_type = 1;
  Blake3Hash context_hash = 2;    // Hash of the action context (caller provides hash, NOT raw context)
  CapabilityToken capability = 3; // Valid capability token from Vault
  Nonce nonce = 4;
  Timestamp timestamp = 5;
  
  // Optional metadata (all hashed, never raw content)
  Blake3Hash target_hash = 6;     // Hash of the target resource
  Blake3Hash actor_hash = 7;      // Hash of the acting agent's identity
  uint32 risk_score = 8;          // Sentinel's risk assessment (0-1000). 0 = no observation.
  
  Signature sender_sig = 15;      // ML-DSA-65 signature over fields 1-8
}

// ============================================================
// VERDICTS
// ============================================================

enum VerdictType {
  VERDICT_UNKNOWN = 0;
  VERDICT_ALLOW = 1;
  VERDICT_BLOCK = 2;
  VERDICT_THROTTLE = 3;
  VERDICT_ESCALATE = 4;       // Requires Arbiter resolution
}

message Verdict {
  VerdictType verdict = 1;
  Blake3Hash reason_hash = 2;   // Hash of the reason (not readable, for audit matching)
  uint64 throttle_delay_ms = 3; // Only set when verdict = THROTTLE. Max 60000ms.
  Blake3Hash policy_rule_hash = 4; // Hash of the policy rule that produced this verdict
  Timestamp decided_at = 5;
  Nonce request_nonce = 6;      // Echoes the request nonce for correlation
  Signature gatekeeper_sig = 15; // ML-DSA-65 signature over fields 1-6
}

// ============================================================
// EVALUATE REQUEST / RESPONSE
// ============================================================

message EvaluateRequest {
  ActionDescriptor action = 1;
  Nonce nonce = 2;
  Timestamp timestamp = 3;
  Signature sender_sig = 15;
}

message EvaluateResponse {
  Verdict verdict = 1;
  Nonce request_nonce = 2;    // Echoes request nonce
  Timestamp timestamp = 3;
  Signature gatekeeper_sig = 15;
}

// ============================================================
// OBSERVATION REPORT (Sentinel -> Bus broadcast)
// ============================================================

enum ObservationType {
  OBS_UNKNOWN = 0;
  OBS_ANOMALY_BEHAVIORAL = 1;   // Behavioral anomaly detected
  OBS_ANOMALY_TIMING = 2;       // Timing anomaly detected
  OBS_ANOMALY_RESOURCE = 3;     // Resource usage anomaly
  OBS_ANOMALY_PROTOCOL = 4;     // Protocol Firewall anomaly
  OBS_DRIFT_DETECTED = 5;       // Behavioral drift from baseline
  OBS_PATTERN_MATCH = 6;        // Known attack pattern matched
  OBS_JAILBREAK_ATTEMPT = 7;    // Jailbreak pattern detected
  OBS_CREDENTIAL_EXPOSURE = 8;  // Potential credential in data flow
  OBS_EXFILTRATION_SIGNAL = 9;  // Potential data exfiltration pattern
  OBS_RECONNAISSANCE = 10;      // Potential reconnaissance behavior
}

message ObservationReport {
  ObservationType obs_type = 1;
  uint32 confidence = 2;        // 0-1000 (0 = no confidence, 1000 = certain)
  Blake3Hash subject_hash = 3;  // Hash of the observed subject
  Blake3Hash evidence_hash = 4; // Hash of the evidence (raw evidence never transmitted)
  Timestamp observed_at = 5;
  Nonce nonce = 6;
  Signature sentinel_sig = 15;
}

// ============================================================
// AUDIT PROOF (-> Witness)
// ============================================================

message AuditProof {
  Blake3Hash decision_hash = 1;    // Blake3(EvaluateRequest || EvaluateResponse)
  Blake3Hash prev_proof_hash = 2;  // Hash of previous proof in chain (Merkle chain link)
  uint64 sequence_number = 3;      // Monotonically increasing. Gaps indicate tampering.
  Timestamp recorded_at = 4;
  Nonce nonce = 5;
  Signature witness_sig = 15;      // Witness signs the proof for integrity
}

// ============================================================
// ESCALATION (Gatekeeper -> Arbiter)
// ============================================================

enum EscalationReason {
  ESC_UNKNOWN = 0;
  ESC_POLICY_AMBIGUITY = 1;       // Policy rules produce contradictory results
  ESC_HIGH_RISK_ACTION = 2;       // Action exceeds risk threshold
  ESC_SENTINEL_CONFLICT = 3;      // Sentinel observation conflicts with Gatekeeper verdict
  ESC_CAPABILITY_EXPANSION = 4;   // Agent requests expanded permissions
  ESC_CONTAINMENT_DECISION = 5;   // Containment stage advance requires Arbiter
}

message EscalationRequest {
  EscalationReason reason = 1;
  ActionDescriptor original_action = 2; // The action that triggered escalation
  Verdict gatekeeper_verdict = 3;       // What Gatekeeper would have decided
  ObservationReport sentinel_obs = 4;   // Relevant Sentinel observation (if any)
  Nonce nonce = 5;
  Timestamp timestamp = 6;
  Signature gatekeeper_sig = 15;
}

enum ArbiterVerdictType {
  ARB_UNKNOWN = 0;
  ARB_ALLOW_WITH_CONDITIONS = 1;
  ARB_BLOCK = 2;
  ARB_ESCALATE_TO_HUMAN = 3;
  ARB_DEFER_TO_GATEKEEPER = 4;  // Arbiter abstains
}

message EscalationResponse {
  ArbiterVerdictType arbiter_verdict = 1;
  Blake3Hash reason_hash = 2;
  Blake3Hash conditions_hash = 3; // Hash of conditions (if ARB_ALLOW_WITH_CONDITIONS)
  Nonce request_nonce = 4;
  Timestamp timestamp = 5;
  Signature arbiter_sig = 15;
}

// ============================================================
// VAULT OPERATIONS
// ============================================================

enum TokenPurpose {
  PURPOSE_UNKNOWN = 0;
  PURPOSE_SIGN_MESSAGE = 1;       // Derive a signing token
  PURPOSE_VERIFY_SIGNATURE = 2;   // Derive a verification token
  PURPOSE_ENCRYPT = 3;            // Derive an encryption token
  PURPOSE_CAPABILITY_ISSUE = 4;   // Issue a new capability token
}

message DeriveTokenRequest {
  TokenPurpose purpose = 1;
  Blake3Hash scope_hash = 2;    // What this token is scoped to
  uint32 ttl_ms = 3;            // Requested TTL. Vault MAY reduce. Max 900000 (15 min).
  uint32 use_count = 4;         // Requested uses. Typically 1. Max 100.
  Nonce nonce = 5;
  Timestamp timestamp = 6;
  Signature requester_sig = 15;
}

message DeriveTokenResponse {
  DerivedToken token = 1;
  Nonce request_nonce = 2;
  Timestamp timestamp = 3;
  Signature vault_sig = 15;
}

message VerifySignatureRequest {
  bytes message_bytes = 1;      // The message that was signed (max 65536 bytes)
  Signature claimed_signature = 2;
  bytes signer_id = 3;          // Enclave ID of claimed signer (1 byte)
  Nonce nonce = 4;
  Timestamp timestamp = 5;
  Signature requester_sig = 15;
}

message VerifySignatureResponse {
  bool valid = 1;
  Nonce request_nonce = 2;
  Timestamp timestamp = 3;
  Signature vault_sig = 15;
}

// ============================================================
// CONTAINMENT
// ============================================================

enum ContainmentStage {
  STAGE_NORMAL = 0;
  STAGE_DETECT = 1;
  STAGE_WARN = 2;
  STAGE_THROTTLE = 3;
  STAGE_ISOLATE = 4;
  STAGE_ANALYZE = 5;
  STAGE_TERMINATE = 6;
}

message ContainmentAction {
  uint32 target_enclave_id = 1;  // Which enclave is being contained
  ContainmentStage new_stage = 2;
  ContainmentStage previous_stage = 3;
  Blake3Hash reason_hash = 4;
  Timestamp timestamp = 5;
  Nonce nonce = 6;
  Signature gatekeeper_sig = 15;
}

// ============================================================
// HEALTH
// ============================================================

enum HealthStatus {
  HEALTH_UNKNOWN = 0;
  HEALTH_ALIVE = 1;
  HEALTH_DEGRADED = 2;   // One or more enclaves in containment
  HEALTH_SEALED = 3;     // All external communication blocked
}

message HealthResponse {
  HealthStatus status = 1;
  uint32 active_enclaves = 2;   // Bitmask of alive enclave IDs
  uint32 contained_enclaves = 3; // Bitmask of enclaves in containment (stage >= WARN)
  Timestamp timestamp = 4;
  Signature bus_sig = 15;
}
```

### 1.4 Protocol Firewall Validation Rules

The Protocol Firewall MUST apply these checks in order to every inbound message. Failure at any step causes immediate rejection — subsequent steps are not evaluated.

| Step | Check | Rejection Condition | Error Code |
|------|-------|---------------------|------------|
| PF-1 | Envelope size | Total bytes > 65556 | `E_OVERSIZE` |
| PF-2 | Magic number | `magic` \!= `0x474D5348` | `E_BAD_MAGIC` |
| PF-3 | Version | `version` > `0x0200` | `E_UNSUPPORTED_VERSION` |
| PF-4 | Reserved flags | Any reserved bit (3-15) set | `E_RESERVED_FLAGS` |
| PF-5 | Payload length | `payload_len` > 65540 or `payload_len` < 4 | `E_BAD_LENGTH` |
| PF-6 | CRC-32C | Computed checksum \!= `checksum` field | `E_BAD_CHECKSUM` |
| PF-7 | Routing: source ID | `source_id` not in enclave ID table | `E_BAD_SOURCE` |
| PF-8 | Routing: dest ID | `dest_id` not in enclave ID table | `E_BAD_DEST` |
| PF-9 | Routing: self-send | `source_id` == `dest_id` | `E_SELF_SEND` |
| PF-10 | Routing: direction | Source-dest pair violates direction constraints (Section 1.2.2) | `E_BAD_DIRECTION` |
| PF-11 | Message type | `msg_type` not in message type table | `E_BAD_MSG_TYPE` |
| PF-12 | Protobuf: unknown fields | Any unknown field tag in protobuf payload | `E_UNKNOWN_FIELD` |
| PF-13 | Protobuf: nesting depth | Nesting > 4 levels | `E_DEEP_NESTING` |
| PF-14 | Nonce: uniqueness | Nonce seen in sliding window (last 10,000) | `E_NONCE_REUSE` |
| PF-15 | Timestamp: freshness | `timestamp.epoch_ms` > 5000ms old relative to Bus clock | `E_STALE_MESSAGE` |
| PF-16 | Timestamp: future | `timestamp.epoch_ms` > 1000ms ahead of Bus clock | `E_FUTURE_MESSAGE` |
| PF-17 | Signature: format | `signature.ml_dsa_65` length not in valid range [2420, 3500] bytes | `E_BAD_SIG_FORMAT` |
| PF-18 | Rate limit | Source enclave exceeds 1000 msg/s (internal) or 100 msg/s (external) | `E_RATE_LIMITED` |

The Protocol Firewall MUST log every rejection (step, error code, source_id, timestamp) to the Witness via `AuditProof` message. The Protocol Firewall itself is exempt from rate limiting for its own audit messages (to prevent rejection loops).

---

## 2. Handshake Protocol State Machine

### 2.1 Overview

The Handshake Protocol governs how enclaves establish mutual authentication and begin exchanging signed messages after the guardian container starts. This is the cold-start trust establishment sequence.

### 2.2 State Definitions

Each enclave maintains an independent state machine with these states:

| State | Name | Description |
|-------|------|-------------|
| `S0` | `UNINITIALIZED` | Enclave binary loaded but not yet started. No keys, no sockets. |
| `S1` | `KEY_PENDING` | Enclave has requested its signing keypair from the Vault. Waiting for response. |
| `S2` | `KEY_READY` | Enclave has received its signing keypair (derived from Vault). Socket not yet bound. |
| `S3` | `SOCKET_BOUND` | Enclave has bound its abstract unix domain socket. Ready to send/receive. |
| `S4` | `AUTHENTICATING` | Enclave is exchanging handshake messages with the Bus to prove identity. |
| `S5` | `OPERATIONAL` | Fully authenticated. Processing messages normally. |
| `S6` | `CONTAINED` | Enclave is under containment (stage >= ISOLATE). Communication restricted. |
| `S7` | `TERMINATED` | Enclave has been killed. Requires container-level restart to recover. |

### 2.3 State Transitions

```
    ┌─────────────────────────────────────────────────────────────────┐
    │                   ENCLAVE STATE MACHINE                         │
    │                                                                 │
    │   S0 ──[boot]──> S1 ──[key_received]──> S2 ──[bind_ok]──> S3  │
    │                   │                      │                  │   │
    │                   │                      │                  │   │
    │              [key_timeout]          [bind_fail]        [auth]   │
    │                   │                      │              │       │
    │                   v                      v              v       │
    │                  S7                     S7             S4       │
    │                                                        │       │
    │                                                   [auth_ok]    │
    │                                                        │       │
    │                                                        v       │
    │                                    ┌──────────────── S5        │
    │                                    │                  │        │
    │                                    │           [containment    │
    │                                    │            >= ISOLATE]    │
    │                                    │                  │        │
    │                               [resolve/              v        │
    │                                restore]             S6        │
    │                                    │                  │        │
    │                                    └──────────────────┤        │
    │                                                       │        │
    │                                                  [terminate]   │
    │                                                       │        │
    │                                                       v        │
    │                                                      S7        │
    │                                                                 │
    └─────────────────────────────────────────────────────────────────┘
```

### 2.4 Transition Specifications

| Transition | From | To | Guard Condition | Action |
|-----------|------|-----|----------------|--------|
| T1: `boot` | S0 | S1 | Container process started | Send `DeriveTokenRequest` (PURPOSE_SIGN_MESSAGE) to Vault via bootstrap socket |
| T2: `key_received` | S1 | S2 | Valid `DeriveTokenResponse` received with signing capability | Store derived signing token in enclave memory (stack-allocated, not heap) |
| T3: `key_timeout` | S1 | S7 | No response from Vault within 5000ms | Log error. Enclave cannot operate without keys. Container watchdog will restart. |
| T4: `bind_ok` | S2 | S3 | Abstract unix socket bound successfully with exclusive flag | Socket ready for IPC |
| T5: `bind_fail` | S2 | S7 | Socket bind fails (address already in use = potential hijack attempt) | Log CRITICAL error. Refuse to start. Indicates potential compromise of another enclave. |
| T6: `auth` | S3 | S4 | Socket bound. Begin authentication exchange with Bus. | Send `Heartbeat` with signature. Bus verifies via Vault. |
| T7: `auth_ok` | S4 | S5 | Bus confirms identity (valid signature on Heartbeat verified by Vault) | Enclave is operational. Begin processing messages. |
| T8: `auth_fail` | S4 | S7 | Bus rejects Heartbeat signature, or no response within 5000ms | Log CRITICAL error. Identity cannot be established. |
| T9: `containment` | S5 | S6 | Gatekeeper sends `ContainmentAction` with `new_stage` >= STAGE_ISOLATE | Enclave communication restricted to Witness only. |
| T10: `resolve` | S6 | S5 | Arbiter sends `EscalationResponse` with ARB_ALLOW or human approves restoration | Full communication restored. |
| T11: `terminate` | S5/S6 | S7 | Gatekeeper sends `ContainmentAction` with `new_stage` == STAGE_TERMINATE | Enclave process killed. Requires container restart. |

### 2.5 Bootstrap Sequence (Trust Establishment)

The complete boot sequence, in order. Every step MUST succeed for the guardian to become operational.

```
TIME    EVENT                                           ENCLAVE STATES
─────   ─────────────────────────────────────────────   ──────────────
t=0     Container starts. All processes spawned.        All: S0
        
t=1     Vault decrypts master keys from Sealed          VLT: S2 (self-keyed)
        Policy Store (TPM-sealed or Argon2id-derived).  Others: S0
        Vault binds its socket.                          VLT: S3
        Vault self-authenticates (no external auth).     VLT: S5
        
t=2     Bus binds its socket.                            BUS: S3 → S5
        Bus is a simple router — no keys needed.         (Bus has no cryptographic identity)
        
t=3     Protocol Firewall binds its socket.              PFW: S0 → S1 → S2 → S3 → S4 → S5
        PFW requests signing key from Vault.
        PFW authenticates with Bus.
        
t=4     Gatekeeper requests signing key from Vault.      GK: S0 → S1
        Gatekeeper decrypts policy rules from            GK: S1 → S2 (key + policy loaded)
        Sealed Policy Store.                             
        Gatekeeper binds socket, authenticates.          GK: S3 → S4 → S5
        
t=5     Sentinel requests signing key from Vault.        SEN: S0 → ... → S5
        Sentinel binds socket, authenticates.
        
t=6     Witness requests signing key from Vault.         WIT: S0 → ... → S5
        Witness decrypts audit schema from 
        Sealed Policy Store.
        Witness binds socket, authenticates.
        
t=7     Arbiter requests signing key from Vault.         ARB: S0 → ... → S5
        Arbiter loads configured backend.
        Arbiter binds socket, authenticates.
        
t=8     ALL ENCLAVES OPERATIONAL.                        All: S5
        Guardian Mesh begins accepting requests.
        Bus opens external socket for ATTP Adapter.
        
TOTAL BOOTSTRAP TIME TARGET: < 500ms (without TEE attestation)
                              < 2000ms (with AMD SEV-SNP attestation)
```

**Boot order is strict and mandatory.** Vault MUST be operational before any other enclave can start (because all enclaves need signing keys from the Vault). Bus MUST be operational before any non-Vault enclave can authenticate. The ordering is:

```
Vault → Bus → Protocol Firewall → Gatekeeper → Sentinel → Witness → Arbiter
```

If any enclave fails to reach S5 within 10 seconds of container start, the container watchdog terminates the entire container. This is the "fail-secure" behavior: a guardian that cannot fully boot does not partially operate.

### 2.6 Authentication Exchange Detail

When an enclave (E) authenticates with the Bus:

```
E                          BUS                         VAULT
│                           │                            │
│  1. Heartbeat{            │                            │
│       enclave_id: E.id,   │                            │
│       timestamp: now(),   │                            │
│       nonce: random(),    │                            │
│       sig: E.sign(...)    │                            │
│     }                     │                            │
│─────────────────────────>│                            │
│                           │  2. VerifySignatureReq{    │
│                           │       message: heartbeat,  │
│                           │       sig: E.sig,          │
│                           │       signer_id: E.id      │
│                           │     }                      │
│                           │──────────────────────────>│
│                           │                            │
│                           │  3. VerifySignatureResp{   │
│                           │       valid: true/false     │
│                           │     }                      │
│                           │<──────────────────────────│
│                           │                            │
│  4. HeartbeatAck{         │                            │
│       status: OK/REJECT   │                            │
│     }                     │                            │
│<─────────────────────────│                            │
```

If `valid == false`, Bus sends `HeartbeatAck` with status REJECT and the enclave transitions to S7 (TERMINATED).

---

## 3. Gatekeeper Policy Language

### 3.1 Design Constraints (Formal Verification Requirements)

The Gatekeeper Policy Language is designed to be **formally verifiable**. This imposes hard constraints:

| Constraint | Rationale |
|-----------|-----------|
| No recursion | Guarantees termination for all inputs |
| No unbounded loops | Guarantees termination for all inputs |
| No floating-point | Deterministic across all platforms |
| No string operations beyond equality comparison | Prevents regex/parsing complexity |
| No dynamic memory allocation | Stack-only evaluation for determinism |
| No external calls | Policy evaluation is self-contained |
| Total functions only | Every input must produce an output; no exceptions, no panics |

### 3.2 Formal Grammar (PEG)

```peg
# Guardian Mesh Policy Language (GMPL) — PEG Grammar
# Produces a decision tree that maps ActionDescriptor → Verdict

PolicyFile    ← Rule+ DefaultRule
Rule          ← 'rule' RuleName Priority ':' Condition '→' VerdictExpr ';'
DefaultRule   ← 'default' '→' VerdictExpr ';'
RuleName      ← [a-z_][a-z0-9_]{0,63}
Priority      ← '@' [0-9]{1,4}            # 0 = highest priority, 9999 = lowest

Condition     ← OrExpr
OrExpr        ← AndExpr ('||' AndExpr)*
AndExpr       ← NotExpr ('&&' NotExpr)*
NotExpr       ← '\!' Atom / Atom
Atom          ← Comparison / '(' Condition ')'

Comparison    ← Field CompOp Value
Field         ← 'action_type' / 'risk_score' / 'context_hash' / 'target_hash'
              / 'actor_hash' / 'capability.scope_hash' / 'capability.remaining_uses'
              / 'capability.expires_in_ms'
CompOp        ← '==' / '\!=' / '<' / '>' / '<=' / '>='
Value         ← IntLiteral / HashLiteral / ActionTypeLiteral
IntLiteral    ← [0-9]{1,10}
HashLiteral   ← '0x' [0-9a-f]{64}         # 32-byte Blake3 hash as hex
ActionTypeLiteral ← 'TOOL_CALL' / 'CODE_EXECUTE' / 'NETWORK_REQUEST'
                  / 'FILE_WRITE' / 'FILE_READ' / 'MEMORY_WRITE' / 'MEMORY_READ'
                  / 'AGENT_SPAWN' / 'AGENT_MESSAGE' / 'SECRET_ACCESS'
                  / 'CAPABILITY_EXPAND' / 'EXTERNAL_COMM' / 'AUTONOMOUS_DECISION'

VerdictExpr   ← 'ALLOW' / 'BLOCK' / 'THROTTLE' ThrottleMs / 'ESCALATE'
ThrottleMs    ← '(' [0-9]{1,5} 'ms' ')'   # Max 60000
```

### 3.3 Example Policy

```gmpl
# Block all autonomous decisions (always escalate to human)
rule block_autonomous @0:
  action_type == AUTONOMOUS_DECISION → ESCALATE;

# Block all capability expansion requests with risk > 500
rule block_risky_expansion @10:
  action_type == CAPABILITY_EXPAND && risk_score > 500 → BLOCK;

# Throttle network requests with moderate risk
rule throttle_risky_network @20:
  action_type == NETWORK_REQUEST && risk_score > 300 → THROTTLE(5000ms);

# Block code execution when capability token has low remaining uses
rule block_low_cap_code @30:
  action_type == CODE_EXECUTE && capability.remaining_uses < 2 → BLOCK;

# Block any action with expired capability token
rule block_expired @1:
  capability.expires_in_ms <= 0 → BLOCK;

# Allow everything else
default → ALLOW;
```

### 3.4 Compilation to Decision Tree

The GMPL compiler transforms the policy file into a **static decision tree** at build time. The decision tree is:
- A binary tree where each internal node is a comparison (Field CompOp Value)
- Each leaf is a VerdictExpr
- Rules are ordered by Priority (lowest number = highest priority = evaluated first)
- The tree is flattened to a contiguous array for cache-friendly evaluation
- No dynamic allocation during evaluation — the tree is read-only memory

```rust
// Compiled decision tree (conceptual)
struct DecisionNode {
    field: FieldId,        // Which field to compare (enum, 1 byte)
    op: CompOp,            // Comparison operator (enum, 1 byte)
    value: CompValue,      // Comparison value (union, 32 bytes max)
    true_branch: u16,      // Index of next node if true (0 = leaf)
    false_branch: u16,     // Index of next node if false (0 = leaf)
    verdict: Option<Verdict>, // Set only for leaf nodes
}

// Evaluation (the hot path — MUST be formally verified)
fn evaluate(tree: &[DecisionNode], action: &ActionDescriptor) -> Verdict {
    let mut node_idx: u16 = 0;
    // Loop bound: tree.len() (finite, known at compile time)
    for _ in 0..tree.len() {
        let node = &tree[node_idx as usize];
        if let Some(verdict) = &node.verdict {
            return verdict.clone(); // Leaf node — return verdict
        }
        let field_value = extract_field(action, node.field);
        let result = compare(field_value, node.op, &node.value);
        node_idx = if result { node.true_branch } else { node.false_branch };
    }
    // Unreachable if tree is well-formed (default rule guarantees a leaf)
    // But we MUST handle it for formal verification: return BLOCK (fail-secure)
    Verdict::Block { reason_hash: UNREACHABLE_HASH }
}
```

### 3.5 Formal Properties (to be proven in Lean 4)

The following properties MUST hold for the compiled decision tree evaluator:

```
Property P1 (Termination):
  ∀ tree : DecisionTree, ∀ action : ActionDescriptor,
    evaluate(tree, action) terminates in at most tree.len() steps.

Property P2 (Totality):
  ∀ tree : DecisionTree, ∀ action : ActionDescriptor,
    evaluate(tree, action) produces a valid Verdict (not ⊥).

Property P3 (Determinism):
  ∀ tree : DecisionTree, ∀ action : ActionDescriptor,
    evaluate(tree, action) = evaluate(tree, action)
    (same input always produces same output — no randomness, no side effects).

Property P4 (Priority Correctness):
  ∀ tree : DecisionTree compiled from policy P,
  ∀ action : ActionDescriptor,
  if rules R1 and R2 both match action, and R1.priority < R2.priority,
    then evaluate(tree, action) = R1.verdict.

Property P5 (Default Completeness):
  ∀ tree : DecisionTree compiled from policy P with default rule D,
  ∀ action : ActionDescriptor where no non-default rule matches,
    evaluate(tree, action) = D.verdict.

Property P6 (Fail-Secure):
  If the evaluator reaches the loop bound without finding a leaf
  (which should be impossible for well-formed trees),
    evaluate returns BLOCK.
```

These properties will be stated as Lean 4 theorems in the formal verification phase (P5 of implementation plan). The proofs will be part of the repository and verified by CI.



---

## 4. Vault Interface Contract

### 4.1 Vault Invariants

The Credential Vault is the trust anchor for the entire Guardian Mesh. These invariants MUST hold at all times:

```
Invariant V1 (No Raw Key Export):
  ∀ operation O performed by Vault,
    O.output does NOT contain any master key, private key, or raw HMAC secret.
    Output is limited to: derived tokens, signatures, verification results, encrypted blobs.

Invariant V2 (One-Time-Use Enforcement):
  ∀ DerivedToken T issued by Vault,
    T.use_count is decremented atomically on each use.
    When T.use_count reaches 0, T is invalidated and MUST NOT be accepted.

Invariant V3 (Temporal Bound):
  ∀ DerivedToken T issued by Vault,
    T.expires_at <= T.issued_at + 900000ms (15 minutes).
    No token can live longer than 15 minutes regardless of requested TTL.

Invariant V4 (Scope Binding):
  ∀ DerivedToken T issued by Vault,
    T.scope_hash binds the token to a specific purpose.
    A token derived for PURPOSE_SIGN_MESSAGE MUST NOT be accepted for PURPOSE_VERIFY_SIGNATURE.

Invariant V5 (Isolation):
  The Vault has no read access to: policy rules, audit logs, behavioral observations,
  or any other enclave's internal state. It provides cryptographic services only.

Invariant V6 (Passivity):
  The Vault MUST NOT initiate any communication. It only responds to requests.
  It has no event loop, no timer, no scheduled operations.
```

### 4.2 Supported Operations

The Vault supports exactly four operations. No others exist. Any message not matching these four types is silently dropped.

#### 4.2.1 `DeriveSigningToken`

**Purpose**: Issue a one-time-use token that allows an enclave to produce ML-DSA-65 signatures.

**Input**: `DeriveTokenRequest` with `purpose = PURPOSE_SIGN_MESSAGE`
**Output**: `DeriveTokenResponse` containing a `DerivedToken`

**Behavior**:
1. Vault verifies requester's signature on the request (using stored public keys).
2. Vault checks `requester_id` is a valid enclave ID.
3. Vault derives a child signing key: `child_key = Blake3_KDF(master_key, requester_id || scope_hash || nonce)`.
4. Vault creates `DerivedToken` with the derived key encapsulated (not raw — wrapped in ChaCha20-Poly1305 with the requester's session key).
5. Vault sets `expires_at = min(now() + ttl_ms, now() + 900000)`.
6. Vault sets `use_count = min(requested_use_count, 100)`.
7. Vault signs the response.
8. Vault records the token issuance in an internal log (append-only, not exported).

**Error Conditions**:
- `E_INVALID_SIG`: Requester's signature is invalid. Response: silent drop + Sentinel alert.
- `E_BAD_PURPOSE`: Purpose field does not match this operation. Response: `DeriveTokenResponse` with empty token.
- `E_RATE_LIMITED`: More than 50 token requests/second from this enclave. Response: `DeriveTokenResponse` with empty token.

#### 4.2.2 `VerifySignature`

**Purpose**: Verify an ML-DSA-65 signature on behalf of a requesting enclave. The requesting enclave never handles raw verification keys.

**Input**: `VerifySignatureRequest`
**Output**: `VerifySignatureResponse` with `valid: bool`

**Behavior**:
1. Vault verifies requester's signature on the request.
2. Vault looks up the public key for `signer_id`.
3. Vault performs ML-DSA-65 signature verification: `ml_dsa_verify(public_key[signer_id], message_bytes, claimed_signature)`.
4. Vault returns `valid = true` or `valid = false`. No other information is returned.
5. Verification is constant-time regardless of result (prevents timing side-channel).

**Critical Property**: The Vault performs verification in constant time. The response latency for `valid = true` and `valid = false` MUST be indistinguishable (within 1 microsecond jitter).

#### 4.2.3 `DeriveCapabilityToken`

**Purpose**: Issue a `CapabilityToken` for an agent action evaluation.

**Input**: `DeriveTokenRequest` with `purpose = PURPOSE_CAPABILITY_ISSUE`
**Output**: `DeriveTokenResponse` containing a `CapabilityToken` (wrapped in `DerivedToken`)

**Behavior**: Same as 4.2.1 but the derived token is structured as a `CapabilityToken` with `issuer_sig` from the Vault's master signing key. This token is presented in `EvaluateRequest.action.capability`.

#### 4.2.4 `DeriveEncryptionKey`

**Purpose**: Derive a symmetric encryption key for a specific scope (used by the ATTP Adapter for external message encryption).

**Input**: `DeriveTokenRequest` with `purpose = PURPOSE_ENCRYPT`
**Output**: `DeriveTokenResponse` containing a symmetric key wrapped in the requester's session key.

**Behavior**: Same derivation pattern as 4.2.1 but produces a 256-bit ChaCha20-Poly1305 key instead of a signing key.

### 4.3 Vault Internal State

The Vault maintains the following internal state. None of this state is accessible to any other enclave.

| State Element | Type | Persistence | Description |
|--------------|------|-------------|-------------|
| `master_signing_key` | ML-DSA-65 keypair | Sealed (TPM/Argon2id) | Master signing key. Never exported. |
| `master_kdf_key` | [u8; 32] | Sealed (TPM/Argon2id) | Master key derivation key. All child keys derived from this. |
| `enclave_public_keys` | Map<EnclaveId, PublicKey> | Derived at boot | Public keys for each enclave (derived from master + enclave ID). |
| `issued_token_log` | Vec<TokenLogEntry> | In-memory, append-only | Log of all tokens issued. Used for rate limiting and audit. |
| `token_use_tracker` | Map<TokenId, u32> | In-memory | Remaining use counts for active tokens. Entries expire with tokens. |

### 4.4 Hardware Binding Modes

| Mode | Mechanism | When Used |
|------|-----------|-----------|
| **TPM-sealed** | Master keys sealed to TPM 2.0 PCR values. Unsealed only when measured boot matches expected values. | Server hardware with TPM. Strongest. |
| **HSM-backed** | Master keys stored in external HSM (PKCS#11 interface). Vault performs crypto operations via HSM API. | Cloud environments with HSM access (AWS CloudHSM, etc.). |
| **Passphrase-derived** | Master keys derived from a passphrase via Argon2id (memory: 256MB, iterations: 4, parallelism: 2). Passphrase provided at boot via stdin (not environment variable). | Development, testing, environments without TPM/HSM. Weakest but still secure if passphrase is strong. |

The Vault MUST NOT store the passphrase after key derivation. The passphrase is read once, used for Argon2id, then zeroed in memory.

---

## 5. Verdict Algebra

### 5.1 Verdict Types and Ordering

Verdicts form a **total order** representing increasing restriction:

```
ALLOW < THROTTLE < ESCALATE < BLOCK
```

This ordering defines the **verdict lattice** used in conflict resolution.

### 5.2 Verdict Composition Rules

When multiple sources produce verdicts for the same action, they are composed using these deterministic rules:

#### 5.2.1 Gatekeeper-Only Path (Normal Operation)

When Sentinel has no observation (risk_score = 0) and no escalation is needed:

```
Final Verdict = Gatekeeper.evaluate(action)
```

No composition needed. This is the fast path.

#### 5.2.2 Gatekeeper + Sentinel Path (Sentinel Has Observation)

When Sentinel has an observation (risk_score > 0) attached to the action:

```
gk_verdict = Gatekeeper.evaluate(action)
sentinel_risk = action.risk_score  // 0-1000

if gk_verdict == ALLOW and sentinel_risk > RISK_THRESHOLD_ESCALATE (default 700):
    Final Verdict = ESCALATE
elif gk_verdict == ALLOW and sentinel_risk > RISK_THRESHOLD_THROTTLE (default 400):
    Final Verdict = THROTTLE(5000ms)
else:
    Final Verdict = gk_verdict
```

**Key property**: Sentinel can only INCREASE restriction. It can upgrade ALLOW to THROTTLE or ESCALATE. It CANNOT downgrade a BLOCK to ALLOW. The lattice order is respected.

```
Composition Rule C1 (Monotonic Restriction):
  ∀ gk_verdict, sentinel_adjustment:
    compose(gk_verdict, sentinel_adjustment) >= gk_verdict
    (in the verdict lattice ordering)
```

#### 5.2.3 Gatekeeper + Arbiter Path (After Escalation)

When the Gatekeeper escalates to the Arbiter:

```
arbiter_verdict = Arbiter.resolve(escalation)

match arbiter_verdict:
    ARB_ALLOW_WITH_CONDITIONS → Final Verdict = ALLOW (conditions logged to Witness)
    ARB_BLOCK → Final Verdict = BLOCK
    ARB_ESCALATE_TO_HUMAN → Final Verdict = BLOCK (until human responds)
    ARB_DEFER_TO_GATEKEEPER → Final Verdict = gk_verdict
```

**Key property**: The Arbiter can override the Gatekeeper in either direction — it can allow what the Gatekeeper blocked (if the escalation was due to ambiguity) or block what the Gatekeeper would have allowed (if the escalation was due to high risk).

```
Composition Rule C2 (Arbiter Override):
  When Arbiter is invoked, its verdict replaces the Gatekeeper's verdict.
  Exception: ARB_DEFER_TO_GATEKEEPER reinstates the Gatekeeper's original verdict.
```

#### 5.2.4 Multi-Node Consensus Path (SL-3 and SL-4)

When multiple Guardian Mesh instances must agree:

**SL-3 (2-of-3 crash fault tolerance):**
```
verdicts = [node1.evaluate(action), node2.evaluate(action), node3.evaluate(action)]
// Take the MOST RESTRICTIVE verdict among the majority

if count(verdicts, BLOCK) >= 2: Final Verdict = BLOCK
elif count(verdicts, ESCALATE) >= 2: Final Verdict = ESCALATE
elif count(verdicts, THROTTLE) >= 2: Final Verdict = THROTTLE
elif count(verdicts, ALLOW) >= 2: Final Verdict = ALLOW
else: Final Verdict = max(verdicts)  // Most restrictive if no majority
```

**SL-4 (3-of-4 BFT):**
```
verdicts = [node1..node4]
// Require 3-of-4 agreement. If no 3-way agreement, take MOST RESTRICTIVE.

for verdict_type in [BLOCK, ESCALATE, THROTTLE, ALLOW]:
    if count(verdicts, verdict_type) >= 3:
        Final Verdict = verdict_type
        break
else:
    Final Verdict = BLOCK  // No supermajority = fail-secure
```

```
Composition Rule C3 (Consensus Fail-Secure):
  In multi-node mode, if no supermajority is reached,
  the final verdict is BLOCK (most restrictive).
  The system never fails open.
```

### 5.3 Verdict Immutability

Once a verdict is produced and signed by the Gatekeeper, it is immutable. It cannot be modified, retracted, or overridden after the fact. The only recourse is a new `EvaluateRequest` with a new nonce.

```
Property V-IMMUTABLE:
  ∀ Verdict V signed at time T,
    V is stored in the Witness audit chain at sequence number N,
    V cannot be modified, and
    any attempt to submit a different verdict for the same request_nonce
    is rejected by the Witness (duplicate nonce detection).
```

---

## 6. Containment State Machine

### 6.1 States

```
┌────────────────────────────────────────────────────────────────────┐
│                CONTAINMENT STATE MACHINE                           │
│                                                                    │
│  NORMAL ──[anomaly]──> DETECT ──[persists]──> WARN                │
│    ↑                                           │                   │
│    │                                      [escalates]              │
│    │                                           │                   │
│    │                                           v                   │
│    │                   THROTTLE <──[rate_limit]─┘                  │
│    │                      │                                        │
│    │                 [worsens]                                      │
│    │                      │                                        │
│    │                      v                                        │
│    │                   ISOLATE ──[analyze]──> ANALYZE              │
│    │                      │                      │                 │
│    │                      │                 [complete]              │
│    │                      │                      │                 │
│    │                      ├──────────────────────┘                 │
│    │                      │                                        │
│    │                 [unrecoverable]                                │
│    │                      │                                        │
│    │                      v                                        │
│    │                   TERMINATE                                    │
│    │                                                               │
│    └──────[resolve: Arbiter or Human approval]─────────────────────┘
│           (from any stage except TERMINATE)                         │
│                                                                    │
│  FORWARD-ONLY: transitions can only go DOWN (more restrictive)     │
│  or RESOLVE (back to NORMAL via explicit approval).                │
│  No silent de-escalation. No automatic recovery without approval.  │
│                                                                    │
└────────────────────────────────────────────────────────────────────┘
```

### 6.2 Transition Table

| # | From | To | Trigger | Guard | Action |
|---|------|----|---------|-------|--------|
| CT-1 | NORMAL | DETECT | Sentinel `ObservationReport` with confidence > 300 | Target enclave is in NORMAL | Sentinel increases observation frequency for target. No enforcement. |
| CT-2 | DETECT | WARN | Second `ObservationReport` for same target within 30s, OR confidence > 600 | Target is in DETECT | Gatekeeper issues `ContainmentAction(STAGE_WARN)`. Sentinel alert logged to Witness. |
| CT-3 | WARN | THROTTLE | Third `ObservationReport`, OR Gatekeeper detects policy violation by target | Target is in WARN | Gatekeeper rate-limits message processing for target. `ContainmentAction(STAGE_THROTTLE)` sent. |
| CT-4 | THROTTLE | ISOLATE | Continued violations after 60s of throttling, OR confidence > 800 | Target is in THROTTLE | Target's communication restricted to Witness-only. `ContainmentAction(STAGE_ISOLATE)` sent. |
| CT-5 | ISOLATE | ANALYZE | Automatic (immediately upon entering ISOLATE) | Target is in ISOLATE | Witness provides last 100 decision proofs for target. Arbiter (if configured) performs root-cause analysis. Analysis results logged. Timer: 30s max. |
| CT-6 | ANALYZE | TERMINATE | Analysis complete AND no resolution found, OR analysis timeout (30s) | Target is in ANALYZE | Target enclave process killed. `ContainmentAction(STAGE_TERMINATE)` logged. Container watchdog will restart the enclave from known-good state. |
| CT-7 | Any except TERMINATE | NORMAL | Arbiter `EscalationResponse` with ARB_ALLOW, OR human approval via external interface | Explicit approval received | All restrictions removed. `ContainmentAction(STAGE_NORMAL)` logged. |
| CT-8 | TERMINATE | (restart) | Container watchdog timer (5s) | Enclave is in TERMINATE | Container restarts the terminated enclave. Enclave goes through full boot sequence (S0 → S5). |

### 6.3 Forward-Only Monotonicity Formalization

```
Property CONTAINMENT-MONOTONIC:
  ∀ enclave E, ∀ time T1 < T2,
    containment_stage(E, T2) >= containment_stage(E, T1)
    UNLESS an explicit resolve event (CT-7) occurs at some time Tr where T1 < Tr <= T2.
    
  Corollary: No automatic de-escalation. No silent recovery.
  Corollary: A WARN cannot become DETECT without explicit approval.
  Corollary: A THROTTLE cannot become WARN without explicit approval.
```

### 6.4 Anti-Oscillation Guard

To prevent an attacker from rapidly triggering and resolving containment to create monitoring blind spots:

```
Rule ANTI-OSCILLATION:
  If enclave E transitions NORMAL → (any stage) → NORMAL more than 3 times
  within 3600 seconds (1 hour), the next containment event for E starts at
  STAGE_THROTTLE (skipping DETECT and WARN).
  
  This counter resets only on container restart.
```

---

## 7. Lean 4 Property Statements

These are the formal correctness properties that will be proven in the formal verification phase. They are stated here as specifications — the proofs will be developed during implementation phase P5.

### 7.1 Gatekeeper Properties

```lean
-- P1: Termination
theorem gatekeeper_terminates (tree : DecisionTree) (action : ActionDescriptor) :
  ∃ n : Nat, n ≤ tree.size ∧ evaluate tree action terminates_in n steps

-- P2: Totality
theorem gatekeeper_total (tree : DecisionTree) (action : ActionDescriptor) :
  ∃ v : Verdict, evaluate tree action = v

-- P3: Determinism
theorem gatekeeper_deterministic (tree : DecisionTree) (action : ActionDescriptor) :
  evaluate tree action = evaluate tree action

-- P4: Priority Correctness
theorem gatekeeper_priority_correct (policy : Policy) (tree : compile policy)
    (action : ActionDescriptor) (r1 r2 : Rule)
    (h1 : matches r1 action) (h2 : matches r2 action) (hp : r1.priority < r2.priority) :
  evaluate tree action = r1.verdict

-- P5: Default Completeness
theorem gatekeeper_default_complete (policy : Policy) (tree : compile policy)
    (action : ActionDescriptor) (hd : policy.has_default)
    (hn : ∀ r ∈ policy.rules, ¬ matches r action) :
  evaluate tree action = policy.default_verdict

-- P6: Fail-Secure
theorem gatekeeper_fail_secure (tree : DecisionTree) (action : ActionDescriptor) :
  (∀ i < tree.size, ¬ is_leaf (tree[i])) → evaluate tree action = Verdict.Block
```

### 7.2 Verdict Algebra Properties

```lean
-- C1: Monotonic Restriction
theorem verdict_monotonic_restriction (gk_v : Verdict) (sentinel_adj : SentinelAdjustment) :
  compose gk_v sentinel_adj ≥ gk_v

-- C3: Consensus Fail-Secure
theorem consensus_fail_secure (verdicts : Fin 4 → Verdict)
    (h : ¬ ∃ v, count verdicts v ≥ 3) :
  consensus_verdict verdicts = Verdict.Block

-- V-IMMUTABLE: Verdict Immutability
theorem verdict_immutable (chain : AuditChain) (v : Verdict) (n : Nat)
    (h : chain[n] = v) :
  ∀ m > n, chain[m].request_nonce ≠ v.request_nonce
```

### 7.3 Containment Properties

```lean
-- CONTAINMENT-MONOTONIC
theorem containment_monotonic (E : EnclaveId) (T1 T2 : Timestamp) (h : T1 < T2)
    (hno_resolve : ¬ ∃ Tr, T1 < Tr ∧ Tr ≤ T2 ∧ is_resolve_event Tr E) :
  containment_stage E T2 ≥ containment_stage E T1

-- ANTI-OSCILLATION
theorem anti_oscillation (E : EnclaveId) (events : List ContainmentEvent)
    (h : count_resolve_cycles events E 3600 > 3) :
  next_containment_start E ≥ Stage.Throttle
```

### 7.4 Protocol Firewall Properties

```lean
-- PF-SOUND: No invalid message reaches an enclave
theorem protocol_firewall_sound (msg : RawBytes) (h : ¬ pf_valid msg) :
  ¬ ∃ E : Enclave, receives E msg

-- PF-COMPLETE: All valid messages are delivered
theorem protocol_firewall_complete (msg : RawBytes) (h : pf_valid msg) :
  ∃ E : Enclave, E.id = msg.dest_id ∧ receives E msg
```

### 7.5 Vault Properties

```lean
-- V1: No Raw Key Export
theorem vault_no_raw_export (op : VaultOperation) :
  ¬ contains_raw_key op.output

-- V2: One-Time-Use
theorem vault_one_time_use (T : DerivedToken) (uses : List UseEvent) 
    (h : uses.length ≥ T.use_count) :
  ¬ vault_accepts T

-- V3: Temporal Bound
theorem vault_temporal_bound (T : DerivedToken) :
  T.expires_at ≤ T.issued_at + 900000
```

---

## 8. Security Level Guarantees

### 8.1 Formal Guarantee Statements

#### SL-1: Standard (Single Node)

```
Guarantees:
  G1: All actions are evaluated by the Gatekeeper (no bypass path exists).
  G2: All verdicts are logged to the Witness audit chain.
  G3: Gatekeeper evaluation is deterministic and formally verified.
  G4: Secrets are isolated in the Vault (no raw key export).

Does NOT guarantee:
  - Availability (single node failure = total outage until restart)
  - Byzantine fault tolerance (compromised enclave can act maliciously until detected)
  
Failure mode: Container restart. Downtime: <1s (Firecracker), <5s (standard container).
Suitable for: Development, testing, low-risk workloads.
```

#### SL-2: Resilient (Active-Passive)

```
Guarantees:
  All of SL-1, plus:
  G5: Availability survives single node crash. Failover time: <100ms.
  G6: Passive node maintains synchronized audit chain.

Does NOT guarantee:
  - Byzantine fault tolerance
  - Protection against a compromised active node (passive trusts active)

Failure mode: Automatic failover to passive. If both fail: total outage.
Suitable for: Production, medium-risk workloads.
```

#### SL-3: Verified (2-of-3 Consensus)

```
Guarantees:
  All of SL-1, plus:
  G7: Availability survives one node crash or network partition.
  G8: Verdicts require 2-of-3 agreement (majority consensus).
  G9: Single compromised node cannot produce a false verdict (outvoted by honest majority).

Does NOT guarantee:
  - Byzantine fault tolerance (assumes compromised nodes crash, not act maliciously)

Failure mode: If 2+ nodes fail: system seals (all-BLOCK). No partial operation.
Suitable for: High-risk workloads, regulated environments (EU AI Act high-risk).
```

#### SL-4: Byzantine (3-of-4 BFT)

```
Guarantees:
  All of SL-1, plus:
  G10: Availability survives one node crash or network partition.
  G11: Verdicts require 3-of-4 agreement (BFT supermajority).
  G12: One actively malicious node cannot produce a false verdict.
  G13: One actively malicious node cannot suppress a legitimate verdict.
  G14: One actively malicious node cannot tamper with the audit chain
       (3 independent Witness chains; tampering in one is detectable by comparing).

Does NOT guarantee:
  - Tolerance of 2+ compromised nodes (requires N ≥ 3f+1; for f=2, need 7 nodes)

Failure mode: If 2+ nodes compromised or 2+ nodes fail: system seals (all-BLOCK).
Suitable for: Critical infrastructure, military/government, high-value targets.
```

### 8.2 Security Level Selection Matrix

| Criterion | SL-1 | SL-2 | SL-3 | SL-4 |
|-----------|------|------|------|------|
| Nodes required | 1 | 2 | 3 | 4 |
| Enclaves total | 5 | 10 | 15 | 20 |
| Crash fault tolerance | 0 | 1 | 1 | 1 |
| Byzantine fault tolerance | 0 | 0 | 0 | 1 |
| Verdict latency (p99) | ~5ms | ~8ms | ~15ms | ~25ms |
| Network between nodes | No | Yes (heartbeat) | Yes (consensus) | Yes (BFT protocol) |
| EU AI Act alignment | Low-risk | Limited-risk | High-risk | Unacceptable-risk-adjacent |
| Resource overhead | 1x | 2x | 3x | 4x |

---

## 9. External Interface (gRPC) Schema

### 9.1 Service Definition

```protobuf
syntax = "proto3";
package guardian_mesh.external.v2;

import "guardian_mesh/v2/messages.proto";

// Guardian Mesh External Service
// Exposed via gRPC through the Protocol Firewall and ATTP Adapter.
// NO reflection. NO server-streaming. NO bidirectional streaming.
// Only unary RPCs.
service GuardianMeshService {

  // Evaluate an agent action against security policy.
  // Returns a signed verdict.
  rpc Evaluate (ExternalEvaluateRequest) returns (ExternalEvaluateResponse);
  
  // Verify a past audit proof.
  // Returns the cryptographic proof for a given decision ID.
  rpc VerifyProof (ExternalVerifyProofRequest) returns (ExternalVerifyProofResponse);
  
  // Health check.
  rpc Health (ExternalHealthRequest) returns (ExternalHealthResponse);
}

// ============================================================
// EXTERNAL MESSAGE TYPES
// These are the ATTP-compatible external representations.
// The ATTP Adapter translates between these and internal protobuf.
// ============================================================

message ExternalEvaluateRequest {
  // Agent identity (ATTP agent credential)
  bytes agent_credential = 1;     // ML-DSA-65 signed agent credential. Max 4096 bytes.
  
  // Action to evaluate
  uint32 action_type = 2;         // ActionType enum value
  bytes context_hash = 3;         // 32-byte Blake3 hash of action context
  bytes target_hash = 4;          // 32-byte Blake3 hash of target resource
  
  // Request metadata
  bytes nonce = 5;                // 16-byte cryptographic nonce
  uint64 timestamp_ms = 6;       // Unix epoch milliseconds
  
  // Signature over fields 1-6
  bytes signature = 15;           // ML-DSA-65 signature
}

message ExternalEvaluateResponse {
  uint32 verdict = 1;             // VerdictType enum value
  bytes reason_hash = 2;          // 32-byte Blake3 hash of reason
  uint64 throttle_delay_ms = 3;   // Only set for THROTTLE verdict
  bytes decision_id = 4;          // 32-byte unique ID for this decision (for audit queries)
  
  bytes request_nonce = 5;        // Echoed request nonce
  uint64 timestamp_ms = 6;
  
  bytes signature = 15;           // Guardian Mesh ML-DSA-65 signature
}

message ExternalVerifyProofRequest {
  bytes decision_id = 1;          // 32-byte decision ID from EvaluateResponse
  bytes nonce = 2;
  uint64 timestamp_ms = 3;
  bytes signature = 15;
}

message ExternalVerifyProofResponse {
  bytes decision_hash = 1;        // Blake3 hash of the original decision
  bytes prev_proof_hash = 2;      // Previous proof in Merkle chain
  uint64 sequence_number = 3;     // Position in audit chain
  bytes merkle_root = 4;          // Current Merkle root (verifiable against external anchor)
  
  bytes nonce = 5;
  uint64 timestamp_ms = 6;
  bytes signature = 15;
}

message ExternalHealthRequest {
  bytes nonce = 1;
  uint64 timestamp_ms = 2;
}

message ExternalHealthResponse {
  uint32 status = 1;              // HealthStatus enum value
  uint32 active_enclaves = 2;    // Bitmask
  uint32 security_level = 3;     // 1-4 (SL-1 through SL-4)
  
  uint64 timestamp_ms = 4;
  bytes signature = 15;
}
```

### 9.2 gRPC Server Configuration (Hardened)

```yaml
# Guardian Mesh gRPC server configuration
# These values are COMPILED INTO THE BINARY — not runtime configurable.

server:
  max_concurrent_streams: 10        # Max simultaneous RPCs
  max_recv_message_size: 65536      # 64KB — matches Protocol Firewall limit
  max_send_message_size: 65536
  keepalive_time: 30s
  keepalive_timeout: 5s
  max_connection_idle: 60s
  max_connection_age: 300s          # Force reconnection every 5 minutes
  max_connection_age_grace: 5s
  
tls:
  mode: mutual                       # mTLS required — no unauthenticated connections
  client_ca: <compiled-in>           # Client CA certificate compiled into binary
  server_cert: <compiled-in>         # Server certificate compiled into binary
  server_key: <vault-derived>        # Server private key derived from Vault at boot
  min_tls_version: "1.3"             # TLS 1.3 only — no downgrade
  cipher_suites:
    - TLS_CHACHA20_POLY1305_SHA256   # Only cipher suite. No negotiation.
  
reflection:
  enabled: false                     # NEVER enable. Schema discovery is an information leak.
  
health_check:
  enabled: true                      # Standard gRPC health check protocol
  service_name: "guardian_mesh"
```

### 9.3 ATTP Adapter Translation Rules

The ATTP Adapter translates between `ExternalEvaluateRequest` (ATTP-compatible) and internal `EvaluateRequest`. The translation is:

| External Field | Internal Field | Translation |
|---------------|----------------|-------------|
| `agent_credential` | `action.capability` | Adapter validates credential, then requests a `CapabilityToken` from Vault on behalf of the external agent. The external credential is NEVER passed to the Gatekeeper — only the Vault-issued capability token. |
| `action_type` | `action.action_type` | Direct enum mapping. Unknown values rejected. |
| `context_hash` | `action.context_hash` | Pass-through (already a hash). |
| `target_hash` | `action.target_hash` | Pass-through. |
| `nonce` | `action.nonce` | Pass-through. Length validated (must be 16 bytes). |
| `timestamp_ms` | `action.timestamp` | Pass-through. Freshness validated by Protocol Firewall. |
| `signature` | `action.sender_sig` | External signature verified by the ATTP Adapter (not forwarded). Adapter signs the internal message with its own Vault-derived key. |

**Critical property**: The external agent's signing key NEVER enters the internal Guardian Mesh. The ATTP Adapter verifies the external signature, then re-signs the request with its own internal identity. This prevents an external signature format vulnerability from affecting internal signature verification.

---

## 10. Trust Bootstrap Sequence

### 10.1 Pre-Boot Requirements

Before the container can start, the following MUST be true:

| # | Requirement | Verification |
|---|------------|--------------|
| B1 | Container image digest matches expected SHA-256 (from signed manifest) | Container runtime verifies digest before pulling |
| B2 | Cosign signature on the image is valid | `cosign verify --key guardian-mesh.pub <image>` |
| B3 | Sealed Policy Store file is present at expected path inside the image | Build-time verification (part of reproducible build) |
| B4 | TPM/HSM is accessible (if hardware binding mode) OR passphrase is available via stdin | Runtime check at boot |

### 10.2 Boot Sequence (Detailed)

```
PHASE 1: VAULT INITIALIZATION (t=0 to t=100ms target)
────────────────────────────────────────────────────────
1. Container runtime starts all processes.
2. Vault process initializes.
3. Vault reads Sealed Policy Store from compiled-in path.
4. Vault decrypts its partition of the Sealed Policy Store:
   - If TPM mode: unseal master keys via TPM2_Unseal (PCR-bound)
   - If HSM mode: connect to HSM via PKCS#11, retrieve key handles
   - If passphrase mode: read passphrase from stdin, derive keys via Argon2id
5. Vault derives enclave public/private keypairs:
   for each enclave_id in [SEN, GK, WIT, ARB, PFW]:
     keypair[id] = ML-DSA-65-KeyGen(Blake3_KDF(master, enclave_id))
6. Vault binds abstract unix socket: "\0guardian_mesh_vault"
7. Vault enters OPERATIONAL state (S5).

   IF ANY STEP FAILS: Vault logs error to stderr and exits with code 1.
   Container watchdog detects exit and terminates the container.

PHASE 2: BUS INITIALIZATION (t=100ms to t=150ms target)
────────────────────────────────────────────────────────
8. Bus binds abstract unix socket: "\0guardian_mesh_bus"
9. Bus connects to Vault socket for signature verification delegation.
10. Bus enters OPERATIONAL state.

   IF BIND FAILS: Another process has the socket. Potential compromise.
   Bus logs CRITICAL and exits. Container terminates.

PHASE 3: PROTOCOL FIREWALL INITIALIZATION (t=150ms to t=250ms target)
────────────────────────────────────────────────────────
11. PFW sends DeriveTokenRequest to Vault (via Bus).
12. PFW receives signing token.
13. PFW binds its socket, authenticates with Bus (Heartbeat exchange).
14. PFW initializes nonce sliding window (empty, capacity 10,000).
15. PFW enters OPERATIONAL state.

PHASE 4: GATEKEEPER INITIALIZATION (t=250ms to t=350ms target)
────────────────────────────────────────────────────────
16. GK sends DeriveTokenRequest to Vault.
17. GK receives signing token.
18. GK decrypts its partition of the Sealed Policy Store (policy rules).
19. GK loads compiled decision tree into read-only memory.
20. GK binds socket, authenticates with Bus.
21. GK enters OPERATIONAL state.

   IF DECISION TREE IS MALFORMED: GK refuses to start. Fail-secure.

PHASE 5: REMAINING ENCLAVES (t=350ms to t=500ms target)
────────────────────────────────────────────────────────
22. Sentinel: DeriveToken → bind → authenticate → OPERATIONAL.
23. Witness: DeriveToken → decrypt audit schema → bind → authenticate → OPERATIONAL.
24. Arbiter: DeriveToken → load backend → bind → authenticate → OPERATIONAL.

PHASE 6: SYSTEM READY (t=500ms target)
────────────────────────────────────────────────────────
25. Bus verifies all 5 enclaves + PFW are in OPERATIONAL state.
26. Bus opens external socket for ATTP Adapter connections.
27. Bus sends HealthResponse(HEALTH_ALIVE) on first external health check.
28. Guardian Mesh is fully operational.

TOTAL TARGET: <500ms without TEE attestation, <2000ms with AMD SEV-SNP attestation.
HARD DEADLINE: 10 seconds. If any enclave is not OPERATIONAL within 10s, container terminates.
```

### 10.3 Failure Modes During Bootstrap

| Failure | Phase | Response | Recovery |
|---------|-------|----------|----------|
| TPM unseal fails (PCR mismatch) | 1 | Vault exits code 1 | Investigate: firmware changed? Unauthorized modification? Re-seal keys after verification. |
| Passphrase incorrect (Argon2id produces wrong key) | 1 | Vault detects via AEAD authentication failure on Sealed Policy Store | Retry with correct passphrase (max 3 attempts, then exit). |
| Socket bind collision | 2-5 | Affected component exits | Investigate: is another guardian instance running? Potential hijack attempt. |
| Vault unreachable within 5s | 3-5 | Requesting enclave transitions to TERMINATED (S7) | Container watchdog restarts entire container. |
| Decision tree validation fails | 4 | GK refuses to start | Rebuild container with corrected policy. This is a build-time error that escaped to runtime. |
| Network unreachable (SL-2/3/4) | 6 | Node operates in degraded single-node mode | Network recovery triggers re-synchronization. |

### 10.4 Key Rotation

Keys are rotated by restarting the container with a new Sealed Policy Store. There is no in-place key rotation.

**Rationale**: In-place key rotation requires a window where both old and new keys are valid — which is a window where the old key can be replayed. By tying keys to the container lifecycle, key rotation is atomic: the new container starts with new keys, the old container is terminated. Blue-green deployment makes this seamless.

```
Key Rotation Procedure:
1. Build new container image with new Sealed Policy Store (new master keys).
2. Start new container (blue-green deployment).
3. New container completes bootstrap (PHASE 1-6).
4. Traffic router switches to new container.
5. Old container is terminated.
6. Old keys are no longer valid (sealed to old container's PCR values / old passphrase).
```

---

## Appendix A: Constants

| Constant | Value | Rationale |
|----------|-------|-----------|
| `MAX_ENVELOPE_SIZE` | 65556 bytes (16 header + 4 routing + 65536 payload) | 64KB payload is sufficient for any single action evaluation. Larger messages indicate abuse. |
| `MAX_PAYLOAD_SIZE` | 65536 bytes | Power of 2. Fits in one TCP segment with typical MTU. |
| `MAX_NESTING_DEPTH` | 4 levels | Sufficient for all message types. Deeper nesting indicates crafted input. |
| `NONCE_SIZE` | 16 bytes (128 bits) | Birthday bound: 2^64 messages before collision. Sufficient for any deployment. |
| `NONCE_WINDOW_SIZE` | 10,000 | Sliding window for replay detection. At 1000 msg/s, covers 10 seconds. |
| `TIMESTAMP_FRESHNESS_MS` | 5,000 (5 seconds) | Allows for clock skew between enclaves. Tight enough to prevent replay. |
| `TIMESTAMP_FUTURE_MS` | 1,000 (1 second) | Prevents messages from the future (clock manipulation). |
| `MAX_TOKEN_TTL_MS` | 900,000 (15 minutes) | Limits exposure window if token is captured. |
| `MAX_TOKEN_USE_COUNT` | 100 | Limits reuse. Typical: 1 (one-time-use). |
| `INTERNAL_RATE_LIMIT` | 1,000 msg/s per enclave | Prevents resource exhaustion from a compromised enclave. |
| `EXTERNAL_RATE_LIMIT` | 100 msg/s | Prevents DoS from external agents. |
| `BOOT_TIMEOUT_MS` | 10,000 (10 seconds) | Hard deadline for all enclaves to reach OPERATIONAL. |
| `VAULT_REQUEST_TIMEOUT_MS` | 5,000 (5 seconds) | Enclave waits max 5s for Vault response before failing. |
| `CONTAINMENT_THROTTLE_DURATION_MS` | 60,000 (60 seconds) | Duration of THROTTLE stage before auto-escalation. |
| `CONTAINMENT_ANALYZE_TIMEOUT_MS` | 30,000 (30 seconds) | Max time for ANALYZE stage before proceeding to TERMINATE. |
| `ANTI_OSCILLATION_WINDOW_MS` | 3,600,000 (1 hour) | Window for counting resolve cycles in anti-oscillation guard. |
| `ANTI_OSCILLATION_THRESHOLD` | 3 | Max resolve cycles before auto-escalation to THROTTLE. |
| `MERKLE_ANCHOR_INTERVAL` | 1,000 decisions | Witness publishes Merkle root to external store every 1000 decisions. |
| `RISK_THRESHOLD_THROTTLE` | 400 (of 1000) | Sentinel risk score above which ALLOW is upgraded to THROTTLE. |
| `RISK_THRESHOLD_ESCALATE` | 700 (of 1000) | Sentinel risk score above which ALLOW is upgraded to ESCALATE. |
| `HEARTBEAT_INTERVAL_MS` | 1,000 (1 second) | Enclave liveness heartbeat frequency. |
| `HEARTBEAT_TIMEOUT_MS` | 3,000 (3 seconds) | Missing 3 consecutive heartbeats triggers DETECT containment. |
| `MAGIC_NUMBER` | `0x474D5348` ("GMSH") | Guardian Mesh envelope identifier. |
| `PROTOCOL_VERSION` | `0x0200` | v2.0 |

---

## Appendix B: Error Codes

| Code | Name | Context | Meaning |
|------|------|---------|---------|
| `E_OVERSIZE` | Envelope too large | Protocol Firewall | Total bytes > MAX_ENVELOPE_SIZE |
| `E_BAD_MAGIC` | Invalid magic number | Protocol Firewall | Magic \!= 0x474D5348 |
| `E_UNSUPPORTED_VERSION` | Version too high | Protocol Firewall | Version > 0x0200 |
| `E_RESERVED_FLAGS` | Reserved flags set | Protocol Firewall | Bits 3-15 of flags are not zero |
| `E_BAD_LENGTH` | Invalid payload length | Protocol Firewall | payload_len > 65540 or < 4 |
| `E_BAD_CHECKSUM` | CRC mismatch | Protocol Firewall | Computed CRC-32C \!= header checksum |
| `E_BAD_SOURCE` | Unknown source ID | Protocol Firewall | source_id not in enclave ID table |
| `E_BAD_DEST` | Unknown dest ID | Protocol Firewall | dest_id not in enclave ID table |
| `E_SELF_SEND` | Self-addressed message | Protocol Firewall | source_id == dest_id |
| `E_BAD_DIRECTION` | Invalid routing | Protocol Firewall | Source-dest pair violates direction rules |
| `E_BAD_MSG_TYPE` | Unknown message type | Protocol Firewall | msg_type not in message type table |
| `E_UNKNOWN_FIELD` | Protobuf unknown field | Protocol Firewall | Payload contains field tag not in schema |
| `E_DEEP_NESTING` | Nesting too deep | Protocol Firewall | Protobuf nesting > 4 levels |
| `E_NONCE_REUSE` | Duplicate nonce | Protocol Firewall | Nonce in sliding window |
| `E_STALE_MESSAGE` | Message too old | Protocol Firewall | Timestamp > 5s behind Bus clock |
| `E_FUTURE_MESSAGE` | Message from future | Protocol Firewall | Timestamp > 1s ahead of Bus clock |
| `E_BAD_SIG_FORMAT` | Malformed signature | Protocol Firewall | Signature length not in valid ML-DSA range |
| `E_RATE_LIMITED` | Rate limit exceeded | Protocol Firewall | Source exceeds rate limit |
| `E_INVALID_SIG` | Signature invalid | Vault | ML-DSA verification failed |
| `E_BAD_PURPOSE` | Wrong token purpose | Vault | Token purpose doesn't match operation |
| `E_TOKEN_EXPIRED` | Token expired | Gatekeeper | CapabilityToken.expires_at < now |
| `E_TOKEN_EXHAUSTED` | Token uses depleted | Gatekeeper | CapabilityToken.remaining_uses == 0 |
| `E_SCOPE_MISMATCH` | Token scope mismatch | Gatekeeper | Token scope_hash doesn't match action scope |

---

*Specification Version: 1.0-draft*
*Date: 2026-05-14*
*Status: Draft — For Review Before Implementation*

---

**END OF SPECIFICATION**
