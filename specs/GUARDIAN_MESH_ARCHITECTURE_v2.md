# Guardian Mesh Architecture v2.0
## Secure Isolated Guardian System — Revised with Global Intelligence

**Version:** 2.0
**Date:** 2026-05-14
**Classification:** Internal — Critical Architecture
**Status:** For Discussion — Pre-Implementation
**Supersedes:** Guardian Mesh Preamble v1.0 (conversational draft, 2026-05-14)

---

## Table of Contents

1. [Design Philosophy](#1-design-philosophy)
2. [Core Principle: Standards Adoption With Hardened Boundaries](#2-core-principle-standards-adoption-with-hardened-boundaries)
3. [The Five Enclaves](#3-the-five-enclaves)
4. [Hardened Handshake Protocol (ATTP-Compatible)](#4-hardened-handshake-protocol)
5. [Standards Interface Hardening Policy](#5-standards-interface-hardening-policy)
6. [Container Specification & Defense-in-Depth](#6-container-specification--defense-in-depth)
7. [Graduated Containment (Biological Immune Model)](#7-graduated-containment)
8. [Four Deployment Security Levels](#8-four-deployment-security-levels)
9. [Formal Verification Commitment](#9-formal-verification-commitment)
10. [External API Surface](#10-external-api-surface)
11. [Regulatory Compliance Mapping](#11-regulatory-compliance-mapping)
12. [Risks, Limitations & Open Problems](#12-risks-limitations--open-problems)
13. [FOSS Viability & Implementation Plan](#13-foss-viability--implementation-plan)
14. [Revision History](#14-revision-history)

---

## 1. Design Philosophy

### 1.1 What Guardian Mesh Is

A **mesh of isolated cryptographic enclaves** that collectively enforce security policy for agentic AI systems without any single component having full system visibility. Deployable as a FOSS, platform-agnostic, minimal Linux container.

### 1.2 Three Governing Laws

1. **No God Process.** No component has a complete picture. Compromise of any single enclave does not compromise the system.
2. **Deterministic Enforcement.** The enforcement path contains no probabilistic component. Same input, same output, every time. The Gatekeeper cannot be jailbroken because it does not reason — it evaluates.
3. **Standards Inside, Armor Outside.** Where we adopt external standards (ATTP, IETF Agent Trust, PQC algorithms), we wrap them in hardened boundaries that prevent the standard itself from becoming an attack vector. Every standardized interface is a potential weak spot unless explicitly armored.

### 1.3 What Changed from v1.0

| Change | Rationale |
|--------|-----------|
| Added 5th enclave: **Credential Vault** | AI-driven credential theft (V-AI1) and account takeover (V-AI2) demand isolated secret management |
| Handshake Protocol redesigned for ATTP compatibility | IETF/ATTP standardization race demands interoperability — but hardened |
| Arbiter made pluggable | Anthropic CAI 2.0, MOSAIC, ReGuard all offer viable reasoning backends |
| Witness gets external anchoring | Self-referential audit chains can be replayed; external Merkle root anchoring prevents this |
| Graduated containment gains "analyze" stage | MAOS biological immune model adds understanding before termination |
| Formal verification elevated to core requirement | seL4 and VeriGuard prove it's achievable; nobody has done it for AI security |
| Four deployment security levels defined | Redundancy mode changes trust guarantees — must be explicit |
| Standards-hardening policy added | Adopting ATTP/IETF/PQC without hardening imports attack surface |
| Regulatory mapping made structural | EU AI Act + Chinese CAC guidelines mapped to components |

---

## 2. Core Principle: Standards Adoption With Hardened Boundaries

> **"Every standard we adopt is an attack surface we import."**

This principle governs every external protocol, format, or algorithm Guardian Mesh touches. The rule is simple: we never expose a raw standard interface to any internal component. Every standard passes through a hardening layer that:

1. **Validates before parsing.** Input from any standardized protocol is validated against a strict schema before it reaches the parser. Malformed input is rejected at the byte level, not the semantic level.
2. **Limits attack surface.** We implement the minimum viable subset of any standard. Features we don't need are not compiled in — they don't exist in our binary.
3. **Isolates the boundary.** The component that speaks a standard protocol runs in its own isolation domain. If the protocol parser is compromised, the compromise is contained to that domain.
4. **Assumes hostile input.** Every message arriving through a standardized interface is treated as adversarial. There is no "trusted" external input.
5. **Monitors the interface.** The Sentinel observes all standardized interfaces for anomalous patterns — unusual message sizes, unexpected field combinations, timing variations.

### 2.1 Standards We Adopt and How We Harden Them

| Standard | Why We Adopt It | Attack Surface It Creates | How We Harden It |
|----------|----------------|--------------------------|-----------------|
| **ATTP (Agent Trust Transport Protocol)** | Interoperability with emerging agent trust ecosystem. 5 trust levels, bindings for MCP/REST/gRPC/GraphQL. | Protocol complexity. Multiple serialization formats. Trust level negotiation can be manipulated. GraphQL introspection leaks schema. | **Minimal subset**: Implement only gRPC binding (single serialization: protobuf). No GraphQL (introspection risk). No REST (loose typing). Trust level is set at build time, not negotiable at runtime. ATTP messages pass through a dedicated **Protocol Firewall** (separate from Context Firewall) that validates structure before any component sees content. |
| **IETF Agent Trust Auth Framework** | Cross-domain agent identity verification. Verifiable credentials, delegation, revocation. | Credential format parsing (JSON-LD, JWT). Delegation chains can be forged if signature verification is flawed. Revocation checking requires network access. | **Offline-first revocation**: Capability tokens carry embedded expiry — no network revocation check needed. Revocation is achieved by not renewing tokens. JWT parsing uses a **hardened minimal parser** (no dynamic key discovery, no `alg:none`, no JWK URL fetching). Only ML-DSA signatures accepted — algorithm negotiation disabled. |
| **ML-KEM (NIST PQC key encapsulation)** | Post-quantum key exchange for Handshake Protocol. | Implementation bugs in lattice arithmetic. Side-channel leakage during encapsulation/decapsulation. | **Constant-time implementation** mandatory. Use audited library (pqcrypto-rs or similar). No custom implementation. **Fuzzing** of KEM interface with AFL++/libFuzzer before deployment. Side-channel testing on target hardware. |
| **ML-DSA (NIST PQC digital signatures)** | Post-quantum signing for capability tokens, audit proofs, inter-enclave messages. | Signature verification timing leaks. Key generation entropy quality. Large signature sizes (2-4KB) could be used for DoS. | **Constant-time verification**. Hardware entropy source (RDRAND + /dev/urandom mixed) for key generation. **Signature size budget**: maximum 4KB per message enforced at Protocol Firewall. Messages exceeding budget are dropped before signature verification. |
| **Blake3 (hashing)** | Audit chain integrity. Already quantum-resistant. 3.5 GB/s throughput. | Minimal — hash functions have small attack surface. Length extension attacks (not applicable to Blake3 but must verify). | Blake3 is inherently resistant to length extension. Use **keyed mode** (HMAC-equivalent) for inter-enclave message authentication. Verify implementation against reference vectors. |
| **Protobuf (serialization)** | Structured message passing between enclaves and via ATTP gRPC binding. | Protobuf parsing vulnerabilities (CVE history exists). Unknown fields silently accepted by default. Recursive message nesting causes stack overflow. | **Proto3 only** (no proto2 — simpler, fewer edge cases). **Unknown fields rejected** (custom deserializer that fails on any unknown field tag). **Maximum nesting depth: 4 levels**. Maximum message size: 64KB. Fuzz-tested with protobuf-mutator. |
| **Unix Domain Sockets (IPC)** | Inter-enclave communication. No network exposure. | File descriptor leaks. Race conditions in socket creation. Peer credential spoofing if SO_PEERCRED is relied upon incorrectly. | **Abstract namespace sockets** (no filesystem path — cannot be accessed by other processes). Socket created at enclave startup with **exclusive bind** — if bind fails, enclave refuses to start (prevents hijacking). Peer authentication via HMAC on first message, not SO_PEERCRED. |
| **OCI Container Image Format** | Distribution of Guardian Mesh as container. | Image tampering in registries. Layer injection. Tag mutability. | **Content-addressable only**: Deploy by digest (SHA-256), never by tag. **Cosign signature verification** before loading. **Reproducible builds** (Nix) so digest can be independently verified from source. |

---

## 3. The Five Enclaves

### 3.1 Architecture Diagram

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                     MINIMAL LINUX CONTAINER                                  │
│              (Distroless, <50MB, read-only rootfs, zero capabilities)        │
│                                                                              │
│  ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌───────────┐    │
│  │ SENTINEL  │ │ GATEKEEPER│ │  WITNESS  │ │  ARBITER  │ │ CREDENTIAL│    │
│  │ (Observe) │ │ (Enforce) │ │  (Audit)  │ │ (Decide)  │ │   VAULT   │    │
│  │           │ │           │ │           │ │           │ │ (Secrets) │    │
│  │ Sees:     │ │ Sees:     │ │ Sees:     │ │ Sees:     │ │ Sees:     │    │
│  │ behavior  │ │ policy    │ │ proofs    │ │ verdicts  │ │ nothing   │    │
│  │ signals   │ │ rules     │ │ only      │ │ only      │ │ external  │    │
│  │           │ │           │ │           │ │           │ │           │    │
│  │ Cannot:   │ │ Cannot:   │ │ Cannot:   │ │ Cannot:   │ │ Cannot:   │    │
│  │ block,    │ │ observe,  │ │ block,    │ │ observe,  │ │ see, read │    │
│  │ read      │ │ audit, or │ │ enforce,  │ │ enforce,  │ │ or serve  │    │
│  │ policy    │ │ read      │ │ or read   │ │ or audit  │ │ raw keys  │    │
│  │           │ │ secrets   │ │ behavior  │ │           │ │ — only    │    │
│  │           │ │           │ │           │ │           │ │ derived   │    │
│  │           │ │           │ │           │ │           │ │ tokens    │    │
│  └─────┬─────┘ └─────┬─────┘ └─────┬─────┘ └─────┬─────┘ └─────┬─────┘    │
│        │             │             │             │             │            │
│        └─────────────┴──────┬──────┴─────────────┴─────────────┘            │
│                             │                                                │
│                    ┌────────┴────────┐                                       │
│                    │  HANDSHAKE BUS  │                                       │
│                    │ (Abstract unix  │                                       │
│                    │  sockets, HMAC  │                                       │
│                    │  + ML-KEM/DSA)  │                                       │
│                    │                 │                                       │
│                    │  No shared mem  │                                       │
│                    │  No env vars    │                                       │
│                    │  No file I/O    │                                       │
│                    │  No network     │                                       │
│                    └────────┬────────┘                                       │
│                             │                                                │
│  ┌──────────────────────────┴──────────────────────────────────────────┐    │
│  │                    PROTOCOL FIREWALL                                 │    │
│  │  (Validates all standardized protocol input before any enclave      │    │
│  │   sees it. Schema validation, size limits, nesting limits,          │    │
│  │   unknown-field rejection. Runs in its own isolation domain.)       │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                             │                                                │
│  ┌──────────────────────────┴──────────────────────────────────────────┐    │
│  │                    SEALED POLICY STORE                               │    │
│  │  (Encrypted at rest, loaded once at boot, immutable at runtime)     │    │
│  │  Gatekeeper decrypts policy rules — nobody else can                 │    │
│  │  Witness decrypts audit schema — nobody else can                    │    │
│  │  Vault decrypts secret encryption keys — nobody else can            │    │
│  │  No component can decrypt another component's partition             │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
         │                                          │
         │  Minimal syscall interface               │  External ATTP Interface
         │  (seccomp-bpf: ~8 syscalls)              │  (gRPC-only, hardened,
         │  + Landlock filesystem restriction        │   through Protocol Firewall)
         │                                          │
         ▼                                          ▼
    ┌──────────┐                              ┌──────────┐
    │  HOST    │                              │  AGENT   │
    │  SYSTEM  │                              │  PROCESS │
    │  (opaque)│                              │  (opaque)│
    └──────────┘                              └──────────┘
```

### 3.2 Enclave Specifications

#### SENTINEL (Observer)
- **Purpose**: Monitor behavioral signals, detect anomalies, measure drift, observe standardized interfaces
- **Can see**: Behavioral telemetry, timing patterns, resource usage, protocol interface traffic patterns
- **Cannot**: Block actions, read policy rules, read audit logs, read secrets, modify any other enclave's state
- **Communicates via**: Signed observation reports to Handshake Bus
- **New in v2.0**: Monitors Protocol Firewall for anomalous standardized-interface traffic (unusual ATTP message patterns, signature verification failures, format violations)
- **Formal property**: Sentinel is a pure observer — it has no write path to any enforcement mechanism. Even if fully compromised, it cannot cause the system to allow or block anything.

#### GATEKEEPER (Enforcer)
- **Purpose**: Allow/block/throttle actions based on deterministic policy rules
- **Can see**: Policy rules (decrypted from Sealed Policy Store), action descriptors, capability tokens
- **Cannot**: Observe behavior directly, read audit trail, read secrets, access the Vault, make probabilistic judgments
- **Communicates via**: Signed verdicts to Handshake Bus
- **Critical constraint**: **Deterministic.** No LLM. No ML model. No floating-point arithmetic. No random number generation. Pure, total functions over finite domains. Same input always produces same output.
- **Formal verification target**: Gatekeeper logic will be extracted to Lean 4 and mathematically proven correct against its policy specification. This is the core formal verification commitment (Section 9).
- **New in v2.0**: Policy rules are compiled at build time into a decision tree. No runtime policy parsing. No dynamic rule loading. The decision tree is part of the verified binary.

#### WITNESS (Auditor)
- **Purpose**: Record cryptographic proofs of all decisions, verify integrity, provide external anchoring
- **Can see**: Decision proofs (hashed verdicts), Merkle tree state
- **Cannot**: Block actions, change policy, observe raw behavior, read secrets
- **Communicates via**: Receives proofs, appends to Blake3-hashed chain, periodically publishes Merkle root
- **Critical constraint**: **Append-only.** Cannot modify or delete any record. Write path only — no update, no delete.
- **New in v2.0**: **External Merkle root anchoring.** Every N decisions (configurable, default 1000), the Witness publishes the current Merkle root to an external immutable store (options: public git repository, IPFS, blockchain, or a simple append-only log file on a separate host). This prevents a compromised Witness from silently truncating or replaying the audit chain. The external anchor is verifiable by any third party.
- **Regulatory mapping**: Satisfies EU AI Act Article 12 (record-keeping), Chinese CAC requirement for blockchain-based traceability.

#### ARBITER (Decision Maker)
- **Purpose**: Resolve conflicts between Sentinel observations and Gatekeeper verdicts, escalate to human when needed
- **Can see**: Escalation requests (from Gatekeeper when rules are ambiguous), Sentinel anomaly reports (high-confidence only)
- **Cannot**: Directly observe raw behavior, enforce policy, modify audit trail, access secrets
- **Critical constraint**: Only activates on conflict — silent during normal operation. This is the most sandboxed component.
- **New in v2.0**: **Pluggable reasoning backend.** The Arbiter defines a verdict interface:
  ```rust
  trait ArbiterBackend {
      fn resolve(&self, escalation: Escalation) -> ArbiterVerdict;
  }
  
  enum ArbiterVerdict {
      AllowWithConditions { conditions: Vec<Condition> },
      Block { reason_hash: [u8; 32] },
      EscalateToHuman { context_hash: [u8; 32] },
      DeferToGatekeeper,  // Arbiter abstains — Gatekeeper's original verdict stands
  }
  ```
  Supported backends (pluggable at build time, not runtime):
  - **RuleArbiter**: Deterministic conflict resolution rules (default — keeps entire system formally verifiable)
  - **CAIArbiter**: Anthropic Constitutional AI 2.0 constrained decoding (for deployments needing natural-language reasoning)
  - **MOSAICArbiter**: Plan-check-act-refuse loop (for deployments needing uncertainty calibration)
  - **HumanOnlyArbiter**: Every conflict escalates to human. Zero autonomous resolution. (For maximum safety deployments)

#### CREDENTIAL VAULT (Secrets) — **New in v2.0**
- **Purpose**: Isolated hardware-bound secret storage. Manages all cryptographic keys, API credentials, session tokens, and HMAC shared secrets.
- **Can see**: Encrypted key material (decrypted only inside Vault's memory space)
- **Cannot**: See any other enclave's state, read policy, observe behavior, participate in enforcement decisions
- **Communicates via**: Issues **one-time-use derived tokens** through the Handshake Bus. No enclave ever receives a raw secret — only a derived, time-bounded, scope-limited token.
- **Critical constraint**: **No raw key export.** The Vault performs cryptographic operations internally and returns results (signatures, HMAC tags, derived keys) — never the key itself. Even a memory dump of another enclave reveals no secrets.
- **Hardware binding**: When TPM/HSM is available, master keys are sealed to the hardware. Without hardware, keys are derived from a passphrase + Argon2id KDF at boot time.
- **Why this exists**: The research on V-AI1 (AI-Driven Credential Theft) and V-AI2 (AI-Powered Account Takeover) showed that credential management cannot be a side concern distributed across components. A compromised Gatekeeper with access to signing keys could forge verdicts. A compromised Sentinel with access to HMAC secrets could fabricate observations. Isolating secrets in a dedicated enclave with no-export policy eliminates this entire attack class.

---

## 4. Hardened Handshake Protocol (ATTP-Compatible)

### 4.1 Design Principle

The Handshake Protocol is the communication backbone of Guardian Mesh. It must be:
- **Internally zero-knowledge**: No enclave learns another's internal state
- **Externally interoperable**: Compatible with ATTP for agent ecosystem integration
- **Hardened at every interface**: The protocol itself cannot be exploited

### 4.2 Internal Communication (Enclave-to-Enclave)

```
Component A                    Handshake Bus                    Component B
     │                              │                              │
     │  1. Request derived signing  │                              │
     │     token from Vault         │                              │
     │     (one-time-use)           │                              │
     │                              │                              │
     │  2. Construct message:       │                              │
     │     - Protobuf payload       │                              │
     │       (strict schema,        │                              │
     │        no unknown fields,    │                              │
     │        max 64KB,             │                              │
     │        max depth 4)          │                              │
     │     - Nonce (128-bit)        │                              │
     │     - Timestamp (monotonic)  │                              │
     │     - ML-DSA signature       │                              │
     │       (via Vault-derived     │                              │
     │        one-time token)       │                              │
     │                              │                              │
     │──── sealed envelope ────────>│                              │
     │                              │                              │
     │                              │  3. Protocol Firewall:       │
     │                              │     - Size check (<64KB)     │
     │                              │     - Schema validation      │
     │                              │     - Nonce uniqueness check  │
     │                              │     - Timestamp freshness     │
     │                              │       (reject if >5s old)    │
     │                              │     - Signature format check  │
     │                              │       (before verification)  │
     │                              │                              │
     │                              │  4. Route by envelope tag    │
     │                              │     (Bus cannot read payload)│
     │                              │                              │
     │                              │──── sealed envelope ────────>│
     │                              │                              │
     │                              │     5. B requests verify     │
     │                              │        from Vault (via Bus)  │
     │                              │     6. Vault verifies        │
     │                              │        signature internally  │
     │                              │        Returns: valid/invalid│
     │                              │     7. B processes if valid  │
     │                              │     8. B emits own sealed    │
     │                              │        response              │
```

**Hardening measures on internal protocol:**
- **Nonce reuse detection**: The Protocol Firewall maintains a sliding window of recent nonces (last 10,000). Any reuse is immediately rejected and triggers a Sentinel alert.
- **Monotonic timestamps**: Each enclave maintains its own monotonic clock. Timestamps cannot go backward. Messages more than 5 seconds old are rejected (prevents replay even if nonce check is somehow bypassed).
- **Signature verification in Vault**: Signature verification happens inside the Vault enclave, not in the receiving enclave. This means the receiving enclave never handles raw signature verification logic — it just gets a boolean. The Vault is the only component that touches cryptographic verification code, reducing the number of components that must be hardened against side-channel attacks.
- **No algorithm negotiation**: ML-DSA is the only accepted algorithm. There is no field for algorithm selection. The `alg:none` class of attacks is impossible because there is no algorithm field to manipulate.

### 4.3 External Communication (ATTP-Compatible Interface)

For communication with external agent ecosystems, the Guardian Mesh exposes a hardened ATTP endpoint. This is the **only** external interface.

```
┌──────────────────────────────────────────────────────────────────┐
│                    EXTERNAL ATTP INTERFACE                        │
│                                                                    │
│  ┌──────────────────────────────────────────────────────────────┐│
│  │                 PROTOCOL FIREWALL (outer)                     ││
│  │  - gRPC only (no REST, no GraphQL, no WebSocket)             ││
│  │  - Mutual TLS with certificate pinning                       ││
│  │  - Rate limiting: 100 req/s default, configurable            ││
│  │  - Maximum message size: 64KB                                ││
│  │  - Maximum concurrent connections: 10                        ││
│  │  - IP allowlisting (optional, for known agent peers)         ││
│  │  - Request timeout: 5 seconds (prevents slowloris)           ││
│  └──────────────────────────────────────┬───────────────────────┘│
│                                          │                        │
│  ┌──────────────────────────────────────┴───────────────────────┐│
│  │                 ATTP ADAPTER (hardened subset)                ││
│  │  - Implements ATTP trust level verification                  ││
│  │  - Trust level is BUILD-TIME configured, not negotiable      ││
│  │  - Only accepts ML-DSA signed agent credentials              ││
│  │  - Strips all fields not in our strict schema                ││
│  │  - Translates ATTP messages to internal protobuf format      ││
│  │  - Translator runs in isolated memory space                  ││
│  │  - If translator crashes, external interface is sealed        ││
│  │    (internal Guardian continues operating)                   ││
│  └──────────────────────────────────────┬───────────────────────┘│
│                                          │                        │
│                                    Internal                       │
│                                    Handshake Bus                  │
│                                                                    │
└──────────────────────────────────────────────────────────────────┘
```

**Critical hardening: The ATTP Adapter is a disposable boundary.**
If the external ATTP interface is compromised — protocol exploit, malformed message that crashes the adapter, zero-day in gRPC — the internal Guardian Mesh continues operating normally. The ATTP Adapter is like an airlock: it can be destroyed without breaching the hull.

**What we deliberately do NOT implement from ATTP:**
- **GraphQL binding**: Introspection queries expose the schema. Complexity attacks via nested queries. We don't need it.
- **REST binding**: Loose typing, path traversal risks, verb confusion. We don't need it.
- **Runtime trust level negotiation**: Trust level is a security-critical parameter. It is set at build time and compiled into the binary. An attacker cannot negotiate a lower trust level.
- **Dynamic key discovery (JWK URLs)**: Fetching keys from external URLs introduces network dependency and SSRF risk. All accepted keys are provisioned at build time or through the Vault.

---

## 5. Standards Interface Hardening Policy

This section defines the universal hardening rules applied to every standardized interface, protocol, or format that Guardian Mesh touches.

### 5.1 The Six Hardening Rules

| # | Rule | Rationale |
|---|------|-----------|
| H1 | **Validate before parse.** Raw bytes are checked against structural constraints (size, magic bytes, field count) before any parser runs. | Parser vulnerabilities (buffer overflows, stack exhaustion) are triggered during parsing. Rejecting malformed input before the parser runs eliminates this class. |
| H2 | **Minimum viable subset.** Implement only the features we use. Features we don't need are not compiled into the binary. | Every feature is attack surface. ATTP has 4 transport bindings — we use 1. Protobuf supports unknown fields — we reject them. Less code = fewer bugs. |
| H3 | **Isolate the boundary.** The component that speaks a standard protocol runs in its own isolation domain (separate thread with independent seccomp profile, or separate process). | If the protocol parser is compromised, the compromise is contained. The ATTP Adapter crash does not crash the Gatekeeper. |
| H4 | **No algorithm negotiation.** Cryptographic algorithms are fixed at build time. There is no runtime negotiation, no algorithm selection field, no fallback to weaker algorithms. | Algorithm downgrade attacks (POODLE, DROWN, `alg:none` in JWT) are a perennial vulnerability class. Fixed algorithms eliminate the entire class. |
| H5 | **No dynamic discovery.** Keys, endpoints, schemas, and configurations are provisioned at build time or through the Vault. Nothing is fetched from external URLs at runtime. | SSRF, DNS rebinding, and man-in-the-middle attacks all exploit runtime discovery. Build-time provisioning eliminates the network dependency. |
| H6 | **Fuzz every interface.** Every parser, every deserializer, every protocol handler is fuzz-tested with AFL++/libFuzzer before release. Fuzz findings are blockers — no release with unfixed fuzz crashes. | Fuzzing finds the bugs that humans miss. It is the most cost-effective way to find parser vulnerabilities. Making it a release gate ensures it's not skipped. |

### 5.2 Hardening Applied to Specific Attack Patterns

| Attack Pattern | Standard It Exploits | Our Hardening |
|----------------|---------------------|---------------|
| **Algorithm downgrade** (POODLE, DROWN, JWT `alg:none`) | TLS, JWT, JOSE | Rule H4: No algorithm negotiation. ML-KEM + ML-DSA only. No field for algorithm selection exists in our protocol. |
| **XML/JSON bomb** (billion laughs, recursive nesting) | XML, JSON, Protobuf | Rule H1: Max message size 64KB. Max nesting depth 4. Checked before parser runs. |
| **Deserialization RCE** (Java serialization, Pickle, YAML) | Serialization formats | Rule H2: Protobuf only (no arbitrary code execution during deserialization). No Pickle, no YAML parsing, no Java serialization anywhere in the system. |
| **SSRF via JWK URL** | OAuth, OIDC, JWT | Rule H5: No dynamic key discovery. All keys provisioned at build time or via Vault. |
| **GraphQL introspection** | GraphQL | Rule H2: No GraphQL. Not implemented. Not compiled. |
| **Prototype pollution** | JavaScript/JSON | Rule H2: Rust only. No JavaScript anywhere in the system. Protobuf deserialization into Rust structs — no dynamic property assignment. |
| **Certificate confusion** | TLS, mTLS | External interface uses certificate pinning. Internal communication uses abstract unix sockets (no TLS needed — no network). |
| **Replay attack** | Any protocol | Nonce uniqueness (sliding window of 10,000) + monotonic timestamps + 5-second freshness window. Triple protection. |

---

## 6. Container Specification & Defense-in-Depth

### 6.1 Eight-Layer Defense Stack

| Layer | Technology | What It Prevents | Overhead |
|-------|-----------|-----------------|----------|
| L1 | Distroless/static base (<5MB) | No shell, no package manager, no unnecessary binaries | None |
| L2 | Read-only rootfs | No filesystem modification, no malware persistence | None |
| L3 | seccomp-bpf strict allowlist | Only ~8 syscalls permitted: read, write, epoll_wait, epoll_ctl, clock_gettime, exit_group, futex, mmap | <1% |
| L4 | Landlock LSM | Filesystem access restricted to abstract unix sockets only | <1% |
| L5 | All capabilities dropped | No privilege escalation possible | None |
| L6 | Non-root user (UID 65534) | Limits impact of any compromise | None |
| L7 | Firecracker microVM (optional) | Hardware-grade isolation. Container escape lands in microVM, not on host. <125ms boot. | ~5% |
| L8 | AMD SEV-SNP / Intel TDX Confidential VM (optional) | Memory encryption. Even hypervisor cannot read guardian state. | 2-8% |

### 6.2 Why gVisor Is Not in Our Default Stack

gVisor (user-space kernel) adds ~30-50% syscall latency. For a security system that must evaluate every action in the hot path, this overhead is significant. Instead:
- **Default**: seccomp + Landlock (near-zero overhead, kernel-level enforcement)
- **High-security**: Firecracker microVM (hardware isolation, <5% overhead)
- **Maximum-security**: Confidential VM (memory encryption, 2-8% overhead)

gVisor remains an option for deployments that prioritize isolation purity over latency.

### 6.3 Container Image Integrity

```yaml
# Guardian Mesh container build spec
base: gcr.io/distroless/static:nonroot
build_system: Nix (reproducible builds)
signing: Cosign (Sigstore) — every release signed
verification: cosign verify --key guardian-mesh.pub ghcr.io/guardian-mesh:sha256-<digest>
distribution: Content-addressable only (deploy by digest, never by tag)
reproducibility: nix build .#guardian-mesh → same SHA-256 on any machine
```

---

## 7. Graduated Containment (Biological Immune Model)

Revised from v1.0 to include the **Analyze** stage, inspired by MAOS biological immune system model.

### 7.1 Six-Stage Containment

| Stage | Action | Duration | Reversible? | Who Decides |
|-------|--------|----------|-------------|-------------|
| **1. Detect** | Sentinel flags anomaly. No action taken. Observation only. | Immediate | N/A | Sentinel |
| **2. Warn** | Alert generated. Component continues operating. Sentinel increases observation frequency. | Until resolved or escalated | N/A | Sentinel |
| **3. Throttle** | Gatekeeper rate-limits the affected action type. System continues with reduced throughput. | Configurable (default 60s) | Yes — automatic if anomaly resolves | Gatekeeper |
| **4. Isolate** | Affected component's communication is restricted to the Witness only (for continued audit logging). All other inter-enclave communication severed. | Until Arbiter resolves or human intervenes | Yes — Arbiter or human can restore | Gatekeeper + Arbiter |
| **5. Analyze** *(new in v2.0)* | Isolated component's recent behavior is captured and analyzed. Witness provides the last N decision proofs. Arbiter (if configured) attempts root-cause inference. Results fed to policy learner for future prevention. | Up to 30 seconds | N/A (analysis only) | Arbiter + Witness |
| **6. Terminate** | Component is killed and restarted from known-good state. If restart fails, component remains dead and system operates in degraded mode. | Immediate | No — requires full restart | Gatekeeper (deterministic) |

### 7.2 Forward-Only Security Monotonicity

**The security state can never decrease.** Once a containment stage is reached, the system can only advance to a higher stage or resolve the issue. It cannot silently drop back to a lower stage without explicit Arbiter resolution or human intervention.

This prevents:
- **Rollback exploitation** (V-H13): Attacker cannot trigger rollback to bypass a containment action
- **Oscillation attacks**: Attacker cannot rapidly trigger/resolve anomalies to create monitoring blind spots
- **Fatigue attacks**: System cannot be trained to ignore repeated warnings

---

## 8. Four Deployment Security Levels

| Level | Name | Configuration | Trust Guarantee | Target Use |
|-------|------|--------------|----------------|------------|
| **SL-1** | **Standard** | Single container. 5 enclaves as threads. Watchdog timer. | Single-node integrity. No redundancy. Restart on failure (<1s with Firecracker). | Development, testing, low-risk workloads |
| **SL-2** | **Resilient** | Active-passive pair. Heartbeat monitoring. <100ms failover. | Crash fault tolerance. Survives single node failure. | Production, medium-risk workloads |
| **SL-3** | **Verified** | 2-of-3 consensus. Gatekeeper decisions require majority agreement. | Crash + omission fault tolerance. Survives one node crash or network partition. | High-risk workloads, regulated environments |
| **SL-4** | **Byzantine** | 3-of-4 BFT consensus. Tolerates one actively malicious node. | Byzantine fault tolerance. Survives one compromised guardian. | Critical infrastructure, military/government, environments where the guardian itself may be targeted |

**Architecture constraint**: All four levels use the same binary. The deployment manifest selects the security level. No code changes between levels — only configuration.

**EU AI Act alignment**: SL-1 maps to low-risk AI. SL-2 to limited-risk. SL-3 to high-risk. SL-4 to unacceptable-risk-adjacent systems that require maximum assurance.

---

## 9. Formal Verification Commitment

### 9.1 What We Verify

The **Gatekeeper** is the formal verification target. It is the only component that makes enforcement decisions. If the Gatekeeper is proven correct, the system's enforcement guarantees are mathematical, not probabilistic.

### 9.2 How We Verify

| Step | Action | Tool |
|------|--------|------|
| 1 | Write Gatekeeper policy evaluation logic in a **verifiable subset of Rust** (no unsafe, no dynamic dispatch, no unbounded loops, no floating-point) | Rust (restricted subset) |
| 2 | Extract the logic to **Lean 4** formal specification | Manual extraction + automated translation |
| 3 | State correctness properties: "For all valid inputs, the Gatekeeper produces the correct verdict according to the policy specification" | Lean 4 theorem |
| 4 | **Prove** the properties hold for all inputs | Lean 4 proof assistant |
| 5 | Verify that the Rust implementation matches the Lean 4 specification (bisimulation or refinement proof) | Lean 4 + Rust verification tooling |

### 9.3 What This Gives Us

- **Mathematical guarantee**: The Gatekeeper correctly enforces its policy for all possible inputs. Not "we tested 10 million cases and they all passed" — "we proved it for the infinite set of all possible inputs."
- **First-of-kind**: No AI security system has formal verification. seL4 has it for kernels. VeriGuard has it for code generation. We would be the first for security policy enforcement.
- **Regulatory advantage**: EU AI Act Article 15 requires "accuracy and robustness." A formal proof is the strongest possible evidence of robustness.

### 9.4 Architectural Constraints This Imposes

The Gatekeeper must be written under these constraints to remain formally verifiable:
- **No dynamic dispatch** (no trait objects, no function pointers)
- **No unbounded loops** (all loops have provable termination bounds)
- **No floating-point arithmetic** (non-deterministic across platforms)
- **No runtime policy loading** (policies compiled into the binary as decision trees)
- **No heap allocation in the hot path** (stack-only evaluation for determinism)
- **No unsafe Rust** (safety invariants must be compiler-checked)

These constraints make the Gatekeeper less flexible but provably correct. Flexibility lives in the Arbiter (pluggable, not verified). Correctness lives in the Gatekeeper (rigid, verified).

---

## 10. External API Surface

The Guardian Mesh exposes exactly **four endpoints** — three internal (unix socket) and one external (gRPC through Protocol Firewall):

### 10.1 Internal Endpoints (Unix Socket)

```rust
// Evaluation — the primary function
fn evaluate(action: ActionDescriptor) -> Verdict;

// Audit query — retrieve proof for a past decision
fn audit_proof(decision_id: DecisionId) -> CryptographicProof;

// Health — system status
fn heartbeat() -> HealthStatus;

// Secret derivation — request a derived token from the Vault
fn derive_token(purpose: TokenPurpose, scope: Scope, ttl: Duration) -> DerivedToken;
```

### 10.2 External Endpoint (gRPC via Protocol Firewall)

```protobuf
service GuardianMesh {
  // Evaluate an agent action against security policy
  rpc Evaluate (EvaluateRequest) returns (EvaluateResponse);
  
  // Verify an audit proof
  rpc VerifyProof (VerifyProofRequest) returns (VerifyProofResponse);
  
  // Health check
  rpc Health (HealthRequest) returns (HealthResponse);
}

// No streaming RPCs (reduces complexity and attack surface)
// No reflection service (prevents schema discovery by attackers)
// No server-side status codes beyond OK, INVALID_ARGUMENT, INTERNAL, UNAVAILABLE
```

### 10.3 What We Do NOT Expose

- **No configuration API.** System is configured at build time.
- **No management interface.** No admin panel, no dashboard, no REST API.
- **No telemetry export.** Sentinel observations stay internal. External monitoring reads the Witness audit chain.
- **No policy update API.** Policy changes require a new binary (rebuild + redeploy).
- **No secret management API.** The Vault has no external interface. Secrets are provisioned at build time or boot time only.

---

## 11. Regulatory Compliance Mapping

### 11.1 EU AI Act Alignment

| EU AI Act Requirement | Article | Guardian Mesh Component | How It's Satisfied |
|-----------------------|---------|------------------------|-------------------|
| Risk management system | Art. 9 | Sentinel + Gatekeeper + Graduated Containment | Continuous risk identification (Sentinel), deterministic mitigation (Gatekeeper), proportional response (6-stage containment) |
| Data governance | Art. 10 | Credential Vault + Sealed Policy Store | Secrets isolated in hardware-bound Vault. Policy encrypted at rest. No data leakage between enclaves. |
| Technical documentation | Art. 11 | This document + formal specification | Architecture, threat model, and formal proofs constitute technical documentation. |
| Record-keeping | Art. 12 | Witness (Blake3 audit chain + external Merkle anchoring) | Every decision cryptographically recorded. Tamper-evident. Externally verifiable. |
| Transparency | Art. 13 | FOSS codebase + reproducible builds + Witness audit chain | Code is open. Builds are reproducible. Decisions are auditable. |
| Human oversight | Art. 14 | Arbiter (HumanOnlyArbiter backend) + Graduated Containment escalation | Conflicts escalate to human. HumanOnlyArbiter mode ensures zero autonomous decisions on conflicts. |
| Accuracy & robustness | Art. 15 | Formal verification of Gatekeeper + 8-layer defense-in-depth | Mathematical proof of correctness (strongest possible accuracy evidence) + defense-in-depth (robustness). |

### 11.2 Chinese CAC/NDRC/MIIT Alignment (May 2026 Guidelines)

| Chinese Requirement | Guardian Mesh Component | How It's Satisfied |
|--------------------|------------------------|-------------------|
| Behavior fencing (行为围栏) | Gatekeeper (deterministic policy enforcement) | Gatekeeper implements behavioral boundaries as compiled decision trees. |
| Blockchain-based traceability | Witness (external Merkle root anchoring) | Periodic Merkle root publication to external immutable store provides blockchain-equivalent traceability. |
| Decision-making boundaries (user-only, user-authorized, autonomous) | Arbiter (pluggable backends from HumanOnly to RuleArbiter) | Deployment security level + Arbiter backend selection maps directly to the three decision categories. |
| Safety assessment systems | Sentinel + Graduated Containment | Continuous behavioral assessment (Sentinel) with proportional response (containment stages). |
| Supply chain security | Container image integrity (Cosign + reproducible builds) | Every binary is signed, content-addressable, and independently reproducible from source. |

---

## 12. Risks, Limitations & Open Problems

### 12.1 Honest Limitations

| Limitation | Explanation | Mitigation Path |
|------------|-------------|-----------------|
| **Cold start trust** | Initial secrets must be provisioned from somewhere. This is fundamentally unsolvable without hardware trust. | TPM/HSM where available. Argon2id KDF from passphrase where not. Reproducible builds as secondary trust anchor. Multiple independent verification paths. |
| **Performance overhead** | Every action passes through 5 enclaves with cryptographic signing/verification. Estimated 5-15ms per decision. | Fast-path for pre-approved action types (cached capability tokens skip full evaluation). Batch evaluation for low-risk action classes. |
| **Policy expressiveness** | Deterministic Gatekeeper cannot handle novel, unseen attack patterns. | Sentinel flags anomalies. Arbiter handles ambiguity. The system explicitly trades flexibility for correctness. |
| **Update mechanism** | Immutable container = no hot-patching. Policy updates require rebuild + redeploy. | Blue-green deployment with zero-downtime rotation. Version-pinned policy with signed update manifests. |
| **Semantic gap** | Guardian sees action descriptors and context hashes — not raw content. Cannot make content-aware decisions. | Content inspection happens before the Guardian, in a separate disposable analysis sandbox. Guardian evaluates typed signals, not raw content. |
| **ATTP immaturity** | ATTP is a May 2026 Internet-Draft. It may change significantly before standardization. | Implement behind the ATTP Adapter abstraction. If ATTP changes, only the adapter changes — internal protocol is unaffected. |
| **Formal verification scope** | Only the Gatekeeper is formally verified. Other enclaves rely on testing + isolation. | Gatekeeper is the enforcement bottleneck — if it's correct, enforcement is correct. Other enclaves are defense-in-depth, not the primary guarantee. |
| **Vault as single point of secret access** | If the Vault is compromised, all secret operations are compromised. | Vault has the smallest code surface of any enclave (secret storage + derivation only). Smallest attack surface. Hardware binding when available. |

### 12.2 Open Research Questions

1. **Can the Arbiter be formally verified with a pluggable backend?** If the backend is deterministic (RuleArbiter), yes. If probabilistic (CAIArbiter), the backend is unverified but the interface contract can be verified.
2. **What is the optimal Merkle root anchoring interval?** Too frequent = overhead. Too infrequent = window for audit manipulation. Needs empirical study.
3. **How does the 5-enclave model perform under BFT consensus?** Each node runs 5 enclaves, and 4 nodes must agree. That's 20 enclave instances. Is the communication overhead manageable?
4. **Can ATTP trust levels map cleanly to our deployment security levels?** Preliminary analysis suggests SL-1 = ATTP Trust Level 1-2, SL-4 = ATTP Trust Level 5. Needs formal mapping.

---

## 13. FOSS Viability & Implementation Plan

| Factor | Decision | Rationale |
|--------|----------|-----------|
| **Language** | Rust | Memory safety, no GC, formal verification potential, industry trend (aaOS, Capsule) |
| **Crypto library** | ring + pqcrypto-rs | ring for classical (audited, battle-tested). pqcrypto-rs for PQC (NIST reference implementations in Rust). |
| **Hash** | Blake3 (keyed mode) | Quantum-resistant. 3.5 GB/s. Keyed mode replaces HMAC. |
| **Serialization** | Protobuf (proto3, hardened) | Strict schema. No unknown fields. Fuzz-tested. |
| **IPC** | Abstract unix domain sockets | No filesystem. No network. Minimal syscall surface. |
| **Build system** | Nix | Reproducible builds. Anyone can verify. |
| **Container** | OCI (distroless base) | Platform-agnostic. ~5MB. |
| **Signing** | Cosign (Sigstore) | Transparent, auditable release pipeline. |
| **License** | Apache-2.0 | Permissive. Enterprise-friendly. Patent grant. |
| **Formal verification** | Lean 4 | Modern proof assistant. Active community. Good Rust interop tooling. |
| **Fuzzing** | AFL++ / libFuzzer / cargo-fuzz | Industry-standard. Integrated into CI. |
| **CI/CD** | GitHub Actions | Open, auditable pipeline. |

### 13.1 Implementation Phases

| Phase | Scope | Deliverable | Duration |
|-------|-------|-------------|----------|
| **P0: Specification** | Formal spec of Handshake Protocol, Gatekeeper policy language, Vault interface | Published specification document (no code) | 4 weeks |
| **P1: Gatekeeper + Vault** | Deterministic rule evaluator + secret store. Minimal viable guardian. | Single binary, 2 enclaves, unix socket API | 6 weeks |
| **P2: Sentinel + Witness** | Observation layer + audit chain. Full 4-enclave system. | Blake3 audit chain, anomaly detection, external anchoring | 6 weeks |
| **P3: Arbiter + Containment** | Conflict resolution + graduated containment. Full 5-enclave system. | Pluggable Arbiter, 6-stage containment, SL-1 deployment | 4 weeks |
| **P4: ATTP Adapter** | External interoperability. Protocol Firewall + gRPC endpoint. | ATTP-compatible external interface with full hardening | 4 weeks |
| **P5: Formal Verification** | Lean 4 extraction + proof of Gatekeeper correctness. | Mathematical proof of enforcement correctness | 8 weeks |
| **P6: BFT + SL-4** | Multi-node consensus. Full security level support. | BFT deployment mode, all 4 security levels | 6 weeks |
| **P7: Red Team + Release** | Adversarial testing against all threat vectors (V-C1 through V-AI11). | v1.0 release with security audit report | 4 weeks |

**Total estimated timeline: ~42 weeks (10 months)**

---

## 14. Revision History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2026-05-14 | Initial conversational draft. 4 enclaves, basic Handshake Protocol. |
| 2.0 | 2026-05-14 | Major revision incorporating global security research. Added 5th enclave (Credential Vault). Redesigned Handshake Protocol for ATTP compatibility with hardened boundaries. Added Protocol Firewall. Pluggable Arbiter. External Merkle anchoring for Witness. Biological immune model for containment (6 stages). Four deployment security levels. Formal verification commitment. Standards Interface Hardening Policy. Regulatory compliance mapping (EU AI Act + Chinese CAC). Complete reference architecture. |

---

*End of Document*
