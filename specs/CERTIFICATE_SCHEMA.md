# Guardian Mesh Certificate Schema v1

**Status:** Implemented (v0.8.0)  
**Work Order:** WO-6 / GMSI-1  
**Updated:** 2026-10-19

This document defines the Guardian Mesh certificate schema version 1, which binds release evidence to gate verdicts under the daemon's cryptographic signature.

## Overview

A Guardian Mesh certificate is a **sealed envelope** (the existing `SealedEnvelope` wire format) carrying a structured certificate body as its payload. The certificate attests to the binding between:

- A specific release artifact (identified by its evidence hash)
- A gate verdict issued over that evidence
- The policy (gate version) and test results presented at issuance
- The issuing daemon's identity (its signing key fingerprint)
- The issuance timestamp

The certificate format is **self-contained**: all fields needed to verify a certificate travel inside the sealed envelope, so any holder can present a certificate to a second Guardian Mesh instance for independent re-verification via the existing `VerifyProof` RPC.

## Wire Format

A certificate is a `SealedEnvelope` with:

- **`payloadType`**: `guardian_mesh.Certificate` (as bytes)
- **`payload`**: the certificate body as canonical JSON bytes (see Body Schema below)
- **`ml_dsa_65_signature`**: ML-DSA-65 signature over `crc32c || payload`, signed by the daemon's persistent signing key (the WO-3 identity)
- **`crc32c`**: CRC32C digest of the payload
- **`timestamp`**: issuance timestamp (Unix nanoseconds)
- **`nonce`**: 32-byte random nonce

All other `SealedEnvelope` fields follow the existing specification. The signature is produced through the daemon's standard sealing path (the same mechanism that verdict proofs use).

## Body Schema

The certificate body is a JSON object with the following fields (in canonical order for signing):

```json
{
  "schema": "guardian-mesh/certificate",
  "schema_version": 1,
  "serial": "<unique-serial>",
  "issuer": "<daemon-signing-key-fingerprint>",
  "product": "<product-name>",
  "version": "<product-version>",
  "verdict": "PASS" | "PASS WITH FINDINGS",
  "evidence_hash": "<sha256-hex>",
  "evidence_scope": "working-tree" | "full-history",
  "tests": {
    "passed": <count>,
    "failed": <count>,
    "total": <count>
  },
  "policy": "<gate-version-string>",
  "pf_outcomes": null,
  "issued_at": <unix-seconds>,
  "supersedes": "<serial>" | null
}
```

### Field Definitions

- **`schema`**: Fixed string `"guardian-mesh/certificate"` identifying this document type.
- **`schema_version`**: Integer `1` for this version of the schema.
- **`serial`**: A unique, persistent certificate identifier assigned by the issuing daemon. Serials are unique across the daemon's lifetime and survive restarts.
- **`issuer`**: The daemon's signing-key fingerprint (lowercase hex SHA-256 of the daemon's ML-DSA-65 public key). This is the WO-3 identity; a certificate verifies only against the issuer named in this field.
- **`product`**: The product name (as provided by the presenter at issuance).
- **`version`**: The product version (as provided by the presenter at issuance).
- **`verdict`**: The gate verdict being certified. Must be one of:
  - `"PASS"`: the gate allowed issuance with no findings
  - `"PASS WITH FINDINGS"`: the gate allowed issuance but recorded findings
  - Verdicts other than these two values (e.g., `"BLOCKED"`) do NOT result in issuance.
- **`evidence_hash`**: Lowercase hex SHA-256 of the evidence bytes presented at issuance. The daemon recomputes this hash over the presented evidence and refuses issuance if it does not match the claimed hash (GMSI-2: hash-verifiable handoff).
- **`evidence_scope`**: The scope of evidence covered by the `evidence_hash`:
  - `"working-tree"`: only the working tree was scanned
  - `"full-history"`: the full git history was scanned (GMSI-5)
- **`tests`**: Test counts as declared by the presenter:
  - **`passed`**: number of tests that passed
  - **`failed`**: number of tests that failed
  - **`total`**: total number of tests run (`passed + failed` in most cases)
- **`policy`**: The gate version string (e.g., `"gate-v1.2.0"`) naming the policy under which the verdict was issued.
- **`pf_outcomes`**: OPTIONAL in v1. Reserved for GMSI-7 (measured per-rule Protocol Firewall outcomes once WO-19 lands). Until then, this field is `null` and MUST NOT carry placeholder or constant values. Future versions will populate this field with the daemon's measured PF pass/fail counts at issuance time.
- **`issued_at`**: Issuance timestamp as Unix seconds (not nanoseconds; this is a coarser-grained timestamp than the envelope's `timestamp` field).
- **`supersedes`**: The serial of the certificate this one supersedes, or `null` if this is the first certificate for the product. When a new certificate is issued for a product, the previous ACTIVE certificate's serial is recorded here, and that certificate's status transitions to SUPERSEDED.

### Certificate Fingerprint

The **certificate fingerprint** is the lowercase hex SHA-256 hash of the exact sealed payload bytes (the canonical JSON certificate body as serialized). The fingerprint is **NOT a field inside the sealed payload itself**; instead, it is:

- Returned in the `IssueCertificate` response alongside the sealed envelope
- Stored in the certificate registry record
- Included in the `CertificateStatus` response body as a derived field

This design ensures that any holder can recompute the fingerprint by hashing the exact payload bytes of the presented sealed envelope and comparing it to the fingerprint presented alongside the envelope (GMSI-2: the copy presented is byte-identical to the copy at mint).

## Honesty Clauses

The certificate certifies the **binding**, not the truth of all declarations:

1. **The daemon vouches for**:
   - The evidence hash match at issuance (the daemon recomputes SHA-256 over the presented evidence and refuses issuance on mismatch)
   - The signature (the certificate is sealed with the daemon's persistent signing key)
   - The lifecycle state transitions it performed (issuance, supersession, revocation)
   - The issuer identity (the `issuer` field equals the daemon's own signing-key fingerprint)

2. **The daemon does NOT vouch for**:
   - The truth of the `scope`, `tests`, or `policy` declarations — these are **the presenter's claims**, bound under the daemon's signature. The certificate attests that the presenter declared these values at issuance time, not that they are accurate.
   - Deployment choices, runtime behavior, or operational posture — the certificate warrants only the exact artifact tested (identified by `evidence_hash`), against the policy named (`policy`), on the date stamped (`issued_at`).

A certificate is not a warranty of the code's quality, fitness, or security. It is a tamper-evident record of what the gate computed for a specific evidence pack at a specific time.

## Lifecycle

Certificates have a lifecycle managed by the issuing daemon:

### States

- **ACTIVE**: the certificate is the current, valid certificate for the product+version. At most one certificate per product+version is ACTIVE at any given time.
- **SUPERSEDED**: a newer certificate was issued for the product (any version), and this certificate is no longer the current one. The newer certificate's `supersedes` field points to this certificate's serial.
- **REVOKED**: the certificate was explicitly revoked (via `RevokeCertificate`) or automatically revoked because a gate verdict of `BLOCKED` was issued for the product+version.
- **UNKNOWN**: the serial is not found in the registry (never issued, or the registry was lost).

### Events

1. **Issuance** (`IssueCertificate` RPC):
   - Input: product, version, verdict, evidence bytes, evidence_hash (claimed), evidence_scope, tests, policy.
   - Rules (all enforced in the daemon, fail-closed):
     - The daemon computes SHA-256 over the presented evidence bytes. If it does not match `evidence_hash`, issuance is refused (nothing is recorded).
     - Evidence size cap: **10 MB**. Evidence packs larger than this are refused with a clear error. (This cap is separate from the 64 KiB `SealedEnvelope` size cap, which applies to envelopes, not to evidence documents.)
     - `verdict == "BLOCKED"`: NO issuance. If an ACTIVE certificate exists for that product+version, it is REVOKED (status → REVOKED in the registry, event appended to the audit log), and the refusal message states that revocation occurred.
     - `verdict == "PASS"` or `verdict == "PASS WITH FINDINGS"`: issue the certificate. Assign a unique serial (persistent across restarts), build the body, seal it, persist the registry record as ACTIVE, append the issuance event to the audit log. Any previously ACTIVE certificate for the product (any version, including the same version if reissued) becomes SUPERSEDED (status → SUPERSEDED, `superseded_by` points to the new serial). The new certificate's `supersedes` field names the old serial.
     - Any other verdict string: refusal (clear error, nothing recorded).
   - Output: the sealed certificate envelope, the serial, and the fingerprint.

2. **Supersession**:
   - Happens automatically during issuance. When a new certificate is issued for a product, the product's previously ACTIVE certificate (if any) transitions to SUPERSEDED. The new certificate records the superseded serial in its `supersedes` field.
   - Only one certificate per product is ACTIVE at a time (across all versions). Issuing a certificate for `myapp v2.0` supersedes the ACTIVE certificate for `myapp v1.0`.

3. **Revocation** (`RevokeCertificate` RPC):
   - Explicit revocation: operator calls `RevokeCertificate(serial, reason)`. If the serial is ACTIVE, status → REVOKED, event appended to the audit log. Unknown serials return an error.
   - Automatic revocation: a `BLOCKED` verdict during issuance revokes any ACTIVE certificate for that product+version (see Issuance above).

4. **Status Query** (`CertificateStatus` RPC):
   - Input: serial.
   - Output: status (ACTIVE | SUPERSEDED | REVOKED | UNKNOWN) and the stored body fields for known serials.

### Registry Persistence

The certificate registry persists under the daemon's workspace directory (following the WO-3 persistence pattern for keys). The registry survives daemon restarts. Certificate issuance uses the daemon's persistent signing key (WO-3), so certificates issued across restarts verify against the same public key (and thus the same `issuer` fingerprint).

All lifecycle events (issuance, supersession, revocation) are appended to the daemon's hash-chained audit log (the WO-4/WO-6 audit trail). Each event records the serial, the product+version, the event type, and the reason (if applicable).

## v1 Trust Posture

**Issuance is a daemon-local operation.** The daemon binds to localhost (or sits behind an authenticated access control layer, as the production deployment does). There is no public issuance endpoint in v1. The trust model is:

- The daemon runs on an operator-controlled host.
- The operator (or an agent acting on their behalf, with appropriate authorization) calls `IssueCertificate` with the evidence pack and metadata.
- The daemon verifies the evidence hash match and issues the certificate.
- The issued certificate can be presented to **any** Guardian Mesh daemon for verification via `VerifyProof` (the certificate is self-contained).

Future versions may introduce multi-daemon issuance (BFT consensus, TEE attestation), external anchoring, or certificate transparency logs. v1 does not include these features.

## Verification

A certificate holder verifies a certificate by:

1. **Re-verify the signature**: Present the sealed envelope to the `VerifyProof` RPC of any Guardian Mesh daemon (not necessarily the issuer). The daemon verifies the ML-DSA-65 signature against the `issuer` public key (which the holder can fetch from the issuer's `Health` RPC or obtain out-of-band).
2. **Recompute the fingerprint**: Compute SHA-256 over the exact payload bytes of the presented envelope and verify it matches the fingerprint presented alongside the envelope (e.g., from the `IssueCertificate` response or the `CertificateStatus` response). This proves the copy presented is byte-identical to the copy issued (GMSI-2).
3. **Check the lifecycle status**: Query the issuer's `CertificateStatus(serial)` RPC to verify the certificate is ACTIVE (not SUPERSEDED or REVOKED).

A certificate that passes all three checks is valid. A certificate that fails any check (signature invalid, fingerprint mismatch, status REVOKED) is invalid.

## Example Certificate Body

```json
{
  "schema": "guardian-mesh/certificate",
  "schema_version": 1,
  "serial": "cert-20261019-000001",
  "issuer": "dd2cf1a350e0b31c30fcf0db2d1dd73ade7487af08385ddce6b99e7d1f40a8c9",
  "product": "guardian-mesh",
  "version": "0.8.0",
  "verdict": "PASS WITH FINDINGS",
  "evidence_hash": "a3f2b8c4d1e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1",
  "evidence_scope": "full-history",
  "tests": {
    "passed": 85,
    "failed": 0,
    "total": 85
  },
  "policy": "gate-v1.0.0",
  "pf_outcomes": null,
  "issued_at": 1729372800,
  "supersedes": "cert-20261018-000023"
}
```

## Version History

- **v1** (2026-10-19, WO-6): Initial schema. `pf_outcomes` reserved but not populated.
