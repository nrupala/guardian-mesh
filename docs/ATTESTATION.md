# Guardian Mesh Attestation — Public Verification Instructions

Guardian Mesh releases are signed and reproducible. Every release publishes:
- A binary (e.g., `guardian-meshd`)
- An attestation package (e.g., `guardian-meshd-v0.13.0.attestation.json`)

A tenant can verify the running daemon is the attested build before trusting its first verdict.

## Verification workflow

### 1. Obtain the release artifacts

Download the daemon binary and its `.attestation.json` file from the release page.

### 2. Build or download `gm-attest`

The `gm-attest` CLI is included in the Guardian Mesh repository:

```bash
cd guardian-mesh-work/wo13/guardian-meshd
cargo build --release --bin gm-attest
# Binary: target/release/gm-attest
```

Alternatively, download a pre-built `gm-attest` binary from the release page (if published).

### 3. Verify the attestation

Run:

```bash
gm-attest verify --package guardian-meshd-v0.13.0.attestation.json --binary guardian-meshd
```

If the attestation is valid, you will see:

```
ATTESTATION VALID
Fingerprint: <sha256-hex>
```

Exit code 0 means the binary matches the attested build and the signature is valid. Exit code 1 means the attestation is invalid (reason printed).

### 4. Compare with the running daemon

Connect to the daemon's Health endpoint and read the `build_commit`, `build_version`, and `binary_sha256` fields:

```bash
grpcurl -plaintext localhost:50051 guardian_mesh.GuardianMesh/Health
```

Example response:

```json
{
  "status": "SERVING",
  "build_version": "0.13.0",
  "build_commit": "abc123def456...",
  "binary_sha256": "7a8b9c0d1e2f3..."
}
```

**Before trusting a first verdict**, compare:
- `binary_sha256` from Health matches the attestation package's `subject_sha256`
- `build_commit` from Health matches the attestation package's `git_commit`
- `build_version` from Health matches the attestation package's `version`

If all three match, the running daemon is the attested build.

### 5. (Optional) Reproduce the build

To verify reproducibility, clone the repository at the attested commit and run:

```bash
git checkout <build_commit>
./scripts/reproducible-build.sh
```

The script builds the daemon twice in separate temporary directories with the same `SOURCE_DATE_EPOCH` and path remapping. If both builds produce identical SHA-256 hashes, the build is reproducible.

Exit code 0 means reproducible. Exit code 1 means the builds differ.

## Attestation package contents

An attestation package is a JSON file containing:

- `statement`: The provenance statement (in-toto / SLSA v1 structure)
  - `statement_type`: `"https://in-toto.io/Statement/v1"`
  - `subject_name`: `"guardian-meshd"`
  - `subject_sha256`: SHA-256 of the binary (lowercase hex)
  - `predicate_type`: `"https://slsa.dev/provenance/v1"`
  - `build_type`: Build system URI (e.g., `https://guardian-mesh.aimlds.org/build/cargo/v1` for native builds, `.../cargo-zigbuild/v1` for cross-compilation)
  - `builder_id`: `"guardian-mesh release pipeline"`
  - `invocation_id`: Release run identifier
  - `git_commit`: Full commit hash the binary was built from
  - `version`: Daemon crate version (e.g., `"0.13.0"`)
  - `target_triple`: Rust target triple (e.g., `"x86_64-unknown-linux-gnu"`)
  - `toolchain`: Toolchain version (e.g., `"rustc 1.75.0"`)
  - `source_date_epoch`: Unix timestamp of the commit (for reproducibility)
  - `cargo_lock_sha256`: SHA-256 of `Cargo.lock` at build time
  - `build_command`: The exact reproducible build command
- `fingerprint`: SHA-256 of the canonical JSON serialization of `statement`
- `signer_fingerprint`: SHA-256 fingerprint of the daemon signing key (ML-DSA-65 public key)
- `verifying_key_hex`: Hex-encoded ML-DSA-65 verifying key (1952 bytes)
- `envelope_b64`: Base64-encoded sealed envelope containing the signed statement

The signature uses ML-DSA-65 (post-quantum lattice signature). The `gm-attest verify` command reconstructs the canonical JSON, recomputes all fingerprints, parses the sealed envelope, verifies the signature, and checks all fields against the binary.

## HONESTY BOUNDARY

**What this attestation provides:**

- **Signed provenance** (builder-signed, published per release): The release pipeline signs the build, asserting it was built from a specific commit, with specific dependencies, at a specific time.
- **Reproducibility**: Any party can rebuild the binary from the attested source and verify the hash matches (subject to toolchain availability and determinism).
- **Daemon build identity in Health**: The running daemon reports its binary SHA-256 and build commit so a tenant can compare them with the attestation before trusting verdicts.
- **SLSA L2-style assurance**: The build is signed by a known key, the provenance is published, and the build can be reproduced from public sources.

**What this attestation does NOT (yet) provide:**

- **SLSA L3+ isolated build environment**: The release pipeline is not (yet) a hermetic, third-party-hosted builder. The build happens in the maintainer's environment. An attacker with access to the release pipeline can tamper with the build.
- **Transparency log**: The attestation is published alongside the release but not submitted to a public transparency log (e.g., sigstore). There is no global append-only log of all Guardian Mesh releases.
- **TPM measured boot / platform attestation**: The daemon does not (yet) report a TPM PCR or other hardware root-of-trust measurement. A compromised OS or bootloader can replace the binary after boot.
- **Binary signature verification by the OS**: The daemon binary is signed (via the attestation package), but the OS does not enforce signature verification at load time (unless the operator configures it, e.g., via IMA/EVM on Linux).

**Specification status after WO-13:**

- **CP-19** (Signed, reproducible builds with provenance): [PARTIAL] — v1 ships builder-signed provenance and reproducible builds; SLSA L3 (hermetic builder, non-falsifiable provenance) remains target.
- **CP-21** (Guardian itself is attested before trust): [PARTIAL] — Health exposes build identity; tenants can verify the binary matches the attestation; measured boot / TPM attestation remains target.
- **DC-17** (Releases signed and reproducible, tenants verify before first verdict): [PARTIAL] — WO-13 v1 ships signed provenance + Health build identity; measured boot / trust-bundle publication remain target.

**Recommended workflow:**

1. Download the release binary and attestation from a trusted channel (HTTPS, verify TLS certificate).
2. Run `gm-attest verify` against the binary and attestation.
3. Query the daemon's Health endpoint after deployment.
4. Compare `binary_sha256` and `build_commit` from Health with the attestation's `subject_sha256` and `git_commit` before trusting the first verdict.
5. (Optional) Reproduce the build yourself to verify the published hash is correct.

This workflow allows a stranger to verify a release's provenance from public artifacts alone, fulfilling the compliance plan §3.2 acceptance criteria.

## Further reading

- Spec: `specs/GUARDIAN_MESH_REVISED_SPEC.md` §6.8 (DC-17), §3.6 (CP-19, CP-21)
- SLSA provenance: [https://slsa.dev/](https://slsa.dev/)
- in-toto: [https://in-toto.io/](https://in-toto.io/)
- Reproducible builds: [https://reproducible-builds.org/](https://reproducible-builds.org/)
