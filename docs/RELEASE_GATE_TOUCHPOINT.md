<!-- Copyright (c) 2026 Nrupal Akolkar -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Release Gate Touchpoint (WO-37 / T1) — Operator Protocol

Guardian Mesh v0.28.0 wires T1, the release gate, through `gm certificate`. This
document is the protocol a release-gate operator follows. The lifecycle rules
and field definitions are in [CERTIFICATE_SCHEMA](../specs/CERTIFICATE_SCHEMA.md);
the CLI surface is in [CLI](CLI.md).

## 1. Run the release gate

Run the release gate against the artifact being released. The gate verdict is
the decision of record. A gate that cannot run is NOT RUN, never PASS; no
certificate may be claimed for a release without a gate verdict.

## 2. Present the gate evidence pack to the production daemon

```bash
gm certificate issue \
  --product <product> \
  --version <version> \
  --verdict "<verdict>" \
  --evidence-file <gate-pack-file> \
  --evidence-scope <working-tree|full-history> \
  --tests-passed <n> \
  --tests-failed <n> \
  --policy <gate-version> \
  --cert-out <file>
```

The CLI reads the evidence file and computes its SHA-256 itself; the operator
never types a hash. A BLOCKED verdict issues nothing and revokes any ACTIVE
certificate for that product+version daemon-side. No certificate means no
"certified" claim may be made — fail closed.

Exit 0 with `"issued": true` means a certificate was written to the cert file.
Exit 1 with `"issued": false` means the daemon refused, and the refusal reason
is the answer: nothing was written, and an existing ACTIVE certificate for that
product+version has been revoked if the verdict was BLOCKED. Exit 2 means
usage, evidence-file or transport failure; nothing was issued.

## 3. Verify the proof independently

```bash
gm certificate verify --cert-file <file> --endpoint <second-daemon>
```

Verify against a second daemon instance or a separate client — never only the
instance that issued the certificate. `"valid": true` (exit 0) is required
before the release record may cite the certificate. An invalid proof (exit 1)
or an unreachable verifier (exit 2) means the certificate cannot be cited.

## 4. Cite the certificate and keep its state current

Cite the serial and fingerprint in the release record (PR / CHANGELOG). Check
the lifecycle state at any time:

```bash
gm certificate status --serial <serial>
```

Withdraw a verdict by revoking the certificate:

```bash
gm certificate revoke --serial <serial> --reason "<reason>"
```

## Honesty box

The certificate binds the presenter's declarations — product, version, verdict,
test counts, policy and evidence scope — to the evidence hash under the daemon's
signature. Per [CERTIFICATE_SCHEMA](../specs/CERTIFICATE_SCHEMA.md), it
certifies the binding, not the truth of the declarations, and it is not a
warranty of quality or security.

First exercise: Guardian Mesh v0.28.0's own release (this WO) is the first
release certified through this CLI path. Earlier releases used per-run ad-hoc
wire clients and are not retroactively re-issued.
