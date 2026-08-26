# Security Policy

## Supported versions

Only the latest `main` and the most recent `release/v<N>` tag receive security
patches. Prior releases are archived in `releases/archive/` for reference but
are not patched.

## Reporting a vulnerability

Please report security vulnerabilities privately to the maintainers by opening
a **draft security advisory** on GitHub
(Repository → Security → Advisories → New advisory), or by email to the
maintainer account (`nrupalakolkar@gmail.com`).

Do **not** open a public issue for a security vulnerability.

## Response

We aim to:

- Acknowledge receipt within **48 hours**.
- Provide a fix timeline within **5 business days**.
- Ship a patched release and tag it `release/v<N>`.

## Security posture

Guardian Mesh is a security product; cryptographic handling is deliberate:

- Signatures/keys use **ML-DSA-65** (FIPS 204).
- Integrity uses **CRC32C**; audit digests use **SHA-256**.
- Sessions are authenticated with **HMAC-SHA256** over a rotating handshake key.
- The gRPC daemon serves **plaintext by default** — terminate TLS/mTLS in
  front of it for any real deployment, and set a strong
  `GUARDIAN_MESH_HANDSHAKE_SECRET`.

## Supported versions

| Version | Supported |
|---------|-----------|
| latest `main` | ✅ |
| latest `release/v<N>` | ✅ |
| older releases | ❌ (archived only) |