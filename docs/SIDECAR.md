# Sidecar Form (WO-18 profile 1 / DP-3)

Guardian Mesh v0.17.0 adds WO-18 profile 1: a container/sidecar form of the
existing daemon for orchestrated workloads (DP-3). The guardian runs beside the
workload in the same Pod (Kubernetes) or the same network namespace (Docker
Compose), and the workload calls it at `127.0.0.1:50051`.

This release claims only WO-18 profile 1. The edge profile (DP-6), CLI (CC-4)
and MCP surface (CC-5) are not part of it and remain target.

## What the sidecar form is

The sidecar is packaging, not a new enforcement mode. It is the same
single-node `guardian-meshd` binary, built into a minimal container image and
run as a non-root process next to the guarded workload. Both containers share
the Pod network namespace, so the workload reaches the guardian over loopback.

Nothing intercepts or redirects the workload's traffic. The workload must make
the handshake, evaluate, simulate, verify and audit calls itself.

## Build

Build from the repository root:

```bash
docker build -t guardian-mesh:0.17.0 .
```

The image is multi-stage: `rust:1-bookworm` builds the release binary (with
`protobuf-compiler` installed for the `tonic-prost-build` step), and
`debian:bookworm-slim` is the runtime. The runtime image contains no toolchain,
runs as the non-root user `guardian` (uid/gid 10001), and carries no secret.

To stamp the build with a commit, pass the optional build arg. If it is omitted,
`build.rs` falls back to git (absent in the image) and records `unknown`; the
Dockerfile does not fake a value.

```bash
docker build \
  --build-arg GUARDIAN_MESH_GIT_COMMIT="$(git rev-parse HEAD)" \
  -t guardian-mesh:0.17.0 .
```

`SOURCE_DATE_EPOCH` is also read by `build.rs` (build-time only, default `0`).

## Run standalone

The handshake secret is injected at run time, never baked into the image. Use a
named volume for `/data` so the signing key and hash-chained audit log survive
container restarts.

```bash
docker volume create guardian-data

docker run --rm \
  --name guardian-mesh \
  -p 127.0.0.1:50051:50051 \
  -v guardian-data:/data \
  -e GUARDIAN_MESH_HANDSHAKE_SECRET="$(cat /path/to/handshake-secret)" \
  guardian-mesh:0.17.0
```

The image's `WORKDIR` is `/app` on purpose: the daemon's program-dir guard
refuses to start when the workspace resolves inside the program directory, and
`/app` keeps the workspace under `/data` outside it.

## Docker Compose

The local example is in `deploy/sidecar/docker-compose.yaml`:

```bash
cd deploy/sidecar
docker compose up --build
```

The `workload-example` service uses `network_mode: "service:guardian-mesh"`,
which is the compose analogue of a Kubernetes sidecar: it shares the guardian's
network namespace and reaches it at `127.0.0.1:50051`. The `guardian-data` named
volume persists `/data`. The port is published on loopback for local development
only; in orchestration the sidecar is pod-local and needs no published port.

The compose file reads `GUARDIAN_MESH_HANDSHAKE_SECRET` from your shell or an
`.env` file and falls back to a clearly-placeholder value. Never commit a real
secret.

## Kubernetes

The example is in `deploy/sidecar/kubernetes.yaml` and contains a Deployment, a
PersistentVolumeClaim and a placeholder Secret in one file.

Recommended apply order:

1. Create the handshake Secret from your secret manager (the file contains a
   placeholder Secret only so the example is self-contained).
2. Apply the PersistentVolumeClaim `guardian-mesh-data`.
3. Apply the Deployment `guarded-workload-example`.

```bash
kubectl apply -f deploy/sidecar/kubernetes.yaml
```

There is no Service. A sidecar is pod-local: the workload reaches the guardian
at `127.0.0.1:50051` through the shared pod network namespace. The guardian
container runs as uid 10001, drops all capabilities, disallows privilege
escalation, and uses a read-only root filesystem; `/data` is the only write
path.

The PVC matters. The workspace holds the daemon signing key and the
hash-chained audit log. Losing it loses proof continuity (the WO-3 persistence
property): proofs issued before the loss can no longer be tied to the same key
and audit chain. `emptyDir` is acceptable for trials only, never for production.

The readiness and liveness probes are TCP probes. The daemon does not implement
the standard gRPC health service; its own `Health` RPC is the application-level
check. TCP probes only prove the listener is up.

## Configuration

These are the `GUARDIAN_MESH_*` variables the daemon actually reads at run time
(from `guardian-meshd/src/config.rs`), with the values the container image sets.
Unset variables use the daemon's built-in defaults.

| Variable | What it controls | Container default |
|---|---|---|
| `GUARDIAN_MESH_WORKSPACE` | Workspace directory: signing key, policy, sessions, revocation registry and hash-chained audit log. | `/data/workspace` |
| `GUARDIAN_MESH_OUTPUT` | Output directory for per-project evaluation artifacts. | `/data/output` |
| `GUARDIAN_MESH_BIND_ADDR` | Listener address. Use `0.0.0.0` in a container so the Pod/workload can connect. | `0.0.0.0` |
| `GUARDIAN_MESH_PORT` | Listener port. | `50051` |
| `GUARDIAN_MESH_HANDSHAKE_SECRET` | HMAC handshake secret. Inject at run time (environment or Secret). | Not set by the image; it carries no secret. If unset, the daemon falls back to its built-in development default - never rely on that. |
| `GUARDIAN_MESH_POLICY_THROTTLE_RATE` | Default policy/firewall rate limit. | `100` |
| `GUARDIAN_MESH_POLICY_ESCALATE_ACTIONS` | Comma-separated action types that require escalation. | Empty |
| `GUARDIAN_MESH_POLICY_ADMIN_KEYS_DIR` | Directory of administrator keys for policy changes. | Unset |
| `GUARDIAN_MESH_REVOCATION_BOUND_SECS` | DC-14 revocation propagation bound in seconds (`0` falls back to 60). | `60` |
| `GUARDIAN_MESH_SPIFFE_TRUST_DOMAINS` | Comma-separated SPIFFE trust domains accepted at handshake. | Empty |
| `GUARDIAN_MESH_REQUIRE_SPIFFE` | Require SPIFFE SVID attestation (`1`/`true`). | `false` |
| `GUARDIAN_MESH_PGP_ADMIN_KEYS_DIR` | Directory of OpenPGP administrator keys. | Unset |
| `GUARDIAN_MESH_TENANTS` | Comma-separated tenant ids to register (the default tenant is always present). | Empty |
| `GUARDIAN_MESH_TENANT_RATE_BUDGET` | Per-tenant rate budget per window. | Defaults to the policy throttle rate (`100`) |
| `GUARDIAN_MESH_TENANT_BUDGET_WINDOW_MS` | Tenant budget sliding window in milliseconds (positive values only). | `1000` |
| `GUARDIAN_MESH_NODE_ID` | Node identity reported by `Health` and in proofs. | Derived from the signing-key fingerprint |
| `GUARDIAN_MESH_DEGRADED` | Start in declared degraded mode (`1`/`true`). | `false` |
| `GUARDIAN_MESH_DEGRADED_SAFE_ACTIONS` | Comma-separated action types still allowed while degraded. | Empty |

Build-time only: `GUARDIAN_MESH_GIT_COMMIT` and `SOURCE_DATE_EPOCH` are read by
`guardian-meshd/build.rs` to stamp build identity. They are not runtime
configuration.

## How the workload calls the guardian

The workload is an ordinary Guardian Mesh client:

1. Handshake and obtain a session (HMAC handshake secret; optional SPIFFE/PGP
   factors depending on configuration).
2. Call `Evaluate` for real actions (or `Simulate` for a dry run) over gRPC or
   gRPC-web at `127.0.0.1:50051`.
3. Use `VerifyProof` to check sealed verdict proofs, and the audit/read RPCs for
   evidence.

The sidecar speaks the same verdict protocol and produces the same
interchangeable proofs as every other profile (DP-8): a proof issued here
verifies on the other profiles and vice versa.

## Fail-closed duty of the workload

The guardian does not capture traffic, so the workload owns the enforcement
discipline. If the guardian gives no answer - connection refused, timeout,
transport error, or a proof that does not verify - the workload must not act.
Treat every missing answer as `BLOCK` by default. Never treat "the guardian did
not answer" as permission to proceed.

## Explicit non-claims

- **Packaging, not new capability.** The container form packages the existing
  single-node daemon. It adds no new verdict capability and no clustering
  (WO-16 DC-1/DC-3 remain open).
- **Not forced routing.** Nothing captures the workload's traffic (spec CM-4 is
  not built). The workload must call the guardian. Omitting the call is still
  possible; the sidecar form does not change that.
- **No TEE attestation and no external anchoring.** Both are designed, not
  built.
- **License.** Apache License 2.0 plus the Payment Rider. It is never
  "unmodified Apache 2.0"; see `LICENSE` and `LICENSE-RIDER.md`.
