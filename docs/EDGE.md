# Edge Profile (WO-18 profile 2 / DP-6)

Guardian Mesh v0.18.0 adds WO-18 profile 2: an edge profile of the existing
single-node daemon for resource-capped edge and server-class endpoints (DP-6) -
small ARM/x86 gateways and industrial PCs. The daemon runs under an operator-set
memory/CPU ceiling and makes its verdicts offline.

This release claims only WO-18 profile 2. The CLI (CC-4) and MCP surface (CC-5)
remain target and are not part of it.

## What the edge profile is

The edge profile is deployment packaging and configuration of the same
single-node `guardian-meshd` binary that every other profile runs. It adds no
new verdict capability and changes no daemon behaviour. What it adds is a
defined way to run the daemon on a small endpoint under a hard resource ceiling,
with all verdict work local.

The edge guardian speaks the same verdict protocol and produces the same
interchangeable proofs as every other profile (DP-8): a proof issued on an edge
endpoint verifies on the other profiles and vice versa.

Nothing intercepts or redirects the workload's traffic. The workload must make
the handshake, evaluate, simulate, verify and audit calls itself.

## Two forms

### systemd (bare metal / gateway)

Use `deploy/edge/guardian-meshd.service` when the endpoint runs a normal Linux
userland and you want the guardian as a first-class service: a gateway,
industrial PC, or server-class host with systemd and cgroups. The unit runs the
binary as the dedicated non-root user `guardian`, applies the ceilings with
systemd/cgroups, and hardens the service (read-only system, private `/tmp`, no
home access, no privilege escalation).

Install the binary at `/usr/local/bin/guardian-meshd`, create the `guardian`
account and directories as described at the top of the unit, place the
operator's settings in `/etc/guardian-mesh/guardian-mesh.env`, then enable the
unit. The file `deploy/edge/guardian-mesh.env.example` lists every real
`GUARDIAN_MESH_*` variable.

### container (Docker Compose)

Use `deploy/edge/docker-compose.yaml` when the endpoint already has a container
runtime, when the image is the unit of consistency across a fleet, or when the
host is managed as an immutable appliance. It builds from the repository
`Dockerfile`, runs as the image's non-root `guardian` user, keeps state in the
named volume `guardian-data` at `/data`, and publishes the port on host
loopback only.

```bash
cd deploy/edge
docker compose up --build
```

Both forms run the same binary and produce the same proofs. Pick the one that
matches how the endpoint is managed, not a behavioural difference.

## Ceilings

DP-6 requires configurable memory/CPU ceilings. On the edge profile those
ceilings are set per deployment and enforced by the runtime:

- **systemd form**: `MemoryMax=256M`, `CPUQuota=50%`, `TasksMax=64` in
  `deploy/edge/guardian-meshd.service`.
- **container form**: `mem_limit: 256m`, `cpus: 0.5` in
  `deploy/edge/docker-compose.yaml`.

These are **starting ceilings for a small gateway**, not measurements. Measured
footprint guidance lives in this document's release record, filled in by
verification; no measured number is asserted here.

This is deliberate and honest: **the daemon has no memory/CPU ceiling setting in
`guardian-meshd/src/config.rs`.** Ceilings are enforced by systemd/cgroups or by
the container runtime, not by the daemon. To change them, edit the single place
for your form - the unit file or the compose file - and restart. `TasksMax` is
the systemd process/thread cap and has no compose equivalent in this example.

A ceiling that is too small fails closed in the ordinary way: the runtime may
throttle or kill the process, and the workload treats a missing answer as
`BLOCK` (see below). Raise the ceiling on the endpoint if the daemon cannot
start or answer.

## Offline operation

**The daemon makes no outbound calls; verdicts and proof verification are fully
local.** The edge guardian needs no network connectivity to decide, to seal a
proof, or to verify one. Its listener serves local clients only.

What this means concretely:

- **No licence check.** There is no phone-home or entitlement service.
- **No telemetry.** Nothing is reported to the project or a third party.
- **No update check.** The daemon does not look for or fetch updates.

**No edge-to-core sync or uplink is built.** BM-7 edge-to-core sync is design,
not shipped. An edge guardian's proofs verify locally and travel only when an
operator carries them (for example on removable media or through an existing
management channel); nothing uploads automatically. Proofs remain portable
between profiles (DP-8), but their transport is manual.

## Persistence

The workspace holds the daemon signing key, policy, sessions, revocation
registry, and the hash-chained audit log.

- **systemd form**: `/var/lib/guardian-mesh` (workspace and output).
- **container form**: `/data` (the named volume `guardian-data`).

Losing the workspace loses **proof continuity** (the WO-3 persistence property):
proofs issued before the loss can no longer be tied to the same signing key and
audit chain. Put it on durable local storage, restrict access to the service
account, and back it up as part of the endpoint's normal data protection. No
backup or replication mechanism is built into the daemon.

## Configuration

These are the `GUARDIAN_MESH_*` variables the daemon actually reads at run time
(from `guardian-meshd/src/config.rs`). The systemd form sets the addressing and
workspace defaults in the unit; the container form inherits the image defaults.
Unset variables use the daemon's built-in defaults.

| Variable | What it controls | systemd default | container default |
|---|---|---|---|
| `GUARDIAN_MESH_WORKSPACE` | Workspace: signing key, policy, sessions, revocation registry and hash-chained audit log. | `/var/lib/guardian-mesh/workspace` | `/data/workspace` |
| `GUARDIAN_MESH_OUTPUT` | Output directory for per-project evaluation artifacts. | `/var/lib/guardian-mesh/output` | `/data/output` |
| `GUARDIAN_MESH_BIND_ADDR` | Listener address. | `127.0.0.1` (loopback by default) | `0.0.0.0` (needed for the published port; host publish is loopback-only) |
| `GUARDIAN_MESH_PORT` | Listener port. | `50051` | `50051` |
| `GUARDIAN_MESH_HANDSHAKE_SECRET` | HMAC handshake secret. | Not in the unit; comes from the EnvironmentFile at run time. | Not in the image; passed through from the shell environment at run time. |
| `GUARDIAN_MESH_NODE_ID` | Node identity reported by `Health` and in proofs. | Derived from the signing-key fingerprint | Derived from the signing-key fingerprint |
| `GUARDIAN_MESH_POLICY_THROTTLE_RATE` | Default policy/firewall rate limit. | `100` | `100` |
| `GUARDIAN_MESH_POLICY_ESCALATE_ACTIONS` | Comma-separated action types that require escalation. | Empty | Empty |
| `GUARDIAN_MESH_POLICY_ADMIN_KEYS_DIR` | Directory of administrator keys for policy changes. | Unset | Unset |
| `GUARDIAN_MESH_REVOCATION_BOUND_SECS` | DC-14 revocation propagation bound in seconds (`0` falls back to 60). | `60` | `60` |
| `GUARDIAN_MESH_SPIFFE_TRUST_DOMAINS` | Comma-separated SPIFFE trust domains accepted at handshake. | Empty | Empty |
| `GUARDIAN_MESH_REQUIRE_SPIFFE` | Require SPIFFE SVID attestation (`1`/`true`). | `false` | `false` |
| `GUARDIAN_MESH_PGP_ADMIN_KEYS_DIR` | Directory of OpenPGP administrator keys. | Unset | Unset |
| `GUARDIAN_MESH_TENANTS` | Comma-separated tenant ids to register (the default tenant is always present). | Empty | Empty |
| `GUARDIAN_MESH_TENANT_RATE_BUDGET` | Per-tenant rate budget per window. | Defaults to the policy throttle rate (`100`) | Defaults to the policy throttle rate (`100`) |
| `GUARDIAN_MESH_TENANT_BUDGET_WINDOW_MS` | Tenant budget sliding window in milliseconds (positive values only). | `1000` | `1000` |
| `GUARDIAN_MESH_DEGRADED` | Start in declared degraded mode (`1`/`true`). | `false` | `false` |
| `GUARDIAN_MESH_DEGRADED_SAFE_ACTIONS` | Comma-separated action types still allowed while degraded. | Empty | Empty |

Build-time only: `GUARDIAN_MESH_GIT_COMMIT` and `SOURCE_DATE_EPOCH` are read by
`guardian-meshd/build.rs` to stamp build identity. They are not runtime
configuration.

The handshake secret has no value in the example environment file or in the
compose file, not even a placeholder literal. Inject it at deploy time from your
secret manager and never commit it.

## Fail-closed duty of the workload

The guardian does not capture traffic, so the workload owns the enforcement
discipline. If the guardian gives no answer - connection refused, timeout,
transport error, or a proof that does not verify - the workload must not act.
Treat every missing answer as `BLOCK` by default. Never treat "the guardian did
not answer" as permission to proceed.

## Explicit non-claims

- **Packaging and configuration, not new capability.** The edge profile packages
  the existing single-node daemon. It adds no new verdict capability and no
  clustering (WO-16 DC-1/DC-3 remain open).
- **No edge-to-core sync.** BM-7 is design, not shipped; see Offline operation.
- **No measured numbers.** Every resource value in this document is a ceiling,
  never a measurement. Verification measures the daemon under the ceiling and
  stamps the values into the release record below.
- **Not forced routing.** Nothing captures the workload's traffic (spec CM-4 is
  not built). The workload must call the guardian; omitting the call is still
  possible.
- **No TEE attestation and no external anchoring.** Both are designed, not
  built.
- **License.** Apache License 2.0 plus the Payment Rider. It is never
  "unmodified Apache 2.0"; see `LICENSE` and `LICENSE-RIDER.md`.

## Release record

- Measured footprint (Wright verification, 2026-11-07): the shipped
  image's daemon used 5.8–10.2 MB RSS with a 10.6 MB peak (VmHWM) across
  Health, a signed Evaluate, proof verification and the e2e burst suite,
  with 6 threads — over 24x headroom under the 256M starting ceiling.
  Ceiling *enforcement* itself was NOT RUN in the verifying sandbox
  (its nested cgroup controllers are not delegated); see the gate
  verdict. Offline operation was behaviour-proven in a loopback-only
  network namespace: Health SERVING, Evaluate ALLOW, proof VALID,
  with all egress unreachable.
- Tests: cargo test (workspace root) 240/240 and conformance_ 13/13,
  Wright-verified 2026-11-07; WebUI ci + build + lint green; container
  box-e2e 14/16 (the two standing local classes: PF-18 burst timing on
  the contended sandbox VM and the stale Health-fields harness check).
- Gate verdict: PASS WITH FINDINGS — Release Gate 2026-11-07
  (guardian-mesh-wo18-edge-2026-11-07).
