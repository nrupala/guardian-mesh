# Multi-Tenancy (WO-15 / v0.14.0)

Guardian Mesh v0.14.0 introduces multi-tenancy: policy bundles, ML-DSA key bindings, rate budgets, and audit partitions are scoped per tenant. Cross-tenant access requires two confirmations under the BM-3 rule.

## Configuration

### Environment Variables

- `GUARDIAN_MESH_TENANTS`: Comma-separated list of tenant IDs to register at startup (default: empty, meaning only "default" tenant).
  - Example: `GUARDIAN_MESH_TENANTS="tenant-a,tenant-b,tenant-c"`
  - Tenant IDs are validated: 1-64 chars, first char ASCII lowercase alphanumeric, remaining chars ASCII lowercase alphanumeric/`-`/`_`.

- `GUARDIAN_MESH_TENANT_RATE_BUDGET`: Per-tenant rate budget limit (default: value of `GUARDIAN_MESH_POLICY_THROTTLE_RATE` cast to u64).
  - A limit of `0` means unlimited (budget tracking still counts usage).
  - Example: `GUARDIAN_MESH_TENANT_RATE_BUDGET=1000`

### Default Tenant

The `"default"` tenant is always registered and cannot be removed. Sessions without an explicit `tenant_id` in the handshake request are assigned to the default tenant.

## Four Tenant Scopings

### 1. Policy Bundles

Each tenant can have its own `PolicyBundle`. Tenant policy decisions are evaluated **before** the global policy engine:

- If a tenant policy rule denies an action, the evaluation returns `BLOCK` immediately with a DC-15 structured reason.
- If no tenant policy matches or the tenant policy allows, evaluation proceeds to the global policy.

**Note:** In v1, tenant policy bundles are set via the library API and tests only. There is **no admin RPC** for tenant policy management.

### 2. ML-DSA Key Bindings

ML-DSA-65 verifying keys are bound to tenants at handshake time:

- The first handshake with a given key binds it to the requested tenant.
- Subsequent handshakes with the same key for a **different** tenant are refused with `permission_denied` (cross-tenant key access).
- Re-binding to the **same** tenant is allowed.

This prevents a single compromised key from being used across tenant boundaries.

### 3. Rate Budgets

Each tenant has an independent rate budget:

- Exhausting one tenant's budget does not affect other tenants.
- Budget consumption occurs only on real `Evaluate` calls, not on `Simulate`.
- When a tenant's budget is exhausted, further `Evaluate` calls return `resource_exhausted`.

**Honesty Boundary:** Budgets are in-memory and reset on daemon restart in v1.

### 4. Audit Partitions

Each tenant has its own audit partition with an independent hash chain:

- Audit entries appended for one tenant are invisible to other tenants.
- Per-partition sequence numbers start at 1.
- Hash chains are verified per-partition.

**Honesty Boundary:** Audit partitions are in-memory and reset on daemon restart in v1.

## Cross-Tenant Reads (BM-3 Two-Confirmation Rule)

The `TenantStatus` RPC enforces the BM-3 two-confirmation rule for cross-tenant reads:

- Same-tenant reads (or empty `requester_tenant`) are always allowed.
- Cross-tenant reads require `confirmations >= 2`.
- Without sufficient confirmations, the response returns `found = false` with zeroed numeric fields and a message naming the BM-3 / DC-15 requirement.

This prevents one tenant from observing another tenant's budget usage or audit activity without explicit dual authorization.

## TenantStatus RPC

- **Summary mode** (empty `tenant_id`): Returns the list of all registered tenant IDs with `found = false` and `message = "summary"`.
- **Specific tenant**: Returns budget limit/used/remaining, audit entry count, policy configuration status, and policy version.
- **Cross-tenant guard**: Enforces the two-confirmation rule as described above.

## Honesty Boundaries

v0.14.0 is a **single-node, in-process** multi-tenancy implementation:

- **No process isolation:** All tenants run in the same daemon process. CP-14's SC-39 process isolation requirement is **not claimed** in v1.
- **In-memory state:** Budgets and audit partitions are in-memory and reset on daemon restart. No persistence.
- **No cross-node tenancy:** Tenant isolation applies only within a single daemon instance.
- **No admin RPC for tenant policies:** Tenant policy bundles are set via the library API and tests only. There is no RPC endpoint for managing tenant policies in v1.

## Spec Status

- **DC-15** (policies, keys, budgets, and audit partitions must be tenant-scoped; cross-tenant access under BM-3): **PARTIAL**
  - Achieved: Tenant-scoped policy/keys/budgets/audit with cross-tenant guards.
  - Not achieved: Process isolation, cross-node tenancy, persistent audit.

- **DC-16** (tenant isolation must be behaviour-proven): **PARTIAL**
  - Achieved: Isolation is behaviour-proven in integration tests (budget exhaustion, audit partition invisibility, cross-tenant key denial).
  - Not achieved: No process-level or node-level isolation proofs.

- **CP-14** (tenant isolation: no tenant sees, slows, or starves another): **PARTIAL**
  - Achieved: Budget isolation, audit partition isolation, policy isolation.
  - Not achieved: SC-39 process isolation not claimed.

## Examples

### Register Tenants at Startup

```bash
export GUARDIAN_MESH_TENANTS="tenant-alpha,tenant-beta"
export GUARDIAN_MESH_TENANT_RATE_BUDGET=500
./guardian-meshd
```

### Handshake with a Specific Tenant

```typescript
const response = await client.handshake({
  sourceEnclave: "my-service",
  sourcePublicKey: myMlDsaVerifyingKey,
  tenantId: "tenant-alpha",
  // ... other fields
});
// response.tenantId === "tenant-alpha"
```

### Query Tenant Status

```typescript
// Summary (all tenants)
const summary = await client.tenantStatus({
  tenantId: "",
  requesterTenant: "",
  confirmations: 0,
});

// Specific tenant (same-tenant read)
const status = await client.tenantStatus({
  tenantId: "tenant-alpha",
  requesterTenant: "",
  confirmations: 0,
});

// Cross-tenant read (requires 2 confirmations)
const crossStatus = await client.tenantStatus({
  tenantId: "tenant-alpha",
  requesterTenant: "tenant-beta",
  confirmations: 2,
});
```

## Testing

WO-15 includes integration tests covering:

- Handshake with unregistered tenant (invalid_argument)
- Handshake with registered tenant returns tenant_id and evaluates normally
- Cross-tenant key binding is permission_denied
- Tenant budget exhaustion throttles the exhausted tenant while others continue
- Audit partitions are isolated (entries appended for one tenant are invisible to others)
- Tenant policy deny blocks with DC-15 reason; same action under another tenant is unaffected
- TenantStatus summary lists all tenants
- TenantStatus cross-tenant reads require two confirmations

All tests must pass before release.
