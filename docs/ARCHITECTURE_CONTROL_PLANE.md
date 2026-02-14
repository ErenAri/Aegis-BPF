# AegisBPF Future Architecture: Control Plane, Multi-Tenancy, and Canary Rollout

Status: Design Proposal (not implemented)
Version: 0.1 (2026-02-14)

This document describes three future architecture extensions for AegisBPF. All
three are design-only; no implementation exists today. Each section is labeled
with a feature identifier (F1, F2, F3) and declares its dependencies on the
others.

---

## F1: Central Control Plane

### Motivation

AegisBPF currently operates as a standalone agent. Each host loads its own
policy file from disk and has no coordination mechanism with other hosts. This
works well for single-host or small-fleet deployments, but creates operational
friction at scale:

- Policy drift between hosts is invisible until an incident occurs.
- Rolling out a new policy requires external orchestration (Ansible, SSH loops).
- There is no centralized view of agent health or applied policy versions.

A central control plane addresses these gaps by providing a single source of
truth for policy distribution, agent inventory, and drift detection.

### Architecture Overview

The control plane follows a **pull-based** architecture. Agents poll the server
at a configurable interval for policy updates. This design avoids inbound
connectivity requirements on agent hosts and tolerates transient network
partitions gracefully: agents continue enforcing their last-known-good policy
when the server is unreachable.

```
+------------------------------------------------------------------+
|                     Control Plane Server                          |
|                                                                   |
|  +---------------------+   +------------------+                   |
|  |    Policy Store      |   |  Agent Registry  |                  |
|  |  +---------------+   |   |  +------------+  |                  |
|  |  | policy_v34    |   |   |  | agent-a    |  |                  |
|  |  | policy_v35    |   |   |  | agent-b    |  |                  |
|  |  | policy_v36    |   |   |  | agent-c    |  |                  |
|  |  +---------------+   |   |  | ...        |  |                  |
|  +---------------------+    |  +------------+  |                  |
|                             +------------------+                  |
|  +----------------------------------------------------------+     |
|  |                       REST API                            |    |
|  |  PUT /policy/{agent}     POST /agents/register            |    |
|  |  GET /agents             GET  /agents/{id}/health         |    |
|  |  GET /policy/{agent}     GET  /agents/{id}/drift          |    |
|  +----------------------------------------------------------+     |
+------------------------------+-----------------------------------+
                               |
                     TLS / mTLS |  (agents poll every 30-120s)
                               |
          +--------------------+---------------------+
          |                    |                     |
+---------+-------+  +---------+-------+  +----------+------+
|   Agent Host 1  |  |   Agent Host 2  |  |   Agent Host N   |
|                 |  |                 |  |                  |
|  +-----------+  |  |  +-----------+  |  |  +-----------+   |
|  | aegisbpf  |  |  |  | aegisbpf  |  |  |  | aegisbpf  |   |
|  | daemon    |  |  |  | daemon    |  |  |  | daemon    |   |
|  +-----------+  |  |  +-----------+  |  |  +-----------+   |
|  | BPF maps  |  |  |  | BPF maps  |  |  |  | BPF maps  |   |
|  +-----------+  |  |  +-----------+  |  |  +-----------+   |
+-----------------+  +-----------------+  +------------------+
```

### API Specification

All endpoints are served over TLS. Agents authenticate with mTLS client
certificates. Human operators authenticate with bearer tokens scoped by RBAC
role.

#### PUT /policy/{agent}

Upload or update the policy for a specific agent (or agent group). The request
body is a signed policy bundle. The server validates the signature, increments
the policy version counter, and stores the new policy.

Request:
```
PUT /policy/agent-group-prod HTTP/1.1
Content-Type: application/octet-stream
Authorization: Bearer <operator-token>

<signed policy bundle bytes>
```

Response:
```json
{
  "policy_version": 36,
  "sha256": "a1b2c3d4e5f6...",
  "agents_targeted": 42,
  "status": "staged"
}
```

#### GET /agents

List all registered agents with summary health and policy status.

Response:
```json
{
  "agents": [
    {
      "id": "agent-a",
      "group": "prod",
      "last_poll": "2026-02-14T10:32:00Z",
      "policy_version_applied": 35,
      "policy_version_available": 36,
      "health": "healthy",
      "drift": false
    }
  ]
}
```

#### GET /agents/{id}/health

Detailed health report for a single agent. Includes the agent-reported
`policy.applied.sha256` for server-side drift comparison.

Response:
```json
{
  "id": "agent-a",
  "uptime_seconds": 86400,
  "policy_version_applied": 35,
  "policy_applied_sha256": "a1b2c3d4e5f6...",
  "ringbuf_drops": 0,
  "rss_kb": 12288,
  "block_count": 1042,
  "enforce_mode": true,
  "lsm_hook": "file_open",
  "kernel_version": "6.14.0-37-generic",
  "last_poll": "2026-02-14T10:32:00Z"
}
```

### Policy Versioning

Each policy stored on the server carries a **monotonic version counter**. The
counter is a 64-bit unsigned integer that increments on every policy mutation.
It never decreases, even if a policy is reverted to an earlier state (the
reverted content receives a new, higher version number).

Agents include their current `policy_version` and `policy.applied.sha256` in
every poll request. The server responds with a new policy bundle only when the
agent's version is behind. This minimizes bandwidth and avoids unnecessary
policy re-application.

Version semantics:
- `policy_version` is per agent group, not global.
- The anti-rollback counter in signed policy bundles (see `POLICY_SEMANTICS.md`,
  "Signed bundle semantics") is set equal to the server-side version counter.
- Agents reject any bundle whose version is less than or equal to the currently
  applied version.

### Role-Based Access Control (RBAC)

Policy modification is gated by RBAC roles scoped to agent groups.

| Role               | Permissions                                    |
|--------------------|------------------------------------------------|
| `viewer`           | GET /agents, GET /agents/{id}/health           |
| `policy-editor`    | PUT /policy/{group} for assigned groups        |
| `policy-admin`     | PUT /policy/{group} for all groups             |
| `super-admin`      | All operations, including agent deregistration |

Roles are bound to identities (users or service accounts) through a role
binding table. Each binding specifies the identity, the role, and the set of
agent groups the role applies to. This prevents a team responsible for
`staging` from modifying policies in `production`.

### Drift Detection

Drift occurs when the policy actually applied on an agent diverges from the
policy the server believes should be applied. Common causes include manual
local overrides, failed partial applies, or filesystem corruption.

Detection mechanism:

1. The agent computes `SHA-256(policy file on disk)` and reports it as
   `policy.applied.sha256` in every poll and health response.
2. The server computes the expected SHA-256 from the canonical policy stored
   for that agent's group and version.
3. If the hashes differ, the server marks the agent as `drift: true`.
4. Drift status is surfaced in `GET /agents` and `GET /agents/{id}/drift`.
5. Operators can configure alerts on drift via Prometheus metrics exported by
   the control plane:
   - `aegis_control_plane_drift_agents{group="prod"}` (gauge)

Remediation is pull-based: a drifted agent receives the correct policy on its
next poll cycle. If drift persists after two poll cycles, the server emits a
warning-level log and increments `aegis_control_plane_drift_persistent_total`.

### Communication Security

- **Agent-to-server**: mTLS with per-agent client certificates. The server
  validates the client certificate CN against the agent registry.
- **Operator-to-server**: TLS with bearer token authentication.
- **Certificate rotation**: Agents support hot-reload of client certificates
  without daemon restart.
- **Network failure**: Agents continue enforcing their last-known-good policy
  indefinitely. The poll interval backs off exponentially (30s to 600s) during
  sustained server unreachability.

---

## F2: Multi-Tenant Support

**Dependencies**: None (can be implemented independently of F1).

### Motivation

In shared infrastructure (multi-tenant Kubernetes clusters, systemd-nspawn
hosts, multi-user workstations), a single flat policy namespace is
insufficient. Tenants need isolation guarantees: one tenant's deny rules must
not affect another tenant's workloads, and per-tenant observability must be
possible without exposing cross-tenant data.

### Design: cgroup-Based Tenant Isolation

Linux cgroup v2 provides a natural hierarchy for tenant isolation. Each tenant
is assigned a cgroup slice (e.g., `tenant-a.slice`), and policy rules are
scoped to that slice.

#### Policy Syntax Extension

Policy sections gain an optional `cgroup=` scope qualifier:

```
version=2

[deny_path:cgroup=/tenant-a.slice]
/opt/tenant-a/data/secrets.db

[deny_path:cgroup=/tenant-b.slice]
/opt/tenant-b/data/credentials.json

[deny_inode:cgroup=/tenant-a.slice]
2049:789012

[allow_cgroup:cgroup=/tenant-a.slice]
/sys/fs/cgroup/tenant-a.slice/trusted-service.scope
```

Semantics:
- A scoped section applies only to processes whose cgroup path is a descendant
  of the specified cgroup subtree.
- Unscoped sections (no `cgroup=` qualifier) apply globally, preserving
  backward compatibility with `version=1` policies.
- The `cgroup=` value is a cgroup v2 path relative to the cgroup filesystem
  root (e.g., `/tenant-a.slice`, not `/sys/fs/cgroup/tenant-a.slice`).

#### Per-Tenant Stats Maps

Today, AegisBPF maintains global stats maps (`block_stats`) and per-rule stats
maps (`deny_inode_stats`, `deny_path_stats`, `deny_cgroup_stats`). Multi-tenant
support adds tenant-keyed stats maps for per-tenant observability.

BPF map design:

```
Map name:        tenant_block_stats
Map type:        BPF_MAP_TYPE_HASH
Key:             u64 (cgroup ID of tenant root)
Value:           struct { u64 blocks; u64 allows; u64 audits; }
Max entries:     1024 (configurable)
```

The BPF program resolves the current process's cgroup ID at hook time and
increments the corresponding tenant counter. If the cgroup ID does not match
any tenant root, the event is counted under a reserved `cgroup_id=0` entry
(host-level / unscoped).

Prometheus metrics exported per tenant:

```
aegis_tenant_blocks_total{tenant_cgroup_id="12345"} 42
aegis_tenant_allows_total{tenant_cgroup_id="12345"} 9001
aegis_tenant_audits_total{tenant_cgroup_id="12345"} 7
```

#### Tenant Isolation Guarantees

| Property                    | Guarantee                                       |
|-----------------------------|------------------------------------------------|
| Rule isolation              | Scoped rules apply only within tenant cgroup    |
| Stats isolation             | Per-tenant counters; no cross-tenant leakage    |
| Event isolation             | Ring buffer events tagged with cgroup ID         |
| allow_cgroup isolation      | Scoped allow_cgroup cannot bypass other tenants |
| Policy modification         | Requires RBAC role for the tenant (with F1)      |

#### Requirements

- **cgroup v2**: The host must use the unified cgroup hierarchy. Legacy cgroup
  v1 or hybrid mode is not supported for multi-tenant isolation.
- **cgroup delegation**: Tenant cgroup subtrees must be delegated so that
  tenant workloads run within the expected hierarchy. Systemd slice units or
  Kubernetes cgroup drivers handle this automatically.
- **Namespace-aware daemon**: The aegisbpf daemon must be extended to resolve
  cgroup paths from the host cgroup namespace, not from within a container's
  cgroup namespace. This ensures consistent tenant identification regardless
  of mount namespace.
- **Map capacity planning**: The `tenant_block_stats` map has a fixed maximum
  entry count. Deployments exceeding this limit require map resize or
  partitioning (one BPF program set per tenant group).

---

## F3: Canary Rollout via Control Plane

**Dependencies**: Requires F1 (Central Control Plane).

### Motivation

AegisBPF already provides canary validation tooling for single-host staged
rollout (see `scripts/canary_gate.sh` and `docs/CANARY_RUNBOOK.md`). The
existing `canary_gate.sh` script runs a five-phase validation sequence
(environment check, health snapshot, smoke test, soak reliability, post-run
metrics) on a single host. The `canary_deploy.sh` script extends this to a
percentage-based fleet deployment via SSH.

These tools work, but they operate outside the agent's own update loop. F3
brings canary rollout semantics into the control plane itself, enabling
server-coordinated progressive deployment with automatic promotion or
rollback.

### Design: Server-Coordinated Canary

#### Agent Tagging

Each agent in the registry carries a `rollout_tier` label:

| Tier       | Description                                                |
|------------|------------------------------------------------------------|
| `canary`   | Receives new policy first; closely monitored                |
| `stable`   | Receives policy only after canary promotion                 |
| `holdback` | Never receives automatic updates; manual-only               |

Tier assignment is stored in the Agent Registry (F1) and modifiable via API:

```
PATCH /agents/{id}
{ "rollout_tier": "canary" }
```

Operators designate a small subset of agents (typically 1-5%) as `canary` tier.
The remaining production agents are `stable`.

#### Rollout Sequence

```
  Operator uploads policy v37
          |
          v
  +------------------+
  | Control Plane    |
  | stages policy    |
  | v37 as "canary"  |
  +--------+---------+
           |
           |  canary agents poll
           v
  +------------------+        +------------------+
  | Canary Agent 1   |        | Canary Agent 2   |
  | applies v37      |        | applies v37      |
  | reports health   |        | reports health   |
  +--------+---------+        +--------+---------+
           |                           |
           +----------+----------------+
                      |
                      v
             +-----------------+
             | Health Monitor  |
             | observes for    |
             | N minutes       |
             +-----------------+
                      |
            +---------+---------+
            |                   |
       all healthy         any unhealthy
            |                   |
            v                   v
   +----------------+  +------------------+
   | Auto-promote   |  | Auto-rollback    |
   | v37 -> stable  |  | canary -> v36    |
   | tier           |  | alert operator   |
   +----------------+  +------------------+
            |
            v
   stable agents poll
   and receive v37
```

#### Health Evaluation Criteria

The control plane evaluates canary health using the same metrics that
`canary_gate.sh` validates locally, reported via the agent health endpoint:

| Metric                   | Threshold (configurable)         | Source                  |
|--------------------------|----------------------------------|-------------------------|
| Ring buffer drops        | < MAX_RINGBUF_DROPS (default 100)| agent health report     |
| RSS growth               | < MAX_RSS_GROWTH_KB (default 64M)| agent health report     |
| Event drop ratio         | < 0.1%                           | agent health report     |
| Agent responsiveness     | poll within 2x interval          | server-side observation |
| Block error rate         | no unexpected block spikes       | agent metrics           |

The observation window (`CANARY_OBSERVE_MINUTES`) defaults to 15 minutes and
is configurable per rollout. Health checks run every 30 seconds during the
observation window.

#### Promotion and Rollback

**Auto-promote**: If all canary agents report healthy for the full observation
window, the server promotes the policy from `canary` to `stable` status.
Stable-tier agents receive the new policy on their next poll.

**Auto-rollback**: If any canary agent fails a health criterion during the
observation window:

1. The server reverts the canary agents to the previous policy version (v36).
2. The policy v37 is marked as `rollback:failed_canary` in the Policy Store.
3. An alert is emitted via the control plane's alerting integration.
4. The rollout does not proceed to stable-tier agents.

**Manual override**: Operators can force-promote or force-rollback at any time
via the API:

```
POST /rollout/{policy_version}/promote
POST /rollout/{policy_version}/rollback
```

#### Relationship to Existing Canary Tooling

F3 does not replace `canary_gate.sh` or `canary_deploy.sh`. Those scripts
remain useful for:

- Pre-merge validation in CI (canary_gate.sh runs against a single test host).
- Environments without a control plane deployment.
- Manual staged rollouts where full automation is not desired.

F3 builds on the same health criteria and validation philosophy established by
`canary_gate.sh`, elevating them from script-driven single-host checks to
server-coordinated fleet-wide progressive deployment.

---

## Dependency Graph

```
F2 (Multi-Tenant)       F1 (Control Plane)
     [independent]              |
                                |
                          F3 (Canary Rollout)
                          [requires F1]
```

F1 and F2 can be implemented in parallel. F3 requires F1 to be operational
before it can be built.

---

## Open Questions

1. **Policy Store backend**: Should the control plane use an embedded database
   (SQLite, bbolt) or require an external store (PostgreSQL, etcd)?
2. **Agent identity bootstrap**: How do agents obtain their initial mTLS
   certificate? Options include a bootstrap token, cloud instance identity
   (AWS IMDSv2, GCP metadata), or manual provisioning.
3. **Multi-region**: Should the control plane support active-active replication
   across regions, or is a single primary with read replicas sufficient?
4. **Tenant lifecycle**: How are tenants provisioned and decommissioned? Should
   the control plane manage tenant cgroup creation, or assume external
   orchestration (systemd, Kubernetes)?
5. **Canary blast radius**: Should the server enforce a maximum canary
   percentage (e.g., never more than 10% of agents in canary tier)?
