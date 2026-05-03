# Multi-cluster fleet view

`aegisfleet` is a small read-only CLI that aggregates AegisPolicy and
AegisClusterPolicy status across multiple Kubernetes clusters. It
closes the "no fleet view across clusters yet" gap from the Honest
Limitations list without introducing a new control plane: each spoke
cluster keeps running its own `aegis-operator`, and `aegisfleet` only
reads.

## What it is — and what it isn't

| Property | Status |
|----------|--------|
| Reads `AegisPolicy` + `AegisClusterPolicy` from many clusters | ✅ |
| Aggregates status into a single table or JSON document | ✅ |
| Surfaces per-cluster failures (kubeconfig, connection, RBAC) | ✅ |
| Exit codes suitable for CI gating (`0` ok, `2` policy not Ready, `3` cluster failure) | ✅ |
| Pushes / fans out policies to spoke clusters | ❌ — out of scope |
| Hub CRD (`AegisFleetPolicy`) | ❌ — out of scope |
| Cross-cluster admission control | ❌ — out of scope |

The push / fan-out flow is a separate roadmap item; introducing it
will be additive and won't change the read-only contract above.

## Building

```bash
$ cd operator
$ make build-fleet
go build -o bin/aegisfleet ./cmd/aegisfleet/
```

The binary depends only on the operator's existing `client-go` /
`controller-runtime` deps — no new modules.

## Configuring clusters

Pick whichever input style fits your environment.

### Directory of kubeconfigs

```bash
$ ls /etc/aegisfleet/kubeconfigs
prod-eu.kubeconfig
prod-us.kubeconfig
staging.kubeconfig

$ aegisfleet --kubeconfig-dir=/etc/aegisfleet/kubeconfigs
```

The cluster name in the output table is the filename with the
extension stripped, so `prod-eu.kubeconfig` becomes `prod-eu`.
Subdirectories are ignored; symlinks are followed.

### Explicit `--kubeconfig` flags

```bash
$ aegisfleet \
    --kubeconfig=prod-eu=/srv/k/eu \
    --kubeconfig=prod-us=/srv/k/us \
    --kubeconfig=/srv/k/staging.yaml
```

`name=path` syntax sets the display name explicitly; bare paths
derive the name from the filename. Mixing the two styles with
`--kubeconfig-dir` is allowed; duplicate names cause an early error.

## Output

### Table (default)

```
$ aegisfleet --kubeconfig-dir=/etc/aegisfleet/kubeconfigs

CLUSTER   NAMESPACE   NAME                  SCOPE       MODE     PHASE    READY   GEN  NODES  AGE
prod-eu   -           kernel-protect        Cluster     audit    Applied  True    1    -      30m
prod-eu   production  block-files           Namespaced  enforce  Applied  True    2    14     3h
prod-us   production  block-files           Namespaced  enforce  Pending  False   2    -      3h
staging   default     allow-debug-tooling   Namespaced  audit    Applied  True    1    -      12h

FLEET ERRORS:
  drift-test [connect]: Get "https://10.0.0.7:6443": dial tcp 10.0.0.7:6443: connect: connection refused
```

### JSON

```bash
$ aegisfleet --kubeconfig-dir=/etc/aegisfleet/kubeconfigs --output=json
{
  "rows": [
    {
      "cluster": "prod-eu",
      "name": "kernel-protect",
      "scope": "Cluster",
      "mode": "audit",
      "phase": "Applied",
      "ready": "True",
      "generation": 1,
      "createdAt": "2026-04-15T13:00:00Z"
    }
  ],
  "errors": [
    {"cluster": "drift-test", "stage": "connect", "message": "..."}
  ]
}
```

The `errors` array is omitted when empty (Go's `omitempty`), so a
healthy fleet produces a clean object.

## Filtering

| Flag | Effect |
|------|--------|
| `--namespace=<ns>` | Restricts AegisPolicy listing to one namespace per cluster. AegisClusterPolicy entries are unaffected (cluster-scoped by definition). |
| `--timeout=<duration>` | Per-cluster query timeout. A slow or unreachable cluster doesn't stall the rest of the fleet. Default 15s. |

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Every cluster was reachable and every policy reports Ready=True (or has no Ready condition yet). |
| `2` | At least one policy reports Ready=False. Errors block. |
| `3` | At least one cluster failed (kubeconfig load, connection, RBAC, CRD not installed). Cluster failures rank above policy failures so infrastructure issues don't get hidden behind a Ready=False that may be downstream of them. |

This makes `aegisfleet` directly usable as a CI gate:

```bash
$ aegisfleet --kubeconfig-dir=/etc/aegisfleet/kubeconfigs --output=json > /tmp/fleet.json || rc=$?
$ case ${rc:-0} in
    0) echo "Fleet healthy" ;;
    2) echo "::error::A policy is not Ready"; exit 1 ;;
    3) echo "::error::A cluster is unreachable"; exit 1 ;;
  esac
```

## RBAC

`aegisfleet` needs only `get` + `list` on `aegispolicies` and
`aegisclusterpolicies` (cluster-scoped) in each spoke. A typical
ClusterRole on each spoke:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: aegisfleet-reader
rules:
- apiGroups: ["aegisbpf.io"]
  resources: ["aegispolicies", "aegisclusterpolicies"]
  verbs: ["get", "list"]
```

Bind it to the ServiceAccount whose token is in the kubeconfig you
ship to the operator running `aegisfleet`. Read-only RBAC keeps the
blast radius of a stolen fleet kubeconfig minimal — no policy
mutation, no exec into pods, no secret access.

## See also

- [`operator/cmd/aegisfleet/main.go`](../operator/cmd/aegisfleet/main.go) — flag parsing + dispatch.
- [`operator/internal/fleet/`](../operator/internal/fleet/) — aggregation + rendering, including unit tests.
- [`docs/POSITIONING.md`](POSITIONING.md) — broader roadmap and gap analysis.
