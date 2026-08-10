# aegis-responder — Falco → AegisBPF enforcement adapter

Turns [Falco](https://falco.org) detections into AegisBPF **kernel enforcement**.
Falco is a CNCF *graduated* detector but only alerts; this adapter closes the
loop by installing a race-free in-kernel deny on the node where the alert fired.

```
Falco (detect, eBPF) ──► Falcosidekick (webhook output) ──► aegis-responder
                                                               │  POST /block/add <path>
                                                               │  POST /network/deny/ip <ip>
                                                               ▼
                                              AegisBPF control socket (see docs/CONTROL_API.md)
                                                               ▼
                                              race-free -EPERM in-kernel, this node
```

Verified end-to-end: a Falco webhook for *"Write below binary dir"* drove
`POST /block/add <path>` and the target file became `-EPERM` on the next read.

## Safe by default
- **Explicit allowlist** — only Falco rules named in the config trigger any
  action. Everything else is `no-action`.
- **`min_priority`** gate — ignore alerts below a Falco priority.
- **`dry_run`** (or `AEGIS_RESPONDER_DRYRUN=1`) — log the intended action without
  enforcing. Start here.
- **Target validation** — every enforcement target is shape-checked before it
  reaches the socket: `block-file` requires an absolute path with no `..`,
  `deny-ip`/`deny-cidr` must parse as an IP/CIDR, and any target carrying a
  newline/NUL is rejected (no control-protocol injection from Falco fields).
- **Optional shared-secret auth** — set `auth_token` (or `AEGIS_RESPONDER_TOKEN`)
  to require a matching `X-Aegis-Token` header (constant-time compare). Unset =
  unauthenticated; the responder logs a warning and you must restrict network
  exposure yourself.
- **Body limit** — webhook requests are capped at 64 KiB.
- Stdlib-only Go (no third-party deps).

## Configuration (`config.json`)
```json
{
  "socket": "/var/run/aegisbpf/aegisbpf.sock",
  "dry_run": false,
  "min_priority": "warning",
  "auth_token": "",
  "rules": [
    { "rule": "Write below binary dir",         "action": "block-file", "field": "fd.name" },
    { "rule": "Unexpected outbound connection", "action": "deny-ip",    "field": "fd.sip"  }
  ]
}
```
- `action`: `block-file` → `POST /block/add`, `deny-ip` → `POST /network/deny/ip`,
  `deny-cidr` → `POST /network/deny/cidr`.
- `field`: the Falco `output_fields` key holding the target (path / IP / CIDR).
- `auth_token`: optional shared secret; when set, callers must send a matching
  `X-Aegis-Token` header. Leave empty to accept unauthenticated requests.

Env overrides: `AEGIS_RESPONDER_CONFIG` (path), `AEGIS_RESPONDER_ADDR` (default
`:8080`), `AEGIS_API_SOCKET` (overrides `socket`), `AEGIS_RESPONDER_DRYRUN=1`,
`AEGIS_RESPONDER_TOKEN` (overrides `auth_token`).

## Run
```bash
go build -o aegis-responder .
AEGIS_RESPONDER_CONFIG=./config.json ./aegis-responder    # run as the AegisBPF socket owner (root)
```
Point Falcosidekick's webhook output at it:
```yaml
# falcosidekick values
webhook:
  address: "http://aegis-responder.aegis.svc.cluster.local:8080/"
```

## Kubernetes
Run as a **DaemonSet** next to the AegisBPF agent so alerts enforce on the node
that raised them (Falcosidekick should route by node, or run one responder per
node behind a node-local Service). The responder needs read access to the agent's
control socket — mount it via `hostPath` and run as root (same uid as the agent,
which owns the `0600` socket). See [`deploy/daemonset.yaml`](deploy/daemonset.yaml).

## Prerequisites
- AegisBPF agent running with the control socket enabled:
  `AEGIS_API_SOCKET=/var/run/aegisbpf/aegisbpf.sock` (see
  [`docs/CONTROL_API.md`](../../../docs/CONTROL_API.md)).
- Falco + Falcosidekick in the cluster.

## Roadmap
- **TTL / auto-expiry** of dynamically-added denies (so a transient alert can't
  permanently wedge a path) — recommended before high-volume automated response.
- A native **Falco Talon actionner** to upstream into `falcosecurity/falco-talon`
  (this webhook responder is the standalone equivalent that needs no Talon fork).
