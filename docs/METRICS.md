# Metrics

AegisBPF exposes its enforcement state as Prometheus metrics. There are two ways
to get them — pick one:

## 1. Built-in HTTP endpoint (opt-in)

Set `AEGIS_METRICS_ADDR` on the agent and it serves the exposition over HTTP:

```bash
AEGIS_METRICS_ADDR=127.0.0.1:9635 aegisbpf run --enforce
curl -s http://127.0.0.1:9635/metrics
```

- `GET /metrics` → Prometheus exposition (`text/plain; version=0.0.4`).
- `GET /healthz` → `ok` (liveness).
- Off unless `AEGIS_METRICS_ADDR` is set. The daemon reuses its already-loaded
  BPF state, so a scrape does not reload anything.

**Security.** The endpoint has no authentication (standard for a Prometheus
scrape target). Bind **loopback** (`127.0.0.1:9635`) unless a scraper needs the
node/pod IP; to expose it, bind `:9635` (all interfaces) and restrict access with
a firewall or Kubernetes `NetworkPolicy`. In Kubernetes, add a container port and
a `ServiceMonitor`/`PodMonitor` pointing at `/metrics`.

## 2. node_exporter textfile collector (no open port)

If you'd rather not open a port, write the exposition to a file that
node_exporter serves. Ships as a systemd timer:

```bash
systemctl enable --now aegisbpf-metrics.timer   # runs `aegisbpf metrics` every 30s
```

It writes `${AEGIS_METRICS_TEXTFILE}` (default
`/var/lib/node_exporter/textfile_collector/aegisbpf.prom`) atomically (temp +
rename). Point node_exporter at that directory with
`--collector.textfile.directory`. You can also run it by hand:

```bash
aegisbpf metrics --out /var/lib/node_exporter/textfile_collector/aegisbpf.prom
aegisbpf metrics            # or just print to stdout
aegisbpf metrics --detailed # high-cardinality per-path / per-inode / per-ip series
```

## What's exposed

Low-cardinality by default (35+ families), read straight from the pinned BPF
maps and agent state. Highlights:

| Metric | Type | Meaning |
|---|---|---|
| `aegisbpf_blocks_total` | counter | Total blocked file operations |
| `aegisbpf_ringbuf_drops_total` | counter | Dropped ring-buffer events |
| `aegisbpf_net_blocks_total{type=…}` | counter | Blocked network ops by direction |
| `aegisbpf_deny_inode_entries` / `aegisbpf_deny_path_entries` | gauge | Active file-deny map sizes |
| `aegisbpf_deny_ttl_entries` | gauge | Control-API denies with a pending TTL (auto-expiry) |
| `aegisbpf_map_utilization{map=…}` | gauge | Per-map fill ratio (capacity pressure) |
| `aegisbpf_runtime_state{state=…}` | gauge | Posture: ENFORCE / ENFORCE_SIGNAL / AUDIT_FALLBACK / DEGRADED |
| `aegisbpf_hook_latency_max_ns` | gauge | Worst-case LSM hook latency |
| `aegisbpf_backpressure_*` | counter | Dual-path telemetry submit/drop counters |
| `aegisbpf_enforce_capable` | gauge | Whether the kernel/config can enforce |

`--detailed` (CLI) adds high-cardinality per-path / per-inode / per-ip / per-port
series — use sparingly.

> **Note.** Daemon in-process health counters (e.g. `pin_heal_*`) are surfaced via
> structured logs today; exposing them as metrics is a planned follow-up (the
> counters are made scrape-safe first).
