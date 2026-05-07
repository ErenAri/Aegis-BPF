# Event Loss and Backpressure

## Problem

All eBPF-based systems rely on ring buffers.
Under load, events may be dropped.

## Key principle

**Enforcement and telemetry are independent.**

- Enforcement (LSM) → always executed in kernel
- Telemetry (ring buffer) → may drop under pressure

## What event loss means

| Mode | Impact |
|------|--------|
| Audit mode | Missing logs only |
| Enforce mode | Blocking still works |

## Metrics

Expose:

- ring_buffer_drops_total
- events_total
- drop_ratio

## Recommended thresholds

- <0.01% → normal
- 0.01–0.1% → investigate
- >0.1% → alert

## Operational response

1. Increase ring buffer size
2. Reduce event verbosity
3. Scale node resources

## Guarantee

> AegisBPF never disables enforcement due to telemetry loss

## Ring buffer overflow policy (operator-visible contract)

Until v0.x the daemon's behaviour on `bpf_ringbuf_reserve` failure was
implicit. From this release onward it is a named, operator-selectable
policy that is logged at startup and can be locked in by the deployment.

### Selecting the policy

```
aegisbpf run --ringbuf-overflow-policy=priority-fallback
# or, equivalently, via env var (e.g. in the systemd unit):
AEGIS_RINGBUF_OVERFLOW_POLICY=priority-fallback
```

The CLI flag accepts both kebab-case (`priority-fallback`) and the
underscore alias (`priority_fallback`); parsing is case-insensitive.

### Supported policy

| Policy | Status | Behaviour |
|---|---|---|
| `priority-fallback` | **Supported (default)** | Security-critical events (blocks, kernel security, forensics) reserve from the *priority* ringbuf first; on failure they fall back to the *main* ringbuf and increment `aegisbpf_backpressure_priority_drops_total`. Telemetry events (exec) use the main ringbuf directly and are dropped first under load (`aegisbpf_backpressure_telemetry_drops_total`). This is the same dual-path behaviour used in soak validation. |

### Reserved roadmap policies

These names are recognised by the parser but are **not yet implemented**.
Asking for them at startup causes the daemon to refuse to start with a
"reserved for a future release" error rather than silently falling
through to the default — operators always know which policy is active.

| Policy | Roadmap | Intended behaviour |
|---|---|---|
| `sample` | Phase 2 | Apply a deterministic rate-limit at the BPF side before reserve, so overload sheds events evenly across event types instead of tail-dropping. |
| `spool-to-disk` (alias `spool`) | Phase 3 | When both ringbufs are full, append a compact serialised event to a bounded on-disk spool ring and drain it on the next read cycle. Trades disk I/O for zero-loss telemetry under bursts. |

### Verifying the active policy

At daemon start the policy and its description are emitted as a
structured INFO log line:

```
[INFO] Ringbuf overflow policy {policy=priority-fallback, description="security-critical events use the priority ringbuf and fall back to the main ringbuf on pressure; telemetry is shed first"}
```

Operators should grep for this line in their journal pipeline to assert
the policy did not change between releases.

### Why this is a contract, not an implementation detail

The implicit dual-path behaviour has shipped since the priority ringbuf
landed, but it was never named or pinned. Naming it and reserving the
roadmap values means:

1. A future release that introduces `sample` cannot silently change the
   default — operators have to opt in.
2. The startup log + Prometheus metrics already in place
   (`aegisbpf_backpressure_priority_drops_total`,
   `aegisbpf_backpressure_telemetry_drops_total`) are now anchored to a
   documented policy name, so alerts/runbooks can reference it.
3. CI rejection tests assert that unknown / reserved names exit non-zero
   so a typo in a config-management template is loud, not silent.
