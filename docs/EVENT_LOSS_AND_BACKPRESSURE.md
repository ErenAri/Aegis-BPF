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
