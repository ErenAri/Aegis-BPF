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

## Bounded time-window event dedup (operator-tunable)

A misbehaving binary can hammer the same denied path/inode at tens of
thousands of events per second. Each duplicate is an honest report
of an honest event, but the SIEM sees the same record N times and
real signal drowns in volume. AegisBPF ships an opt-in, in-process
deduper for **block events** to coalesce these bursts without
losing accountability.

### Selecting the policy

```
aegisbpf run --event-dedup-window-ms=5000 --event-dedup-max-entries=4096
# or, equivalently, via env vars (e.g. in the systemd unit):
AEGIS_EVENT_DEDUP_WINDOW_MS=5000
AEGIS_EVENT_DEDUP_MAX_ENTRIES=4096
```

The default is `--event-dedup-window-ms=0`, which disables the
deduper completely; existing deployments see no behaviour change
unless they opt in.

### Dedup contract

Within the active window, identical block events keyed on
`(event_class, cgid, inode, pid, dev)` are suppressed. The first
emit *after* the window expires for that key carries a
`"suppressed_during_prior_window": N` field showing how many
emissions were collapsed during the previous window — the count is
**always reported on the next emit**, never silently dropped.

| Phase | Behaviour |
|---|---|
| Window disabled (`--event-dedup-window-ms=0`) | Every event emitted as today; no per-event JSON augmentation |
| First sighting of a key | Emitted immediately, no augmentation |
| Duplicates inside the active window | Suppressed (no stdout, no journald), counter incremented |
| First event after window expires | Emitted with `suppressed_during_prior_window` field carrying the prior-window count, then a fresh window starts |
| Table at `--event-dedup-max-entries` capacity, brand-new key arrives | Oldest entry evicted; `evictions()` increments. Lost suppression count is observable via that counter, not silent |

### What this is *not*

- **Not enforcement-affecting.** The BPF LSM hook still returns
  `-EPERM` on every duplicate. The kernel blocks every attempt;
  dedup only collapses the userspace log line.
- **Not enabled by default.** Operators who depend on every block
  event being reported individually keep that behaviour by leaving
  the default in place.
- **Not OCSF-augmented (yet).** When `--event-format=ocsf` is in
  effect, dedup *suppression* still works (duplicates are dropped
  inside the window) but the OCSF payload does not carry the
  prior-window count today; this surfaces only in the Aegis-native
  JSON. OCSF schema augmentation is a tracked follow-up.
- **Not applied to network, exec, forensic, kernel, or
  state-change events.** Only `BlockEvent`. Other event classes
  remain untouched until their own dedup keys are vetted.

### Why this is in the daemon, not the SIEM

A SIEM-side dedup is post-hoc and lossy: by the time the events
arrive, network and disk have already paid the cost of the
duplicate noise, and rate limits on the SIEM ingest pipeline can
drop original signal events to make room for duplicates of one
runaway process. Coalescing in the daemon, before the events
leave the host, keeps the cost proportional to *distinct* threat
signal.
