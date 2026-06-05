# Enforcement-grade soak evidence (laptop, kernel 6.17)

Real BPF-LSM enforcement run on bare-metal hardware, capturing the property that
matters for an *enforcement* agent: **enforcement held under sustained load with
zero missed decisions**, while the agent stayed leak-free and lossless.

## Environment

| | |
|---|---|
| Kernel | `6.17.0-35-generic` |
| LSM | `lsm=landlock,lockdown,yama,apparmor,bpf` (BPF-LSM **active**) |
| BTF | kernel built-in (`/sys/kernel/btf/vmlinux`) |
| Concurrent load | a live `kind` Kubernetes cluster on the same host — i.e. a real exec/file event firehose, not a synthetic-clean box |
| Agent | `aegisbpf 0.8.0`, BPF object compiled from source against the live kernel BTF |

## What each artifact proves

| file | mode | result | what it demonstrates |
|---|---|---|---|
| `enforce-headline-180s.json` | enforce | **pass** | 180 s, **779,431 denials this run** (~4,330/s), **canary 0 misses / 12 checks**, RSS growth **0 KB**, ringbuf drops **0**, drop ratio **0.000%** |
| `canary-teeth-no-enforcement.json` | enforce, rule absent | **fail** (by design) | the in-band canary is not theater: with enforcement absent, **6/6 reads leaked** and the soak **failed** |
| `canary-real-enforcing.json` | enforce, rule active | **pass** | the same 60 s run with enforcement on: **0/6 leaked**, honest delta **245,733 denials** |
| `audit-180s.json` | audit | **pass** | telemetry-pipeline stability under the firehose: 787K events, **0 drops**, **0 KB** RSS growth (run before the delta/canary harness fix, so its count is the absolute cumulative counter) |

The teeth/real pair is the point: a canary that cannot fail proves nothing. This
one **fails when enforcement is absent and passes when it holds** — verified
adversarially in the same session.

## The in-band enforcement canary

`scripts/soak_reliability.sh` was upgraded so an *enforce*-mode soak does more than
watch counters move — every poll it attempts to read the blocked path and **asserts
the read is denied**. Any success is a *missed enforcement decision* and fails the
soak (`enforce_canary_misses > 0` → `pass: false`). It also now baselines the
**pinned, cumulative** decision counter and reports the per-run **delta**
(`decisions_this_run`) instead of the misleading absolute value.

## Honest caveats (what this is NOT)

- **Duration:** 180 s (and 60 s validation), not the 24 h / 168 h tiers. Flat RSS
  here means no *fast* leak and the harness is sound; a *slow* leak needs a long run
  (same command, `DURATION_SECONDS=86400`).
- **One kernel.** This is 6.17 only. Cross-kernel behaviour (5.15 / 6.1 / 6.8 / RHEL)
  needs the kernel matrix — a single laptop cannot cover it.
- **Load shape** is the host's real k8s churn plus 4 file workers — realistic, but
  not a controlled rate. The denial count is the workers hammering the blocked inode.
- The companion `scripts/redteam_bypass.sh` separately proves the denial is *real*
  (hardlink / symlink / `/proc/self/fd` / bind-mount / rename / TOCTOU all blocked,
  13/13) — this soak proves it *holds under sustained load*.

## Reproduce

```bash
# Build the BPF object from source against this kernel, then:
sudo env AEGIS_BIN=./build/aegisbpf SOAK_MODE=enforce SOAK_ENFORCE_SIGNAL=none \
  SOAK_BLOCK_PATH=/tmp/scratch/target DURATION_SECONDS=180 WORKERS=4 \
  OUT_JSON=/tmp/out.json bash scripts/soak_reliability.sh
# (create /tmp/scratch/target first; never point SOAK_BLOCK_PATH at a system file in enforce mode)
```
