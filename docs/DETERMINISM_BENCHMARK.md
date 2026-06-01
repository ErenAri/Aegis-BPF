# Determinism Benchmark Methodology

> **Status:** Step 4 of [ENFORCEMENT_WEDGE_STRATEGY.md](ENFORCEMENT_WEDGE_STRATEGY.md).
> **Scope:** enforcement **determinism**, not performance overhead. For the
> overhead methodology see [COMPETITIVE_BENCH_METHODOLOGY.md](COMPETITIVE_BENCH_METHODOLOGY.md).

This document defines how we compare enforcement *determinism* across eBPF
runtime-security tools, and records what we **measure** on our own agent versus
what we **cite** from peer documentation. We do not publish numbers we did not
produce. (See "Measured vs cited" below.)

## 1) Why determinism, not just overhead

The enforcement wedge (vs Tetragon) is *determinism*: does the denied operation
get prevented **in-kernel before it executes**, or is it stopped **after the
fact** by terminating the process? The latter is collateral (the whole process
dies) and — per Tetragon's own documentation — does not guarantee the operation
did not already complete.

## 2) Mechanism taxonomy

Every enforcement decision falls into one of three classes:

| Class | Mechanism | Operation prevented? | Dependency | Scope |
|-------|-----------|----------------------|------------|-------|
| **S-LSM** | BPF-LSM hook returns `-EPERM` | Yes, synchronously in-kernel | BPF-LSM present | operation-scoped; caller gets EPERM |
| **S-OVR** | kprobe return-override (error injection) | Yes, synchronously | `CONFIG_BPF_KPROBE_OVERRIDE` + error-injectable function | operation-scoped |
| **A-SIG** | post-hoc signal (e.g. SIGKILL) to the process | **Not guaranteed** — race with the syscall | signal delivery | process-collateral |

## 3) Tool / mode → class mapping

| Tool / mode | Class | Notes |
|-------------|-------|-------|
| **AegisBPF** default (`--enforce`) | **S-LSM** | primary mechanism; `-EPERM` from the LSM hook, no kernel-config dependency |
| AegisBPF `--enforce-signal=term\|kill` | S-LSM **+** optional A-SIG escalation | the deny already happened via `-EPERM`; the signal is **additive**, not the enforcement |
| AegisBPF `--enforce-fallback=signal` (no-LSM hosts only) | A-SIG | explicitly a weaker tier; the daemon will not claim ENFORCE on a genuinely no-LSM host (No-Pretend invariant) |
| **Tetragon** `Override` | S-OVR | requires `CONFIG_BPF_KPROBE_OVERRIDE` and an error-injectable function ([docs][t-start]) |
| **Tetragon** `Sigkill` | A-SIG | always available; post-hoc; *"a `SIGKILL` sent in a `write()` ... does not guarantee that the data will not be written"* ([docs][t-enf]) |

The key claim is narrow and defensible: **AegisBPF's default, always-on
mechanism is the synchronous class (S-LSM) with no kernel-config or
function-allowlist dependency.** Tetragon's synchronous class (S-OVR) is gated on
`CONFIG_BPF_KPROBE_OVERRIDE`; its dependency-free class (A-SIG) is post-hoc.
AegisBPF's own A-SIG path exists only as a no-LSM fallback and never masquerades
as enforce.

## 4) The determinism metric

For a denied operation, record:

1. **Prevented in-kernel?** Did the syscall return an error without executing?
2. **Config dependency?** Does prevention require a non-default kernel option?
3. **Scope:** operation-scoped (caller gets an error it can handle) or
   process-collateral (whole process terminated)?
4. **Caller-observable?** Can the caller see and handle the denial?

S-LSM scores yes / none / operation-scoped / yes. A-SIG scores no(not
guaranteed) / n-a / process-collateral / no.

## 5) Reproducible procedure — AegisBPF side (MEASURED)

`tests/enforcement/determinism_demo.sh` boots the real artifact and attempts a
denied `connect()` from a non-exempt cgroup in two modes. Sample run on
Linux 6.17 (`--enforce-signal=none` vs `=term`):

```
AegisBPF mode                                | probe observable           | process exit
---------------------------------------------+----------------------------+-------------
A: -EPERM only  (--enforce-signal=none)      | RESULT eperm_survived      | 0
B: -EPERM + SIGTERM (--enforce-signal=term)  | <process-terminated>       | 143 (SIGTERM)
```

Reading: in **both** modes the connect is denied **synchronously** with `-EPERM`
(class S-LSM) — the operation never executes. In A the caller receives EPERM and
**survives** to handle it; in B an **optional** SIGTERM additionally terminates
the process. The signal is escalation layered on top of an already-synchronous
deny — it is never the thing that prevents the operation.

Run it yourself:

```bash
sudo AEGIS_BIN=build/aegisbpf AEGIS_BPF_OBJ=build/aegis.bpf.o \
  bash tests/enforcement/determinism_demo.sh
```

## 6) Reproducible procedure — Tetragon side (RUNNABLE; not run here)

We do **not** ship Tetragon measurements we did not produce. To reproduce the
contrast on a host with Tetragon installed:

1. Install Tetragon (the project's `scripts/install_peer_tools.sh tetragon`
   covers this for the comparison harness).
2. Apply a `TracingPolicy` that enforces on the connect path with a `Sigkill`
   action (class A-SIG). Consult the current
   [Tetragon enforcement docs][t-enf] for exact `matchActions` syntax — we
   intentionally do not inline a possibly-stale CRD here.
3. Attempt the denied `connect()` and observe: the process is terminated, and
   (per the `write()` example in Tetragon's docs) for write-class operations the
   side effect is **not guaranteed** to be prevented.
4. For the synchronous comparison, repeat with an `Override` action and note the
   `CONFIG_BPF_KPROBE_OVERRIDE` requirement and the error-injectable-function
   constraint.

## 7) Measured vs cited

- **Measured (this repo, this kernel):** AegisBPF S-LSM behavior — synchronous
  `-EPERM`, caller survival, optional signal escalation. Reproduced by
  `determinism_demo.sh` and the per-class proofs in `enforcement_proof.sh`.
- **Cited (peer documentation):** Tetragon's `Override` config dependency and
  `Sigkill` post-hoc semantics, quoted from Tetragon's own docs ([enforcement][t-enf],
  [getting-started][t-start]).

## 8) What this methodology cannot tell you

- It does **not** rank tools on detection breadth, observability, or features —
  only on the determinism of the enforcement mechanism.
- It does **not** measure Tetragon performance or claim Tetragon fails to block;
  Tetragon's `Override` is genuinely synchronous where its kernel prerequisites
  hold. The claim is strictly about *default-available* determinism and
  dependencies.
- A real cluster-scale head-to-head (policy churn, many workloads) is the
  domain of the comparison harness (`comparison.yml`), not this microbenchmark.

[t-enf]: https://tetragon.io/docs/concepts/enforcement/
[t-start]: https://tetragon.io/docs/getting-started/enforcement/
