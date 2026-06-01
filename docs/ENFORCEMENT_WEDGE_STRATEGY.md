# Strategy: The Deterministic BPF-LSM Enforcement Wedge

> **Status:** north-star strategy (decision record + execution plan).
> **Decision date:** 2026-06-01.
> **One-line position:** *AegisBPF is the most rigorous, provable, fail-closed
> BPF-LSM enforcement primitive — synchronous in-kernel denial with an
> atomically-applied policy and published, machine-checked guarantees.*

This document records **what category we compete in, what we deliberately do
NOT build, why, and the ordered plan to get there.** It is intentionally
opinionated. Its job is to prevent scope drift.

Related: [POSITIONING.md](POSITIONING.md),
[COMPETITIVE_BENCH_METHODOLOGY.md](COMPETITIVE_BENCH_METHODOLOGY.md),
[CAPABILITY_POSTURE_CONTRACT.md](CAPABILITY_POSTURE_CONTRACT.md),
[ROADMAP_TO_EXCELLENCE.md](ROADMAP_TO_EXCELLENCE.md).

---

## 1. The decision

We compete in **one lane: kernel-level eBPF runtime enforcement** — the lane
owned today by **Tetragon** (and partly KubeArmor). We do **not** attempt to be
a networking dataplane (Cilium) or a detection ecosystem (Falco).

Within that lane we take the **enforcement slice only** ("Reading B"):

- **We own:** synchronous, fail-closed, *provably-deterministic* denial on the
  BPF-LSM surface, with an atomically-applied policy and a published,
  machine-checked posture contract.
- **We cede (on purpose):** programmable tracing-policy breadth, rich selector
  composition, process-lineage observability, and the event/telemetry pipeline.
  Those are Tetragon's, and out-building them is a losing fight.

This is **not blue ocean.** It is a defensible *position inside an occupied
lane*, won by rigor and proof — not by having more features or a unique
mechanism.

---

## 2. Verified competitive truth (don't overclaim)

Researched 2026-06-01 against Tetragon's own docs. Stated conservatively so this
document never drifts from reality.

**Tetragon's enforcement mechanisms** ([enforcement docs][t-enf]):

1. **`Override`** — overrides a function's return value so the call never
   executes. Tetragon's docs state *"only system calls and security check
   functions allow to change their return value in this manner."* It uses the
   kernel **error-injection** framework and requires
   **`CONFIG_BPF_KPROBE_OVERRIDE`** ([getting-started/enforcement][t-start]).
2. **`Sigkill`** — sends SIGKILL to the offending process. Tetragon's docs
   carry an explicit determinism caveat: *"sending a `SIGKILL` signal does not
   always stop the operation… a `SIGKILL` sent in a `write()` system call does
   not guarantee that the data will not be written to the file,"* and recommend
   combining `Signal` **with** `Override` to actually prevent the operation.

Tetragon also supports `BPF_PROG_TYPE_LSM` hooks ([hooks][t-hooks]) — so **LSM
enforcement is NOT unique to us.** We must not claim it is.

**The honest, narrow gap we exploit:**

- Tetragon's *headline* deterministic action (`Override`) carries a **kernel
  config dependency** (`CONFIG_BPF_KPROBE_OVERRIDE`, off on some distros) and a
  **function-allowlist constraint** (error-injectable functions only).
- Its always-available action (`Sigkill`) is **non-deterministic by its own
  documentation** (the `write()` race).
- It is an **observability-first** tool; it does **not publish** a fail-closed
  posture contract or per-enforcement-class end-to-end proof that denial fires.
  (Even Tetragon ships posture-detection bugs — e.g. cilium/tetragon#3872,
  "pretends LSM is not enabled but it is" — the *same* class of silent-downgrade
  bug we have hit. The problem is real and unsolved by the leader. That is the
  opening.)

**Our honest claim** therefore is about **rigor, contract, and proof** on the
LSM surface — *not* "we can do something Tetragon can't":

> On the BPF-LSM surface, AegisBPF gives synchronous fail-closed denial with an
> atomically-applied policy and a published, machine-checked posture contract —
> no `CONFIG_BPF_KPROBE_OVERRIDE` dependency, no documented `write()` race, and
> no silent downgrade to audit. Tetragon gives far more breadth; we give a
> deny primitive you can *prove*.

---

## 3. What we already have (verified in-tree, 2026-06-01)

This is a head start, not a greenfield:

- **16 BPF-LSM hooks + 5 tracepoints**: exec (`bprm_check_security`), file
  (`file_open`, `inode_permission`), `mmap_file`, `ptrace_access_check`, `bpf`,
  module-load (`kernel_read_file` + `kernel_load_data`), 6× socket
  (connect/bind/listen/accept/sendmsg/recvmsg), `inode_copy_up`, `locked_down`.
- **A real posture contract** ([CAPABILITY_POSTURE_CONTRACT.md][contract]) with:
  - `enforce_blockers` codes (`BPF_LSM_DISABLED`, `CORE_UNSUPPORTED`,
    `NETWORK_HOOK_UNAVAILABLE`, …),
  - `runtime_state` ∈ `{ENFORCE, AUDIT_FALLBACK, DEGRADED}`,
  - a **"No Pretend Enforce Invariant"** ("No valid path may claim effective
    enforce behavior while unmet blockers exist"),
  - fail-closed Helm defaults, and CI contract gates.
- **Atomic policy apply** via generation gating (expected vs committed
  generation; enforcement downgrades to audit until they match).
- **K8s-native surface already exists**: a Go operator with `AegisPolicy` /
  `AegisClusterPolicy` CRDs (exec/file/network rules, `mode: enforce|audit`
  default **audit**, label selectors) and `k8s_identity` in the agent.
- **Kernel CI seed**: `kernel-matrix.yml`, `kernel-bpf-test.yml`,
  `tests/bpf/test_bpf_prog_run.cpp`, `tests/e2e/test_bypasses.cpp`.

## 4. The gap that actually blocks us (this is the whole game)

The posture contract is excellent **on paper**, but the headline guarantee has
been **silently false in the shipped path** at least three times in recent work:

1. optional LSM hooks queried by bare name → all silently disabled (audit);
2. `policy_generation` map unpinned → live `apply` downgraded everything to
   audit cross-process;
3. daemon startup wiped the deny flags an earlier `apply` wrote → the shipped
   systemd `apply → run` order **never enforced** (fixed 2026-06-01, PR #185).

None were design flaws. All were the **same failure mode: a determinism claim
that was asserted, not proven end-to-end.** And the existing `kernel-matrix.yml`
did not catch them — it asserts only *file* deny paths (overlayfs/bind/symlink)
on a *single* "kernel-latest" runner, and never exercises the `apply → run` path
or the non-file classes (module/ptrace/bpf/exec/network).

**Closing that gap is the entire strategy.** Everything else is downstream of it.

---

## 5. Scope boundary (the discipline)

Write it down; say no to the rest.

| In scope (deepen) | Out of scope (cede / decline) |
|---|---|
| BPF-LSM hook coverage + synchronous deny path | CNI / networking dataplane (→ Cilium) |
| Fail-closed posture contract, machine-checked | Detection rule ecosystem / SIEM breadth (→ Falco) |
| Atomic, generation-gated policy apply | Multi-LSM backends: AppArmor/SELinux (→ KubeArmor) |
| Per-class end-to-end enforcement proof (CI) | Programmable arbitrary-kprobe tracing engine (→ Tetragon) |
| Public bypass catalog + regression tests | Rich selector composition / observability pipeline (→ Tetragon) |
| Kernel-compat matrix + honest capability labels | Service mesh, L7 policy, Gateway API |

**Default answer to "can it also do X?":** *"No — use the tool that owns X.
AegisBPF is the enforcement layer beneath it."* That sentence is the moat.

---

## 6. Execution plan (ordered; each step unblocks the next)

### Step 1 — End-to-end enforcement proof harness  ← **start here**
*Extend, don't rebuild,* `kernel-matrix.yml` so it is the artifact that backs
the determinism claim:

- Boot the **real shipped artifact** (packaged daemon + systemd `apply → run`
  order, the path users actually run — the one that was broken).
- For **every enforcement class** (module, ptrace, bpf, exec, file, network),
  attempt the denied action in a non-exempt cgroup and **assert the syscall
  returns `-EPERM`** and the action did not occur.
- **Negative invariant:** assert `runtime_state == ENFORCE` with no unexpected
  `enforce_blockers`; **fail the build** if anything silently degraded to
  `AUDIT_FALLBACK`/`DEGRADED`. This makes the "No Pretend Enforce Invariant"
  machine-checked instead of aspirational.
- Run across **real kernels**: 5.15, 6.1, 6.6, 6.8, 6.12 (LTS + current).
- This permanently retires the class of bug from §4.

### Step 2 — Wire capability labels to that harness
Every `ENFORCED` claim must point to a green per-class test; every
`enforce_blocker` must have a test that proves it triggers the contracted
fallback. Honesty becomes structural, not editorial.

### Step 3 — Public bypass catalog
Grow `tests/e2e/test_bypasses.cpp` into a published catalog: each bypass class →
PoC + mitigation + **regression test**. *This is the "deterministic" claim made
real* — and it is exactly what Tetragon does not publish.

### Step 4 — Flagship head-to-head proof + whitepaper
Using [COMPETITIVE_BENCH_METHODOLOGY.md][bench] and `comparison.yml`, publish a
**reproducible** demonstration of the determinism dimension. Flagship artifact:
reproduce Tetragon's own documented `write()` caveat — SIGKILL-only enforcement
permits the partial write — and show AegisBPF's LSM deny prevents it
synchronously. State fairly: Tetragon's `Override` is deterministic *where
`CONFIG_BPF_KPROBE_OVERRIDE` and an error-injectable function exist*; our LSM
path has neither dependency. Pair with a short whitepaper: threat model,
benchmarks, and **explicit limitations** (incl. BPF-LSM-absent → audit).

### Step 5 — Pilots + independent audit
Only now. Three real users with staging/production reports, then a funded audit.
These are the *output* of Steps 1–4, not parallel tasks — they are worthless
until the primitive is proven.

---

## 7. Host-first vs K8s-first (resolved)

- **Prove host/syscall-level first.** Determinism is cleanest and most
  fundamental at the kernel boundary; Step 1 is host-level and lane-agnostic.
- **Keep the existing operator/CRDs, but freeze their scope.** Do not add
  selectors/observability to chase Tetragon. `mode: audit` default stays
  (fail-safe).
- **Invest in K8s-native distribution only after the primitive is proven.**
  Tetragon's users live in Kubernetes; that is the eventual go-to-market, and
  the operator already exists, so it is not greenfield — just deferred.

Sequence: **prove at the host level → distribute at the K8s level → freeze
operator scope in between.**

---

## 8. Risks & honest costs

- **Highest proof bar of the four lanes.** Every rough edge is measured against a
  Cisco-funded product. Upside: clearing that bar on determinism yields maximal
  credibility *because* the incumbent is strong.
- **LSM enforcement is not unique to us** (Tetragon has it). Our wedge must stay
  *rigor + contract + proof*, never "a mechanism they lack."
- **Adoption is the hardest item** and cannot be shortcut; it is gated on
  Steps 1–4 producing trustable proof.
- **Kernel dependency is real**: without BPF-LSM we degrade to audit. This must
  be stated up front everywhere — never discovered by a user.

## 9. What "winning the slice" looks like

- A cold-booted node, on any supported kernel, provably returns `-EPERM` on
  every enforcement class — or loudly refuses to claim enforce.
- A public bypass catalog with a regression test per entry.
- A reproducible, fair head-to-head showing the determinism difference.
- ≥3 named adopters running it as the enforcement layer beneath their stack.
- The sentence *"we're the deny engine you put under Tetragon/Falco/Cilium"* is
  uncontested.

---

[t-enf]: https://tetragon.io/docs/concepts/enforcement/
[t-start]: https://tetragon.io/docs/getting-started/enforcement/
[t-hooks]: https://tetragon.io/docs/concepts/tracing-policy/hooks/
[contract]: CAPABILITY_POSTURE_CONTRACT.md
[bench]: COMPETITIVE_BENCH_METHODOLOGY.md
