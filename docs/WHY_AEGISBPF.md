# Why AegisBPF

## TL;DR

AegisBPF is not a general-purpose eBPF observability or detection tool.
It is a **deterministic runtime enforcement engine** built on BPF LSM.

If you need detection → use Falco or Tracee.
If you need Kubernetes-native tracing → use Tetragon.
If you need **guaranteed in-kernel blocking with explicit failure semantics** → use AegisBPF.

---

## Positioning

| Need | Best Tool |
|------|----------|
| Runtime detection / alerting | Falco / Tracee |
| Kubernetes-aware tracing | Tetragon |
| Policy-based workload protection | KubeArmor |
| Deterministic LSM enforcement | **AegisBPF** |

---

## What makes AegisBPF different

### 1. Deterministic enforcement

- Uses BPF LSM `-EPERM` return path
- No userspace roundtrip
- No signal-based race conditions

### 2. Explicit failure semantics

- fail-closed vs audit-fallback
- break-glass override
- deadman TTL auto-revert

### 3. O(1) policy evaluation

- Hash/LPM map lookup
- Independent of rule count

### 4. Enforcement guarantees (provable)

Each guarantee has a reproducible test:

- file deny
- network deny
- cgroup bypass
- break-glass

---

## When NOT to use AegisBPF

- You need large rule libraries → use Falco
- You need behavioral detection → use Tracee
- You need Kubernetes-native CRD-first UX → use Tetragon/KubeArmor

---

## Strategic focus

AegisBPF is intentionally narrow:

> Minimal, verifiable, deterministic enforcement layer

Not a SIEM.
Not a detection engine.
Not a tracing platform.

This constraint is the advantage.
