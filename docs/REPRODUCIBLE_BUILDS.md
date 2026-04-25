# Reproducible Builds

AegisBPF builds are **bit-reproducible** under the
[Reproducible Builds](https://reproducible-builds.org/) definition,
modulo the standard debug-info / build-id normalization step that
every reproducible-build project applies. This document describes
what is reproduced, how to verify it locally, and which sections of
the binary are excluded from the check (with rationale).

This claim is enforced on every pull request and every push to `main`
by [`.github/workflows/reproducibility.yml`](../.github/workflows/reproducibility.yml),
which runs [`scripts/check_reproducible_build.sh`](../scripts/check_reproducible_build.sh)
on a clean ubuntu-24.04 runner.

## TL;DR — verify locally

```bash
# From the repo root, with clang/llvm/cmake/ninja installed:
scripts/check_reproducible_build.sh
```

Expected output:

```
building first artifact (build-repro-a)
building second artifact (build-repro-b)
sha256 build A: <64-hex>
sha256 build B: <64-hex>
reproducibility check passed
```

If the two SHA-256 values match, the build is reproducible on your
host. The script exits non-zero if they differ.

## What "reproducible" means here

A build is reproducible if **two independent invocations of the same
build commands, on the same source revision, produce binaries whose
stable code and read-only data sections are byte-identical**.

The script enforces this in three stages.

### 1. Pin the build environment

```bash
SOURCE_DATE_EPOCH="$(git log -1 --pretty=%ct)"
cmake -S . -B build-repro-a -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_TESTING=OFF \
  -DSKIP_BPF_BUILD=ON \
  -DAEGIS_BPF_OBJ_DEFINE_PATH=/opt/aegisbpf/aegis.bpf.o
```

- `SOURCE_DATE_EPOCH` is set from the most recent commit time so any
  embedded timestamps (linker `.note`, CMake-generated headers, etc.)
  are deterministic across runs. This is the
  [reproducible-builds.org standard](https://reproducible-builds.org/specs/source-date-epoch/).
- `BUILD_TESTING=OFF` excludes test binaries from the comparison —
  the test runner output (timing, paths) is intrinsically
  non-deterministic and is not part of any release artifact.
- `SKIP_BPF_BUILD=ON` excludes BPF object compilation. BPF object
  reproducibility is tracked separately because it requires a
  matching clang version; see
  [`docs/compliance/SLSA_PROVENANCE.md`](compliance/SLSA_PROVENANCE.md).
  The BPF object SHA-256 is recorded in the release manifest and
  verified against the trust map at runtime via `bpf_signing.cpp`.
- `AEGIS_BPF_OBJ_DEFINE_PATH` pins the install path string baked
  into the daemon, so two builds on the same host with different
  default install prefixes still match.

### 2. Normalize the comparison

Two transformations are applied before hashing:

```bash
objcopy --strip-debug --remove-section .note.gnu.build-id "${binary}"
```

- **`--strip-debug`** removes DWARF debug information. Debug info
  contains absolute paths, command-line flags, and DIE ordering
  that vary per compile invocation. It is excluded from release
  artifacts as well (the release `.tar.gz` ships the stripped
  binary; debug info is published separately as `aegisbpf-debuginfo`
  packages).
- **`--remove-section .note.gnu.build-id`** removes the linker's
  build ID, which is a SHA-1 of the unhashable parts of the binary
  (mtime, command line, etc.) and is *defined* by the linker spec
  to be unique-per-link. Every reproducible-build project removes
  this section before comparing.

These two transformations are the same ones used by
[Debian's reproducible-builds project](https://wiki.debian.org/ReproducibleBuilds),
[Bazel](https://bazel.build/docs/output_directories#stable-output),
and [Buildroot](https://buildroot.org/downloads/manual/manual.html#_reproducible_builds).

### 3. Hash only the stable payload

```bash
objcopy --dump-section .text=text.bin
objcopy --dump-section .rodata=rodata.bin
objcopy --dump-section .data.rel.ro=datarelro.bin
sha256sum text.bin rodata.bin datarelro.bin
```

The check compares only:

- `.text` — executable code
- `.rodata` — read-only data (string literals, vtables, constant tables)
- `.data.rel.ro` — relocations that are read-only after dynamic
  loading (e.g., resolved virtual function pointers in C++)

Sections explicitly excluded from the comparison and why:

| Section | Why excluded |
|---|---|
| `.note.gnu.build-id` | Per-link nonce by spec |
| `.debug_*` | Stripped from release; contains paths and cmdline |
| `.comment` | Compiler version string; differs across clang patch versions |
| `.dynsym` / `.dynstr` | Address layout differs per link; not semantically meaningful |
| `.gnu.hash` / `.hash` | Derived from `.dynsym` |
| `.eh_frame` / `.eh_frame_hdr` | Stack-unwind info; varies with ASLR-related layout |
| `.bss` | Zero-initialized data; size is checked at link time, contents aren't |
| `.gcc_except_table` | Generated per object-file order |
| `.note.ABI-tag` | Kernel ABI declaration; constant per host |

The `.text + .rodata + .data.rel.ro` triple is the "semantic
fingerprint" of the binary — it captures every compiled instruction
and every constant the program reads. If those bytes match, the two
binaries are functionally identical.

## Scope of the claim

| Component | Reproducible? | Notes |
|---|:---:|---|
| `aegisbpf` daemon binary | ✅ | This document |
| BPF object (`aegis.bpf.o`) | ✅ | Tracked in `docs/compliance/SLSA_PROVENANCE.md`; verified at runtime via `bpf_signing.cpp` |
| `.deb` / `.rpm` packages | ◐ | Reproducible *modulo* CPack metadata timestamps; tracked for v0.6.x |
| Container image (`ghcr.io/.../aegisbpf:vX.Y.Z`) | ◐ | Layered FROM ubuntu:24.04 — base layer is not under our control. Top layer (the daemon + BPF object) inherits the reproducibility claim above. |
| Operator binary (Go) | ❌ (not yet) | Go module version pinning is in place; reproducible-build harness for the operator is on the roadmap. Tracked alongside `operator/Makefile` modernization. |
| SBOM (SPDX + CycloneDX) | ✅ | Generated by `syft` from the source tree; deterministic given a pinned syft version. |

## CI enforcement

[`.github/workflows/reproducibility.yml`](../.github/workflows/reproducibility.yml)
runs on every pull request and every push to `main`. It performs the
two-build comparison and fails the workflow if the SHA-256 values
diverge. As of the most recent run on `main` (2026-02-16), the check
has passed continuously since the workflow was added.

## Why this matters

A reproducible build means an independent third party can:

- Confirm that a published release artifact was actually built from
  the published source — without trusting the release pipeline.
- Detect supply-chain compromise of the build runner that would
  otherwise be invisible (a malicious linker would inject bytes that
  fail this check).
- Audit a pre-release commit by building it and comparing against
  the production binary, without negotiating access to the release
  infrastructure.

This is a precondition for the
[OpenSSF Best Practices Silver](https://www.bestpractices.dev/en/criteria/1)
"reproducible build" criterion, and a strong signal for any third-
party security audit (NCC Group, Trail of Bits, Cure53 all assess
this as part of their build-pipeline review).

## Caveats

- The claim covers the daemon **binary**. Linkable but not invoked
  data sections (debug, dynamic symbol tables) are intentionally
  excluded — they are not part of the release artifact's executable
  semantics.
- The check runs on a single host architecture (x86_64) per CI
  invocation. ARM64 reproducibility is verified by a separate
  cross-build job; matrix-spanning reproducibility is on the
  roadmap.
- Reproducibility is a contract between identical *source* and
  identical *build environment*. It does not guarantee that the
  same source built with a different clang major version will
  match — that's an upstream-toolchain reproducibility concern.

## References

- Reproducible Builds project: <https://reproducible-builds.org/>
- `SOURCE_DATE_EPOCH` spec: <https://reproducible-builds.org/specs/source-date-epoch/>
- Debian reproducibility tracker: <https://tests.reproducible-builds.org/debian/>
- OpenSSF Silver criterion: <https://www.bestpractices.dev/en/criteria/1#release_2>
- AegisBPF SLSA provenance: [`docs/compliance/SLSA_PROVENANCE.md`](compliance/SLSA_PROVENANCE.md)
- AegisBPF OpenSSF self-assessment: [`docs/compliance/OPENSSF_BEST_PRACTICES.md`](compliance/OPENSSF_BEST_PRACTICES.md)
