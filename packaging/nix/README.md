# Nix packaging

A hermetic Nix build of the AegisBPF agent (the `aegisbpf` binary + `aegis.bpf.o`
+ systemd unit + example config).

## Build

```bash
nix-build packaging/nix/test-default.nix     # -> ./result/bin/aegisbpf
```

This pins nixpkgs, feeds the checked-in `vmlinux.x86_64.h`, and uses an unwrapped
LLVM-18 clang for the BPF object (see notes below).

## Files

- `package.nix` — the derivation (`callPackage`-style). Inputs: `cmake`,
  `pkg-config`, `clang` (unwrapped), `bpftools`, `libbpf`, `elfutils`, `zlib`,
  `zstd`, `linuxHeaders`, plus a `vmlinuxHeader` (defaults to the checked-in one).
- `test-default.nix` — pins nixpkgs and calls `package.nix` with the LLVM-18
  unwrapped clang; the local build entry point.
- `vmlinux.x86_64.h` — pre-generated CO-RE header (`bpftool btf dump file
  /sys/kernel/btf/vmlinux format c`). CO-RE relocates field offsets against the
  *target* kernel at load time, so the compile-time header only needs to define
  the referenced types — a single checked-in header keeps the build reproducible
  and hermetic (no `/sys/kernel/btf` dependency).

## Why these specific inputs

- **`-DVMLINUX_H=`** — upstream CMake flag (added for this) that supplies a
  pre-generated `vmlinux.h` instead of dumping the running kernel's BTF, so the
  BPF object builds in a sandbox with no `/sys/kernel/btf`.
- **unwrapped clang** — the stdenv cc-wrapper injects hardening flags
  (`-fzero-call-used-regs`, …) the `bpf` target rejects; unwrapped clang compiles
  with exactly `-target bpf`. `linuxHeaders` via `CPATH` supplies `asm-generic/*`.
- **LLVM 18** — newer LLVM regresses BPF stack usage past the 512-byte verifier
  limit; 18 matches the project's tested clang matrix.
- **`ENABLE_RUST_PARSER_LINK=OFF`** (default) — no cargo/Rust needed; the daemon
  is byte-identical without the diagnostic Rust shadow.

## nixpkgs

`package.nix` here is the reference/local expression. The `NixOS/nixpkgs`
submission lives under `pkgs/by-name/ae/aegisbpf/` and fetches a pinned tag via
`fetchFromGitHub`, reusing the same build logic.
