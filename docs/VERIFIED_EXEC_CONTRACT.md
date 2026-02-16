# Verified Exec Contract (VERIFIED_EXEC)

Status: **contract**

This document defines the **VERIFIED_EXEC** identity used by protected-resource
policies (`[protect_connect]`, `[protect_path]`).

## What VERIFIED_EXEC Means

A process is `VERIFIED_EXEC` when its current image is kernel-attributable as:

- **Immutable on disk**: `fs-verity` is enabled on the executable (`FS_VERITY_FL`).
- **Owned by root**: `uid=0`.
- **Not group/other writable**: `mode & 022 == 0`.
- **Under trusted roots**: path begins with one of:
  - `/usr/`, `/bin/`, `/sbin/`, `/lib/`, `/lib64/`
- **Not overlayfs**: overlay-backed executables are treated as unverified.

`VERIFIED_EXEC` is computed on successful `execve()` via the kernel hook
`lsm/bprm_check_security` and is inherited across `fork()` until the next exec.

## Script Semantics (`#!`)

For `#!` scripts:

- The **script file** and the **interpreter binary** must both satisfy the
  `VERIFIED_EXEC` definition above.

### `#!/usr/bin/env ...` Shebangs

`/usr/bin/env` resolves the final interpreter via `PATH`, which is not directly
kernel-attestable at the initial script exec.

Contract behavior:

- The script's `VERIFIED_EXEC` result is recorded when `/usr/bin/env` is
  executed for the shebang.
- On the *next exec in the same PID* (the final interpreter that `env` execs),
  the process is treated as `VERIFIED_EXEC` only if:
  - the script file was `VERIFIED_EXEC`, and
  - the final interpreter binary is `VERIFIED_EXEC`.

If either check fails, the process is treated as **unverified** for protected
resources (fail-closed).

## Interpreter Inline-Code Semantics (`-c` / `-e`)

To prevent bypass via runtime-provided code, processes are treated as unverified
for protected resources when invoked with inline-code flags:

- `bash|sh|dash -c`
- `python* -c`
- `node|perl|ruby -e`

## How Protected Resources Use VERIFIED_EXEC

When a policy enables protected resources (version 4+):

- `[protect_connect]`: all IPv4/IPv6 `connect()` attempts require `VERIFIED_EXEC`.
- `[protect_path]`: accesses matching protected inodes require `VERIFIED_EXEC`.

In enforce mode, non-`VERIFIED_EXEC` attempts are denied with `-EPERM`. In audit
mode, they are audited (events emitted) but allowed.

If enforce is requested but the required kernel hooks are unavailable, startup
fails closed by default (or falls back to audit if explicitly configured via
`--enforce-gate-mode=audit-fallback`).

## Runtime Dependency Trust (`[protect_runtime_deps]`)

When a policy enables `[protect_runtime_deps]`, `VERIFIED_EXEC` must remain
true across runtime executable dependencies (loader/shared objects/mapped
executable files):

- Hook: `lsm/file_mmap`
- Scope: mappings with `PROT_EXEC`
- Rule: if a currently `VERIFIED_EXEC` process maps a file that does not satisfy
  `VERIFIED_EXEC`, process trust is downgraded to unverified.

Enforcement behavior:

- mmap is kept **allow** for compatibility.
- protected resource decisions then fail closed for that process:
  - `[protect_connect]` => connect denied
  - `[protect_path]` => protected file access denied

Startup gating:

- In enforce mode with `[protect_runtime_deps]`, missing `file_mmap` hook is a
  capability blocker.
- Default behavior is fail-closed (or explicit audit fallback with
  `--enforce-gate-mode=audit-fallback`).

## Enabling fs-verity

Prerequisites:

- File must be on an `fs-verity` capable filesystem (commonly `ext4` or `f2fs`).
- The file must be finalized (enable verity after writing).

Example:

```bash
sudo apt-get install -y fsverity
sudo chown root:root /usr/local/bin/mytool
sudo chmod 0755 /usr/local/bin/mytool
sudo fsverity enable /usr/local/bin/mytool
```

## Non-Goals / Known Limits

- This contract does **not** integrate with IMA appraisal/measurement yet.
- Containers using overlayfs for executables are treated as unverified.
