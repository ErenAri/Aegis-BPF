# Policy Format (v1-v6)

Policy files are line-oriented and ASCII-only. Lines starting with `#` are
comments. Blank lines are ignored.

For normative runtime behavior (evaluation order, namespace effects, inode/path
edge cases), see `docs/POLICY_SEMANTICS.md`.

## Header

The header is a set of `key=value` pairs before any section.

Required:
- `version=<1|2|3|4|5|6>`

Notes:
- `version=1` and `version=2` remain valid for file/network rules.
- `version=3` is required when using binary hash sections.
- `version=4` is required when using exec-identity protected-resource sections.
- `version=5` is required when using IMA appraisal gating.
- `version=6` is required when using cgroup-scoped deny sections.

Example:
```
version=6
```

## Sections

### [deny_path]
One path per line. The path must exist when applying the policy because the
agent resolves the inode for enforcement. Relative paths are allowed but
discouraged.

Note: enforce decisions are inode-driven; path entries are also kept for
tracepoint-audit observability.

### [deny_inode]
One entry per line in `dev:ino` format. These are enforced only when BPF LSM is
enabled (tracepoint fallback does not match inodes).

Inode rules survive rename/hardlink changes but can be affected by inode reuse
after delete/recreate cycles.

### [allow_cgroup]
One entry per line. Use a cgroup path (preferred) or `cgid:<id>` when a path is
not available.

This section is an explicit bypass control: matching cgroups skip deny rules.

### [deny_ptrace]
Flag section with no entries. When present, ptrace attempts are blocked through
the kernel ptrace LSM hook when the hook is available.

### [deny_module_load]
Flag section with no entries. When present, kernel module load paths are blocked
through the kernel read/load LSM hooks when available.

### [deny_bpf]
Flag section with no entries. When present, BPF program-load abuse is blocked
through the kernel lockdown/BPF path when the hook is available. Use this with
`[deny_module_load]` for broader kernel-tampering coverage.

### [deny_binary_hash] (version 3+)
One entry per line in `sha256:<64-hex>` format.

During policy apply, the agent scans known executable paths and resolves matching
hashes to inode deny entries.

### [allow_binary_hash] (version 3+)
One entry per line in `sha256:<64-hex>` format.

During policy apply, hashes are resolved to executable inode identities and
stored in the kernel exec allowlist map. Runtime enforcement occurs at
`lsm/bprm_check_security`, so non-allowlisted binaries are denied before
`execve()` completes in enforce mode.

Audit-only mode can fall back to userspace exec-event validation when kernel
exec-identity enforcement is unavailable.

### [protect_connect] (version 4+)
When present, all IPv4/IPv6 `connect()` attempts are treated as a *protected
resource*:
- Processes with `VERIFIED_EXEC` identity are allowed (subject to other deny
  rules).
- Processes without `VERIFIED_EXEC` are denied in enforce mode (and audited in
  audit mode).

`VERIFIED_EXEC` is defined in `docs/VERIFIED_EXEC_CONTRACT.md`.

This is a fail-closed policy: if `--enforce` is requested but the required
kernel hooks are not available, startup fails closed by default (or falls back
to audit when `--enforce-gate-mode=audit-fallback` is configured).

### [protect_path] (version 4+)
One path per line. These are inode-resolved at policy apply time and treated as
protected resources:
- `VERIFIED_EXEC` processes may access them.
- non-`VERIFIED_EXEC` processes are denied (or audited) when a match occurs.

This section is distinct from `[deny_path]` which always denies regardless of
exec identity.

### [protect_runtime_deps] (version 4+)
When present, runtime executable mappings (`mmap(..., PROT_EXEC, ...)`) for
currently `VERIFIED_EXEC` processes must also satisfy the `VERIFIED_EXEC`
identity contract.

Behavior:
- If a process mapped an executable dependency (loader/shared object/JIT file)
  that fails `VERIFIED_EXEC` checks, the process trust is downgraded from
  `VERIFIED_EXEC` to unverified for subsequent protected-resource decisions.
- The mmap is allowed (compatibility), but protected resources (`[protect_path]`
  and `[protect_connect]`) then fail closed for that process in enforce mode.

Requirements:
- Must be used together with `[protect_connect]` or `[protect_path]`.
- Requires `lsm/file_mmap`; enforce startup fails closed (or audit-fallback if
  explicitly configured) when unavailable.

### [require_ima_appraisal] (version 5+)
When present, enforce mode requires host-level IMA appraisal policy to be
active on the node.

Behavior:
- Enforce mode fails closed if IMA appraisal is unavailable.
- With `--enforce-gate-mode=audit-fallback`, daemon transitions to
  `AUDIT_FALLBACK` and reports `IMA_APPRAISAL_UNAVAILABLE`.
- Audit mode continues and reports unmet posture in `capabilities.json`.

This section does not change exec behavior directly; it hardens protected-resource
policy posture by requiring kernel integrity appraisal capability.

### [trusted_exec_hash] (version 5+)
One `sha256:<64-hex>` digest per line — the SHA-256 of a binary's file contents
(matching the node's IMA file hash; SHA-256 is the IMA default). A non-empty
allowlist activates the in-kernel IMA-hash exec verifier
(`bpf_ima_file_hash()` in `bprm_check_security`, kernel 6.1+ with `CONFIG_IMA`):
each `execve` is hashed in-kernel and allowed only if the digest is present.

Behavior:
- In enforce mode, a binary whose IMA hash is **not** in the allowlist is denied
  (`-EPERM`); in audit mode it is logged and allowed.
- A binary that IMA cannot appraise (no hash available) **fails open** by default
  (the fs-verity exec-identity path still applies) — unless `[ima_fail_closed]`
  is set (below).
- Requires kernel 6.1+ and `CONFIG_IMA`; on older kernels the hook is not
  attached and this section has no effect.

```
[trusted_exec_hash]
sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
```

### [ima_fail_closed] (version 5+)
A flag section (no entries). When set, a binary that IMA cannot appraise is
treated as untrusted and **denied** in enforce mode instead of failing open.
Requires a non-empty `[trusted_exec_hash]` allowlist (otherwise rejected at parse
time). Use on hosts where every executable is expected to be IMA-measured.

### [deny_comm]
One executable basename per line, with a maximum of 15 bytes
(`TASK_COMM_LEN - 1`). Runtime matching is performed in `bprm_check_security`
against the basename being executed.

### [scan_paths] (version 3+)
Optional additional absolute directories to include during
`[deny_binary_hash]` and `[allow_binary_hash]` scans.

### [cgroup_deny_inode] (version 6+)
One cgroup-scoped inode deny per line:

```
<cgroup_path_or_cgid> <dev>:<ino>
```

The cgroup may be a path or `cgid:<id>`. Example:

```
cgid:12345 259:67890
```

### [cgroup_deny_ip] (version 6+)
One cgroup-scoped IPv4 deny per line:

```
<cgroup_path_or_cgid> <ipv4>
```

IPv6 is intentionally not accepted by this section in the current daemon.

### [cgroup_deny_port] (version 6+)
One cgroup-scoped port deny per line:

```
<cgroup_path_or_cgid> <port>[:<protocol>[:<direction>]]
```

`protocol` is `tcp`, `udp`, or `any`; `direction` is `egress`, `bind`, or
`both`.

## CLI lifecycle

- `policy lint <file>`: parse and validate formatting.
- `policy lint <file> --fix [--out <path>]`: emit a normalized policy file
  (sorted/deduped sections) to `<file>.fixed` by default.
- `policy apply <file> [--reset] [--sha256 <hex>|--sha256-file <path>] [--no-rollback]`:
  apply rules to pinned maps. `--reset` clears deny/allow maps and counters
  before applying. `--sha256`/`--sha256-file` enforce integrity checks. By
  default, failures trigger an automatic rollback to the last applied policy.
- `policy export <file>`: export pinned state into a v1 policy file.
- `policy show`: print the last applied policy stored at `/var/lib/aegisbpf/policy.applied`
  with an optional `# applied_sha256:` comment when available.
- `policy rollback`: apply the previous policy stored at `/var/lib/aegisbpf/policy.applied.prev`.

Environment variables:
- `AEGIS_POLICY_SHA256`: expected sha256 (hex) for `policy apply`.
- `AEGIS_POLICY_SHA256_FILE`: path to a sha256sum file for `policy apply`.

## Example
```
version=6

[deny_path]
/etc/shadow
/var/log/auth.log

[deny_inode]
2049:123456

[allow_cgroup]
/sys/fs/cgroup/my_service
cgid:10243

[allow_binary_hash]
sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef

[protect_connect]

[protect_runtime_deps]

[require_ima_appraisal]

[deny_comm]
xmrig
minerd

[protect_path]
/etc/shadow

[cgroup_deny_inode]
cgid:10243 2049:123456

[cgroup_deny_ip]
cgid:10243 10.0.0.1

[cgroup_deny_port]
cgid:10243 443:tcp:egress
```
