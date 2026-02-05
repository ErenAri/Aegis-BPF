# Policy Format (v1)

Policy files are line-oriented and ASCII-only. Lines starting with `#` are
comments. Blank lines are ignored.

For normative runtime behavior (evaluation order, namespace effects, inode/path
edge cases), see `docs/POLICY_SEMANTICS.md`.

## Header

The header is a set of `key=value` pairs before any section.

Required:
- `version=1`

Example:
```
version=1
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
version=1

[deny_path]
/etc/shadow
/var/log/auth.log

[deny_inode]
2049:123456

[allow_cgroup]
/sys/fs/cgroup/my_service
cgid:10243
```
