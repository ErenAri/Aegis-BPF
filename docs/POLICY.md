# Policy Format (v1)

Policy files are line-oriented and ASCII-only. Lines starting with `#` are
comments. Blank lines are ignored.

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

### [deny_inode]
One entry per line in `dev:ino` format. These are enforced only when BPF LSM is
enabled (tracepoint fallback does not match inodes).

### [allow_cgroup]
One entry per line. Use a cgroup path (preferred) or `cgid:<id>` when a path is
not available.

## CLI lifecycle

- `policy lint <file>`: parse and validate formatting.
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
