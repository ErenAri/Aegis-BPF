# Policy Semantics

Version: 1.1 (2026-04-09)
Status: Canonical semantics reference for the v1-v5 daemon contract plus
the v0.5.0 operator policy model.

This document defines how policy rules are interpreted at runtime, including
edge cases that matter for production correctness.

## Rule model

Policy sections:
- `[deny_path]` -> canonicalized path + inode-derived deny entries
- `[deny_inode]` -> explicit `dev:ino` deny entries
- `[protect_path]` -> inode-derived protected entries (deny only for non-`VERIFIED_EXEC`)
- `[protect_connect]` -> protect all IPv4/IPv6 connect() attempts for non-`VERIFIED_EXEC`
- `[protect_runtime_deps]` -> require runtime executable mappings to preserve `VERIFIED_EXEC`
- `[require_ima_appraisal]` -> require IMA appraisal capability for enforce posture
- `[allow_cgroup]` -> cgroup exemptions (`/sys/fs/cgroup/...` or `cgid:<id>`)
- `[deny_ip]`, `[deny_cidr]`, `[deny_port]`, `[deny_ip_port]` -> network deny rules
- `[deny_binary_hash]` -> policy-apply inode deny expansion from SHA256 matches
- `[allow_binary_hash]` -> policy-apply exec inode allowlist enforced at `bprm_check_security`

Supported versions:
- `version=1` and `version=2` are accepted by parser.
- Use `version=2` for network-aware policies.
- Use `version=3` for binary hash policy sections.
- Use `version=4` for protected-resource and verified-exec policies.
- Use `version=5` for IMA appraisal posture gating (`[require_ima_appraisal]`).

## File decision semantics

In enforce-capable mode (BPF LSM enabled), file decisions are inode-driven:
1. If inode is not in `deny_inode_map` -> allow
2. If inode is in survival allowlist -> allow
3. If cgroup is in `allow_cgroup_map` -> allow
4. If rule is `protect` and process is `VERIFIED_EXEC` -> allow
5. Otherwise -> audit or deny (`-EPERM`) based on mode

In fallback tracepoint mode:
- `deny_path_map` is checked on `openat` events for audit only.
- No kernel block is possible in this path.

## Deterministic precedence and conflict resolution

File-path precedence (highest to lowest):
1. Survival allowlist entry for the current inode -> allow
2. `allow_cgroup` match -> allow
3. `deny_inode` / inode-derived deny from `deny_path` -> deny in enforce mode
4. No deny match -> allow

Network-path precedence:
1. `allow_cgroup` match -> allow (intentional bypass control)
2. If `protect_connect` is enabled and process is not `VERIFIED_EXEC` -> deny
2. Exact IP deny -> deny
3. CIDR deny -> deny
4. Port deny -> deny
5. No deny match -> allow

Startup gating:
- Enforce mode fails closed when policy-required network hooks
  (`socket_connect` and/or `socket_bind`) are unavailable.
- Enforce mode fails closed when `[require_ima_appraisal]` is active and IMA
  appraisal is unavailable.
- Audit mode logs the degraded network-hook state and continues.

Exec-identity precedence (`[allow_binary_hash]`, version 3+):
1. Kernel exec-identity mode disabled (`exec_identity_mode_map=0`) -> allow
2. Cgroup is allowlisted or inode is in survival allowlist -> allow
3. Executable inode in `allow_exec_inode_map` -> allow
4. Audit mode -> emit block/audit event only
5. Enforce mode -> deny with `-EPERM` and optional signal per `--enforce-signal`

Verified exec identity (`VERIFIED_EXEC`, version 4+):
- Computed at `lsm/bprm_check_security` on successful exec.
- For ELF executables:
  - `fs-verity` enabled (`FS_VERITY_FL`)
  - root-owned (`uid=0`)
  - not group/other writable (`mode & 022 == 0`)
  - path under trusted roots (`/usr`, `/bin`, `/sbin`, `/lib`, `/lib64`)
  - overlayfs executables are treated as unverified (fail-closed)
- For `#!` scripts:
  - both the script file and interpreter binary must satisfy the above
  - `#!/usr/bin/env ...` shebangs carry the script verification to the next
    exec and require both the script and the PATH-resolved final interpreter to
    be `VERIFIED_EXEC` (otherwise treated as unverified for protected resources)
- For interpreter inline-code execution:
  - `bash|sh|dash -c`, `python* -c`, and `node|perl|ruby -e` are treated as
    unverified for protected resources.

Runtime dependency trust (`[protect_runtime_deps]`, version 4+):
- Applies to executable mappings (`mmap` with `PROT_EXEC`) through
  `lsm/file_mmap`.
- If a currently `VERIFIED_EXEC` process maps an executable dependency that does
  not satisfy `VERIFIED_EXEC` checks, the process trust is downgraded to
  unverified.
- Mapping is allowed for compatibility, but subsequent protected-resource
  decisions (`[protect_path]`, `[protect_connect]`) fail closed in enforce mode.
- Enforce startup requires the `file_mmap` hook when this section is active.

IMA appraisal gating (`[require_ima_appraisal]`, version 5+):
- Enforce mode requires node capability `features.ima_appraisal=true`.
- If unavailable and `--enforce-gate-mode=fail-closed` (default), startup
  exits with reason `IMA_APPRAISAL_UNAVAILABLE`.
- With `--enforce-gate-mode=audit-fallback`, daemon drops to audit-only and
  reports the same reason in state-change and capability artifacts.

Conflict handling:
- Duplicate deny entries are de-duplicated by map key identity.
- `deny_path` and `deny_inode` converge to the same inode deny key when they
  refer to the same object.
- `allow_cgroup` always has explicit precedence over deny rules by design; this
  is security-sensitive and must be tightly controlled.

## Path rule normalization

When applying `deny_path` rules:
- Input path MUST be non-empty and contain no NUL byte.
- Path is canonicalized (resolves symlinks, `.`/`..`).
- Canonical path length must be `< kDenyPathMax`.
- Canonical inode is inserted into `deny_inode_map`.
- Canonical path is inserted into `deny_path_map`.
- If raw input differs from canonical path, raw path is also added to
  `deny_path_map` for observability.

Implication: enforcement follows inode identity; path entries mostly support
audit fallback and operator readability.

## Inode rule semantics

`deny_inode` rules match exact `{dev, ino}` pairs:
- Survive rename and hard-link changes.
- Are independent of textual path.
- Can be affected by inode reuse after file deletion/recreation.
- May appear under multiple path views (bind mounts, container mount
  namespaces) while still enforcing on the same inode identity.

## Cgroup allow semantics

`allow_cgroup` is an explicit bypass control:
- If process cgroup ID matches allowed entry, deny rules are skipped.
- This applies to both file and network hooks.
- Use sparingly and treat changes as security-sensitive.

## Network rule semantics

`socket_connect` match order:
1. Exact IP:port deny (`deny_ip_port_v4` / `deny_ip_port_v6`)
2. Exact IP deny (`deny_ipv4` / `deny_ipv6`)
3. CIDR deny (`deny_cidr_v4` / `deny_cidr_v6` LPM trie)
4. Port deny (`deny_port`) with protocol+direction matching

`socket_sendmsg` uses the same outbound match order when the kernel exposes the
`socket_sendmsg` hook. The remote tuple comes from `msg_name` when provided or
from connected-socket state otherwise.

`socket_accept` uses the same remote match order as `socket_connect` for the
accepted peer tuple, then falls back to local-port deny on the accepted socket.

`socket_bind` and `socket_listen` continue to apply port deny logic only.

IPv6:
- IPv6 exact and CIDR matching are enforced in connect hooks.
- AF_INET6 traffic is not default-allowed; it is evaluated by rule maps.

## Enforcement action semantics

Enforce mode always denies with `-EPERM`. Optional process signaling is
separate from the deny decision:
- `none`: deny only
- `term` (default): send `SIGTERM` + deny
- `kill`: escalate `TERM -> KILL` based on strike threshold/window
- `int`: send `SIGINT` + deny

Exec identity fallback (audit-only):
- If kernel exec-identity enforcement is unavailable, audit mode may use
  userspace hash validation on exec events.
- `--allow-unknown-binary-identity` remains break-glass behavior for hash read
  failures in this fallback path.
- Enforce mode fails closed when `[allow_binary_hash]` is active but kernel exec
  identity prerequisites are missing.

## Signed bundle semantics

For signed policies:
- Signature must verify against trusted key set.
- `policy_version` must be monotonic (anti-rollback counter).
- Bundle expiration is enforced when set.
- On successful apply, version counter is updated.

## Edge-case matrix

| Scenario | Behavior |
|---|---|
| Symlink in `deny_path` | Canonical target inode is enforced |
| File rename | Inode deny continues to apply |
| Hard link path change | Inode deny continues to apply |
| Bind mount alias | Same inode still denied; path telemetry may differ |
| Mount namespace path drift | Policy apply canonicalization uses agent namespace view |
| Inode reused after delete/recreate | Old deny entry may no longer map to intended object |
| No BPF LSM | Audit-only fallback (no block) |

## Namespace and mount consistency contract

- Policy canonicalization is resolved from the agent's mount namespace at apply
  time.
- Enforcement guarantee is inode-based, not path-string-based.
- Container/user namespace path differences do not change inode deny decisions,
  but they can change operator-facing telemetry paths.
- For Kubernetes/containers using bind mounts or overlay layers, treat inode
  rules as authoritative and path rules as operator convenience + fallback
  audit signal.

## Authoring guidance

- Prefer `deny_inode` for strict enforcement invariants.
- Use `deny_path` for operator-friendly inputs and fallback observability.
- Keep `allow_cgroup` minimal and review via security workflow.
- Treat policy changes as deployable artifacts: lint, sign, canary, then rollout.

## Operator policy model (v0.5.0+)

The Kubernetes operator (`AegisPolicy` and `AegisClusterPolicy` in
`aegisbpf.io/v1alpha1`) compiles its CRDs into the same INI format
described above. Two v0.5.0 features extend the authoring surface
without changing the daemon contract:

1. **Per-rule `action`** on `FileRule` and `NetworkRule` (`Allow` or
   `Block`, default `Block`).
2. **`spec.workloadSelector`** with the full Kubernetes `LabelSelector`
   model (`matchLabels` + `matchExpressions`), plus a separate
   `namespaceSelector` and a `matchNamespaceNames` shortcut. The
   v0.4.x `spec.selector` field is retained as deprecated and is
   reported via the `Deprecated` status condition.

### Per-rule Action and Allow > Block precedence

Rules with `action: Block` (or no action) lower to the corresponding
`[deny_*]` section. Rules with `action: Allow` lower to the matching
`[allow_*]` section:

| Rule shape          | Block section       | Allow section        |
|---------------------|---------------------|----------------------|
| `path`              | `[deny_path]`       | `[allow_path]`       |
| `ip` only           | `[deny_ip]`         | `[allow_ip]`         |
| `cidr`              | `[deny_cidr]`       | `[allow_cidr]`       |
| `port` only         | `[deny_port]`       | `[allow_port]`       |
| `ip` + `port`       | `[deny_ip_port]`    | `[allow_ip_port]`    |
| `binaryHash`        | `[deny_binary_hash]`| `[allow_binary_hash]`|

`Action: Allow` is **rejected** by the admission webhook in two cases
where the daemon has no matching allow path:

- `FileRule.inode` (no `[allow_inode]` section in the daemon)
- `FileRule` inside `protect:` (protect always implies Block)

When the operator merges all applicable policies into a single
`aegis-merged-policy` ConfigMap, it applies an **Allow > Block
precedence sweep**: any literal that appears in an `[allow_*]` section
is removed from the corresponding `[deny_*]` section. Sections that
become empty after the sweep are dropped from the merged output. This
mirrors Tetragon and KubeArmor merge semantics.

The precedence sweep operates on **literal target equality**, not on
range containment. An `allow_ip: 198.51.100.42` does **not** override a
`deny_cidr: 198.51.100.0/24`; the daemon will still block the IP via
the LPM trie. If you need a hole inside a CIDR block, allow the
matching CIDR or list each carved-out IP individually under the
narrower deny target.

Same-target Allow/Block collisions inside a **single** spec are
rejected at admission. The webhook reports the conflicting target so
authors resolve the ambiguity in source rather than relying on the
merge sweep. Cross-policy overrides (e.g. a namespaced AegisPolicy
allowing what a global AegisClusterPolicy blocks) are valid and
expected — that is the documented use case for the precedence rule.

### WorkloadSelector and namespace scope

`spec.workloadSelector` selects pods using:

- `podSelector` — a `metav1.LabelSelector` (matchLabels +
  matchExpressions, supporting `In`, `NotIn`, `Exists`,
  `DoesNotExist`).
- `namespaceSelector` — a `metav1.LabelSelector` over namespace
  labels. The well-known `kubernetes.io/metadata.name` label resolves
  by-name selection.
- `matchNamespaceNames` — convenience shortcut equivalent to a
  `namespaceSelector` with `matchExpressions[kubernetes.io/metadata.name In [...]]`.

For **namespaced AegisPolicy** the selector is always pinned to the
policy's own namespace; the admission webhook rejects any
`namespaceSelector` or `matchNamespaceNames` value that resolves
outside that namespace, with one allowed shortcut: a `namespaceSelector`
that explicitly pins to the policy's own namespace by
`kubernetes.io/metadata.name` is accepted, because it is semantically
identical to omitting the field. Use **AegisClusterPolicy** when you
need cross-namespace scope.

For v0.5.0 the operator evaluates the selector at "is there at least
one matching workload anywhere in scope?" granularity to decide whether
a policy contributes to the merged ConfigMap. Per-pod ConfigMap
sharding (per-workload enforcement) is tracked for v0.6.0; until then
the merged ConfigMap is applied node-wide.

### Backwards compatibility with `spec.selector`

The legacy `spec.selector` field (PolicySelector) is retained without
schema changes, so v0.4.x YAMLs continue to admit and reconcile. When
both `spec.selector` and `spec.workloadSelector` are set,
`workloadSelector` wins and `spec.selector` is ignored. Any policy that
still uses `spec.selector` reports a `Deprecated=True` condition with
reason `LegacySelectorInUse`; the policy itself stays Ready.

### Conditions surfaced by the operator

The status conditions used in v0.5.0 are:

| Type             | Meaning                                                  |
|------------------|----------------------------------------------------------|
| `Ready`          | Spec parsed, translated, and ConfigMap is in sync        |
| `PolicyValid`    | Spec passed validation and translation                   |
| `EnforceCapable` | Per-node enforcement readiness (default: `Unknown`)      |
| `Degraded`       | Transient/recoverable problem (e.g. ConfigMap write)     |
| `Deprecated`     | The policy uses a deprecated API surface                 |

Reason strings are stable API; see the
`api/v1alpha1` package constants for the canonical list.
