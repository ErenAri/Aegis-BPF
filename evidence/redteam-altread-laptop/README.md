# Alternate-read-path red-team (laptop, kernel 6.17)

A second adversarial battery, complementary to `scripts/redteam_bypass.sh`. Where the
bypass suite attacks **path aliasing** (hardlink / symlink / bind-mount / rename /
TOCTOU), this one attacks the other axis: reaching a denied file's **content** through
read paths that do not look like a plain `open()` — the places an LSM file gate most
plausibly has a hole.

## Why these vectors

AegisBPF gates the read path with **two** inode-keyed LSM hooks — `lsm/file_open` and
`lsm/inode_permission`, both keyed on `{i_ino, i_sb->s_dev}`. Every VFS open, however it
is issued, funnels through `may_open()` → `inode_permission` and `security_file_open`, so
a correct implementation denies all of these. The interesting question is whether an
*asynchronous* or *handle-based* open slips past — historically the richest source of
LSM-bypass CVEs.

| vector | why it's a candidate | verdict |
|---|---|---|
| **io_uring `OPENAT` + `READ`** | async submission runs in an `io-wq` kernel-worker context; historically bypassed LSM/audit | **BLOCKED** (`OPENAT` → `-EPERM`) |
| **`open_by_handle_at`** | reopens by NFS-style file handle, skipping path lookup entirely | **BLOCKED** (`-EPERM`) |
| **`openat2`** | the newer open syscall with `RESOLVE_*` flags — a distinct entry point | **BLOCKED** |

All three denied. No enforcement hole found on 6.17.

### The io_uring result has teeth

A `-EPERM` from io_uring proves nothing if the ring never worked. The captured run
includes a **positive control**: the same helper doing `OPENAT` + `READ` on an
*unblocked* file **succeeds** — `res=4 (opened)`, `READ res=31`, returns the marker
bytes. So the blocked-case denial is real enforcement acting on a working async path,
not an incidental setup failure.

## Honest boundaries (expected ALLOWED — documented, not bugs)

These are the shape of *any* open-time inode LSM, asserted explicitly so the limits are
visible rather than hidden:

| boundary | why it is allowed | the real defense |
|---|---|---|
| **pre-block fd survives** | an fd opened **before** the rule keeps working; `read()` on an open fd re-triggers neither hook. Deny is not retroactive. | add the rule before the workload starts; the agent's policy is loaded at boot |
| **raw block-device read** | reading the backing block device bypasses the VFS; the target inode's hooks never fire (a *different* inode is opened). Confirmed by grepping the loop device for the marker. | block-level controls — dm-verity / disk encryption — not a file LSM's job |

A note on `process_vm_readv` / `ptrace`: reading another process's memory is **not** a
file-deny bypass (no `file_open` on the target inode occurs). It is governed by a
separate hook, `lsm/ptrace_access_check` + the `deny_ptrace` policy knob, and is out of
scope for this file battery.

## Artifacts

- `run.log` — full captured run: the 6-row harness table (6/6) **plus** the io_uring
  positive control, with host / LSM / agent-version / UTC-timestamp header.
- Harness: `scripts/redteam_altread.sh` (self-contained; compiles a small C helper for
  the io_uring and `open_by_handle_at` probes, uses a loopback ext4 fs for the raw-device
  test, self-cleans).

## Reproduce

```bash
# Build the BPF object from source against this kernel first (SKIP_BPF_BUILD=OFF), then:
sudo BIN=./build/aegisbpf bash scripts/redteam_altread.sh
# exit 0 iff every vector matched its expectation (3 BLOCKED bypass candidates,
# 2 ALLOWED documented boundaries)
```

## Caveats

- **One kernel (6.17).** io_uring's LSM coverage has shifted across releases; older
  kernels (5.6–5.11 era) are exactly where an async-open gap could exist. Cross-kernel
  confirmation needs the kernel matrix — a single laptop cannot cover it.
- Scope is **file-content read** bypasses. Write/exec paths and the network hooks are
  covered by other batteries.
