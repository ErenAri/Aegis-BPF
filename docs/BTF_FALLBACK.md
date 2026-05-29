# BTF fallback for kernels without `/sys/kernel/btf/vmlinux`

CO-RE (Compile Once -- Run Everywhere) BPF programs need a BTF blob to
relocate field offsets at load time. Modern kernels (>= 5.4 on most
distros, >= 5.8 on RHEL/CentOS Stream) ship their own at
`/sys/kernel/btf/vmlinux`. Older or stripped-down kernels don't, and
the BPF object will fail to load with errors like:

```
libbpf: failed to find valid kernel BTF
libbpf: Error loading BTF: No such file or directory
```

`aegisbpfd` carries a multi-step fallback that lets it run on those
kernels provided you supply a matching BTF blob -- either manually or
via automatic download from BTFhub-archive.

## Resolution order

`aegisbpfd` resolves the BTF blob at startup via
[`src/btf_loader.cpp`](../src/btf_loader.cpp). First hit wins:

| # | Location | Source tag | When to use |
|---|----------|------------|-------------|
| 1 | `$AEGIS_BTF_PATH` | `override` | Operator-driven explicit path; useful for CI matrices and air-gapped hosts. |
| 2 | `/sys/kernel/btf/vmlinux` | `kernel` | Default on any modern kernel; nothing to install. |
| 3 | `/lib/modules/<release>/btf/vmlinux` | `modules` | Some Debian/Ubuntu kernels ship BTF here even when `/sys/kernel/btf` is absent (`linux-image-extra-*`). |
| 4 | `/var/lib/aegisbpf/btfs/<release>.btf` | `var-lib` | Runtime-writable cache; populate via `btfgen.sh`, `aegisbpfctl btf install`, or a post-install hook. |
| 5 | `/usr/lib/aegisbpf/btfs/<release>.btf` | `usr-lib` | Package-shipped BTF blobs (e.g. RPM/DEB carrying a curated set of kernels). |
| 6 | `/etc/aegisbpf/btfs/<release>.btf` | `etc` | Operator-managed, follows the same convention as `/etc/aegisbpf/keys.d/`. |
| 7 | BTFhub-archive auto-download | `btfhub-download` | Opt-in via `AEGIS_BTF_AUTO_DOWNLOAD=1`. Downloads and caches in `/var/lib/aegisbpf/btfs/`. |

`<release>` is the output of `uname -r`, e.g.
`5.10.0-21-amd64` or `4.18.0-553.el8_10.x86_64`.

If none of the above are readable, the daemon emits:

```
WARN No BTF found; CO-RE relocations will likely fail
  kernel_release=4.18.0-553.el8 searched=/lib/modules/...:/var/lib/...:/usr/lib/...:/etc/...
```

...and lets `bpf_object__open_file` fail organically with a clear
libbpf error rather than wedging silently.

## Override semantics

`AEGIS_BTF_PATH` takes precedence over every fallback. If the path is
set but the file is unreadable the daemon **fails fast** rather than
falling back to the kernel-built-in: a typo in the override is much
more likely than a deliberate mid-run swap, and silently picking a
mismatched BTF would cause subtle CO-RE field-offset drift that's
painful to debug.

```bash
$ sudo AEGIS_BTF_PATH=/srv/btfs/4.18.0-553.el8.btf aegisbpfd run
```

## Using btfgen.sh

[`scripts/btfgen.sh`](../scripts/btfgen.sh) downloads pre-built BTF
blobs from Aqua Security's
[BTFhub-archive](https://github.com/aquasecurity/btfhub-archive) --
the same community archive that Falco, Tetragon, and Tracee use.

### Download BTF for a specific kernel

```bash
$ sudo ./scripts/btfgen.sh 5.15.0-91-generic
btfgen: Downloading BTF for kernel 5.15.0-91-generic (arch=x86_64) ...
btfgen: Saved: /var/lib/aegisbpf/btfs/5.15.0-91-generic.btf (from ubuntu/22.04/x86_64)
/var/lib/aegisbpf/btfs/5.15.0-91-generic.btf
```

### Download BTF for the running kernel

```bash
$ sudo ./scripts/btfgen_all.sh
# equivalent to: btfgen.sh --auto
```

### Custom output directory

```bash
$ ./scripts/btfgen.sh 5.15.0-91-generic --output-dir ./my-btfs
```

### List available kernels for a distro

```bash
$ ./scripts/btfgen.sh --list ubuntu/22.04
```

### Options

| Flag | Description |
|------|-------------|
| `--output-dir <dir>` | Override output directory (default: `/var/lib/aegisbpf/btfs`) |
| `--arch <arch>` | Override architecture (default: auto-detected via `uname -m`) |
| `--distro <d/v>` | Override distro/version (default: auto-detected from `/etc/os-release`) |
| `--list <distro/ver>` | List available kernels for a given distro/version |
| `--auto` | Use the running kernel's release (`uname -r`) |
| `--force` | Re-download even if a cached blob already exists |
| `-q`, `--quiet` | Suppress progress output |

### Idempotency

If the output file already exists, `btfgen.sh` prints the cached path
and exits 0 without re-downloading. Use `--force` to override.

### Distro detection

When no `--distro` is specified, the script reads `/etc/os-release` to
detect the running distro and version, then tries that first. If no
match is found for the detected distro, it falls back to trying all
supported distro/version combinations in the archive.

## Enabling auto-download (step 7)

Set `AEGIS_BTF_AUTO_DOWNLOAD=1` to let `aegisbpfd` automatically
invoke `btfgen.sh` at startup when no BTF blob is found locally. The
downloaded blob is cached at `/var/lib/aegisbpf/btfs/<release>.btf`
so subsequent restarts do not re-download.

```bash
$ sudo AEGIS_BTF_AUTO_DOWNLOAD=1 aegisbpfd run
```

**This is opt-in by default.** Auto-downloading is never attempted
unless the environment variable is explicitly set to `1`. Reasons:

- Network access at daemon startup may be unexpected in locked-down
  environments.
- Air-gapped deployments cannot reach GitHub.
- Pre-populating the cache via `btfgen.sh` or package post-install
  hooks is the recommended approach for production.

The script location is resolved in this order:

1. `AEGIS_BTFGEN_PATH` environment variable (explicit override).
2. `/usr/lib/aegisbpf/scripts/btfgen.sh` (package-installed).
3. `/usr/share/aegisbpf/scripts/btfgen.sh` (alternative package path).

## Supported distros

BTFhub-archive carries BTF blobs for kernels from these distributions:

- Ubuntu (18.04, 20.04, 22.04, 24.04)
- Debian (10, 11, 12)
- Fedora (38, 39, 40)
- CentOS (7, 8, 9)
- RHEL (7, 8, 9)
- Amazon Linux (2, 2023)
- Oracle Linux (7, 8, 9)
- SLES (12, 15)
- openSUSE (15)
- Arch Linux (rolling)

Architectures: `x86_64`, `arm64`.

## Verifying the chosen blob

The daemon logs the selection at startup:

```
INFO Using custom BTF blob path=/var/lib/aegisbpf/btfs/4.18.0-553.el8.btf
     source=var-lib kernel_release=4.18.0-553.el8.x86_64
```

For auto-downloaded blobs:

```
INFO Using custom BTF blob path=/var/lib/aegisbpf/btfs/4.18.0-553.el8.btf
     source=btfhub-download kernel_release=4.18.0-553.el8.x86_64
```

If you want to confirm without actually starting the daemon, the same
resolver is reachable from the `aegisbpfctl probe` command (it logs
the BTF source under `kernel_features`).

## Failure modes

| Condition | Behaviour |
|-----------|-----------|
| Modern kernel, BTF in `/sys/kernel/btf/vmlinux` | `source=kernel`, no fallback consulted, no log spam. |
| `AEGIS_BTF_PATH` set + readable | `source=override`, daemon trusts the operator's choice. |
| `AEGIS_BTF_PATH` set + unreadable | Hard fail at startup with `BpfLoadFailed`; fix the path or unset the env var. |
| No kernel BTF, blob found at fallback path | `source=var-lib` / `usr-lib` / `etc` / `modules`; daemon proceeds. |
| No kernel BTF, auto-download succeeds | `source=btfhub-download`; blob cached for next restart. |
| No kernel BTF, auto-download fails | `WARN` log lists every searched path including the failed download attempt. |
| No kernel BTF, auto-download disabled | `WARN` log lists every searched path; libbpf returns the underlying error from `bpf_object__open_file`. |

## See also

- [`scripts/btfgen.sh`](../scripts/btfgen.sh) -- BTFhub-archive downloader.
- [`scripts/btfgen_all.sh`](../scripts/btfgen_all.sh) -- convenience wrapper using `uname -r`.
- [`src/btf_loader.cpp`](../src/btf_loader.cpp), [`tests/test_btf_loader.cpp`](../tests/test_btf_loader.cpp).
- [BTFhub-archive](https://github.com/aquasecurity/btfhub-archive) -- upstream BTF blobs for kernels without built-in BTF.
- [BTF in libbpf](https://docs.kernel.org/bpf/libbpf/program_types.html#btf-relocations) -- kernel docs on CO-RE relocations.
