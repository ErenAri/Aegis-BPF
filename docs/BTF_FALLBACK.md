# BTF fallback for kernels without `/sys/kernel/btf/vmlinux`

CO-RE (Compile Once – Run Everywhere) BPF programs need a BTF blob to
relocate field offsets at load time. Modern kernels (≥ 5.4 on most
distros, ≥ 5.8 on RHEL/CentOS Stream) ship their own at
`/sys/kernel/btf/vmlinux`. Older or stripped-down kernels don't, and
the BPF object will fail to load with errors like:

```
libbpf: failed to find valid kernel BTF
libbpf: Error loading BTF: No such file or directory
```

`aegisbpfd` carries a fallback that lets it run on those kernels
provided you ship a matching BTF blob in one of a few well-known
locations.

## Resolution order

`aegisbpfd` resolves the BTF blob at startup via
[`src/btf_loader.cpp`](../src/btf_loader.cpp). First hit wins:

| # | Location | Source tag | When to use |
|---|----------|------------|-------------|
| 1 | `$AEGIS_BTF_PATH` | `override` | Operator-driven explicit path; useful for CI matrices and air-gapped hosts. |
| 2 | `/sys/kernel/btf/vmlinux` | `kernel` | Default on any modern kernel; nothing to install. |
| 3 | `/lib/modules/<release>/btf/vmlinux` | `modules` | Some Debian/Ubuntu kernels ship BTF here even when `/sys/kernel/btf` is absent (`linux-image-extra-*`). |
| 4 | `/var/lib/aegisbpf/btfs/<release>.btf` | `var-lib` | Runtime-writable cache; populate via `aegisbpfctl btf install` or a post-install hook. |
| 5 | `/usr/lib/aegisbpf/btfs/<release>.btf` | `usr-lib` | Package-shipped BTF blobs (e.g. RPM/DEB carrying a curated set of kernels). |
| 6 | `/etc/aegisbpf/btfs/<release>.btf` | `etc` | Operator-managed, follows the same convention as `/etc/aegisbpf/keys.d/`. |

`<release>` is the output of `uname -r`, e.g.
`5.10.0-21-amd64` or `4.18.0-553.el8_10.x86_64`.

If none of the above are readable, the daemon emits:

```
WARN No BTF found; CO-RE relocations will likely fail
  kernel_release=4.18.0-553.el8 searched=/lib/modules/...:/var/lib/...:/usr/lib/...:/etc/...
```

…and lets `bpf_object__open_file` fail organically with a clear
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

## Generating BTF blobs from BTFhub

[`scripts/btfgen.sh`](../scripts/btfgen.sh) wraps Aqua Security's
[BTFhub-archive](https://github.com/aquasecurity/btfhub-archive) and
the in-tree `bpftool gen min_core_btf` command to produce a tiny
per-kernel BTF blob that contains only the types `aegis.bpf.o`
actually relocates against. A typical run produces blobs in the
~1–10 KB range vs. the ~5 MB full vmlinux BTF.

```bash
$ ./scripts/btfgen.sh build/aegis.bpf.o --output-dir packaging/btfhub/btfs
```

The output filenames are `<distro>-<arch>_<kernel-version>.btf`. The
runtime resolver looks for `<release>.btf` (no distro prefix), so
copy/symlink the matching blob into one of the locations above:

```bash
# Pick the blob matching `uname -r` and stage it for the daemon.
$ release=$(uname -r)
$ install -m 0644 packaging/btfhub/btfs/ubuntu-22.04-x86_64_${release}.btf \
    /var/lib/aegisbpf/btfs/${release}.btf
```

## Verifying the chosen blob

The daemon logs the selection at startup:

```
INFO Using custom BTF blob path=/var/lib/aegisbpf/btfs/4.18.0-553.el8.btf
     source=var-lib kernel_release=4.18.0-553.el8.x86_64
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
| No kernel BTF, no fallback | `WARN` log lists every searched path; libbpf returns the underlying error from `bpf_object__open_file`. |

## See also

- [`scripts/btfgen.sh`](../scripts/btfgen.sh) — BTFhub-archive harvester + `bpftool gen min_core_btf` driver.
- [`src/btf_loader.cpp`](../src/btf_loader.cpp), [`tests/test_btf_loader.cpp`](../tests/test_btf_loader.cpp).
- [BTFhub-archive](https://github.com/aquasecurity/btfhub-archive) — upstream BTF blobs for kernels without built-in BTF.
- [BTF in libbpf](https://docs.kernel.org/bpf/libbpf/program_types.html#btf-relocations) — kernel docs on CO-RE relocations.
