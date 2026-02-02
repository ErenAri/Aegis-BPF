# AegisBPF

**AegisBPF** is an eBPF-based runtime security agent that monitors and blocks unauthorized file access using Linux Security Modules (LSM). It provides kernel-level enforcement with minimal overhead.

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                              AegisBPF                                        │
│                                                                              │
│   ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐   │
│   │   Block     │    │   Allow     │    │   Policy    │    │  Metrics    │   │
│   │  deny list  │    │  allowlist  │    │  management │    │  & stats    │   │
│   └──────┬──────┘    └──────┬──────┘    └──────┬──────┘    └──────┬──────┘   │
│          │                  │                  │                  │          │
│          └──────────────────┴──────────────────┴──────────────────┘          │
│                                      │                                       │
│                              ┌───────┴───────┐                               │
│                              │  BPF Maps     │                               │
│                              │  (pinned)     │                               │
│                              └───────┬───────┘                               │
│                                      │                                       │
├──────────────────────────────────────┼───────────────────────────────────────┤
│                               KERNEL │                                       │
│                              ┌───────┴───────┐                               │
│                              │   LSM Hook    │◄──── open() blocked here      │
│                              │  file_open    │                               │
│                              └───────────────┘                               │
└──────────────────────────────────────────────────────────────────────────────┘
```

## Features

- **Kernel-level blocking** - Uses BPF LSM hooks to block file opens before they complete
- **Inode-based rules** - Block by device:inode for reliable identification across renames
- **Path-based rules** - Block by file path for human-readable policies
- **Cgroup allowlisting** - Exempt trusted workloads from deny rules
- **Audit mode** - Monitor without blocking (works without BPF LSM)
- **Prometheus metrics** - Export block counts and statistics
- **Structured logging** - JSON or text output to stdout/journald
- **Policy files** - Declarative configuration with SHA256 verification
- **Kubernetes ready** - Helm chart for DaemonSet deployment

## Architecture

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                                User Space                                    │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────────┐ │
│  │                         aegisbpf daemon                                 │ │
│  │                                                                         │ │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐   │ │
│  │  │  CLI     │  │  Policy  │  │  Event   │  │ Metrics  │  │ Logging  │   │ │
│  │  │ Parser   │  │ Manager  │  │ Handler  │  │ Exporter │  │ (JSON)   │   │ │
│  │  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘   │ │
│  │       │             │             │             │             │         │ │
│  │       └─────────────┴─────────────┴─────────────┴─────────────┘         │ │
│  │                                   │                                     │ │
│  │                           ┌───────┴───────┐                             │ │
│  │                           │    libbpf     │                             │ │
│  │                           └───────┬───────┘                             │ │
│  └───────────────────────────────────┼─────────────────────────────────────┘ │
│                                      │                                       │
│                              bpf() syscall                                   │
│                                      │                                       │
├──────────────────────────────────────┼───────────────────────────────────────┤
│                                Kernel Space                                  │
│                                      │                                       │
│  ┌───────────────────────────────────┴───────────────────────────────────┐   │
│  │                          BPF Subsystem                                │   │
│  │                                                                       │   │
│  │  ┌────────────────┐    ┌────────────────┐    ┌────────────────────┐   │   │
│  │  │   LSM Hook     │    │   Tracepoint   │    │     BPF Maps       │   │   │
│  │  │  file_open     │    │ openat/exec    │    │                    │   │   │
│  │  │                │    │                │    │  ┌──────────────┐  │   │   │
│  │  │  ┌──────────┐  │    │  ┌──────────┐  │    │  │ deny_inode   │  │   │   │
│  │  │  │ ENFORCE  │  │    │  │  AUDIT   │  │    │  │ deny_path    │  │   │   │
│  │  │  │  MODE    │  │    │  │  MODE    │  │    │  │ allow_cgroup │  │   │   │
│  │  │  └──────────┘  │    │  └──────────┘  │    │  │ events (rb)  │  │   │   │
│  │  └───────┬────────┘    └───────┬────────┘    │  │ block_stats  │  │   │   │
│  │          │                     │             │  └──────────────┘  │   │   │
│  │          │     Ring Buffer     │             │                    │   │   │
│  │          └─────────────────────┴─────────────┴────────────────────┘   │   │
│  └───────────────────────────────────────────────────────────────────────┘   │
│                                      │                                       │
│                                      ▼                                       │
│                              ┌───────────────┐                               │
│                              │   open()      │                               │
│                              └───────────────┘                               │
└──────────────────────────────────────────────────────────────────────────────┘
```

## Quick Start

### Prerequisites

- Linux kernel 5.8+ with BTF support
- BPF LSM enabled for enforce mode (check: `cat /sys/kernel/security/lsm | grep bpf`)
- Cgroup v2 mounted at `/sys/fs/cgroup`

Optional environment check:
```bash
scripts/verify_env.sh --strict
```

### Install Dependencies (Ubuntu/Debian)

```bash
sudo apt-get update
sudo apt-get install -y clang llvm bpftool libbpf-dev libsystemd-dev \
    pkg-config cmake ninja-build python3-jsonschema
```

### Build

```bash
cmake -S . -B build -G Ninja
cmake --build build
```

### Run

```bash
# Audit mode (observe without blocking)
sudo ./build/aegisbpf run --audit

# Enforce mode (block matching file opens)
sudo ./build/aegisbpf run --enforce

# With JSON logging
sudo ./build/aegisbpf run --log-format=json

# Select LSM hook (default: file_open)
sudo ./build/aegisbpf run --enforce --lsm-hook=both

# Increase ring buffer and sample events to reduce drops under heavy load
sudo ./build/aegisbpf run --audit --ringbuf-bytes=67108864 --event-sample-rate=10
```

## How It Works

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         File Access Blocking Flow                           │
└─────────────────────────────────────────────────────────────────────────────┘

    User Process                    Kernel                      AegisBPF
         │                            │                            │
         │  open("/etc/shadow")       │                            │
         │ ──────────────────────────►│                            │
         │                            │                            │
         │                            │  LSM: file_open            │
         │                            │ ──────────────────────────►│
         │                            │                            │
         │                            │    ┌────────────────────┐  │
         │                            │    │ Check allow_cgroup │  │
         │                            │    │     (ALLOWED?)     │  │
         │                            │    └─────────┬──────────┘  │
         │                            │              │             │
         │                            │              ▼ NO          │
         │                            │    ┌────────────────────┐  │
         │                            │    │  Check deny_inode  │  │
         │                            │    │    (BLOCKED?)      │  │
         │                            │    └─────────┬──────────┘  │
         │                            │              │             │
         │                            │              ▼ NO          │
         │                            │◄─────────────┘             │
         │                            │   Return 0 (allow)         │
         │                            │   or -EPERM (deny)         │
         │                            │                            │
         │  Success / EPERM           │                            │
         │ ◄──────────────────────────│                            │
         │                            │                            │
```

## Usage

### Run Options

```bash
# Choose LSM hook (default: file_open)
sudo aegisbpf run --enforce --lsm-hook=file
sudo aegisbpf run --enforce --lsm-hook=inode
sudo aegisbpf run --enforce --lsm-hook=both

# Increase ring buffer size (bytes) to reduce ringbuf drops
sudo aegisbpf run --audit --ringbuf-bytes=67108864

# Sample block events (1 = all events, 10 = 1 out of 10)
sudo aegisbpf run --audit --event-sample-rate=10
```

### Performance and Soak (Sample Results)

Results vary by host and workload. The following example was measured on February 2, 2026:

```text
# perf_compare.sh (1,000,000 ops)
baseline_us_per_op=1.94
with_agent_us_per_op=1.98
delta_pct=2.06

# perf_compare.sh with both hooks (LSM_HOOK=both)
baseline_us_per_op=1.93
with_agent_us_per_op=1.97
delta_pct=2.07

# Soak (200,000 denied opens, audit mode)
ringbuf_drops_delta=0
```

### Block Commands

```bash
# Add file to deny list
sudo aegisbpf block add /usr/bin/malware

# List all blocked entries
sudo aegisbpf block list

# Remove from deny list
sudo aegisbpf block del /usr/bin/malware

# Clear all rules and statistics
sudo aegisbpf block clear
```

### Allow Commands

```bash
# Allow cgroup (processes bypass deny rules)
sudo aegisbpf allow add /sys/fs/cgroup/system.slice

# List allowed cgroups
sudo aegisbpf allow list

# Remove from allowlist
sudo aegisbpf allow del /sys/fs/cgroup/system.slice
```

### Policy Files

```ini
# /etc/aegisbpf/policy.conf
version=1

[deny_path]
/usr/bin/dangerous
/opt/malware/binary

[deny_inode]
259:12345

[allow_cgroup]
/sys/fs/cgroup/system.slice
cgid:123456
```

```bash
# Validate policy
sudo aegisbpf policy lint /etc/aegisbpf/policy.conf

# Apply with SHA256 verification
sudo aegisbpf policy apply /etc/aegisbpf/policy.conf --sha256 abc123...

# Export current rules
sudo aegisbpf policy export /tmp/current.conf

# Rollback to previous policy
sudo aegisbpf policy rollback
```

### Monitoring

```bash
# View statistics
sudo aegisbpf stats

# Export Prometheus metrics
sudo aegisbpf metrics --out /var/lib/prometheus/aegisbpf.prom

# Health check
sudo aegisbpf health
```

## Event Format

Events are emitted as newline-delimited JSON:

```json
{
  "event": "BLOCK",
  "ts": 1234567890123456789,
  "pid": 12345,
  "ppid": 1000,
  "uid": 1000,
  "gid": 1000,
  "comm": "bash",
  "path": "/usr/bin/malware",
  "reason": "deny_path",
  "cgid": 5678,
  "cgroup_path": "/sys/fs/cgroup/user.slice"
}
```

## Deployment

### Docker

```bash
docker build -t aegisbpf .
docker run --privileged --pid=host \
    -v /sys/fs/bpf:/sys/fs/bpf \
    -v /sys/fs/cgroup:/sys/fs/cgroup:ro \
    -v /sys/kernel/btf:/sys/kernel/btf:ro \
    aegisbpf run --audit
```

### Kubernetes (Helm)

```bash
helm install aegisbpf ./helm/aegisbpf \
    --set agent.auditMode=false \
    --set agent.logFormat=json
```

### Systemd

```bash
sudo cmake --install build
sudo systemctl enable --now aegisbpf
```

## Data Flow Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              Data Flow                                      │
└─────────────────────────────────────────────────────────────────────────────┘

                    ┌─────────────────────────────────┐
                    │         Policy File             │
                    │   /etc/aegisbpf/policy.conf     │
                    └───────────────┬─────────────────┘
                                    │
                                    ▼
┌───────────────┐           ┌───────────────┐           ┌───────────────┐
│    CLI        │           │   aegisbpf    │           │   journald    │
│   Commands    │──────────►│    daemon     │──────────►│   / stdout    │
│               │           │               │           │               │
└───────────────┘           └───────┬───────┘           └───────────────┘
                                    │
                                    │ bpf() syscall
                                    ▼
                    ┌───────────────────────────────┐
                    │         BPF Maps              │
                    │   /sys/fs/bpf/aegis/          │
                    │                               │
                    │  ┌─────────────────────────┐  │
                    │  │ deny_inode   (hash map) │  │
                    │  │ deny_path    (hash map) │  │
                    │  │ allow_cgroup (hash map) │  │
                    │  │ events       (ring buf) │  │
                    │  │ block_stats  (array)    │  │
                    │  └─────────────────────────┘  │
                    └───────────────┬───────────────┘
                                    │
                                    ▼
                    ┌───────────────────────────────┐
                    │      BPF LSM Program          │
                    │      (kernel space)           │
                    │                               │
                    │   open() ───► check maps     │
                    │              ──► allow/deny   │
                    └───────────────────────────────┘
```

## Metrics

AegisBPF exports Prometheus-compatible metrics:

| Metric | Type | Description |
|--------|------|-------------|
| `aegisbpf_blocks_total` | counter | Total blocked file opens |
| `aegisbpf_ringbuf_drops_total` | counter | Events dropped due to buffer overflow |
| `aegisbpf_deny_inode_entries` | gauge | Number of inode deny rules |
| `aegisbpf_deny_path_entries` | gauge | Number of path deny rules |
| `aegisbpf_allow_cgroup_entries` | gauge | Number of allowed cgroups |
| `aegisbpf_blocks_by_cgroup_total` | counter | Blocks per cgroup |
| `aegisbpf_blocks_by_path_total` | counter | Blocks per file path |

## Security Hardening

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           Security Layers                                   │
└─────────────────────────────────────────────────────────────────────────────┘

    ┌─────────────────────────────────────────────────────────────────────┐
    │                         Layer 4: Code Signing                       │
    │                    Sigstore/Cosign + SBOM                           │
    └─────────────────────────────────────────────────────────────────────┘
                                    │
    ┌─────────────────────────────────────────────────────────────────────┐
    │                         Layer 3: MAC Policies                       │
    │                    AppArmor / SELinux                               │
    └─────────────────────────────────────────────────────────────────────┘
                                    │
    ┌─────────────────────────────────────────────────────────────────────┐
    │                         Layer 2: Seccomp                            │
    │                    Syscall allowlist (--seccomp)                    │
    └─────────────────────────────────────────────────────────────────────┘
                                    │
    ┌─────────────────────────────────────────────────────────────────────┐
    │                         Layer 1: Capabilities                       │
    │              CAP_SYS_ADMIN, CAP_BPF, CAP_PERFMON                    │
    └─────────────────────────────────────────────────────────────────────┘
```

Enable all hardening layers:
```bash
sudo aegisbpf run --enforce --seccomp
```

See [SECURITY.md](SECURITY.md) for vulnerability reporting and hardening details.

## Documentation

| Document | Description |
|----------|-------------|
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | System design and internals |
| [TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) | Common issues and solutions |
| [SIEM_INTEGRATION.md](docs/SIEM_INTEGRATION.md) | Splunk, ELK, QRadar integration |
| [CHANGELOG.md](docs/CHANGELOG.md) | Version history |
| [aegisbpf.1.md](docs/man/aegisbpf.1.md) | Man page |

## Requirements

- Linux kernel 5.8+ with:
  - `CONFIG_BPF=y`
  - `CONFIG_BPF_SYSCALL=y`
  - `CONFIG_BPF_JIT=y`
  - `CONFIG_BPF_LSM=y` (for enforce mode)
  - `CONFIG_DEBUG_INFO_BTF=y`
- Cgroup v2 (unified hierarchy)
- Root privileges or `CAP_SYS_ADMIN`, `CAP_BPF`, `CAP_PERFMON`

### Enable BPF LSM

If `bpf` is missing from `/sys/kernel/security/lsm`:

```bash
# Edit GRUB configuration
sudo vim /etc/default/grub
GRUB_CMDLINE_LINUX="lsm=lockdown,capability,landlock,yama,bpf"

# Update and reboot
sudo update-grub
sudo reboot
```

## Performance

BPF LSM overhead is minimal:
- ~100-500ns per file open
- O(1) hash map lookups
- Lock-free ring buffer for events
- ~10MB base memory usage

Run the benchmark:
```bash
ITERATIONS=200000 FILE=/etc/hosts scripts/perf_open_bench.sh
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Run tests: `scripts/dev_check.sh`
4. Submit a pull request

## License

MIT License See [LICENSE](LICENSE) for details.
