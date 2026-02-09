# AegisBPF

**AegisBPF** is an eBPF-based runtime security agent that monitors and blocks unauthorized file access using Linux Security Modules (LSM). It provides kernel-level enforcement with minimal overhead.

```
┌───────────────────────────────────────────────────────────────────────────────┐
│                              AegisBPF                                         │
│                                                                               │
│   ┌─────────────┐   ┌─────────────┐   ┌─────────────┐    ┌─────────────┐      │
│   │  File/Net   │   │   Allow     │   │   Policy    │    │  Metrics    │      │
│   │ deny rules  │   │  allowlist  │   │ + signatures│    │  + health   │      │
│   └──────┬──────┘   └──────┬──────┘   └──────┬──────┘    └──────┬──────┘      │
│          └─────────────────┴─────────────────┴──────────────────┘             │
│                                      │                                        │
│                              ┌───────┴────────┐                               │
│                              │ Pinned BPF Maps│                               │
│                              │ + Ring Buffer  │                               │
│                              └───────┬────────┘                               │
│                                      │                                        │
├──────────────────────────────────────┼────────────────────────────────────────┤
│                               KERNEL │                                        │
│                         ┌────────────┴──────────────┐                         │
│                         │ LSM hooks (enforce/audit) │                         │
│                         │ file_open/inode_permission│                         │
│                         │ socket_connect/socket_bind│                         │
│                         └────────────┬──────────────┘                         │
│                         ┌────────────┴─────────────┐                          │
│                         │ Tracepoint fallback      │                          │
│                         │ openat/exec/fork/exit    │                          │
│                         └──────────────────────────┘                          │
└───────────────────────────────────────────────────────────────────────────────┘
```

## Features

- **Kernel-level blocking** - Uses BPF LSM hooks to block file opens before they complete
- **Inode-based rules** - Block by device:inode for reliable identification across renames
- **Path-based rules** - Block by file path for human-readable policies
- **Dual-stack network policy** - Deny IPv4 and IPv6 IP/CIDR/port rules in kernel hooks
- **Cgroup allowlisting** - Exempt trusted workloads from deny rules
- **Audit mode** - Monitor without blocking (works without BPF LSM)
- **Prometheus metrics** - Export block counts and statistics
- **Structured logging** - JSON or text output to stdout/journald
- **Policy files and signed bundles** - Declarative configuration with SHA256 verification and signature enforcement
- **Kubernetes ready** - Helm chart for DaemonSet deployment

## Claim Taxonomy

To avoid overclaiming, features are labeled as:

- `ENFORCED`: operation is denied in-kernel in supported mode
- `AUDITED`: operation is observed/logged but not denied
- `PLANNED`: not shipped yet

Current flagship contract:

> Block unauthorized file opens/reads using inode-first enforcement for
> cgroup-scoped workloads, with safe rollback and signed policy provenance.

Current scope labels:
- `ENFORCED`: file deny via LSM (`file_open` / `inode_permission`), network
  deny for configured connect/bind rules when LSM hooks are available
- `AUDITED`: tracepoint fallback path (no syscall deny), detailed metrics mode
- `PLANNED`: broader runtime surfaces beyond current documented hooks

## Validation Results

**Latest Independent Validation:** 2026-02-07 

AegisBPF has been independently validated on Google Cloud Platform with kernel 6.8.0-1045-gcp:

| Test Category | Result | Details |
|---------------|--------|---------|
| **Unit Tests** |  183/183 PASS | All tests passed including golden vectors |
| **E2E Tests** |  100% PASS | Smoke (audit/enforce), chaos, enforcement matrix |
| **Security Validation** | 3/3 PASS | Enforcement blocks access, symlinks/hardlinks can't bypass |
| **Performance Impact** |  ~27% overhead | Audit mode: 528 MB/s (baseline: 721 MB/s) |
| **Binary Hardening** |  VERIFIED | FORTIFY_SOURCE, stack-protector, PIE, full RELRO |

**Security Hardening Applied:**
- Compiler security flags (FORTIFY_SOURCE=2, stack-protector-strong, PIE, RELRO)
- Timeout protection on BPF operations (prevents indefinite hangs)
- Secure temporary file creation via `mkstemp()` (symlink-attack resistant)
- Atomic file writes (write-rename pattern) for all persistent state
- Trusted key directory permission validation with symlink rejection
- Break-glass token cryptographic validation (Ed25519 + expiry)
- Auto-revert to audit-only on deny-rate spikes (configurable threshold)
- BPF map entry count verification after policy apply (crash-safe rollback)
- Thread-safe time formatting (`localtime_r`/`gmtime_r`)
- Seccomp allowlist hardened (removed `SYS_execve`, replaced `popen` with zlib)
- O(1) cgroup path resolution via `open_by_handle_at`
- BpfState move semantics fully correct (no dangling pointers)
- Compile-time struct layout assertions (BPF/userspace size + offset checks)

**Remaining Recommendations Before Production:**
1. Run in audit mode for 1+ weeks before enabling enforcement
2. Document recovery procedures for enforcement misconfiguration

Full validation report available in CI artifacts and `docs/VALIDATION_2026-02-07.md`.

## Evidence & CI

Public proof lives in the docs and CI artifacts:
- Evidence checklist and gates: `docs/PRODUCTION_READINESS.md`
- Kernel/CI execution model: `docs/CI_EXECUTION_STRATEGY.md`
- Kernel/distro compatibility: `docs/COMPATIBILITY.md`
- Threat model + non-goals: `docs/THREAT_MODEL.md`
- Enforcement guarantees + TOCTOU analysis: `docs/GUARANTEES.md`
- Performance profile + tuning: `docs/PERFORMANCE.md`
- Policy semantics contract: `docs/POLICY_SEMANTICS.md`
- Enforcement semantics whitepaper: `docs/ENFORCEMENT_SEMANTICS_WHITEPAPER.md`
- Edge-case compliance suite: `docs/EDGE_CASE_COMPLIANCE_SUITE.md`
- Edge-case compliance results: `docs/EDGE_CASE_COMPLIANCE_RESULTS.md`
- External validation status: `docs/EXTERNAL_VALIDATION.md`
- Performance baseline report: `docs/PERF_BASELINE.md`

Kernel-matrix artifacts are uploaded by `.github/workflows/kernel-matrix.yml`
as `kernel-matrix-<runner>` (kernel + distro + test logs).

## Architecture

```
+----------------------------- User Space -----------------------------+
|                                                                      |
|  +----------------------------------------------------------------+  |
|  |                       aegisbpf daemon                          |  |
|  |                                                                |  |
|  |  +-----------+ +-----------+ +-----------+ +--------+ +------+ |  |
|  |  |    CLI    | |  Policy   | |   Event   | |Metrics | | Log  | |  |
|  |  | Dispatch  | |  + Sign   | |  Handler  | |+Health | |(JSON)| |  |
|  |  +-----------+ +-----------+ +-----------+ +--------+ +------+ |  |
|  +----------------------------------------------------------------+  |
|                                |                                     |
|                         +------+------+                              |
|                         |   libbpf    |                              |
|                         +------+------+                              |
|                                |                                     |
+--------------------------------|-------------------------------------+
                          bpf() syscall
+--------------------------------|-------------------------------------+
|                                |            Kernel Space             |
|  +-----------------------------+-----------------------------+       |
|  |                      BPF Subsystem                        |       |
|  |                                                           |       |
|  |  +------------------------+ +---------------------------+ |       |
|  |  |      LSM Hooks         | |   Tracepoint Fallback     | |       |
|  |  | file_open              | | openat / exec / fork      | |       |
|  |  | inode_permission       | | (audit when no BPF LSM)   | |       |
|  |  | socket_connect / bind  | +---------------------------+ |       |
|  |  +------------------------+                               |       |
|  |                                                           |       |
|  |  +------------------------------------------------------+ |       |
|  |  |                     BPF Maps                         | |       |
|  |  | deny_* / allow_*    net_* / survival_*               | |       |
|  |  | agent_meta / stats  events ring buffer               | |       |
|  |  +------------------------------------------------------+ |       |
|  +-----------------------------------------------------------+       |
|                                                                      |
|              file/network ops: allowed, audited, or blocked          |
+----------------------------------------------------------------------+
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

# Enforce mode with explicit signal policy (default is SIGTERM)
sudo ./build/aegisbpf run --enforce --enforce-signal=term

# SIGKILL mode escalates: TERM first, KILL only after repeated denies
sudo ./build/aegisbpf run --enforce --enforce-signal=kill

# Tune SIGKILL escalation policy (used only with --enforce-signal=kill)
sudo ./build/aegisbpf run --enforce --enforce-signal=kill \
  --kill-escalation-threshold=8 \
  --kill-escalation-window-seconds=60

# With JSON logging
sudo ./build/aegisbpf run --log-format=json

# Select LSM hook (default: file_open)
sudo ./build/aegisbpf run --enforce --lsm-hook=both

# Increase ring buffer and sample events to reduce drops under heavy load
sudo ./build/aegisbpf run --audit --ringbuf-bytes=67108864 --event-sample-rate=10
```

## How It Works

```
                    File Access Blocking Flow

  User Process              Kernel (BPF LSM)
       |
       |  open("/etc/shadow")
       |----------------------->|
       |                        |
       |                 allow_cgroup? ----yes----> ALLOW
       |                        |no
       |                        v
       |                   deny_inode? ----yes--+
       |                        |no             |
       |                        v               v
       |                 survival_allowlist? -> ALLOW
       |                        |no
       |                        v
       |                 audit mode?
       |                  /          \
       |                yes           no
       |                 |             |
       |            emit event     signal + -EPERM
       |              ALLOW          DENY
       |                        |
       |<-----------------------|
       |  Success / EPERM
```

## Usage

### Run Options

```bash
# Choose LSM hook (default: file_open)
sudo aegisbpf run --enforce --lsm-hook=file
sudo aegisbpf run --enforce --lsm-hook=inode
sudo aegisbpf run --enforce --lsm-hook=both

# Choose enforce signal action (default: term)
sudo aegisbpf run --enforce --enforce-signal=term
sudo aegisbpf run --enforce --enforce-signal=none
# 'kill' escalates to SIGKILL only after repeated denies in a short window
sudo aegisbpf run --enforce --enforce-signal=kill

# Tune escalation policy for kill mode
sudo aegisbpf run --enforce --enforce-signal=kill \
  --kill-escalation-threshold=8 \
  --kill-escalation-window-seconds=60

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

# Apply signed bundle (recommended for production)
sudo aegisbpf policy apply /etc/aegisbpf/policy.signed --require-signature

# Export current rules
sudo aegisbpf policy export /tmp/current.conf

# Rollback to previous policy
sudo aegisbpf policy rollback
```

### Monitoring

```bash
# View statistics
sudo aegisbpf stats

# View detailed high-cardinality debug breakdowns
sudo aegisbpf stats --detailed

# Export Prometheus metrics
sudo aegisbpf metrics --out /var/lib/prometheus/aegisbpf.prom

# Export high-cardinality metrics for short-lived debugging
sudo aegisbpf metrics --detailed --out /tmp/aegisbpf.debug.prom

# Health check
sudo aegisbpf health

# Enable OTel-style policy spans in logs (for troubleshooting)
AEGIS_OTEL_SPANS=1 sudo aegisbpf policy apply /etc/aegisbpf/policy.conf
```

## Event Format

Events are emitted as newline-delimited JSON:

```json
{
  "type": "block",
  "pid": 12345,
  "ppid": 1000,
  "start_time": 123456789,
  "exec_id": "12345:123456789",
  "trace_id": "12345:123456789",
  "parent_start_time": 123400000,
  "parent_exec_id": "1000:123400000",
  "parent_trace_id": "1000:123400000",
  "cgid": 5678,
  "cgroup_path": "/sys/fs/cgroup/user.slice",
  "comm": "bash",
  "path": "/usr/bin/malware",
  "ino": 123456,
  "dev": 259,
  "action": "TERM"
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
sudo systemctl daemon-reload
sudo systemctl enable --now aegisbpf
```

`/etc/default/aegisbpf` defaults to:

- `AEGIS_REQUIRE_SIGNATURE=1`
- `AEGIS_POLICY=` (empty, service starts without applying a startup policy)

For production, set `AEGIS_POLICY` to a signed policy bundle path (for example
`/etc/aegisbpf/policy.signed`) and keep signature enforcement enabled.

## Data Flow Diagram

```
+----------------------------+
|    Policy bundle/rules     |
| /etc/aegisbpf/policy.signed|
+-------------+--------------+
              |
              v
+-------+  +------------------+  +------------------+
|  CLI  |->|    aegisbpf      |->| journald/stdout  |
|  Cmds |  |     daemon       |  | (structured logs)|
+-------+  +--------+---------+  +------------------+
                     |
                  bpf() syscall
                     |
           +---------+---------+
           |     BPF Maps      |
           | /sys/fs/bpf/aegis/|
           |                   |
           | deny_* allow_*    |
           | deny_ipv4/ipv6    |
           | deny_cidr_v4/v6   |
           | deny_port         |
           | net_*/block_stats |
           | survival/meta     |
           | events (ring buf) |
           +---------+---------+
                     |
           +---------+---------+
           | BPF hooks (kernel)|
           | - file_open       |
           | - inode_permission|
           | - socket_connect  |
           | - socket_bind     |
           | - tracepoints     |
           +-------------------+
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
| `aegisbpf_net_blocks_total` | counter | Blocked network operations by type (`connect`/`bind`) |
| `aegisbpf_net_ringbuf_drops_total` | counter | Dropped network events |
| `aegisbpf_net_rules_total` | gauge | Active network deny rules by type (`ip`/`cidr`/`port`) |

High-cardinality debug metrics are available with `aegisbpf metrics --detailed`:
`aegisbpf_blocks_by_cgroup_total`, `aegisbpf_blocks_by_inode_total`,
`aegisbpf_blocks_by_path_total`, `aegisbpf_net_blocks_by_ip_total`,
`aegisbpf_net_blocks_by_port_total`.

## Security Hardening

```
+----------------------------------------------------------+
| Layer 5: Cryptographic                                   |
| Constant-time comparisons, BPF integrity, policy sigs    |
+----------------------------------------------------------+
| Layer 4: Code Signing                                    |
| Sigstore/Cosign + SBOM                                   |
+----------------------------------------------------------+
| Layer 3: MAC Policies                                    |
| AppArmor / SELinux                                       |
+----------------------------------------------------------+
| Layer 2: Seccomp                                         |
| Syscall allowlist (--seccomp)                            |
+----------------------------------------------------------+
| Layer 1: Capabilities                                    |
| CAP_SYS_ADMIN, CAP_BPF, CAP_PERFMON                      |
+----------------------------------------------------------+
```

**Cryptographic protections:**
- All hash comparisons use constant-time algorithms to prevent timing attacks
- BPF object integrity verified via SHA256 before loading
- Policy signing with Ed25519 signatures (recommended for production)

Enable all hardening layers:
```bash
sudo aegisbpf run --enforce --seccomp
```

See [SECURITY.md](SECURITY.md) for vulnerability reporting, environment variables, and hardening details.

Security boundaries, attacker model, and known blind spots are documented in
[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).  Enforcement guarantees and
TOCTOU analysis are in [docs/GUARANTEES.md](docs/GUARANTEES.md).

## Documentation

### Core Documentation

| Document | Description |
|----------|-------------|
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | System design and internals |
| [API_REFERENCE.md](docs/API_REFERENCE.md) | API reference for types, functions, and BPF maps |
| [DEVELOPER_GUIDE.md](docs/DEVELOPER_GUIDE.md) | Development setup, coding standards, and contribution guide |
| [POLICY.md](docs/POLICY.md) | Policy file format and semantics |
| [POLICY_SEMANTICS.md](docs/POLICY_SEMANTICS.md) | Precise runtime rule semantics and edge-case behavior |
| [NETWORK_LAYER_DESIGN.md](docs/NETWORK_LAYER_DESIGN.md) | Network blocking architecture |
| [THREAT_MODEL.md](docs/THREAT_MODEL.md) | Threat model, coverage boundaries, and known bypass surface |
| [GUARANTEES.md](docs/GUARANTEES.md) | Enforcement guarantees, TOCTOU analysis, and known bypass classes |
| [BYPASS_CATALOG.md](docs/BYPASS_CATALOG.md) | Known bypasses, mitigations, and accepted gaps |
| [REFERENCE_ENFORCEMENT_SLICE.md](docs/REFERENCE_ENFORCEMENT_SLICE.md) | Decision-grade enforcement reference slice |

### Operations

| Document | Description |
|----------|-------------|
| [PRODUCTION_READINESS.md](docs/PRODUCTION_READINESS.md) | Production readiness checklist and operator guidance |
| [PRODUCTION_DEPLOYMENT_BLUEPRINT.md](docs/PRODUCTION_DEPLOYMENT_BLUEPRINT.md) | Deployment hardening and rollout blueprint |
| [CANARY_RUNBOOK.md](docs/CANARY_RUNBOOK.md) | Staging canary and soak validation workflow |
| [RELEASE_DRILL.md](docs/RELEASE_DRILL.md) | Pre-release packaging and upgrade drill |
| [KEY_MANAGEMENT.md](docs/KEY_MANAGEMENT.md) | Policy signing key rotation and revocation runbook |
| [INCIDENT_RESPONSE.md](docs/INCIDENT_RESPONSE.md) | Incident handling procedures |
| [METRICS_OPERATIONS.md](docs/METRICS_OPERATIONS.md) | Metric interpretation, thresholds, and operator actions |
| [EVIDENCE.md](docs/EVIDENCE.md) | Public CI evidence and artifact map |
| [EXTERNAL_VALIDATION.md](docs/EXTERNAL_VALIDATION.md) | Independent review and pilot case study summaries |
| [runbooks/](docs/runbooks/) | Alert/incident/maintenance operational runbooks |
| [VENDORED_DEPENDENCIES.md](docs/VENDORED_DEPENDENCIES.md) | Vendored dependency inventory and review cadence |
| [TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) | Common issues and solutions |
| [SIEM_INTEGRATION.md](docs/SIEM_INTEGRATION.md) | Splunk, ELK, QRadar integration |

### Reference

| Document | Description |
|----------|-------------|
| [SUPPORT_POLICY.md](docs/SUPPORT_POLICY.md) | Supported versions, compatibility, and deprecation guarantees |
| [COMPATIBILITY.md](docs/COMPATIBILITY.md) | Kernel and version compatibility matrix |
| [PERF.md](docs/PERF.md) | Performance tuning and benchmarking |
| [PERFORMANCE.md](docs/PERFORMANCE.md) | Performance profile, memory formulas, and ring buffer sizing |
| [BRANCH_PROTECTION.md](docs/BRANCH_PROTECTION.md) | Protected-branch baseline and required checks |
| [QUALITY_GATES.md](docs/QUALITY_GATES.md) | CI gate policy and coverage ratchet expectations |
| [CI_EXECUTION_STRATEGY.md](docs/CI_EXECUTION_STRATEGY.md) | Privileged CI and kernel-matrix execution strategy |
| [repo_labels.json](config/repo_labels.json) | Repository label source of truth for triage/release policy |
| [CHANGELOG.md](docs/CHANGELOG.md) | Version history |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Contributor workflow and local quality checks |
| [GOVERNANCE.md](GOVERNANCE.md) | Project decision model and maintainer roles |
| [SUPPORT.md](SUPPORT.md) | Support channels and version support scope |
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
- O(1) hash map lookups (deny rule count does not affect per-syscall latency)
- Lock-free ring buffer for events (drops are counted, never blocks enforcement)
- ~5-15MB base memory usage

Run benchmarks:
```bash
# Userspace hot-path benchmarks (no root required)
./build/aegisbpf_bench

# Syscall-level benchmarks with BPF attached (requires root)
sudo scripts/bench_syscall.sh --json --out results.json

# Quick A/B comparison
ITERATIONS=200000 FILE=/etc/hosts scripts/perf_open_bench.sh
```

See [docs/PERFORMANCE.md](docs/PERFORMANCE.md) for memory formulas, ring buffer
sizing guidance, and capacity planning.

## Contributing

1. Read `CONTRIBUTING.md` for workflow and quality expectations
2. Create a focused branch and implement one logical change
3. Run `scripts/dev_check.sh` plus static/security checks in `CONTRIBUTING.md`
4. Open a PR using the template and include validation output

## License

MIT License See [LICENSE](LICENSE) for details.
