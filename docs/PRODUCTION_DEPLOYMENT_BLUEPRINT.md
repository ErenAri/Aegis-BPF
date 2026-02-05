# Production Deployment Blueprint

This blueprint provides a practical, conservative path to deploy AegisBPF in
production environments. It prioritizes safe rollout, explicit prerequisites,
and verifiable observability.

## 1) Preflight (must pass before rollout)

- Run diagnostics:
  - `aegisbpf health`
  - `aegisbpf doctor`
- Verify environment:
  - `scripts/verify_env.sh --strict`
- Confirm kernel prerequisites (BPF LSM, BTF, cgroup v2) per `docs/COMPATIBILITY.md`.

## 2) Systemd deployment (recommended baseline)

### Install artifacts
- Binary: `/usr/sbin/aegisbpf`
- BPF object: `/usr/lib/aegisbpf/aegis.bpf.o`
- Policy and keys:
  - `/etc/aegisbpf/policy.conf`
  - `/etc/aegisbpf/keys/` (trusted public keys)

### Service configuration
- Use `packaging/systemd/aegisbpf.service` and `packaging/systemd/aegisbpf.env`.
- Start in audit mode first, then move to enforce:
  - Audit: `--audit`
  - Enforce: `--enforce --lsm-hook=inode` (file enforce baseline)

### Capability bounds
- Minimal capabilities are documented in `SECURITY.md`.
- Remove unused caps if you do not enable network enforcement.

### Rollout sequence
1. Audit-only (observe logs, verify drops, confirm event schema).
2. Canary cgroups only (allowlist controlled workloads first).
3. Expand allowlist-based rollout to full fleet.

### Rollback
- `aegisbpf policy rollback` is the primary rollback lever.
- Break-glass: create `/etc/aegisbpf/break_glass` to force audit-only.

## 3) Kubernetes deployment guidance (reference)

If deploying in Kubernetes, use a DaemonSet with host mounts for bpffs and
cgroup v2, and explicitly scoped capabilities. Ensure all required kernel
features are enabled on the host.

Recommended guidance:
- Verify kernel features on nodes with `aegisbpf doctor`.
- Mount `/sys/fs/bpf` into the container.
- Provide only the capabilities listed in `SECURITY.md`.
- Start in audit-only mode and promote to enforce in stages.

Note: A hardened Helm chart is planned but not yet included in this repository.

## 4) Observability integration

- Metrics: run `aegisbpf metrics --out /var/lib/node_exporter/textfile_collector/aegisbpf.prom`
  on a timer if using Prometheus textfile collection.
- Logs: use `--log-format=json` for structured pipelines.
- Event schema validation: `scripts/validate_event_schema.py`.

## 5) Air-gapped or restricted environments

- Use signed policy bundles and verify hashes.
- Keep SBOM and release signatures alongside artifacts.
- Validate integrity with `aegisbpf policy apply --sha256 <hash>` or
  signed policy bundles.

## 6) Operational guardrails

- Keep SIGKILL enforcement disabled unless explicitly required and approved.
- Use audit-only or canary rollout for new policy changes.
- Track drop ratios and attach health during rollout.

## Evidence

- Systemd unit: `packaging/systemd/aegisbpf.service`
- Capability bounds: `SECURITY.md`
- Operational runbooks: `docs/runbooks/`
- Diagnostics: `aegisbpf doctor` and `docs/TROUBLESHOOTING.md`
