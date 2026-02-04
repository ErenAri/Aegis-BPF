# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

Preferred path (private):

1. Open GitHub `Security` tab -> `Advisories`
2. Click `Report a vulnerability`
3. Include impact, affected versions, and reproduction details

If private advisory reporting is unavailable, open a minimal public metadata
issue using the `Security report (public metadata only)` issue template and do
not include exploit details.

Initial triage target: acknowledgement within 48 hours.


## Security Hardening

AegisBPF includes multiple security hardening features:

### Seccomp Filter

When running with `--seccomp`, the agent applies a strict seccomp-bpf filter that only allows necessary system calls. This limits the attack surface if the agent is compromised.

```bash
aegisbpf run --seccomp
```

### AppArmor Profile

An AppArmor profile is provided in `packaging/apparmor/usr.bin.aegisbpf`. To install:

```bash
sudo cp packaging/apparmor/usr.bin.aegisbpf /etc/apparmor.d/
sudo apparmor_parser -r /etc/apparmor.d/usr.bin.aegisbpf
```

### SELinux Policy

SELinux policy files are provided in `packaging/selinux/`. To install:

```bash
cd packaging/selinux
make -f /usr/share/selinux/devel/Makefile aegisbpf.pp
sudo semodule -i aegisbpf.pp
sudo restorecon -Rv /usr/bin/aegisbpf /etc/aegisbpf /var/lib/aegisbpf
```

### Minimum Privileges

AegisBPF requires the following capabilities:

| Capability | Purpose |
|------------|---------|
| `CAP_SYS_ADMIN` | BPF operations (loading programs, accessing maps) |
| `CAP_BPF` | BPF syscall access (Linux 5.8+) |
| `CAP_PERFMON` | Performance monitoring for BPF |
| `CAP_NET_ADMIN` | Network-related BPF hooks |
| `CAP_SYS_RESOURCE` | Raise memlock limit for BPF maps |

### Code Signing

All releases are signed using Sigstore Cosign. To verify a release:

```bash
cosign verify-blob \
  --certificate aegisbpf-*.tar.gz.pem \
  --signature aegisbpf-*.tar.gz.sig \
  --certificate-identity-regexp 'https://github.com/aegisbpf/aegisbpf/*' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  aegisbpf-*.tar.gz
```

### Policy Signing Key Operations

Use the dedicated runbook for key rotation and revocation:

- `docs/KEY_MANAGEMENT.md`
- `scripts/sign_policy_external.sh` (KMS/HSM-style external signer workflow)

In production, prefer signed policy bundles plus:

- `aegisbpf policy apply --require-signature`
- periodic key rotation
- revocation drills and incident evidence capture

## Security Best Practices

### Deployment

1. **Run as a dedicated user**: Create a dedicated system user for aegisbpf.
2. **Use read-only root filesystem**: In containers, mount the root filesystem read-only.
3. **Limit network access**: AegisBPF only needs local Unix socket access for journald.
4. **Enable all hardening options**: Use `--seccomp` in production.

### Policy Management

1. **Use SHA256 verification**: When applying policies, use `--sha256` to verify integrity.
2. **Review policies before applying**: Use `policy lint` to validate policies.
3. **Keep policies minimal**: Only deny what's necessary.
4. **Monitor policy changes**: Log all policy modifications.

### Monitoring

1. **Enable alerting**: Use the Prometheus alerts in `config/prometheus/alerts.yml`.
2. **Monitor for anomalies**: High block rates may indicate attacks.
3. **Review blocked events**: Investigate BLOCK events to identify threats or misconfigurations.

## Known Limitations

1. **BPF LSM requirement**: Full blocking requires BPF LSM to be enabled in the kernel.
2. **Root namespace only**: The agent must run in the host PID/cgroup namespace.
3. **No live policy reload**: Policy changes require agent restart.
