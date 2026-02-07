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

## Threat Model and Security Boundaries

Authoritative security scope is documented in `docs/THREAT_MODEL.md`.

At a high level:
- **In scope:** unprivileged process/container attempts to perform denied
  file/network operations.
- **Out of scope:** host root compromise, malicious kernel modules, and
  physical/firmware attacks.
- **Important boundary:** if BPF LSM is unavailable, AegisBPF degrades to
  audit-only behavior and cannot enforce file denial.


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

## Cryptographic Security

### Timing Attack Prevention

All cryptographic comparisons in AegisBPF use constant-time algorithms to prevent timing side-channel attacks:

- **BPF object integrity verification** - SHA256 hash comparison uses `constant_time_hex_compare()`
- **Policy hash verification** - SHA256 integrity checks use constant-time comparison
- **Signed bundle verification** - Policy bundle SHA256 verification uses constant-time comparison

This prevents attackers from inferring valid hash values by measuring comparison timing.

### BPF Object Integrity

AegisBPF verifies the integrity of the BPF object file before loading:

1. Computes SHA256 hash of the BPF object
2. Compares against expected hash from `/etc/aegisbpf/aegis.bpf.sha256` or installed location
3. Rejects loading if hashes don't match

**Important**: The `AEGIS_SKIP_BPF_VERIFY=1` environment variable bypass is **disabled in Release builds**. It is only available in Debug builds for development purposes.

### Input Validation

- **Bundle parsing**: All numeric fields in signed bundles are validated with exception handling to prevent crashes on malformed input
- **JSON escaping**: All control characters are properly escaped in JSON log output to prevent log injection attacks
- **Path validation**: Null bytes, path traversal, and symlink attacks are mitigated through canonicalization

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

## Environment Variables

The following environment variables affect security behavior. In production, avoid setting override variables unless absolutely necessary.

| Variable | Default | Security Impact |
|----------|---------|-----------------|
| `AEGIS_SKIP_BPF_VERIFY` | unset | **Debug builds only**: Bypasses BPF object integrity verification. Disabled in Release builds. |
| `AEGIS_BPF_OBJ` | (auto-detected) | Overrides BPF object file path. Use with caution. |
| `AEGIS_KEYS_DIR` | `/etc/aegisbpf/keys` | Directory for trusted policy signing keys. |
| `AEGIS_POLICY_SHA256` | unset | Expected SHA256 hash for policy verification. |
| `AEGIS_POLICY_SHA256_FILE` | unset | File containing expected SHA256 hash. |
| `AEGIS_OTEL_SPANS` | unset | Enable OpenTelemetry-style trace spans in logs. |

**Production recommendations**:
- Do not set `AEGIS_SKIP_BPF_VERIFY` (ineffective in Release builds anyway)
- Use default paths for BPF objects and keys
- Always use `--sha256` or `--require-signature` for policy application

## Known Limitations

1. **BPF LSM requirement**: Full blocking requires BPF LSM to be enabled in the kernel.
2. **Root namespace only**: The agent must run in the host PID/cgroup namespace.
3. **No live policy reload**: Policy changes require agent restart.
4. **Namespace/path ambiguity**: Path canonicalization occurs in the agent mount
   namespace; bind-mount and overlay paths can differ from workload-visible
   paths.
5. **Coverage limits**: Network enforcement currently focuses on connect/bind
   hooks; other socket paths are not yet covered.

## Security Fixes History

### 2026-02-07: TweetNaCl Memory Exhaustion Prevention (CRITICAL)

**Vulnerability:** Unbounded heap allocation in signature verification could lead to memory exhaustion DoS attacks.

**Impact:** HIGH - Availability impact via memory exhaustion

**Status:** ✅ FIXED

**Details:** See `docs/SECURITY_FIX_TWEETNACL_MEMORY.md`

**Affected Versions:** Pre-fix versions (< v0.1.1)

**Fix Version:** v0.1.1+

**Changes:**
- Replaced heap-based allocation with stack-based buffers (4KB limit)
- Added size validation before cryptographic operations
- Enhanced test coverage with 9 new security tests
- All 153 unit tests pass

**Action Required:** Update to latest version immediately
