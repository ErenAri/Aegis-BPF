# Tutorial 3: Writing Custom Policies

**Difficulty:** Intermediate
**Time:** 15 minutes
**Prerequisites:** Tutorials 1 and 2 completed

## What You'll Learn

- Policy file syntax and version management
- All available policy sections and their uses
- How to use cgroup allowlisting
- How to validate policies before applying
- Best practices for production policies

## Policy File Format

AegisBPF policies use a simple INI-like format:

```ini
# Comments start with #
version=1

# Sections define rule types
[deny_path]
/etc/shadow
/etc/gshadow

[deny_port]
21:tcp:egress

# Boolean sections (no values needed)
[deny_ptrace]
[deny_module_load]
[deny_bpf]
```

## Available Sections

### File Access Control

| Section | Purpose | Value Format |
|---------|---------|-------------|
| `[deny_path]` | Block access to file paths | One path per line |
| `[deny_inode]` | Block access by inode (advanced) | `inode:device` per line |
| `[protect_path]` | Protect files for verified-exec only | One path per line |

### Network Control

| Section | Purpose | Value Format |
|---------|---------|-------------|
| `[deny_ip]` | Block specific IPs | One IP per line (v4 or v6) |
| `[deny_cidr]` | Block IP ranges | CIDR notation (e.g., `10.0.0.0/8`) |
| `[deny_port]` | Block ports | `port:protocol:direction` |
| `[deny_ip_port]` | Block IP+port combos | `ip:port:protocol` |

### Kernel Security

| Section | Purpose | Values |
|---------|---------|--------|
| `[deny_ptrace]` | Block ptrace (process debugging) | None (boolean) |
| `[deny_module_load]` | Block kernel module loading | None (boolean) |
| `[deny_bpf]` | Block BPF program loading | None (boolean) |

### Access Grants

| Section | Purpose | Value Format |
|---------|---------|-------------|
| `[allow_cgroup]` | Exempt cgroups from deny rules | Cgroup path per line |
| `[allow_exec_inode]` | Trusted binary inodes | `inode:device` per line |

## Example: Web Application Server

```ini
# Policy for a web application server
version=2

# Protect system credentials
[deny_path]
/etc/shadow
/etc/gshadow
/etc/security/opasswd
/root/.ssh/id_rsa
/root/.ssh/id_ed25519

# Block data exfiltration channels
[deny_port]
21:tcp:egress     # FTP
23:tcp:egress     # Telnet
25:tcp:egress     # SMTP (use 587 with TLS instead)
6667:tcp:egress   # IRC

# Block cloud metadata endpoint (SSRF prevention)
[deny_ip]
169.254.169.254

# Block kernel tampering
[deny_ptrace]
[deny_module_load]
[deny_bpf]

# Allow the web server cgroup to operate normally
[allow_cgroup]
/sys/fs/cgroup/system.slice/nginx.service
/sys/fs/cgroup/system.slice/myapp.service
```

## Validating Policies

Before applying, validate with the lint command:

```bash
# Check for syntax errors and conflicts
aegisbpf policy lint my-policy.conf
```

The linter checks for:
- Syntax errors (missing version, unknown sections)
- Logical conflicts (e.g., path in both deny and protect)
- Security gaps (e.g., deny_bpf without deny_module_load)
- Best practice recommendations

## Policy Versioning

```ini
# version=1 — Original format
# version=2 — Adds support for deny_ip_port, protect_path

version=2
```

Always specify the version. The daemon validates that the policy version
is compatible with the running agent.

## Hot-Reload Workflow

```bash
# 1. Edit your policy
vim /etc/aegisbpf/production.conf

# 2. Lint it
aegisbpf policy lint /etc/aegisbpf/production.conf

# 3. Apply (median ~115 ms on the reference host, no agent restart
#    needed; the in-agent shadow-map swap itself is <5 ms)
sudo aegisbpf policy apply /etc/aegisbpf/production.conf

# 4. Verify
sudo aegisbpf policy show
```

The policy swap is atomic — there's no window where old rules are removed
but new rules aren't yet applied.

## Best Practices

1. **Start in audit mode**: Test every policy change in `--audit-only` first
2. **Use version control**: Keep policies in Git for change tracking
3. **Lint before applying**: Catch conflicts before they hit production
4. **Use cgroup allowlisting**: Don't block your own services
5. **Include kernel hooks**: `deny_ptrace` + `deny_module_load` + `deny_bpf`
   provides defense-in-depth
6. **Monitor after changes**: Watch `aegisbpf metrics` for unexpected block spikes

## What's Next?

- **Tutorial 4:** [Debugging Policy Denials](04-debugging-denials.md)
- **Example policies:** See `examples/policies/` for production templates
