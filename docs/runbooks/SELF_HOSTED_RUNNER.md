# Self-hosted runner operations

This runbook covers the privileged self-hosted runner used by AegisBPF kernel
and BPF-LSM evidence workflows.

The important distinction is between:

1. a runner service that is stopped locally, and
2. a runner registration that no longer exists on GitHub.

Do not re-register a healthy runner just because the service log says
"registration has been deleted". Check both sides first.

## 1. Inspect the local runner

Find the runner directory and service:

```bash
systemctl list-units --type=service 'actions.runner.*'
systemctl list-unit-files 'actions.runner.*'
```

Inside the runner directory, inspect the local registration:

```bash
cd /opt/actions-runner-<runner-name>
python3 - <<'PY'
import json
with open(".runner") as f:
    r = json.load(f)
print("agentId:", r.get("agentId"))
print("agentName:", r.get("agentName"))
PY
```

## 2. Compare with GitHub

List the repository runners:

```bash
gh api repos/ErenAri/Aegis-BPF/actions/runners \
  --jq '.runners[] | {id,name,status,busy,labels:[.labels[].name]}'
```

If the local `agentId` is present on GitHub with the same runner name, the
registration still exists. Do not generate a new registration in that case.

If the IDs match but the runner is offline, treat it as a local service problem.

## 3. Restart a stopped runner

Inspect recent logs first:

```bash
sudo systemctl status 'actions.runner.*' --no-pager
sudo journalctl -u 'actions.runner.*' -n 200 --no-pager
```

Then start/restart the concrete service shown by `systemctl list-units`:

```bash
sudo systemctl restart actions.runner.<owner-repo>.<runner-name>.service
```

Confirm that GitHub reports:

```text
status = online
busy   = false
```

before depending on the runner for release evidence.

## 4. Capability checks

The current privileged runner is expected to provide:

- BPF syscall support
- BTF
- active BPF-LSM
- bpffs
- passwordless privilege escalation for the runner user
- KVM for VM-backed kernel matrices

Check them directly:

```bash
grep -qw bpf /sys/kernel/security/lsm
mountpoint /sys/fs/bpf
test -r /dev/kvm
command -v bpftool
sudo -n true
```

Kernel configuration checks, where the distro exposes them:

```bash
zgrep -E 'CONFIG_(BPF_LSM|BPF_SYSCALL|DEBUG_INFO_BTF)=' /proc/config.gz 2>/dev/null \
  || grep -E 'CONFIG_(BPF_LSM|BPF_SYSCALL|DEBUG_INFO_BTF)=' /boot/config-"$(uname -r)"
```

Expected values include:

```text
CONFIG_BPF_LSM=y
CONFIG_BPF_SYSCALL=y
CONFIG_DEBUG_INFO_BTF=y
```

A workflow label is scheduling metadata, not proof of these properties. The
workflows must also test the capabilities they depend on.

## 5. /dev/kvm permissions

The runner user must be able to open `/dev/kvm`.

Check:

```bash
ls -l /dev/kvm
getfacl /dev/kvm 2>/dev/null || true
sudo -u <runner-user> test -r /dev/kvm
sudo -u <runner-user> test -w /dev/kvm
```

If access is provided by an ACL rather than group membership, preserve that fact
when rebuilding the host. Do not assume membership in the `kvm` group.

## 6. Labels and queue failures

GitHub does not fail a job whose requested self-hosted label does not exist. It
can remain queued indefinitely.

Before adding or changing a `runs-on` label:

```bash
gh api repos/ErenAri/Aegis-BPF/actions/runners \
  --jq '.runners[] | [.name, ([.labels[].name] | join(","))] | @tsv'
```

The current e2e workflow schedules on the existing privileged-capacity
`self-hosted,kvm` runner and then verifies BPF-LSM explicitly. This avoids an
infinite queue while still making capability drift fail loudly.

If a dedicated BPF-LSM fleet is added later, use the semantic `bpf-lsm` label
only after at least one online runner actually carries it.

## 7. Genuine re-registration

Re-register only when the local registration is absent/stale or the GitHub-side
runner was actually deleted.

The repository helper obtains a fresh short-lived token and installs the
service:

```bash
sudo REPO=ErenAri/Aegis-BPF \
  RUNNER_NAME=<runner-name> \
  LABELS=kvm,bpfcompat \
  scripts/setup_self_hosted_runner.sh
```

Add additional labels only for capabilities the host has actually proven.

The registration token must be freshly generated. Do not retain or document it.

## 8. Pre-release runner gate

Before treating privileged evidence as available:

```bash
gh api repos/ErenAri/Aegis-BPF/actions/runners \
  --jq '.runners[] | select(.status=="online") | {name,status,busy,labels:[.labels[].name]}'
```

Confirm:

- the required scheduling label exists
- at least one matching runner is online
- BPF-LSM/KVM capability checks pass on the host
- no stale Aegis agent, VM, or bpffs pins remain from a previous job

If the runner fleet is unavailable, release validation is infrastructure-blocked,
not green.
