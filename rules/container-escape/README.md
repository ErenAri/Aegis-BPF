# Container Escape

Blocks filesystem paths commonly exploited in container breakout attacks.
These are kernel and pseudo-filesystem interfaces that, when writable from
inside a container, grant host-level code execution or information disclosure.

## Threat model

Container escapes typically exploit one of a handful of host kernel interfaces
that are inadvertently exposed to the container (privileged mode, excessive
capabilities, or misconfigured volume mounts). The most common vectors are:

- Writing to `/sys/kernel/uevent_helper` or `/sys/fs/cgroup/release_agent`
  to trigger host-side command execution.
- Reading `/proc/kcore` or `/dev/mem` to dump host kernel memory.
- Overwriting `/proc/sys/kernel/core_pattern` with a pipe to a user binary.
- Triggering kernel panics or reboots via `/proc/sysrq-trigger`.

This pack denies opens on those paths, stopping the escape at the
file-access layer regardless of container runtime configuration.

## Coverage

- MITRE: T1611 (Escape to Host), T1610 (Deploy Container)
- Scope: filesystem-level access to well-known escape paths
- Out of scope: escapes via kernel exploits, container runtime API abuse,
  or network-based breakouts

## False-positive vectors

- Debugging tools that read `/proc/kcore` (crash, drgn) will be blocked.
  Use `allow_cgroup` to exempt the debugging session's cgroup.
- Monitoring agents that read `/proc/sys/kernel/core_pattern` for
  compliance checks will be blocked. Exempt their cgroup or switch to
  reading via sysctl(8) if available.
- Hosts running legitimate uevent helpers (extremely rare outside embedded
  Linux) need the `/sys/kernel/uevent_helper` entry removed.

## How to install

```sh
sudo aegisbpf policy validate rules/container-escape/container-escape.conf
sudo aegisbpf policy apply --reset rules/container-escape/container-escape.conf
```
