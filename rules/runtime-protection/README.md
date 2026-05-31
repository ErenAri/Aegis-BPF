# Runtime Protection

Write-protects container runtime Unix sockets to prevent attackers from
using container APIs to escape to the host or deploy malicious containers.

## Threat model

Container runtime sockets (Docker, containerd, CRI-O) provide full API
access to the container lifecycle. An attacker who can write to these
sockets can:

- Create a privileged container with the host filesystem mounted,
  effectively escaping the container.
- Execute commands inside existing containers to move laterally.
- Deploy cryptocurrency miners or other malicious workloads.
- Modify container configurations to weaken security policies.

This is one of the most common Kubernetes escape vectors: a pod with the
Docker socket mounted can trivially break out to the host.

## Coverage

- MITRE: T1610 (Deploy Container), T1609 (Container Administration Command)
- Scope: Docker, containerd, CRI-O, Podman sockets; kubelet configuration
- Out of scope:
  - Remote container API access (TCP-exposed Docker API)
  - Kubernetes API server access (network-level control)
  - User-namespaced rootless container sockets

## False-positive vectors

- Legitimate container management operations (docker build, docker run,
  kubectl) will be blocked if their processes are not exempted. Add the
  CI/CD agent or admin shell cgroup to `allow_cgroup`.
- Container orchestration tools (Kubernetes kubelet, Docker Compose) need
  their cgroups exempted to function.
- Monitoring agents that query the Docker API for container metrics
  (cAdvisor, Datadog) require cgroup exemption.

## How to install

```sh
sudo aegisbpf policy validate rules/runtime-protection/runtime-protection.conf
sudo aegisbpf policy apply rules/runtime-protection/runtime-protection.conf --reset
```
