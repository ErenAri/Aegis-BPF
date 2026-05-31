# Pack: cis-k8s-control-plane

Protects the Kubernetes control-plane file artefacts per the CIS
Kubernetes Benchmark v1.9.0 §1 (Master Node Security Configuration).
Apply on hosts running `kube-apiserver`, `kube-controller-manager`,
`kube-scheduler`, or `etcd`.

## What it protects

| File / dir                                    | CIS §              | Why                                       |
| --------------------------------------------- | ------------------ | ----------------------------------------- |
| `/etc/kubernetes/manifests/kube-apiserver.yaml`        | 1.1.1, 1.1.2 | kubelet swaps in attacker-supplied apiserver |
| `/etc/kubernetes/manifests/kube-controller-manager.yaml` | 1.1.3, 1.1.4 |                                          |
| `/etc/kubernetes/manifests/kube-scheduler.yaml`        | 1.1.5, 1.1.6 |                                          |
| `/etc/kubernetes/manifests/etcd.yaml`         | 1.1.7, 1.1.8       |                                          |
| `/var/lib/etcd`                               | 1.1.11, 1.1.12     | cluster state — full compromise           |
| `/etc/kubernetes/admin.conf`                  | 1.1.13, 1.1.14     | cluster-admin credential                  |
| `/etc/kubernetes/scheduler.conf`              | 1.1.15, 1.1.16     |                                          |
| `/etc/kubernetes/controller-manager.conf`     | 1.1.17, 1.1.18     |                                          |
| `/etc/kubernetes/pki`                         | 1.1.19, 1.1.20     | cluster CA + apiserver / etcd certs       |
| `/etc/cni/net.d`                              | 3.1.1 (territory)  | pod-network plumbing                      |

`protect_path` semantics: the targets are read-only to all callers
*except* the components that legitimately own them. Updates via
`kubeadm upgrade` need AegisBPF stopped or the cluster-admin cgroup
allow-listed.

## Threat model

CIS Benchmark §1 explicitly enumerates these files as
single-point-of-failure for cluster compromise. An attacker with code
execution on a master node who can write to `/etc/kubernetes/manifests/`
substitutes a backdoored apiserver pod that the kubelet picks up on
its next sync. Writing to `/var/lib/etcd` rewrites cluster state
directly. Reading `/etc/kubernetes/admin.conf` extracts the
cluster-admin credential.

## Coverage and limitations

- **Covers**: file-access tamper of the listed paths.
- **Out of scope**:
  - File ownership / mode bits (CIS §1.1.x recommends `root:root 600`).
    Use the standard CIS-Audit script for that.
  - Apiserver flag values (CIS §1.2). Those are runtime config; this
    pack protects only the file containing them.
  - In-memory exfiltration of secrets via the apiserver's `/proc`
    address space — see the `kernel-tampering` pack's
    `deny_ptrace`.

## False-positive vectors

| Workflow                          | Affected entries                                      |
| --------------------------------- | ----------------------------------------------------- |
| `kubeadm upgrade`                 | every entry                                           |
| `cert-manager` rotating apiserver cert | `/etc/kubernetes/pki/apiserver.crt`              |
| Disaster-recovery etcd restore    | `/var/lib/etcd`                                       |
| CNI plugin reconfiguration        | `/etc/cni/net.d`                                      |

For maintenance windows, stop AegisBPF temporarily; for steady-state
config rotation (cert-manager), allow-list the component's cgroup.

## Install

```sh
sudo aegisbpf policy validate rules/cis-k8s-control-plane/cis-k8s-control-plane.conf
sudo aegisbpf policy apply rules/cis-k8s-control-plane/cis-k8s-control-plane.conf --reset
sudo aegisbpf run --audit
# 24h audit. If clean, enforce.
```

## References

- CIS Kubernetes Benchmark v1.9.0
  https://www.cisecurity.org/benchmark/kubernetes
- Kubernetes hardening guide (NSA / CISA, August 2022)
- `kubeadm` reference: https://kubernetes.io/docs/reference/setup-tools/kubeadm/
