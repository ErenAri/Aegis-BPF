# Kubernetes Secrets

Protects Kubernetes secrets, service account tokens, and PKI material
on disk from unauthorized reads and writes.

## Threat model

Kubernetes stores sensitive material in several well-known filesystem
locations that attackers target after gaining node-level access:

- **Service account tokens** (`/var/run/secrets/kubernetes.io/`) are
  automatically mounted into every pod and grant API access scoped to the
  service account's RBAC permissions.
- **PKI material** (`/etc/kubernetes/pki/`) contains CA keys and
  certificates that can be used to issue arbitrary cluster credentials.
- **etcd data** (`/var/lib/etcd/`) contains every Kubernetes secret in
  the cluster, often in plaintext.
- **kubeconfig files** contain pre-authenticated contexts for cluster
  admin access.

Compromising any of these allows lateral movement across the entire
Kubernetes cluster.

## Coverage

- MITRE: T1552.001 (Credentials in Files), T1528 (Steal Application Access Token)
- Scope: service account tokens, cluster PKI, etcd data, kubeconfigs,
  encryption config, Helm state
- Out of scope:
  - Kubernetes API-level secret access (RBAC controls)
  - Secrets injected via environment variables
  - External secret stores (Vault, AWS Secrets Manager)

## False-positive vectors

- kubelet, kube-apiserver, and other control-plane components need to read
  PKI material and kubeconfig files. Exempt their cgroups via `allow_cgroup`.
- Pod workloads that legitimately read their service account token (for
  in-cluster API access) will be blocked. Exempt the application's cgroup.
- etcd itself needs read/write access to `/var/lib/etcd/`. Exempt the
  etcd process cgroup.
- Helm and kubectl commands that read kubeconfig will be blocked. Exempt
  admin/CI cgroups.

## How to install

```sh
sudo aegisbpf policy validate rules/k8s-secrets/k8s-secrets.conf
sudo aegisbpf policy apply rules/k8s-secrets/k8s-secrets.conf --reset
```
