# Pack: cis-k8s-worker-node

Protects Kubernetes worker-node file artefacts per the CIS Kubernetes
Benchmark v1.9.0 §4 (Worker Node Security Configuration). Apply on
every host running `kubelet` — control-plane nodes also run `kubelet`,
so this pack composes with `cis-k8s-control-plane`.

## What it protects

| File / dir                                    | CIS §            | Why                                           |
| --------------------------------------------- | ---------------- | --------------------------------------------- |
| `/etc/systemd/system/kubelet.service{,.d}`    | 4.1.1, 4.1.2     | Substitute kubelet binary or args at next reboot |
| `/etc/kubernetes/kubelet.conf`                | 4.1.5, 4.1.6     | kubelet auth credential                       |
| `/etc/kubernetes/bootstrap-kubelet.conf`      | 4.1.5, 4.1.6     | one-time bootstrap token                      |
| `/etc/kubernetes/proxy.conf`                  | 4.1.7, 4.1.8     | kube-proxy auth credential                    |
| `/var/lib/kubelet/config.yaml`                | 4.1.9, 4.1.10    | kubelet runtime config (auth, CGroup driver)  |
| `/var/lib/kubelet/pki`                        | 4.1.5            | kubelet client cert + key                     |
| `/run/containerd/containerd.sock`, `crio.sock`| 5.x territory    | Pivot from compromised pod to host runtime    |

## Threat model

Worker-node compromise on Kubernetes typically follows one of:

1. **Pod escape** to host filesystem; attacker reads
   `/var/lib/kubelet/pki/kubelet-client-current.pem` and impersonates
   the node to the apiserver, gaining read access to all pods'
   secrets that schedule on that node's CSR.
2. **kubelet config tamper**: edit `config.yaml` to enable
   `--anonymous-auth=true` or weaken auth, then restart. Next time
   any tooling polls the kubelet API at port 10250, they hit
   unauthenticated.
3. **Runtime socket abuse**: write directly to
   `/run/containerd/containerd.sock` from a privileged pod to launch
   sibling containers that bypass kube-apiserver admission.

This pack closes those routes at the file-access layer.

## Coverage and limitations

- **Covers**: file-access tamper / read of the listed paths.
- **Out of scope**:
  - File ownership / mode bits — CIS standard audit script handles
    those.
  - kubelet runtime flag values (CIS §4.2). This pack protects only
    the file containing them.
  - Network-level pivoting from a pod (e.g. metadata service abuse
    via `169.254.169.254`). Use a `deny_cidr` rule instead.

## False-positive vectors

| Workflow                          | Affected entries                                |
| --------------------------------- | ----------------------------------------------- |
| `kubeadm upgrade node`            | every entry                                     |
| kubelet client-cert auto-rotation | `/var/lib/kubelet/pki/`                         |
| Container runtime upgrade         | `/run/containerd/containerd.sock` (re-bind)     |
| `nerdctl` from a privileged shell | `/run/containerd/containerd.sock`               |

kubelet client-cert rotation writes a new symlink under
`/var/lib/kubelet/pki/` — `protect_path` on the directory blocks
rotation. Operators with rotation enabled should use a more granular
allow-list or stop AegisBPF for the rotation window.

## Install

```sh
sudo aegisbpf policy validate rules/cis-k8s-worker-node/cis-k8s-worker-node.conf
sudo aegisbpf policy apply rules/cis-k8s-worker-node/cis-k8s-worker-node.conf --reset
sudo aegisbpf run --audit
# 48h audit covers a typical cert-rotation window. If clean, enforce.
```

## References

- CIS Kubernetes Benchmark v1.9.0
  https://www.cisecurity.org/benchmark/kubernetes
- kubelet docs: https://kubernetes.io/docs/reference/command-line-tools-reference/kubelet/
