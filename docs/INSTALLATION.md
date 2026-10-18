# Installing AegisBPF (Linux)

**Choose a disposable test host for your first installation.** AegisBPF is a privileged Linux security agent. Do not enable enforcement on a production host without validating kernel capabilities, your intended policy, rollback and the [threat model](THREAT_MODEL.md).

## Distribution status: packages vs. hosted repositories

| Delivery path | Status | Practical action |
|---|---|---|
| Build from source | Supported in this repository | Use the commands below and inspect the build output |
| GitHub Release `.deb` / `.rpm` / `.tar.gz` | Release workflow is configured to publish these **when a release tag passes its gates** | Inspect the actual assets for the tag; do not assume a package exists |
| Packaging workflow artifact | CI can build and smoke-test `.deb` / `.rpm`, with limited artifact retention | Intended primarily for development/release validation, not an evergreen installer |
| Ubuntu PPA, Fedora COPR, openSUSE OBS, Arch AUR | **Not documented as live hosted repositories** | Do not advertise `apt install aegisbpf` or `dnf install aegisbpf` from a default repository |

CI coverage verifies package installation and file layout in container test images; **it does not prove BPF-LSM enforcement works on every target kernel**. See [Packaging](PACKAGING.md) and [Quality Gates](QUALITY_GATES.md).

## Option 1 — Build a local test binary (Ubuntu/Debian)

Minimum runtime: Linux kernel 5.8+, cgroup v2, BTF. BPF LSM is additionally required for `--enforce`; without it, use only an explicitly permitted audit-only mode. See [Compatibility](COMPATIBILITY.md).

```bash
sudo apt-get update
sudo apt-get install -y clang llvm libbpf-dev libelf-dev zlib1g-dev \
  libsystemd-dev pkg-config cmake ninja-build python3-jsonschema \
  linux-tools-common
sudo apt-get install -y "linux-tools-$(uname -r)" || true
scripts/verify_env.sh --strict
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=OFF
cmake --build build --target aegisbpf
sudo ./build/aegisbpf run --audit
```

If `bpftool` or the runtime dependencies differ on your distribution, consult [Troubleshooting](TROUBLESHOOTING.md). Check `bpftool version` rather than assuming a kernel-tools wrapper is usable. Press `Ctrl+C` to stop the foreground audit-only run. Never silently treat a BPF-LSM missing warning as proof of enforcement.

## Option 2 — Install a *verified, actually published* release package

1. Open [GitHub Releases](https://github.com/ErenAri/Aegis-BPF/releases) and choose an **existing** signed/tagged release. Check that the target architecture and the complete `.deb` or `.rpm` and `SHA256SUMS.txt` artifacts are present.
2. Download the package plus the corresponding checksum manifest. Verify the package's hash against the **release-provided** manifest before installation. Check that the release provenance/attestation is available and valid where published.
3. On Ubuntu/Debian use `sudo apt install ./<downloaded-package>.deb`; on Fedora/RHEL use `sudo dnf install ./<downloaded-package>.rpm`. Resolve dependencies through your distribution; **do not** disable signature or integrity checking to force an install.
4. Run `sudo aegisbpf health`, compare the output to your target host's capabilities, and start in audit mode. Only consider enforcement after isolated BPF-LSM E2E evidence and a documented rollback.

For GitHub CLI users, inspect assets **before** download:

```bash
gh release list -R ErenAri/Aegis-BPF
gh release view <EXISTING_TAG> -R ErenAri/Aegis-BPF --json assets --jq '.assets[].name'
```

Replace `<EXISTING_TAG>` with a real tag returned by GitHub; it is a placeholder, not a literal shell value. **No release was created or promoted by this documentation change.**

## Option 3 — Kubernetes evaluation

See the [Kubernetes Quickstart](QUICKSTART_K8S.md), [RBAC guidance](KUBERNETES_RBAC.md) and [audit-to-enforce rollout](K8S_ROLLOUT_AUDIT_ENFORCE.md). An installed Helm release and healthy pod **do not** prove enforce-capable kernel hooks are active on every node.

## Package maintainer / CI instructions

Maintainers: [Packaging](PACKAGING.md), [Release Drill](RELEASE_DRILL.md), [Release Readiness](RELEASE_READINESS.md) (if present in the repository), and [Evidence](EVIDENCE.md). Public hosted distro repositories, publication credentials and repeatable signed-repository distribution require separate release-engineering work.
