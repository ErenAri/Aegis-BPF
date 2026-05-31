# Package Manager

Write-protects package manager configuration, repository sources, and
signing keys to prevent supply-chain poisoning attacks.

## Threat model

An attacker with write access to the host can compromise the software
supply chain by:

- Adding a malicious APT/YUM repository to `sources.list.d/` that serves
  trojanized packages with higher version numbers.
- Importing a rogue GPG key so the package manager trusts attacker-signed
  packages.
- Modifying the RPM or DPKG database to hide installed backdoors from
  package audits.
- Changing repository URLs to point to attacker-controlled mirrors.

This pack write-protects all standard package manager configuration paths
across Debian, RHEL, and SUSE families.

## Coverage

- MITRE: T1195.002 (Compromise Software Supply Chain), T1072 (Software Deployment Tools)
- Scope: APT, YUM, DNF, RPM, DPKG, Zypper configuration and state files
- Out of scope:
  - pip, npm, gem, and other language-level package managers
  - Container image registries and pull policies
  - Snap, Flatpak store configuration

## False-positive vectors

- Running `apt-get update`, `apt-get install`, `yum install`, or any
  package management operation will be blocked. Exempt the package
  manager's cgroup via `allow_cgroup` or pause enforcement during
  maintenance windows.
- Automated update tools (unattended-upgrades, dnf-automatic) require
  cgroup exemption.
- Configuration management tools that manage repository sources need
  their cgroup exempted.

## How to install

```sh
sudo aegisbpf policy validate rules/package-manager/package-manager.conf
sudo aegisbpf policy apply rules/package-manager/package-manager.conf --reset
```
