# DNS Hijack

Write-protects DNS and name resolution configuration to prevent attackers
from redirecting DNS queries to malicious resolvers or poisoning local
hostname resolution.

## Threat model

DNS hijacking on a compromised host is a high-value technique because it
enables:

- Redirecting all DNS queries to an attacker-controlled resolver for
  man-in-the-middle attacks on TLS (combined with rogue CA injection).
- Poisoning `/etc/hosts` to redirect specific hostnames (e.g., internal
  APIs, update servers) to attacker infrastructure.
- Changing `nsswitch.conf` to prioritize a malicious name resolution
  source over legitimate DNS.
- Redirecting package manager update checks to serve trojanized packages.

This pack write-protects all standard DNS configuration files.

## Coverage

- MITRE: T1584.002 (DNS Server), T1557 (Adversary-in-the-Middle)
- Scope: resolv.conf, hosts, nsswitch.conf, systemd-resolved, dnsmasq
- Out of scope:
  - Application-level DNS configuration (Java DNS settings, browser DoH)
  - Container-internal DNS (/etc/resolv.conf mounted by container runtime)
  - Network-level DNS interception (router/switch-level hijacking)

## False-positive vectors

- DHCP clients (dhclient, NetworkManager) that update `/etc/resolv.conf`
  on lease renewal will be blocked. Exempt their cgroup via `allow_cgroup`.
- VPN clients that modify DNS settings on connect/disconnect need exemption.
- systemd-resolved itself writes to `/etc/resolv.conf` (as a stub) and
  requires cgroup exemption.
- Container runtimes that set up per-container DNS configuration need
  their cgroup exempted.

## How to install

```sh
sudo aegisbpf policy validate rules/dns-hijack/dns-hijack.conf
sudo aegisbpf policy apply --reset rules/dns-hijack/dns-hijack.conf
```
