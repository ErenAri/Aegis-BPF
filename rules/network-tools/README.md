# Network Tools

## Threat model
Restricts network reconnaissance tools used during lateral movement.

## Coverage
- MITRE: T1046 (Network Service Discovery), T1018 (Remote System Discovery)
- Scope: blocks nmap, masscan, zmap, arp-scan, nbtscan

## False-positive vectors
- Network administrators performing legitimate scans
- Monitoring tools using nmap for service discovery

## How to install
```sh
sudo aegisbpf policy validate rules/network-tools/network-tools.conf
sudo aegisbpf policy apply --reset rules/network-tools/network-tools.conf
```
