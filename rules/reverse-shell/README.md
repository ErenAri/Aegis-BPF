# Reverse Shell

Blocks execution of common network relay and reverse-shell tools that
attackers use for interactive command-and-control access after initial
compromise.

## Threat model

After gaining initial code execution (web-app exploit, supply-chain
compromise, SSRF-to-RCE), the attacker's immediate next step is typically
to establish an interactive reverse shell. The most common approach is a
one-liner using `nc`, `ncat`, `socat`, or similar tools already present
on the system.

Blocking execution of these binaries forces the attacker to bring their
own tooling or use language-native reverse shells (Python, Perl, bash
/dev/tcp), which are noisier and more detectable by behavioural monitoring.

## Coverage

- MITRE: T1059 (Command and Scripting Interpreter), T1071 (Application Layer Protocol)
- Scope: blocks exec of listed reverse-shell binaries at standard paths
- Out of scope:
  - Language-native reverse shells (bash /dev/tcp, python pty.spawn)
  - Renamed or custom-compiled netcat variants
  - Legitimate tunneling tools (ssh -R, chisel) used as pivot tools

## False-positive vectors

- System administrators using `nc` for ad-hoc port testing or file
  transfers will be blocked. Use `allow_cgroup` to exempt admin sessions
  or remove the specific `nc` entry.
- Monitoring scripts that use `ncat` for health checks need exemption.
- Nmap is a legitimate admin tool. If you run scheduled vulnerability
  scans from this host, remove the nmap entries or exempt the scanner's
  cgroup.

## How to install

```sh
sudo aegisbpf policy validate rules/reverse-shell/reverse-shell.conf
sudo aegisbpf policy apply --reset rules/reverse-shell/reverse-shell.conf
```
