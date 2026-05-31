# Pack: cryptominers

Blocks exec of well-known cryptominer binaries at their most common
installation paths. **Path-based detection only** — attackers can
rename or move the binary to evade. Pair this with hash-based rules
from your own threat-intel feed for stronger coverage.

## What it blocks

| Family                                 | Paths covered                                | MITRE ATT&CK |
| -------------------------------------- | -------------------------------------------- | ------------ |
| XMRig (Monero)                         | `/usr/{,local/}bin/xmrig`, `/opt/xmrig/xmrig`, `/root/xmrig`, `/root/.xmrig/xmrig`, `/var/tmp/xmrig`, `/tmp/xmrig`, `/dev/shm/xmrig` | T1496        |
| T-Rex / lolMiner / NBMiner             | `/usr/{,local/}bin/{t-rex,lolMiner,nbminer}`, `/opt/t-rex/t-rex` | T1496 |
| CCMiner / cgminer / bfgminer           | `/usr/{,local/}bin/{ccminer,cgminer,bfgminer}` | T1496      |
| Ethminer / PhoenixMiner                | `/usr/{,local/}bin/ethminer`, `/opt/phoenixminer/PhoenixMiner`, `/usr/bin/PhoenixMiner` | T1496 |
| Pacha / WatchDog / Kinsing dropper     | `/tmp/kdevtmpfsi`, `/tmp/kinsing`, `/var/tmp/kinsing`, `/dev/shm/kdevtmpfsi` | T1496 |

## Threat model

Cryptojacking on Linux servers and CI runners is one of the most
common opportunistic post-compromise objectives — abundant CPU/GPU,
moderate detection, monetizable directly. Most droppers fetch their
payload to one of a small handful of well-known paths because the
campaign authors do not invest in evasion (the goal is fleet
coverage, not stealth).

Blocking exec at those paths denies the easy wins. Sophisticated
operators rename and chmod-elsewhere, but at that point detection
shifts to behavioural signals (CPU pinning, pool DNS lookups) that
are out of scope for path-based policy.

## Coverage and limitations

- **Covers**: exec of the listed file paths by any uid.
- **Out of scope**:
  - Renamed binaries (`/tmp/syslog` carrying XMRig). Add behavioural
    rules (`deny_cidr` for known mining-pool subnets, future
    `deny_dns` for `*.pool.*`) for that.
  - In-process mining via legitimate runtimes (a Node.js process
    embedding `cn-cryptonight-wasm`). Use binary-hash rules for the
    parent runtime instead.
  - GPU-only miners hidden in container images. Add the container's
    image-extracted absolute path or use `deny_binary_hash`.

## False-positive vectors

If you actively run a cryptominer on this host (developer testing a
mining pool integration, a sanctioned compute-to-revenue project),
remove the affected entries before applying.

No standard distro or upstream tool installs into these paths under
these names, so non-mining false-positives should be zero on a clean
host.

## Install

```sh
sudo aegisbpf policy validate rules/cryptominers/cryptominers.conf
sudo aegisbpf policy apply rules/cryptominers/cryptominers.conf --reset
sudo aegisbpf run --audit
# 24h audit. If clean, enforce.
```

## How to extend

The fastest way to harden this pack is to add SHA-256 hashes of
miner binaries you have observed in your environment. AegisBPF
supports hash-based exec rules:

```ini
[deny_binary_hash]
sha256:<64-hex-from-your-IR-investigation>
```

The pack ships **without** sample hashes intentionally — see
`rules/README.md` "Provenance and trust" for rationale.
