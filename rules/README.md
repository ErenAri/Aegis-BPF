# AegisBPF Community Rule Library

Curated, MITRE-tagged AegisBPF policy packs that ship with the agent.
Each pack is a small, **focused** `.conf` file in the project's INI policy
format (`docs/POLICY.md`) covering one threat or one hardening
benchmark. Packs are designed to be loaded individually with
`aegisbpf policy apply <pack>.conf` or composed by an operator-curated
top-level policy that `# include`s individual packs by hand.

## Why this exists

The AegisBPF roadmap (`docs/POSITIONING.md` §4.5 #22) calls out the
absence of a community rule library as a *positioning* gap relative to
projects like Falco, whose ruleset is the moat. Shipping a starter set
of audited, MITRE-mapped rules in-tree gives downstream operators a
defensible baseline they can deploy without writing policy from
scratch.

This is **not** a complete coverage matrix. It is a starter set that
operators are expected to read, audit, and adapt for their workload.
Every pack documents its scope and known false-positive vectors.

## Pack layout (25 packs)

```
rules/
├── README.md                       — this file
├── cis-k8s-control-plane/          — CIS Kubernetes Benchmark §1 (control plane)
├── cis-k8s-worker-node/            — CIS Kubernetes Benchmark §4 (worker)
├── cloud-metadata/                 — protect cloud credential files (AWS/Azure/GCP)
├── container-escape/               — block container breakout vectors
├── credential-access/              — block credential dumping tools/paths
├── cryptominers/                   — well-known cryptominer binaries
├── data-exfiltration/              — restrict common exfiltration tools
├── dns-hijack/                     — protect DNS/name resolution configs
├── file-integrity/                 — protect critical system binaries
├── k8s-secrets/                    — protect Kubernetes secrets on disk
├── kernel-tampering/               — block kernel module/BPF/ptrace abuse
├── log-tampering/                  — protect system logs from modification
├── malware-staging/                — block execution from staging directories
├── network-tools/                  — restrict network reconnaissance tools
├── package-manager/                — protect package manager integrity
├── pam-backdoor/                   — protect PAM configuration
├── persistence-cron/               — protect cron/at persistence mechanisms
├── persistence-shell/              — protect shell profile persistence
├── persistence-systemd/            — protect systemd unit persistence
├── privilege-escalation/           — protect sudoers/PAM from abuse
├── reverse-shell/                  — block common reverse shell tools
├── runtime-protection/             — protect container runtime sockets
├── secrets-protection/             — protect on-disk credentials
├── ssh-hardening/                  — protect SSH server + authorized_keys
└── web-shell/                      — block common web shell staging
```

Each pack contains a `.conf` policy file and a `README.md` documenting
threat model, MITRE coverage, false-positive vectors, and install steps.

Every `.conf` file is validated in CI by
`.github/workflows/rule-library.yml`, which runs
`aegisbpf policy validate` on each shipped pack and fails the PR if
any fail to parse.

## Pack file conventions

Each pack `.conf` file MUST:

1. Start with a `# Pack:` header block listing:
   - Pack name
   - One-line purpose
   - MITRE ATT&CK technique IDs covered (`T1XXX[.NNN]` format)
   - CIS Benchmark section refs if applicable
   - Last-reviewed date (`YYYY-MM-DD`)
2. Use the documented INI section keywords only; no wildcards (the
   parser rejects them — see `src/policy_parse.cpp`).
3. Use absolute paths for `deny_path` / `protect_path` (parser
   requirement).
4. Be safe to `policy validate` with no other context (i.e. no
   external file references).

Each pack `README.md` MUST document:

- **Threat model** — what the pack actually defends against.
- **Coverage** — which MITRE techniques and CIS controls are addressed
  and which are out-of-scope.
- **False-positive vectors** — known operator workflows the pack
  would interfere with (e.g. `apt-get update` writing under
  `/var/lib/apt/`).
- **How to install** — the exact `aegisbpf policy apply` invocation,
  including `--require-signature` guidance.

## Loading a pack

```sh
# Audit-mode dry run first — never enforce a fresh pack blind.
sudo aegisbpf policy validate rules/secrets-protection/secrets-protection.conf
sudo aegisbpf policy apply --reset rules/secrets-protection/secrets-protection.conf
sudo aegisbpf run --audit
# Inspect events; if clean for your workload, switch to enforce.
sudo systemctl restart aegisbpf  # picks up /etc/default/aegisbpf
```

Packs are intentionally small so they compose. If you want to layer
several, concatenate them into a single operator-curated policy file
(keep one `version=` line at the top); the parser deduplicates on entry
ingestion.

## Contributing a new pack

1. Open an issue describing the threat and the proposed coverage
   matrix.
2. Author the pack under `rules/<short-name>/<short-name>.conf` with a
   sibling `README.md`.
3. The `rule-library` CI gate must pass:
   `aegisbpf policy validate rules/<short-name>/<short-name>.conf`.
4. Tag a maintainer for review. Maintainers will sanity-check
   false-positive impact against typical workloads (developer laptop,
   CI runner, K8s node) before merging.

## Provenance and trust

- Hash-based rules (`deny_binary_hash` / `allow_binary_hash`) are
  intentionally absent from these starter packs: the project does not
  publish hashes of malware binaries it has not directly verified.
  Operators integrating threat-intel feeds should add hashes from
  their own provenance-tracked sources.
- Path-based rules use only well-documented public install locations
  (CIS Benchmarks, project documentation, distro packaging metadata).

## License

Apache-2.0, same as the parent project.
