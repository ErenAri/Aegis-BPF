# AegisBPF Rule Tag Schema — MITRE ATT&CK and Compliance

## Purpose

AegisBPF policies are INI-style `.conf` files. To make them indexable,
searchable, and usable as threat-intelligence, each shipped policy
declares its coverage against:

- **MITRE ATT&CK Enterprise** — techniques and tactics
- **Compliance frameworks** — CIS, NIST 800-53, NIST 800-190, PCI DSS
- **Target platform** — linux, containers, kubernetes

This document specifies the **structured tag header** format that
downstream tooling (SIEM enrichment, rule catalog pages, detection
dashboards) can parse.

Tags live in comments, so they are backwards-compatible with the
existing policy parser — nothing in the runtime loader has to change.

## Schema

A tag header is a contiguous block of `#@...` comment lines that begins
with `#@aegis-tags` and ends with `#@end-tags`. It must appear in the
first 40 lines of the file (the header preamble), before any INI
section (`[...]`).

```
#@aegis-tags
#@id:        container-hardening
#@version:   1
#@mitre:     T1552.001, T1611, T1055.008, T1547.006, T1562.001, T1071
#@tactic:    TA0006, TA0004, TA0005, TA0003, TA0011
#@platform:  linux, containers
#@compliance: nist-800-190:6.4.1, nist-800-190:6.4.2, nist-800-53:AC-3, nist-800-53:SC-7
#@severity:  high
#@maturity:  stable
#@end-tags
```

### Required fields

| Field | Meaning | Example |
|-------|---------|---------|
| `#@id` | Short machine identifier, kebab-case, unique within the repo | `container-hardening` |
| `#@version` | Integer, starts at 1, bumped on breaking rule changes | `1` |
| `#@mitre` | Comma-separated MITRE ATT&CK technique IDs (with sub-techniques). Use `-` if none apply | `T1552.001, T1611` |
| `#@platform` | Comma-separated target platforms | `linux, containers` |

### Optional fields

| Field | Meaning |
|-------|---------|
| `#@tactic` | Comma-separated MITRE ATT&CK tactic IDs (`TAxxxx`). Usually derivable from the techniques but declared explicitly for tooling. |
| `#@compliance` | Comma-separated `<framework>:<control>` tokens. Framework names: `nist-800-53`, `nist-800-190`, `pci-dss-4`, `cis-k8s`, `iso-27001`, `soc2`. |
| `#@severity` | One of `info`, `low`, `medium`, `high`, `critical`. Defaults to `medium`. |
| `#@maturity` | One of `experimental`, `beta`, `stable`. Defaults to `stable`. |
| `#@reference` | URL (single per line; repeat the tag for multiple). |
| `#@author` | Free-form attribution. |

### Field grammar

- Each field line: `#@<field>: <value>` — the colon and at least one
  space after it are required.
- Lists use comma separators, whitespace ignored.
- Field names are case-insensitive; parsers should lowercase before
  comparing.
- `#@` lines outside the `#@aegis-tags` / `#@end-tags` block are
  reserved for future use and MUST be ignored by current tooling.

## Valid MITRE identifiers

- Techniques: pattern `^T\d{4}(\.\d{3})?$` (e.g. `T1611`, `T1055.008`).
- Tactics: pattern `^TA\d{4}$` (e.g. `TA0005`).
- Tactic <-> technique mapping is **not** re-validated by AegisBPF;
  parsers should treat the ATT&CK STIX bundle as source of truth.
- Use the latest stable ATT&CK version (v14+); do not invent IDs.

## Parser reference implementation (grep)

Quick extraction without writing code:

```bash
# List all MITRE techniques referenced in shipped policies
grep -h '^#@mitre:' examples/policies/*.conf \
  | sed 's/^#@mitre:[[:space:]]*//' \
  | tr ',' '\n' \
  | tr -d ' ' \
  | sort -u

# Find all policies covering T1611 (container escape)
grep -l '^#@mitre:.*T1611' examples/policies/*.conf
```

## Operator requirements

Any automated catalog / dashboard that consumes these tags MUST:

1. Validate technique IDs against the ATT&CK STIX bundle at build time.
2. Fail the build on unknown IDs rather than silently dropping them.
3. Treat an absent `#@aegis-tags` block as "uncategorized" (not an
   error) — community rules may not have them yet.

## Tagged policies (current)

| Policy | MITRE techniques |
|--------|------------------|
| `examples/policies/container-hardening.conf` | T1552.001, T1611, T1055.008, T1547.006, T1562.001, T1071 |
| `examples/policies/cryptocurrency-mining-detection.conf` | T1496, T1071 |
| `examples/policies/cis-kubernetes-benchmark.conf` | T1552.001, T1078.004, T1613 |
| `examples/policies/compliance-pci-dss.conf` | T1552.001, T1003.008, T1070 |
| `examples/policies/minimal-getting-started.conf` | T1552.001, T1055.008 |

## References

- MITRE ATT&CK Enterprise: <https://attack.mitre.org/>
- ATT&CK STIX 2.1 bundle:
  <https://github.com/mitre-attack/attack-stix-data>
- ATT&CK for Containers matrix:
  <https://attack.mitre.org/matrices/enterprise/containers/>
- NIST SP 800-53 Rev 5: <https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final>
- NIST SP 800-190: <https://csrc.nist.gov/pubs/sp/800/190/final>
