# Contributing a community rule

This is a focused checklist for submitting a new rule to
`community-rules/`. For general project contribution guidance, see
the top-level [`CONTRIBUTING.md`](../CONTRIBUTING.md).

## Before you start

- Search this directory and `examples/policies/` for existing
  coverage. Don't duplicate — extend.
- If your rule depends on a specific kernel feature or AegisBPF
  capability, check `docs/COMPATIBILITY.md` first.
- If your rule references threat intelligence (specific IPs,
  domains, hashes), think about whether they will rot. Static
  rules live forever; static IOCs do not.

## Required for every PR

- [ ] One file per logical rule. File name is kebab-case + `.conf`.
- [ ] `#@aegis-tags` block in the first 40 lines, before any INI
      section. See `docs/rules/MITRE_ATTACK_TAG_SCHEMA.md`.
- [ ] Required tag fields: `id`, `version` (start at `1`), `mitre`
      (or `-` if no ATT&CK mapping applies), `platform`.
- [ ] `id` is unique across `examples/policies/` and
      `community-rules/`. The validator enforces this.
- [ ] `#@maturity:` set honestly. Default to `experimental` unless
      you've personally tested in a non-trivial environment.
- [ ] `#@severity:` set. Use the AegisBPF severity ladder
      (`info`, `low`, `medium`, `high`, `critical`).
- [ ] At least one `#@reference:` line — the threat report, blog
      post, advisory, CVE, or upstream rule that motivated this.
- [ ] A header comment block above the tags explaining: what
      threat this catches, what false positives might occur, and
      an example legitimate workload that should NOT be blocked.

## Test your rule locally

```bash
# Validate the tag header
POLICY_DIR=community-rules ./scripts/validate_mitre_tags.sh

# Apply in audit mode against a test cgroup
sudo aegisbpf policy apply community-rules/your-rule.conf --audit

# Trigger the protected condition and observe the audit event
sudo aegisbpf events tail | grep "your-rule-id"
```

## Avoid

- **Hard-coded current IPs / domains / hashes that change.** Use
  CIDR ranges or path patterns, or wait for the threat-intel
  ingestion path.
- **Rules that block on common process names without
  qualification.** `bash`, `python`, `curl`, `nc` are everywhere.
  Scope by parent process, cgroup, container image, or binary
  hash.
- **Duplicating shipped policies.** Extend the existing rule with
  a separate file only if the new coverage is meaningfully
  different. Otherwise, propose an edit to the shipped rule.
- **MITRE tag inflation.** Don't list every plausibly-related
  technique; list the ones the rule actually covers.

## Review process

1. Open the PR. CI runs:
   - `scripts/validate_mitre_tags.sh` over `community-rules/`.
   - `community-rules-validate.yml` (lints structure + checks
     for shipped-policy overlap by `id`).
2. A maintainer reviews within ~14 days for schema, FP risk,
   accuracy, naming.
3. Other community members are welcome to comment with their
   own deployment experience.
4. Once merged, the rule lands as the maturity tier you declared.
   Promoting from `experimental` → `beta` → `stable` is a
   follow-up PR.

## Removing or deprecating a rule

If your rule turns out to be wrong or its threat surface evaporated:

- Open a PR removing the file with a rationale in the commit
  message and a comment in this directory's README under a
  "Removed rules" subsection (add the subsection if needed).
- A `#@maturity: deprecated` value is reserved for future use; do
  not use it yet.

## Questions

Open a [Discussion](https://github.com/ErenAri/Aegis-BPF/discussions)
under the "Ideas" category before writing the rule, especially if
it's a category that doesn't fit the existing examples — saves
review cycles.
