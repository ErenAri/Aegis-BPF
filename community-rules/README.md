# AegisBPF community rules

This directory holds **community-contributed** policy rules. They use
the same INI format and `#@aegis-tags` schema as `examples/policies/`,
but the review bar is different and the maturity ladder is explicit.

## How this differs from `examples/policies/`

| Property | `examples/policies/` | `community-rules/` |
|---|---|---|
| Audience | First-class shipped examples | Community contribution surface |
| Reviewer | AegisBPF maintainers | Maintainers + community feedback |
| Maturity | All `stable` | Mix of `experimental`, `beta`, `stable` |
| Purpose | Anchor docs, CI, tutorials | Capture in-the-wild detections |
| Removal | Requires deprecation cycle | Can be removed for non-maintenance |

When a community rule has been stable for ≥ 3 months, has ≥ 1
external contributor (or has been validated against a real adopter
deployment), and the maintainers want to commit to long-term
support, it can be **promoted** to `examples/policies/` via a PR
that updates `#@maturity` to `stable` and updates this README's
"Promoted rules" section.

This mirrors the model Falco uses for its
[`falcosecurity/rules`](https://github.com/falcosecurity/rules)
repository (community-curated rules with a maturity ladder).
The long-term plan is to move this directory out into a separate
`aegisbpf/rules` repository once it has enough volume to justify
the split — see `docs/POSITIONING.md` §4.5 #22.

## Maturity tiers

| Tier | Meaning | What it means for adopters |
|---|---|---|
| `experimental` | New, untested in production, may have false positives | Use in audit mode only; do not enforce |
| `beta` | Tested by ≥ 1 contributor, low-FP rate observed | Safe for enforce in non-critical environments |
| `stable` | Validated by maintainers and at least one adopter; promotion candidate | Safe for enforce in production |

Tier is declared via `#@maturity:` in the tag header.

## Currently shipped community rules

| Rule | Maturity | MITRE | Purpose |
|---|---|---|---|
| [`kdevtmpfsi-cryptominer.conf`](kdevtmpfsi-cryptominer.conf) | beta | T1496, T1059.004 | Block the Kinsing/kdevtmpfsi cryptominer family by inode-resilient path matching |
| [`web-shell-from-document-root.conf`](web-shell-from-document-root.conf) | experimental | T1505.003, T1059 | Block exec of arbitrary binaries from common web document roots |
| [`kubelet-credentials-protection.conf`](kubelet-credentials-protection.conf) | beta | T1552.001, T1552.005 | Deny non-system processes from reading kubelet TLS material and kubeconfig |

## How to contribute a rule

See [`CONTRIBUTING.md`](CONTRIBUTING.md) in this directory.

In short:

1. Fork and branch.
2. Write a `.conf` file using the INI format documented in
   [`docs/POLICY.md`](../docs/POLICY.md) and the tag schema in
   [`docs/rules/MITRE_ATTACK_TAG_SCHEMA.md`](../docs/rules/MITRE_ATTACK_TAG_SCHEMA.md).
3. Tag it with `#@maturity: experimental` (or `beta` if you've
   tested in your own environment).
4. Open a PR. CI will run `scripts/validate_mitre_tags.sh` against
   `community-rules/` automatically.
5. The maintainers will review for: schema correctness,
   false-positive risk, MITRE tag accuracy, and naming.

## Promoted rules

Rules that have graduated from this directory to
`examples/policies/`:

| Rule | Promoted on | PR |
|---|---|---|
| _(none yet)_ | | |

## Threat intel feeds

Rules in this directory are static. For dynamic threat intelligence
(IP / domain / hash feeds), see
[`docs/POSITIONING.md` §3.3](../docs/POSITIONING.md#33-security-content-standards)
"STIX 2.1 / TAXII" — that's the planned ingestion path. Until that
lands, dynamic IOCs should not be hard-coded into community rules
(they will rot).

## License

All files in this directory are licensed under the same terms as the
rest of AegisBPF (see [`LICENSE`](../LICENSE)). Submitting a rule via
PR is acceptance of those terms per `CONTRIBUTING.md`.
