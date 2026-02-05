# Design Artifact Status

This page tracks synchronization status between active markdown specs in
`docs/` and design artifacts in the repository root.

## Source-of-truth policy

- Source of truth for architecture and behavior contracts: markdown files under
  `docs/`.
- Root PDF (`eBPF Runtime Security Agent Design.pdf`) is an archival export and
  must not be treated as authoritative when it diverges from markdown.

## Root PDF status

- Artifact: `eBPF Runtime Security Agent Design.pdf`
- Status on 2026-02-05: **In sync** (generated from docs at commit `2a08aaf`)
- Notes: Box-drawing diagrams were converted to ASCII to keep PDF output clean.
  The generator prefers DejaVu/Noto fonts when available.
- Blocking delta areas:
  - Product-excellence super-phase gates
  - Updated soak/perf KPI enforcement (`<0.1%` drop ratio, `p95 <= 5%`)
  - External review and pilot evidence tracking

## Refresh checklist

Before a release candidate:

1. Regenerate the PDF from current markdown architecture docs.
   - Command: `scripts/generate_design_pdf.sh`
   - Sources: `docs/DESIGN_PDF_SOURCES.md`
2. Add generation metadata in the PDF cover page:
   - date (UTC)
   - git commit SHA
   - statement that markdown docs remain source of truth
3. Verify all links and section titles match `docs/` names.
4. Update this file status to `In sync` with exact date and SHA.
