#!/usr/bin/env bash
# veristat_check.sh - Compare BPF verifier complexity against baselines
#
# Usage:
#   ./scripts/veristat_check.sh <bpf_object> [--update-baseline]
#
# Requires: bpftool with veristat support (linux-tools >= 6.1)
#
# Exit codes:
#   0 - All programs within threshold
#   1 - One or more programs exceeded threshold
#   2 - Usage error or missing tools

set -euo pipefail

BASELINE_FILE="config/veristat_baseline.json"
THRESHOLD_PERCENT="${VERISTAT_THRESHOLD_PERCENT:-15}"
BPF_OBJ="${1:-}"
UPDATE_BASELINE=false

if [[ "${2:-}" == "--update-baseline" ]]; then
    UPDATE_BASELINE=true
fi

if [[ -z "$BPF_OBJ" ]]; then
    echo "Usage: $0 <bpf_object> [--update-baseline]" >&2
    exit 2
fi

if [[ ! -f "$BPF_OBJ" ]]; then
    echo "Error: BPF object not found: $BPF_OBJ" >&2
    exit 2
fi

# Check for veristat support
if ! command -v bpftool >/dev/null 2>&1; then
    echo "Warning: bpftool not found, skipping veristat check"
    exit 0
fi

# Run veristat and capture output
VERISTAT_OUT=$(mktemp)
trap "rm -f $VERISTAT_OUT" EXIT

echo "Running veristat on $BPF_OBJ..."

# Try veristat subcommand first (bpftool >= 7.1), fall back to prog profile
if bpftool prog veristat "$BPF_OBJ" --output-format json > "$VERISTAT_OUT" 2>/dev/null; then
    echo "veristat completed successfully"
elif sudo bpftool prog veristat "$BPF_OBJ" --output-format json > "$VERISTAT_OUT" 2>/dev/null; then
    echo "veristat completed with sudo"
else
    echo "Warning: veristat not supported by this bpftool version"
    echo "Attempting fallback: loading and inspecting verifier stats..."

    # Fallback: load the object and read verifier stats from prog info
    # This requires CAP_BPF and a compatible kernel
    if sudo bpftool prog load "$BPF_OBJ" /sys/fs/bpf/aegisbpf_veristat_tmp 2>/dev/null; then
        sudo bpftool prog show pinned /sys/fs/bpf/aegisbpf_veristat_tmp --json > "$VERISTAT_OUT" 2>/dev/null || true
        sudo rm -f /sys/fs/bpf/aegisbpf_veristat_tmp 2>/dev/null || true
    else
        echo "Warning: Could not run veristat or load BPF object; skipping complexity check"
        exit 0
    fi
fi

if [[ ! -s "$VERISTAT_OUT" ]]; then
    echo "Warning: veristat produced no output; skipping check"
    exit 0
fi

# Parse and compare against baseline
python3 - "$VERISTAT_OUT" "$BASELINE_FILE" "$THRESHOLD_PERCENT" "$UPDATE_BASELINE" <<'PYTHON'
import json
import os
import sys

veristat_file = sys.argv[1]
baseline_file = sys.argv[2]
threshold_pct = int(sys.argv[3])
update_baseline = sys.argv[4] == "true"

# Load veristat output
with open(veristat_file, "r", encoding="utf-8") as f:
    veristat_data = json.load(f)

# Normalize veristat output into {prog_name: insns_processed}
current = {}
if isinstance(veristat_data, list):
    for entry in veristat_data:
        name = entry.get("prog_name", entry.get("name", "unknown"))
        insns = entry.get("insns_processed", entry.get("verified_insns", 0))
        if insns > 0:
            current[name] = {
                "insns_processed": insns,
                "total_states": entry.get("total_states", 0),
                "peak_states": entry.get("peak_states", 0),
            }
elif isinstance(veristat_data, dict):
    # Single program info format
    name = veristat_data.get("prog_name", veristat_data.get("name", "unknown"))
    insns = veristat_data.get("insns_processed", veristat_data.get("verified_insns", 0))
    if insns > 0:
        current[name] = {
            "insns_processed": insns,
            "total_states": veristat_data.get("total_states", 0),
            "peak_states": veristat_data.get("peak_states", 0),
        }

if not current:
    print("Warning: No verifier stats extracted; skipping comparison")
    sys.exit(0)

# Print current stats
print("\n=== Verifier Complexity Report ===")
print(f"{'Program':<40} {'Instructions':>12} {'States':>10} {'Peak':>10}")
print("-" * 75)
for name, stats in sorted(current.items()):
    print(f"{name:<40} {stats['insns_processed']:>12,} {stats['total_states']:>10,} {stats['peak_states']:>10,}")

# Update baseline mode
if update_baseline:
    os.makedirs(os.path.dirname(baseline_file), exist_ok=True)
    with open(baseline_file, "w", encoding="utf-8") as f:
        json.dump(current, f, indent=2, sort_keys=True)
        f.write("\n")
    print(f"\nBaseline updated: {baseline_file}")
    sys.exit(0)

# Compare against baseline
if not os.path.exists(baseline_file):
    print(f"\nNo baseline found at {baseline_file}")
    print("Run with --update-baseline to create initial baseline")
    # First run: don't fail, just report
    sys.exit(0)

with open(baseline_file, "r", encoding="utf-8") as f:
    baseline = json.load(f)

regressions = []
new_programs = []

for name, stats in current.items():
    if name not in baseline:
        new_programs.append(name)
        continue

    base_insns = baseline[name]["insns_processed"]
    curr_insns = stats["insns_processed"]

    if base_insns == 0:
        continue

    pct_change = ((curr_insns - base_insns) / base_insns) * 100

    if pct_change > threshold_pct:
        regressions.append({
            "program": name,
            "baseline": base_insns,
            "current": curr_insns,
            "change_pct": pct_change,
        })

# Report results
print(f"\nThreshold: {threshold_pct}% regression allowed")

if new_programs:
    print(f"\nNew programs (no baseline): {', '.join(new_programs)}")

if regressions:
    print(f"\n*** REGRESSIONS DETECTED ({len(regressions)} programs) ***")
    for r in regressions:
        print(f"  {r['program']}: {r['baseline']:,} -> {r['current']:,} (+{r['change_pct']:.1f}%)")
    print(f"\nRun with --update-baseline to accept new complexity levels")
    sys.exit(1)
else:
    print("\nAll programs within complexity threshold")
    sys.exit(0)
PYTHON
