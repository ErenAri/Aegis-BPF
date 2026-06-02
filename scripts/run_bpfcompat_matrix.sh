#!/usr/bin/env bash
#
# Run the bpfcompat Layer-A kernel matrix against the current aegis.bpf.o and
# gate on "the REQUIRED enforcement hooks load on every target kernel."
#
# This is the runner-agnostic core of the kernel-compat CI gate (see
# docs/KERNEL_COMPAT_MATRIX.md). It needs an execution environment with KVM and
# the bpfcompat checkout + its cached VM images; point AEGIS_BPFCOMPAT_DIR at the
# bpfcompat repo. It does NOT modify bpfcompat (it only invokes its CLI).
#
# Verdict: bpfcompat does a whole-object load that "fails" whenever any optional
# program is unsupported on a kernel — which AegisBPF gates and degrades over, so
# that is NOT a real failure. We therefore gate on the per-program load_status of
# AegisBPF's REQUIRED hooks (file_open + inode_permission, the required=true
# entries in src/hook_capabilities.cpp): those must load on every target kernel.
# The full per-hook x per-kernel matrix is printed and written as an artifact.
#
# Env:
#   AEGIS_BPFCOMPAT_DIR   path to the bpfcompat checkout (required)
#   AEGIS_BPF_OBJ         path to aegis.bpf.o          (default: build/aegis.bpf.o)
#   AEGIS_BPFCOMPAT_MATRIX matrix yaml                 (default: tests/enforcement/bpfcompat-matrix.yaml)
#   AEGIS_MATRIX_OUT      summary JSON output path     (default: /tmp/aegis-bpfcompat-matrix.json)
#
# Exit: 0 = required hooks loaded on all profiles; 1 = a required hook failed or
# an infra error; 77 = prerequisites missing (skip).
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARTIFACT="${AEGIS_BPF_OBJ:-$REPO_ROOT/build/aegis.bpf.o}"
MATRIX="${AEGIS_BPFCOMPAT_MATRIX:-$REPO_ROOT/tests/enforcement/bpfcompat-matrix.yaml}"
MANIFEST="$REPO_ROOT/tests/enforcement/bpfcompat-manifest.yaml"
SUMMARY="${AEGIS_MATRIX_OUT:-/tmp/aegis-bpfcompat-matrix.json}"
# Per-profile baseline of programs known to load. The gate FAILS if any program
# listed here no longer loads on its profile (a load regression -- e.g. a BPF
# change the verifier rejects on an older kernel). Regenerate after an
# intentional change with: AEGIS_UPDATE_BASELINE=1 bash scripts/run_bpfcompat_matrix.sh
BASELINE="${AEGIS_LOAD_BASELINE:-$REPO_ROOT/tests/enforcement/bpfcompat_load_baseline.json}"

# Absolutize while cwd is still the AegisBPF checkout: the run below cd's into the
# bpfcompat checkout (so it finds vm/cache), and relative inputs (e.g. CI's
# AEGIS_BPF_OBJ=build/aegis.bpf.o) would otherwise resolve against the wrong dir.
ARTIFACT="$(realpath -m "$ARTIFACT")"
MATRIX="$(realpath -m "$MATRIX")"
MANIFEST="$(realpath -m "$MANIFEST")"
SUMMARY="$(realpath -m "$SUMMARY")"
BASELINE="$(realpath -m "$BASELINE")"

# REQUIRED hooks (src/hook_capabilities.cpp required=true). These must load on
# every target kernel; everything else is best-effort/gated.
REQUIRED_PROGS="handle_file_open handle_inode_permission"

skip() { printf '\033[33mSKIP\033[0m %s\n' "$*"; exit 77; }
[ -n "${AEGIS_BPFCOMPAT_DIR:-}" ] || skip "set AEGIS_BPFCOMPAT_DIR to the bpfcompat checkout"
BPFCOMPAT_BIN="$AEGIS_BPFCOMPAT_DIR/bin/bpfcompat"
[ -x "$BPFCOMPAT_BIN" ] || skip "bpfcompat binary not found at $BPFCOMPAT_BIN (build it in the bpfcompat repo)"
[ -f "$ARTIFACT" ] || skip "artifact not found: $ARTIFACT (build the bpf object first)"
[ -e /dev/kvm ] || skip "/dev/kvm not available (KVM required for the VM matrix)"

# Manifest must be in sync with the BPF source (no drift).
python3 "$REPO_ROOT/scripts/gen_bpfcompat_manifest.py" --check || {
  echo "manifest is stale — run scripts/gen_bpfcompat_manifest.py" >&2; exit 1; }

WORKDIR="$(mktemp -d /tmp/aegis-matrix-wd.XXXXXX)"
trap 'rm -rf "$WORKDIR"' EXIT

echo "Running bpfcompat matrix: $(basename "$MATRIX") against $(basename "$ARTIFACT")"
# Run from the bpfcompat checkout: it resolves vm/cache + profiles relative to
# its own cwd. --workdir is an absolute temp so run artifacts do NOT land in the
# checkout's .bpfcompat/. All other paths are absolute too.
(
  cd "$AEGIS_BPFCOMPAT_DIR" &&
    "$BPFCOMPAT_BIN" test \
      --artifact "$ARTIFACT" \
      --manifest "$MANIFEST" \
      --matrix "$MATRIX" \
      --artifact-name aegis-bpf \
      --workdir "$WORKDIR" \
      --out "$WORKDIR/report.json" \
      --timeout "${AEGIS_BPFCOMPAT_TIMEOUT:-480s}"
) >/dev/null 2>&1 || true # whole-object status is not our verdict

RUN_DIR="$(ls -td "$WORKDIR"/runs/*/ 2>/dev/null | head -1)"
[ -n "$RUN_DIR" ] || { echo "no bpfcompat run dir produced (infra error)" >&2; exit 1; }

# Evaluate per-program load_status per profile. Gate on (a) the REQUIRED hooks
# loading everywhere AND (b) no per-program load REGRESSION vs the committed
# baseline -- i.e. no program that previously loaded on a profile now fails.
# (b) is what catches a BPF change the verifier rejects only on some kernels
# (e.g. the older-LTS net-hook regression that single-kernel CI missed).
AEGIS_REQUIRED_PROGS="$REQUIRED_PROGS" AEGIS_RUN_DIR="$RUN_DIR" AEGIS_SUMMARY="$SUMMARY" \
AEGIS_LOAD_BASELINE="$BASELINE" AEGIS_UPDATE_BASELINE="${AEGIS_UPDATE_BASELINE:-0}" python3 - <<'PY'
import json, glob, os, re, sys
run = os.environ["AEGIS_RUN_DIR"]
required = set(os.environ["AEGIS_REQUIRED_PROGS"].split())
baseline_path = os.environ["AEGIS_LOAD_BASELINE"]
update = os.environ.get("AEGIS_UPDATE_BASELINE") == "1"

baseline = {}
if not update and os.path.exists(baseline_path):
    try:
        baseline = (json.load(open(baseline_path)) or {}).get("profiles", {})
    except Exception as e:  # noqa: BLE001
        print(f"warning: could not read load baseline {baseline_path}: {e}", file=sys.stderr)

results = sorted(glob.glob(os.path.join(run, "targets", "*", "validator-result.json")))
if not results:
    print("no validator results found", file=sys.stderr); sys.exit(1)

summary = {"profiles": [], "required_hooks": sorted(required), "ok": True}
new_baseline = {}
print()
print(f"{'profile':<30} {'kernel':<10} loaded/total  required   regressions  verdict")
print("-" * 92)
for f in results:
    d = json.load(open(f))
    profile = os.path.basename(os.path.dirname(f))
    host = d.get("host") or {}
    prof = d.get("profile") or {}
    kernel = host.get("kernel") or host.get("kernel_family") or prof.get("kernel_family")
    if not kernel:
        # Profile IDs always encode the kernel (e.g. oracle-linux-10-uek8-6.12).
        vers = re.findall(r"\d+\.\d+", profile)
        kernel = vers[-1] if vers else "?"
    progs = (d.get("discovery") or {}).get("programs", [])
    ok_set = {p["name"] for p in progs if p.get("load_status") == "ok"}
    total = len(progs)
    new_baseline[profile] = sorted(ok_set)

    missing_required = sorted(required - ok_set)
    regressed = sorted(set(baseline.get(profile, [])) - ok_set)
    verdict = "PASS" if (not missing_required and not regressed) else "FAIL"
    if missing_required or regressed:
        summary["ok"] = False
    summary["profiles"].append({
        "profile": profile, "kernel": kernel,
        "loaded": len(ok_set), "total": total,
        "missing_required": missing_required, "regressed": regressed,
        "loaded_programs": sorted(ok_set), "verdict": verdict,
    })
    req = "ok" if not missing_required else ("MISS:" + ",".join(missing_required))
    reg = "-" if not regressed else ("LOST:" + ",".join(regressed))
    print(f"{profile:<30} {str(kernel):<10} {len(ok_set):>3}/{total:<8} {req:<10} {reg:<12} {verdict}")
print()

if update:
    out = {
        "_comment": ("Per-profile BPF programs expected to load (bpfcompat Layer-A). A program "
                     "listed here that no longer loads fails the matrix gate. Regenerate after an "
                     "intentional change: AEGIS_UPDATE_BASELINE=1 bash scripts/run_bpfcompat_matrix.sh"),
        "profiles": new_baseline,
    }
    with open(baseline_path, "w") as fh:
        json.dump(out, fh, indent=2, sort_keys=True)
        fh.write("\n")
    print(f"load baseline updated -> {baseline_path} ({len(new_baseline)} profiles)")
    json.dump(summary, open(os.environ["AEGIS_SUMMARY"], "w"), indent=2)
    sys.exit(0)

json.dump(summary, open(os.environ["AEGIS_SUMMARY"], "w"), indent=2)
print(f"summary -> {os.environ['AEGIS_SUMMARY']}")
if not baseline:
    print("NOTE: no load baseline committed yet -- gating on REQUIRED hooks only.", file=sys.stderr)
sys.exit(0 if summary["ok"] else 1)
PY
rc=$?
[ "$rc" -eq 0 ] && echo "RESULT: required hooks loaded + no per-program load regression vs baseline." \
              || echo "RESULT: a required hook failed OR a program regressed vs the load baseline."
exit "$rc"
