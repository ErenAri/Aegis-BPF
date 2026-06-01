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

# Absolutize while cwd is still the AegisBPF checkout: the run below cd's into the
# bpfcompat checkout (so it finds vm/cache), and relative inputs (e.g. CI's
# AEGIS_BPF_OBJ=build/aegis.bpf.o) would otherwise resolve against the wrong dir.
ARTIFACT="$(realpath -m "$ARTIFACT")"
MATRIX="$(realpath -m "$MATRIX")"
MANIFEST="$(realpath -m "$MANIFEST")"
SUMMARY="$(realpath -m "$SUMMARY")"

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

# Evaluate per-program load_status per profile; gate on the REQUIRED hooks.
AEGIS_REQUIRED_PROGS="$REQUIRED_PROGS" AEGIS_RUN_DIR="$RUN_DIR" AEGIS_SUMMARY="$SUMMARY" python3 - <<'PY'
import json, glob, os, re, sys
run = os.environ["AEGIS_RUN_DIR"]
required = set(os.environ["AEGIS_REQUIRED_PROGS"].split())
summary = {"profiles": [], "required_hooks": sorted(required), "ok": True}
results = sorted(glob.glob(os.path.join(run, "targets", "*", "validator-result.json")))
if not results:
    print("no validator results found", file=sys.stderr); sys.exit(1)
print()
print(f"{'profile':<32} {'kernel':<22} loaded/total  required  verdict")
print("-" * 84)
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
    missing_required = sorted(required - ok_set)
    verdict = "PASS" if not missing_required else "FAIL"
    if missing_required:
        summary["ok"] = False
    summary["profiles"].append({
        "profile": profile, "kernel": kernel,
        "loaded": len(ok_set), "total": total,
        "missing_required": missing_required, "verdict": verdict,
    })
    req = "ok" if not missing_required else ("MISSING: " + ",".join(missing_required))
    print(f"{profile:<32} {kernel:<22} {len(ok_set):>3}/{total:<8} {req:<9} {verdict}")
print()
json.dump(summary, open(os.environ["AEGIS_SUMMARY"], "w"), indent=2)
print(f"summary -> {os.environ['AEGIS_SUMMARY']}")
sys.exit(0 if summary["ok"] else 1)
PY
rc=$?
[ "$rc" -eq 0 ] && echo "RESULT: required enforcement hooks loaded on all profiles." \
              || echo "RESULT: a required enforcement hook failed to load on some profile."
exit "$rc"
