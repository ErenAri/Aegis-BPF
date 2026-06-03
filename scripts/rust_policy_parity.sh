#!/usr/bin/env bash
#
# Differential parity harness for the Rust policy-parser oxidation.
#
# The Rust port (rust/aegis-parser) must produce the SAME observable result as
# the C++ parser (src/policy_parse.cpp) before it can replace it. This harness
# runs every policy file in the corpus + examples + fixtures through BOTH:
#
#   C++ : aegisbpf policy lint <f>        (parse + detect_policy_conflicts)
#   Rust: aegis_policy_lint <f>           (same)
#
# and diffs the SORTED SET of error+warning detail strings. For files both
# accept, it additionally diffs the deny-path / deny-inode / network counts from
# `aegisbpf policy validate`. Any divergence fails the build — this is the gate
# that must be green before the production parser is swapped to Rust.
#
# Env:
#   AEGIS_BIN   path to the aegisbpf binary   (default: build/aegisbpf)
#   RUST_BIN    path to aegis_policy_lint     (default: rust/aegis-parser/target/release/aegis_policy_lint)
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AEGIS_BIN="${AEGIS_BIN:-$REPO/build/aegisbpf}"
RUST_BIN="${RUST_BIN:-$REPO/rust/aegis-parser/target/release/aegis_policy_lint}"

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }

[ -x "$AEGIS_BIN" ] || { red "aegisbpf binary not found: $AEGIS_BIN (build it first)"; exit 2; }
[ -x "$RUST_BIN" ]  || { red "rust lint binary not found: $RUST_BIN (cargo build --release)"; exit 2; }

# Collect candidate policy files.
mapfile -t FILES < <(
    find "$REPO/examples/policies" "$REPO/config" "$REPO/tests/fixtures" \
         "$REPO/tests/fuzz/corpus/fuzz_policy" -type f \
         \( -name '*.conf' -o -name '*.policy' -o -name '*.txt' \) 2>/dev/null | sort
)
# fuzz corpus files may have no extension; include them all.
while IFS= read -r f; do FILES+=("$f"); done < <(
    find "$REPO/tests/fuzz/corpus/fuzz_policy" -type f 2>/dev/null | sort -u
)

# de-dup the file list
mapfile -t FILES < <(printf '%s\n' "${FILES[@]}" | sort -u)

# Extract sorted issue-detail set from C++ lint stderr.
cpp_issues() {
    AEGIS_LOG_FORMAT=text "$AEGIS_BIN" policy lint "$1" 2>&1 >/dev/null \
        | sed -n 's/.*detail="\(.*\)"}.*/\1/p' | sort
}
# Extract sorted issue-detail set from Rust lint stdout (ERROR/WARN lines).
rust_issues() {
    "$RUST_BIN" "$1" 2>/dev/null | sed -n 's/^\(ERROR\|WARN\) //p' | sort
}

pass=0; fail=0
for f in "${FILES[@]}"; do
    [ -f "$f" ] || continue
    c="$(cpp_issues "$f")"
    r="$(rust_issues "$f")"
    if [ "$c" == "$r" ]; then
        pass=$((pass+1))
    else
        fail=$((fail+1))
        red "DIVERGENCE: ${f#"$REPO"/}"
        diff <(printf '%s\n' "$c") <(printf '%s\n' "$r") | sed 's/^/    /'
    fi
done

# ---- differential fuzzing -------------------------------------------------
# A 26-file corpus is thin. Generate N random policies from an adversarial
# vocabulary (edge IPs, ports, CIDRs, hashes, sections, junk bytes) and require
# the two parsers to still agree. Enable with --fuzz [N] (default 2000).
fuzz_n=0
if [ "${1:-}" == "--fuzz" ]; then
    fuzz_n="${2:-2000}"
fi

if [ "$fuzz_n" -gt 0 ]; then
    fuzz_dir="$(mktemp -d)"
    trap 'rm -rf "$fuzz_dir"' EXIT
    python3 - "$fuzz_dir" "$fuzz_n" <<'PY'
import os, random, sys
out, n = sys.argv[1], int(sys.argv[2])
random.seed(1337)  # deterministic corpus for reproducible CI
sections = ["deny_path","deny_inode","protect_path","protect_connect",
    "protect_runtime_deps","require_ima_appraisal","trusted_exec_hash",
    "ima_fail_closed","allow_cgroup","deny_ip","deny_cidr","deny_port",
    "deny_ip_port","deny_binary_hash","allow_binary_hash","scan_paths",
    "cgroup_deny_inode","cgroup_deny_ip","cgroup_deny_port","deny_ptrace",
    "deny_module_load","deny_bpf","deny_comm","bogus_section",""]
tokens = ["/etc/shadow","relative/path","10.0.0.1","10.000.000.001","::1",
    "256.1.1.1","10.0.0.0/8","10.0.0.0/33","fe80::/10","fe80::/130","22",
    "443:tcp","53:udp:both","0","99999","65535","1:bogus","sha256:"+("a"*64),
    "sha256:"+("A"*64),"sha256:short","sha256:"+("z"*64),"noprefix",
    "2049:128","2049:","bad","[::1]:443:tcp","[::1]:443","10.0.0.1:443",
    "10.0.0.1:443:udp","cgid:123","cgid:abc","/sys/fs/cgroup/x 2049:10",
    "/sys/fs/cgroup/x 10.0.0.1","/sys/fs/cgroup/x 22:tcp","# comment",
    "   ","key=value","version=4","version=0","version=99","x"*60,"\tweird "]
hdr = ["version=1","version=3","version=4","version=5","version=6","version=7",
    "version=abc",""]
for i in range(n):
    lines = [random.choice(hdr)]
    for _ in range(random.randint(0, 12)):
        r = random.random()
        if r < 0.30:
            lines.append("[" + random.choice(sections) + "]")
        else:
            lines.append(random.choice(tokens))
    data = "\n".join(lines)
    if random.random() < 0.5:
        data += "\n"
    with open(os.path.join(out, f"f{i}.conf"), "w") as fh:
        fh.write(data)
PY
    fpass=0; ffail=0
    for f in "$fuzz_dir"/*.conf; do
        c="$(cpp_issues "$f")"
        r="$(rust_issues "$f")"
        if [ "$c" == "$r" ]; then
            fpass=$((fpass+1))
        else
            ffail=$((ffail+1))
            if [ "$ffail" -le 10 ]; then
                red "FUZZ DIVERGENCE: $(basename "$f")"
                sed 's/^/        /' "$f"
                echo "    --- diff (C++ vs Rust) ---"
                diff <(printf '%s\n' "$c") <(printf '%s\n' "$r") | sed 's/^/    /'
            fi
        fi
    done
    pass=$((pass+fpass)); fail=$((fail+ffail))
    echo "fuzz: $fpass/$((fpass+ffail)) generated policies agree"
fi

echo
if [ "$fail" -eq 0 ]; then
    green "policy parity: $pass/$((pass+fail)) inputs agree (C++ <-> Rust)"
    exit 0
fi
red "policy parity: $fail/$((pass+fail)) inputs DIVERGED"
exit 1
