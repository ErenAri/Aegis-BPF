#!/usr/bin/env bash
#
# Differential parity harness for the Rust signed-bundle decoder oxidation.
#
# The Rust port (rust/aegis-parser `bundle` module) must produce the SAME
# observable result as the C++ decoder (`parse_signed_bundle`, src/crypto.cpp)
# before it can replace it. This harness compares the FULL canonical dump of both
# on the same inputs:
#
#   C++ : aegisbpf policy bundle-canonical <f>
#   Rust: aegis_bundle_lint <f>
#
# The dump is `ok` + every parsed field (byte arrays as hex, the policy body as
# length + FNV-1a) on success, or `err <message>` on the first failure. Comparing
# the whole dump proves structural equivalence: same separator split, same
# header/field parsing, same lenient-integer behavior, same first-error-wins
# ordering and error classes. Any divergence fails the build.
#
# Inputs: committed fixtures (tests/fixtures/bundle_parity), REAL signed bundles
# generated here via `bpf keygen` + `policy sign`, plus two deterministic
# generated families (valid synthetic + adversarial) with --fuzz [N] (default
# 2000), giving 2N generated inputs.
#
# Env:
#   AEGIS_BIN   path to the aegisbpf binary   (default: build/aegisbpf)
#   RUST_BIN    path to aegis_bundle_lint     (default: rust/aegis-parser/target/release/aegis_bundle_lint)
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AEGIS_BIN="${AEGIS_BIN:-$REPO/build/aegisbpf}"
RUST_BIN="${RUST_BIN:-$REPO/rust/aegis-parser/target/release/aegis_bundle_lint}"

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }

[ -x "$AEGIS_BIN" ] || { red "aegisbpf binary not found: $AEGIS_BIN (build it first)"; exit 2; }
[ -x "$RUST_BIN" ]  || { red "rust bundle-lint binary not found: $RUST_BIN (cargo build --release)"; exit 2; }

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
# Keep version-counter side effects out of system paths (sign only reads it).
export AEGIS_VERSION_COUNTER_PATH="$work/version_counter"

# Full canonical dump from each decoder (stdout only; logs go to stderr).
cpp_canonical()  { "$AEGIS_BIN" policy bundle-canonical "$1" 2>/dev/null; }
rust_canonical() { "$RUST_BIN" "$1" 2>/dev/null; }

# ---- file list: committed fixtures -----------------------------------------
mapfile -t FILES < <(find "$REPO/tests/fixtures/bundle_parity" -type f 2>/dev/null | sort)

# ---- REAL signed bundles (genuine keygen + sign round-trip) -----------------
if "$AEGIS_BIN" bpf keygen --out "$work/k" >/dev/null 2>&1; then
    idx=0
    for body in \
        $'version=1\n' \
        $'version=6\n[deny_path]\n/etc/shadow\n[deny_ip]\n10.0.0.1\n' \
        $'version=4\n[protect_connect]\n[allow_binary_hash]\nsha256:'"$(printf 'a%.0s' {1..64})"$'\n' \
        $'# comment only\nversion=3\n'; do
        printf '%s' "$body" > "$work/p$idx.conf"
        if "$AEGIS_BIN" policy sign "$work/p$idx.conf" --key "$work/k.key" \
                --output "$work/real$idx.bundle" >/dev/null 2>&1; then
            FILES+=("$work/real$idx.bundle")
        fi
        idx=$((idx + 1))
    done
fi

pass=0; fail=0
for f in "${FILES[@]}"; do
    [ -f "$f" ] || continue
    c="$(cpp_canonical "$f")"
    r="$(rust_canonical "$f")"
    if [ "$c" == "$r" ]; then
        pass=$((pass + 1))
    else
        fail=$((fail + 1))
        red "DIVERGENCE: ${f#"$REPO"/}"
        diff <(printf '%s\n' "$c") <(printf '%s\n' "$r") | sed 's/^/    /'
    fi
done

# ---- differential fuzzing --------------------------------------------------
fuzz_n=0
if [ "${1:-}" == "--fuzz" ]; then
    fuzz_n="${2:-2000}"
fi

if [ "$fuzz_n" -gt 0 ]; then
    fuzz_dir="$work/fuzz"; mkdir -p "$fuzz_dir"
    # Adversarial family (f*.bundle): random header/keys/values/separators.
    python3 - "$fuzz_dir" "$fuzz_n" <<'PY'
import os, random, sys
out, n = sys.argv[1], int(sys.argv[2])
random.seed(2027)  # deterministic for reproducible CI
headers = ["AEGIS-POLICY-BUNDLE-V1", "WRONG-HEADER", "aegis-policy-bundle-v1",
    "AEGIS-POLICY-BUNDLE-V1 ", " AEGIS-POLICY-BUNDLE-V1", ""]
keys = ["format_version", "policy_version", "timestamp", "expires", "signer_key",
    "signature", "policy_sha256", "unknown_key", "no_colon_line", ":", ""]
ints = ["1","0","-1","+5","5abc","abc","  42","999999999999999999999999",
    "4294967296","4294967297","18446744073709551615","18446744073709551616",""]
hexes = ["a"*64, "b"*128, "aabb", "g"*64, "", "a"*63, "a"*65, "A"*64, "DEAD"*16,
    "f"*128, "z"*128]
seps = ["---", "------", ""]
bodies = ["version=1\n[deny_path]\n/x\n", "", "binary\x01\x02data", "no newline",
    "---inner---", "  leading", "\n\nblank lead\n"]
def kv():
    k = random.choice(keys)
    if k in ("no_colon_line", ""):
        return k
    if k in ("format_version","policy_version","timestamp","expires"):
        return f"{k}: {random.choice(ints)}"
    if k in ("signer_key","signature"):
        return f"{k}: {random.choice(hexes)}"
    return f"{k}: {random.choice(ints+hexes+['deadbeef'])}"
for i in range(n):
    lines = [random.choice(headers)]
    for _ in range(random.randint(0, 8)):
        lines.append(kv())
    head = "\n".join(lines)
    sep = random.choice(seps)
    body = random.choice(bodies)
    # place separator (or not); sometimes embed an extra one in the head
    if random.random() < 0.15:
        head = head.replace(":", ":---", 1)
    data = head + ("\n" + sep + "\n" if sep else "\n") + body
    with open(os.path.join(out, f"f{i}.bundle"), "wb") as fh:
        fh.write(data.encode("utf-8", "surrogatepass") if isinstance(data, str) else data)
PY
    # Valid-structure family (v*.bundle): correct header + valid fields + body,
    # exercising the success dump across varied field values (not crypto-signed;
    # parse_signed_bundle validates structure, not the signature).
    python3 - "$fuzz_dir" "$fuzz_n" <<'PY'
import os, random, sys
out, n = sys.argv[1], int(sys.argv[2])
random.seed(0xB00B)  # distinct deterministic stream
H = "AEGIS-POLICY-BUNDLE-V1"
fmt = ["1","2","3","42","4294967295"]              # all -> nonzero u32
nums = ["0","1","7","1780000000","18446744073709551615"]
sk = ["a"*64, "0"*64, "DEADBEEF"*8, "0123456789abcdef"*4]
sg = ["b"*128, "f"*128, ("0123456789abcdef"*8)]
shas = ["deadbeef", "a"*64, "", "533cd867588a70d9"]
bodies = ["version=1\n[deny_path]\n/etc/shadow\n", "version=6\n", "",
    "arbitrary policy body\nwith multiple lines\n", "single"]
for i in range(n):
    lines = [H, f"format_version: {random.choice(fmt)}"]
    if random.random() < 0.8: lines.append(f"policy_version: {random.choice(nums)}")
    if random.random() < 0.7: lines.append(f"timestamp: {random.choice(nums)}")
    if random.random() < 0.6: lines.append(f"expires: {random.choice(nums)}")
    if random.random() < 0.7: lines.append(f"signer_key: {random.choice(sk)}")
    if random.random() < 0.7: lines.append(f"signature: {random.choice(sg)}")
    if random.random() < 0.6: lines.append(f"policy_sha256: {random.choice(shas)}")
    fields = lines[1:]
    random.shuffle(fields)  # field order varies; header (lines[0]) stays first
    data = "\n".join([H] + fields) + "\n---\n" + random.choice(bodies)
    with open(os.path.join(out, f"v{i}.bundle"), "w") as fh:
        fh.write(data)
PY
    fpass=0; ffail=0
    for f in "$fuzz_dir"/*.bundle; do
        c="$(cpp_canonical "$f")"
        r="$(rust_canonical "$f")"
        if [ "$c" == "$r" ]; then
            fpass=$((fpass + 1))
        else
            ffail=$((ffail + 1))
            if [ "$ffail" -le 10 ]; then
                red "FUZZ DIVERGENCE: $(basename "$f")"
                sed 's/^/        /' "$f"; echo
                echo "    --- diff (C++ vs Rust) ---"
                diff <(printf '%s\n' "$c") <(printf '%s\n' "$r") | sed 's/^/    /'
            fi
        fi
    done
    pass=$((pass + fpass)); fail=$((fail + ffail))
    echo "fuzz: $fpass/$((fpass + ffail)) generated bundles agree (adversarial + valid, ${fuzz_n} each)"
fi

echo
if [ "$fail" -eq 0 ]; then
    green "bundle parity: $pass/$((pass + fail)) inputs agree (C++ <-> Rust)"
    exit 0
fi
red "bundle parity: $fail/$((pass + fail)) inputs DIVERGED"
exit 1
