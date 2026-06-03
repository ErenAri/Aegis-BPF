#!/usr/bin/env bash
#
# Differential parity harness for the Rust policy-parser oxidation.
#
# The Rust port (rust/aegis-parser) must produce the SAME observable result as
# the C++ parser (src/policy_parse.cpp) before it can replace it. This harness
# runs every policy file in the corpus + examples + fixtures through BOTH and
# compares their FULL canonical dump (not just counts/issues):
#
#   C++ : aegisbpf policy canonical <f>   (parse + detect_policy_conflicts)
#   Rust: aegis_policy_lint <f>           (same)
#
# The canonical dump is `version`, the set flags, EVERY stored entry in EVERY
# category (in insertion order, ports as parsed `port:proto:dir` tuples), and
# the sorted error/warning detail strings. Comparing the whole dump proves the
# two parsers are *structurally* equivalent — same accept/reject, same de-dup,
# same canonicalization, same stored result — not merely that they agree on how
# many entries survived. Any divergence fails the build; this is the gate that
# must be green before the production parser is swapped to Rust.
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

# Full canonical dump from the C++ parser (stdout only; logs go to stderr).
cpp_canonical() {
    "$AEGIS_BIN" policy canonical "$1" 2>/dev/null
}
# Full canonical dump from the Rust parser (stdout).
rust_canonical() {
    "$RUST_BIN" "$1" 2>/dev/null
}

pass=0; fail=0
for f in "${FILES[@]}"; do
    [ -f "$f" ] || continue
    c="$(cpp_canonical "$f")"
    r="$(rust_canonical "$f")"
    if [ "$c" == "$r" ]; then
        pass=$((pass+1))
    else
        fail=$((fail+1))
        red "DIVERGENCE: ${f#"$REPO"/}"
        diff <(printf '%s\n' "$c") <(printf '%s\n' "$r") | sed 's/^/    /'
    fi
done

# ---- differential fuzzing -------------------------------------------------
# A 26-file corpus is thin, and full-structured parity only bites on error-free
# policies (the canonical dump suppresses entry lines when the parse errors). So
# we generate TWO deterministic families of N policies each (--fuzz [N], default
# 2000), giving 2N generated inputs:
#   * ADVERSARIAL (f*.conf): random junk from an edge vocabulary (bad IPs/ports/
#     CIDRs/hashes, unknown sections, stray bytes) — exercises the accept/reject
#     and error/warning surface.
#   * VALID (v*.conf): random but ALWAYS error-free v6 policies built from valid
#     entries (cross-field flag constraints respected) — exercises the stored
#     ENTRY surface: every category, port/ip:port tuple normalization, and the
#     de-dup logic. This is what makes the structural comparison meaningful.
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
    # Valid-policy generator: always error-free v6 policies (at most warnings),
    # so every sample exercises the stored-entry surface of the canonical dump.
    python3 - "$fuzz_dir" "$fuzz_n" <<'PY'
import os, random, sys
out, n = sys.argv[1], int(sys.argv[2])
random.seed(0xA415)  # distinct deterministic stream for reproducible CI
ri, ch, rnd = random.randint, random.choice, random.random
def few(pool, lo=1, hi=4):
    return [ch(pool) for _ in range(ri(lo, hi))]
abs_paths = ["/etc/shadow","/etc/passwd","/var/run/secrets/token","/usr/bin/app",
    "/opt/x/y","/a","/etc/ssl/private/key.pem","/usr/lib/x.so"]
v4 = ["10.0.0.1","192.168.1.1","172.16.5.9","8.8.8.8","127.0.0.1",
    "255.255.255.255","0.0.0.0"]
v6 = ["::1","2001:db8::1","fe80::1","2001:db8:0:0:0:0:0:7","2001:DB8::ABCD","::"]
cidr = ["10.0.0.0/8","192.168.0.0/16","0.0.0.0/0","172.16.0.0/12","10.1.2.3/32",
    "fe80::/10","2001:db8::/32","::/0"]
# Every valid port-rule shape, incl. empty-proto-with-dir and egress/connect.
ports = ["1","22","80","443","65535","443:tcp","443:udp","443:any",
    "80:tcp:egress","80:tcp:connect","80:udp:bind","80:tcp:both","8080::egress",
    "53::bind","443:any:both"]
inodes = ["0:0","2049:128","100:200","4294967295:18446744073709551615","1:1"]
hexes = ["sha256:"+("a"*64),"sha256:"+("A"*64),"sha256:"+("0123456789abcdef"*4),
    "sha256:"+("Ff"*32)]
comms = ["bash","nc","xmrig","curl","python3","x"*15,"a"]
cgrefs = ["/sys/fs/cgroup/system.slice","/sys/fs/cgroup/user.slice/x","cgid:0",
    "cgid:1000","cgid:42"]
# IPv4 + bracketed IPv6, with/without proto, incl. non-canonical IPv6 forms.
ipports = ["10.0.0.1:443","10.0.0.1:443:tcp","10.0.0.1:443:udp","10.0.0.1:443:any",
    "192.168.1.1:8080","8.8.8.8:53:udp","[::1]:443","[::1]:443:tcp",
    "[2001:db8::1]:8080:udp","[2001:db8:0:0:0:0:0:1]:80","[2001:DB8::2]:80"]
for i in range(n):
    L = ["version=6"]
    if rnd() < 0.7: L += ["[deny_path]"] + few(abs_paths)
    if rnd() < 0.4: L += ["[protect_path]"] + few(abs_paths)
    if rnd() < 0.6: L += ["[deny_inode]"] + few(inodes)
    if rnd() < 0.5: L += ["[allow_cgroup]"] + few(cgrefs)
    if rnd() < 0.6: L += ["[deny_ip]"] + few(v4 + v6)
    if rnd() < 0.5: L += ["[deny_cidr]"] + few(cidr)
    if rnd() < 0.8: L += ["[deny_port]"] + few(ports, 1, 6)
    if rnd() < 0.7: L += ["[deny_ip_port]"] + few(ipports, 1, 5)
    if rnd() < 0.4: L += ["[deny_binary_hash]"] + few(hexes)
    if rnd() < 0.4: L += ["[allow_binary_hash]"] + few(hexes)
    has_trusted = rnd() < 0.4
    if has_trusted: L += ["[trusted_exec_hash]"] + few(hexes)
    if rnd() < 0.4: L += ["[scan_paths]"] + few(abs_paths)
    if rnd() < 0.4: L += ["[deny_comm]"] + few(comms)
    if rnd() < 0.5: L += ["[cgroup_deny_inode]"] + [ch(cgrefs)+" "+ch(inodes) for _ in range(ri(1,3))]
    if rnd() < 0.5: L += ["[cgroup_deny_ip]"] + [ch(cgrefs)+" "+ch(v4) for _ in range(ri(1,3))]
    if rnd() < 0.6: L += ["[cgroup_deny_port]"] + [ch(cgrefs)+" "+ch(ports) for _ in range(ri(1,4))]
    # Flags. Only combinations that never raise a cross-field ERROR:
    if rnd() < 0.4: L += ["[deny_ptrace]"]
    if rnd() < 0.4: L += ["[deny_module_load]"]
    if rnd() < 0.4: L += ["[deny_bpf]"]
    pc = rnd() < 0.4
    if pc: L += ["[protect_connect]"]
    if rnd() < 0.4: L += ["[require_ima_appraisal]"]
    if pc and rnd() < 0.5: L += ["[protect_runtime_deps]"]   # needs protect_connect
    if has_trusted and rnd() < 0.5: L += ["[ima_fail_closed]"]  # needs trusted hash
    data = "\n".join(L)
    if rnd() < 0.5: data += "\n"
    with open(os.path.join(out, f"v{i}.conf"), "w") as fh:
        fh.write(data)
PY
    fpass=0; ffail=0
    for f in "$fuzz_dir"/*.conf; do
        c="$(cpp_canonical "$f")"
        r="$(rust_canonical "$f")"
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
    echo "fuzz: $fpass/$((fpass+ffail)) generated policies agree (adversarial + valid, ${fuzz_n} each)"
fi

echo
if [ "$fail" -eq 0 ]; then
    green "policy parity: $pass/$((pass+fail)) inputs agree (C++ <-> Rust)"
    exit 0
fi
red "policy parity: $fail/$((pass+fail)) inputs DIVERGED"
exit 1
