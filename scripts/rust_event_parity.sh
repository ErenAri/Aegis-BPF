#!/usr/bin/env bash
#
# Differential parity harness for the Rust BPF-event decoder oxidation.
#
# The Rust port (rust/aegis-parser `event` module) must produce the SAME
# observable result as the C++ ring-buffer consumer (`handle_event` + the
# `print_*_event` field extraction, src/events.cpp) before it can replace it.
# This harness compares the FULL canonical decode dump of both on the same raw
# event records:
#
#   C++ : aegisbpf policy event-canonical <f>
#   Rust: aegis_event_lint <f>
#
# The dump is the decoded `type` label + every field (ints decimal, char[] and
# address bytes as length-exact lowercase hex), or `err short_buffer <len>` for a
# too-short record, or `unknown_type <n>` for an unrecognized type. Comparing the
# whole dump proves the memory-unsafe decode is equivalent: same field offsets,
# same integer endianness, same NUL-terminated char[] extraction, same
# direction/rule_type -> label derivation, same clamping (ancestors, argv), and
# the same defined behavior on short/unknown records. Any divergence fails the
# build.
#
# Inputs: committed fixtures (tests/fixtures/event_parity) plus two deterministic
# generated families with --fuzz [N] (default 2000), giving 2N generated inputs:
#   * valid    (v*.bin): Event-shaped records across every event type with
#                        randomized field values (the decode/label surface).
#   * adversarial (f*.bin): random lengths (incl. truncated) and random bytes
#                        with a biased type field (the short_buffer / unknown /
#                        garbage-field surface; Rust must never over-read).
#
# Env:
#   AEGIS_BIN   path to the aegisbpf binary   (default: build/aegisbpf)
#   RUST_BIN    path to aegis_event_lint      (default: rust/aegis-parser/target/release/aegis_event_lint)
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AEGIS_BIN="${AEGIS_BIN:-$REPO/build/aegisbpf}"
RUST_BIN="${RUST_BIN:-$REPO/rust/aegis-parser/target/release/aegis_event_lint}"

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }

[ -x "$AEGIS_BIN" ] || { red "aegisbpf binary not found: $AEGIS_BIN (build it first)"; exit 2; }
[ -x "$RUST_BIN" ]  || { red "rust event-lint binary not found: $RUST_BIN (cargo build --release)"; exit 2; }

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

cpp_canonical()  { "$AEGIS_BIN" policy event-canonical "$1" 2>/dev/null; }
rust_canonical() { "$RUST_BIN" "$1" 2>/dev/null; }

# ---- file list: committed fixtures -----------------------------------------
mapfile -t FILES < <(find "$REPO/tests/fixtures/event_parity" -type f 2>/dev/null | sort)

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
    python3 - "$fuzz_dir" "$fuzz_n" <<'PY'
import os, random, struct, sys

out, n = sys.argv[1], int(sys.argv[2])
SIZE = 344   # sizeof(aegis::Event)
PB = 8       # union payload offset

# Recognized type discriminants (and a few unknowns for the valid stream to
# also touch the unknown_type path deterministically).
TYPES = [1, 2, 3, 4, 10, 11, 12, 13, 14, 15, 20, 21, 22, 30]

def randbytes(rng, k):
    return bytes(rng.randrange(256) for _ in range(k))

def maybe_cstr(rng, width):
    """A byte field that is sometimes NUL-terminated early, sometimes full of
    non-zero bytes (no terminator), sometimes embeds an interior NUL — exercising
    the strnlen extraction boundary."""
    choice = rng.random()
    if choice < 0.3:
        body = randbytes(rng, rng.randrange(0, width))
        return body + b"\x00" * (width - len(body))
    if choice < 0.6:
        # full width, no NUL (forces full-width extraction)
        return bytes((rng.randrange(1, 256)) for _ in range(width))
    if choice < 0.8:
        # interior NUL then garbage (extraction must stop at the NUL)
        cut = rng.randrange(0, width)
        return randbytes(rng, cut) + b"\x00" + randbytes(rng, width - cut - 1) if cut < width else randbytes(rng, width)
    # printable-ish token
    tok = bytes(rng.choice(b"abcdef0123456789/_-.") for _ in range(rng.randrange(0, width)))
    return tok + b"\x00" * (width - len(tok))

# ---- valid-structure family (v*.bin): well-formed records -----------------
# Forensic (type 4) is a BARE forensic_event (104 bytes, fields at offset 0);
# every other type is wrapped in the 344-byte Event envelope (payload at offset 8).
FORENSIC_SIZE = 104
rng = random.Random(0xE7E7)
for i in range(n):
    ty = rng.choice(TYPES + [7, 99])     # a (mostly) recognized type
    if ty == 4:
        b = bytearray(randbytes(rng, FORENSIC_SIZE))  # bare forensic_event
        struct.pack_into('<I', b, 0, ty)
        b[40:56] = maybe_cstr(rng, 16)   # comm
        b[96:104] = maybe_cstr(rng, 8)   # action
        with open(os.path.join(out, f"v{i}.bin"), "wb") as fh:
            fh.write(b)
        continue
    b = bytearray(randbytes(rng, SIZE))  # random padding everywhere...
    struct.pack_into('<I', b, 0, ty)
    # Stamp type-relevant fields with structured-but-random values so the decode
    # surface (offsets, label derivation, clamping) is exercised meaningfully.
    if ty in (10, 11, 12, 13, 14, 15):
        b[PB + 48] = rng.choice([2, 10, rng.randrange(256)])  # family
        b[PB + 49] = rng.choice([6, 17, rng.randrange(256)])  # protocol
        b[PB + 54] = rng.choice([0, 1, 2, 3, 4, 5, rng.randrange(256)])  # direction
        b[PB + 32:PB + 48] = maybe_cstr(rng, 16)              # comm
        b[PB + 76:PB + 84] = maybe_cstr(rng, 8)               # action
        b[PB + 84:PB + 100] = maybe_cstr(rng, 16)             # rule_type
    elif ty == 1:
        b[PB + 72] = rng.choice([0, 1, 3, 8, rng.randrange(256)])  # ancestor_count
        b[PB + 24:PB + 40] = maybe_cstr(rng, 16)                   # comm
    elif ty == 3:
        struct.pack_into('<H', b, PB + 16, rng.choice([0, 1, 3, 8, 9, rng.randrange(65536)]))  # argc
        # Stamp each of the 8 fixed 32-byte argv slots so the slot-walk +
        # NUL-boundary extraction is deterministically exercised (full-width,
        # interior-NUL, and token cases) rather than left to incidental fill.
        for s in range(8):
            b[PB + 24 + s * 32:PB + 24 + (s + 1) * 32] = maybe_cstr(rng, 32)
    elif ty == 2:
        b[PB + 40:PB + 56] = maybe_cstr(rng, 16)    # comm
        b[PB + 68:PB + 324] = maybe_cstr(rng, 256)  # path
        b[PB + 324:PB + 332] = maybe_cstr(rng, 8)   # action
    elif ty in (20, 21, 22):
        b[PB + 32:PB + 48] = maybe_cstr(rng, 16)    # comm
        b[PB + 56:PB + 64] = maybe_cstr(rng, 8)     # action
        b[PB + 64:PB + 80] = maybe_cstr(rng, 16)    # rule_type
    with open(os.path.join(out, f"v{i}.bin"), "wb") as fh:
        fh.write(b)

# ---- adversarial family (f*.bin): random length + random bytes ------------
rng = random.Random(2027)
for i in range(n):
    # Boundary lengths (every edge of both short_buffer checks: the 4-byte type
    # floor, the forensic 103/104 boundary, and the Event 343/344 boundary, plus
    # just over) and a random length across the range.
    length = rng.choice([0, 1, 4, 5, 7, 8, 100, 103, 104, 105, 343, SIZE, SIZE + 1] + [rng.randrange(0, SIZE + 80)])
    b = bytearray(randbytes(rng, length))
    if length >= 4:
        # Bias the type toward recognized values to drive every decode arm.
        struct.pack_into('<I', b, 0, rng.choice(TYPES + [0, 5, 99, 0xffffffff]))
    with open(os.path.join(out, f"f{i}.bin"), "wb") as fh:
        fh.write(b)
PY
    fpass=0; ffail=0
    for f in "$fuzz_dir"/*.bin; do
        c="$(cpp_canonical "$f")"
        r="$(rust_canonical "$f")"
        if [ "$c" == "$r" ]; then
            fpass=$((fpass + 1))
        else
            ffail=$((ffail + 1))
            if [ "$ffail" -le 10 ]; then
                red "FUZZ DIVERGENCE: $(basename "$f")"
                echo "    --- diff (C++ vs Rust) ---"
                diff <(printf '%s\n' "$c") <(printf '%s\n' "$r") | sed 's/^/    /'
            fi
        fi
    done
    pass=$((pass + fpass)); fail=$((fail + ffail))
    echo "fuzz: $fpass/$((fpass + ffail)) generated records agree (valid + adversarial, ${fuzz_n} each)"
fi

echo
if [ "$fail" -eq 0 ]; then
    green "event parity: $pass/$((pass + fail)) inputs agree (C++ <-> Rust)"
    exit 0
fi
red "event parity: $fail/$((pass + fail)) inputs DIVERGED"
exit 1
