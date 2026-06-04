#!/usr/bin/env bash
#
# Binary-hardening contract gate.
#
# AegisBPF compiles the privileged agent with a set of exploit-mitigation flags
# (CMakeLists.txt "Security hardening flags"): full RELRO, PIE, stack-protector,
# a non-executable stack, and — on x86_64 — Intel CET (IBT + shadow stack). Those
# flags are easy to silently drop in a future build-system refactor. This script
# asserts, against the actual linked ELF, that every mitigation is present, so a
# regression fails CI instead of shipping a quietly-weakened binary.
#
# It uses only `readelf` (always available wherever the binary is built) rather
# than `checksec`, and is architecture-aware: CET is asserted only on x86_64.
#
# Usage: check_hardening.sh [path-to-binary]   (default: build/aegisbpf)
set -uo pipefail

BIN="${1:-build/aegisbpf}"

if ! command -v readelf >/dev/null 2>&1; then
    echo "check_hardening: readelf not found" >&2
    exit 2
fi
if [ ! -f "$BIN" ]; then
    echo "check_hardening: binary not found: $BIN" >&2
    exit 2
fi

hdr="$(readelf -hW "$BIN" 2>/dev/null)"
seg="$(readelf -lW "$BIN" 2>/dev/null)"
dyn="$(readelf -dW "$BIN" 2>/dev/null)"
notes="$(readelf -nW "$BIN" 2>/dev/null)"
# __stack_chk_fail is an imported libc symbol — present in .dynsym even if the
# binary is stripped of its .symtab.
dynsyms="$(readelf --dyn-syms -W "$BIN" 2>/dev/null)"

fails=0
pass() { printf '  \033[32mPASS\033[0m  %s\n' "$1"; }
fail() { printf '  \033[31mFAIL\033[0m  %s\n' "$1"; fails=$((fails + 1)); }

echo "Binary-hardening contract: $BIN"

# 1. PIE — position-independent executable (ET_DYN with an interpreter).
if grep -qE 'Type:\s+DYN' <<<"$hdr" && grep -q 'INTERP' <<<"$seg"; then
    pass "PIE (ET_DYN executable)"
else
    fail "PIE — expected ET_DYN with PT_INTERP (got: $(grep -E 'Type:' <<<"$hdr" | tr -s ' '))"
fi

# 2. Full RELRO — GNU_RELRO segment AND BIND_NOW (immediate binding).
has_relro=0; has_now=0
grep -q 'GNU_RELRO' <<<"$seg" && has_relro=1
{ grep -qE 'BIND_NOW' <<<"$dyn" || grep -qE 'FLAGS_1.*\bNOW\b' <<<"$dyn"; } && has_now=1
if [ "$has_relro" = 1 ] && [ "$has_now" = 1 ]; then
    pass "Full RELRO (GNU_RELRO + BIND_NOW)"
else
    fail "Full RELRO — GNU_RELRO=$has_relro BIND_NOW=$has_now"
fi

# 3. Stack canary — references the stack-protector failure handler.
if grep -q '__stack_chk_fail' <<<"$dynsyms"; then
    pass "Stack protector (__stack_chk_fail)"
else
    fail "Stack protector — __stack_chk_fail not referenced"
fi

# 4. Non-executable stack — GNU_STACK present and not executable.
gnu_stack_line="$(grep 'GNU_STACK' <<<"$seg")"
if [ -z "$gnu_stack_line" ]; then
    fail "Non-exec stack — no GNU_STACK segment (implicitly executable)"
elif grep -qE 'GNU_STACK.*\sRWE' <<<"$gnu_stack_line" || grep -qE 'GNU_STACK.*\bE\b' <<<"$gnu_stack_line"; then
    fail "Non-exec stack — GNU_STACK is executable: $(tr -s ' ' <<<"$gnu_stack_line")"
else
    pass "Non-exec stack (GNU_STACK is not executable)"
fi

# 5. Intel CET (x86_64 only) — IBT + shadow stack in .note.gnu.property.
if grep -qE 'Machine:\s+Advanced Micro Devices X86-64' <<<"$hdr"; then
    if grep -qi 'IBT' <<<"$notes" && grep -qi 'SHSTK' <<<"$notes"; then
        pass "Intel CET (IBT + SHSTK)"
    else
        fail "Intel CET — expected IBT + SHSTK in .note.gnu.property (x86_64)"
    fi
else
    echo "  SKIP  Intel CET (not x86_64)"
fi

echo
if [ "$fails" -eq 0 ]; then
    printf '\033[32mhardening: all mitigations present\033[0m\n'
    exit 0
fi
printf '\033[31mhardening: %d mitigation(s) MISSING\033[0m\n' "$fails"
exit 1
