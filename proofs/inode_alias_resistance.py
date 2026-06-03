#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
#
# Machine-checked proof: inode-alias bypass-resistance of the AegisBPF file
# enforcement decision.
#
# WHAT THIS PROVES
# ----------------
# The catalog (docs/BYPASS_CATALOG.md, BYP-M1..M4, BYP-M6) claims the entire
# path-aliasing bypass family — symlink swap, hardlink, rename/path-drift,
# bind-mount, overlayfs merged-path — cannot evade a `[deny_path]` rule, because
# enforcement is *inode-based*. Today that claim rests on behavioral probes
# ("we created an alias and observed -EPERM"). This script upgrades it to a
# machine-checked property of the decision logic itself:
#
#   The enforcement verdict is a pure function of (inode identity, cgroup,
#   rule flags, daemon config). It contains NO dependence on the path string.
#   Therefore any operation that only manufactures a new *path* aliasing the
#   same underlying inode cannot change the verdict.
#
# The decision function `decision(...)` below is a line-for-line transcription of
# the LSM hook bodies in bpf/aegis_file.bpf.h:
#   - handle_file_open             (SEC lsm/file_open)
#   - handle_inode_permission_impl (SEC lsm/inode_permission)
# (overlay's handle_inode_copy_up in bpf/aegis_overlay.bpf.h shares the same
# rule_flags / protect_only / deny gate — see THEOREMS for the overlay case.)
#
# FIDELITY ANCHOR (the one modeling assumption, stated honestly)
# --------------------------------------------------------------
# We model the kernel guarantee that when lsm/file_open or lsm/inode_permission
# fires for an access reached via path `p`, the inode handed to the hook is the
# inode that `p` resolves to — i.e. `resolve(p)`. Every member of the alias
# family is, by construction, "two or more paths naming one inode":
#   symlink  -> link path and target path resolve to the same inode
#   hardlink -> both names share one inode (same i_ino, same i_sb->s_dev)
#   rename   -> the inode is unchanged; only the name moves
#   bindmount-> the bind alias exposes the very same inode object
#   overlay  -> a merged path not yet copied up maps to the lower inode
# The VFS performs this resolution BEFORE the LSM hook is invoked, so the hook
# never sees the path string at all — it sees f_inode / the inode object. This
# is the property the proof leans on; the model<->code correspondence and this
# assumption are documented in proofs/README.md and re-checked by hand on any
# change to the hook bodies (CI guards the transcription via a digest).
#
# The proof is "only as good as the model." We do not overclaim: this is a
# lightweight formal method that locks the *logic structure* (path-independence
# + the exact exemption gating), not a verified compilation of the eBPF bytecode.

import sys

from z3 import (
    And,
    BitVecSort,
    BitVecVal,
    Bool,
    Function,
    If,
    Implies,
    Int,
    IntSort,
    Not,
    Or,
    Solver,
    sat,
    unsat,
)

# ---------------------------------------------------------------------------
# Constants — mirror bpf/aegis_common.h exactly.
# ---------------------------------------------------------------------------
RULE_FLAG_DENY_ALWAYS = BitVecVal(1, 8)            # #define ... 1
RULE_FLAG_PROTECT_VERIFIED_EXEC = BitVecVal(2, 8)  # #define ... 2
ZERO8 = BitVecVal(0, 8)

# Decision outcomes. The enforcement question is "does the hook return -EPERM?",
# i.e. outcome == DENY. AUDIT returns 0 to the kernel (does NOT block) but emits
# an event; ALLOW returns 0 with no event. We separate them so audit mode is
# modeled honestly (audit mode is explicitly non-blocking).
ALLOW = 0
DENY = 1
AUDIT = 2

# ---------------------------------------------------------------------------
# Uninterpreted domain.
# ---------------------------------------------------------------------------
Path = IntSort()    # an opaque path handle (the thing an attacker can mint)
Inode = IntSort()   # inode identity == (i_ino, i_sb->s_dev) packed; opaque key
Cgroup = IntSort()
Flags = BitVecSort(8)

# resolve : Path -> Inode  (the VFS path-walk; the fidelity anchor above)
resolve = Function("resolve", Path, Inode)

# Maps, exactly as the hook consults them — all keyed on inode identity / cgid,
# never on a path:
deny_inode_present = Function("deny_inode_present", Inode, IntSort())  # 0/1 (map hit)
deny_inode_flags = Function("deny_inode_flags", Inode, Flags)          # rule value
cg_deny = Function("cg_deny", Cgroup, Inode, Flags)                    # cgroup_inode_denied
survival = Function("survival", Inode, IntSort())                      # 0/1 (allowlist hit)
cgroup_allowed = Function("cgroup_allowed", Cgroup, IntSort())         # 0/1 (allow_cgroup_map)


def decision(path, cg, *, file_policy_empty, audit, protect_files, verified):
    """Line-for-line model of handle_file_open / handle_inode_permission_impl.

    `file_policy_empty`, `audit`, `protect_files` are daemon-config Bools;
    `verified` is the per-task current_verified_exec() result (a Bool).
    Returns a z3 Int expression in {ALLOW, DENY, AUDIT}.
    """
    key = resolve(path)                                   # struct inode_id key

    cg_rule = cg_deny(cg, key)                            # __u8 cg_rule
    rule = deny_inode_present(key) == 1                   # bpf_map_lookup_elem(&deny_inode_map)
    cg_present = cg_rule != ZERO8

    # if (!rule && !cg_rule) return 0;
    no_rule = And(Not(rule), Not(cg_present))

    # rule_flags = cg_rule ? cg_rule : (rule ? *rule : 0);
    rule_flags = If(cg_present, cg_rule, If(rule, deny_inode_flags(key), ZERO8))

    # protect_only = (rule_flags & PROTECT_VERIFIED_EXEC) && !(rule_flags & DENY_ALWAYS);
    protect_only = And(
        (rule_flags & RULE_FLAG_PROTECT_VERIFIED_EXEC) != ZERO8,
        (rule_flags & RULE_FLAG_DENY_ALWAYS) == ZERO8,
    )

    surv = survival(key) == 1                             # survival_allowlist hit
    # if (!cg_rule && is_cgroup_allowed(cgid)) return 0;
    cg_allow_bypass = And(Not(cg_present), cgroup_allowed(cg) == 1)

    # The exemption ladder, innermost verdict first:
    verdict = If(audit, AUDIT, DENY)                      # bottom: audit? event : -EPERM

    # if (protect_only) { if (!PROTECT_FILES) allow; if (verified) allow; }
    after_protect = If(
        protect_only,
        If(Or(Not(protect_files), verified), ALLOW, verdict),
        verdict,
    )

    return If(
        file_policy_empty, ALLOW,
        If(no_rule, ALLOW,
           If(surv, ALLOW,
              If(cg_allow_bypass, ALLOW,
                 after_protect))),
    )


def check(name, claim, *, expect=unsat):
    """Prove `claim` valid by asserting its negation is unsat (or sat for a
    deliberate witness). Prints PASS/FAIL and returns bool."""
    s = Solver()
    s.add(Not(claim) if expect is unsat else claim)
    res = s.check()
    ok = res == expect
    tag = "PASS" if ok else "FAIL"
    print(f"  [{tag}] {name}")
    if not ok:
        print(f"        expected {expect}, got {res}")
        if res == sat:
            print(f"        counterexample: {s.model()}")
    return ok


def main():
    print("AegisBPF formal proof — inode-alias bypass-resistance")
    print("model: bpf/aegis_file.bpf.h :: handle_file_open / handle_inode_permission_impl")
    print()

    # Free symbols shared across theorems.
    p = Int("p")
    q = Int("q")
    cg = Int("cg")
    fpe = Bool("file_policy_empty")
    aud = Bool("audit")
    pf = Bool("protect_files")
    ve = Bool("verified")

    d_p = decision(p, cg, file_policy_empty=fpe, audit=aud, protect_files=pf, verified=ve)
    d_q = decision(q, cg, file_policy_empty=fpe, audit=aud, protect_files=pf, verified=ve)

    results = []

    # -- T1: path-independence / alias invariance ---------------------------
    # For any two paths resolving to the same inode under the same cgroup and
    # config, the verdict is identical. This is the structural heart: it would
    # FAIL if any branch in the hook consulted the path rather than the inode.
    results.append(check(
        "T1 alias-invariance: resolve(p)==resolve(q) => decision(p)==decision(q)",
        Implies(resolve(p) == resolve(q), d_p == d_q),
    ))

    # -- T2: alias-bypass impossibility (the BYP-M1..M4,M6 claim) ------------
    # A denied file: its inode is in the global deny map with DENY_ALWAYS, the
    # acting cgroup is non-exempt, the inode is not on the survival allowlist,
    # and we are NOT in audit mode (enforce posture). Then EVERY path aliasing
    # that inode is denied with -EPERM — no symlink/hardlink/rename/bindmount/
    # overlay path can reach ALLOW.
    key_p = resolve(p)
    denied_setup = And(
        deny_inode_present(key_p) == 1,
        (deny_inode_flags(key_p) & RULE_FLAG_DENY_ALWAYS) != ZERO8,  # DENY_ALWAYS
        cg_deny(cg, key_p) == ZERO8,        # rely on the global rule (cg-scoped not required)
        cgroup_allowed(cg) == 0,            # acting cgroup is NOT in the allow map
        survival(key_p) == 0,               # inode is NOT on the survival allowlist
        Not(fpe),                           # file policy is loaded
        Not(aud),                           # enforce mode (not audit)
    )
    results.append(check(
        "T2 alias-bypass impossible: denied inode + non-exempt cgroup => DENY for any alias",
        Implies(denied_setup, d_p == DENY),
    ))

    # -- T3: aliasing cannot reach an exemption -----------------------------
    # The escapes from DENY are exactly: file_policy_empty, no-rule, survival,
    # cgroup-allow (global rules only), protect-without-verified, audit. NONE is
    # a function of the path. Concretely: fix cgroup+config+maps, vary only the
    # path within the alias set of a denied inode -> verdict constant. (T1
    # restricted to one inode, framed as the threat model: "attacker controls
    # path minting, nothing else".)
    same_inode = resolve(p) == resolve(q)
    results.append(check(
        "T3 no path-only escape: same inode => identical verdict regardless of which alias",
        Implies(same_inode, d_p == d_q),
    ))

    # -- T4: no aliasing-induced false deny (safety for allowed inodes) -----
    # If an inode is neither globally nor cgroup denied and policy is benign,
    # every alias of it is ALLOWED. Inode-keying must not over-block via aliases.
    allowed_setup = And(
        deny_inode_present(key_p) == 0,
        cg_deny(cg, key_p) == ZERO8,
        Not(fpe),
    )
    results.append(check(
        "T4 no false-deny: un-denied inode => ALLOW for any alias",
        Implies(allowed_setup, d_p == ALLOW),
    ))

    # -- T5: cgroup-scoped deny is NOT bypassable via the global allowlist ---
    # The hook gates is_cgroup_allowed() behind `!cg_rule`, so a cgroup-scoped
    # deny survives even when that cgroup sits in the global allow_cgroup_map.
    # This locks a subtle ordering in the code: a refactor that drops the
    # `!cg_rule` guard would make this theorem FAIL.
    cg_scoped_setup = And(
        cg_deny(cg, key_p) == RULE_FLAG_DENY_ALWAYS,  # cgroup-scoped DENY_ALWAYS
        cgroup_allowed(cg) == 1,                       # AND cgroup is globally allowed
        survival(key_p) == 0,
        Not(fpe),
        Not(aud),
    )
    results.append(check(
        "T5 cgroup-scoped deny beats global allowlist: => DENY despite cgroup_allowed",
        Implies(cg_scoped_setup, d_p == DENY),
    ))

    # -- T6: determinism (the contract) -------------------------------------
    # The verdict is a total function of its inputs: no two evaluations with
    # identical (inode, cgroup, config) disagree. (Sanity that decision() has no
    # hidden nondeterminism; asserted as the determinism contract from
    # ENFORCEMENT_SEMANTICS_WHITEPAPER.)
    d_p2 = decision(p, cg, file_policy_empty=fpe, audit=aud, protect_files=pf, verified=ve)
    results.append(check(
        "T6 determinism: identical inputs => identical verdict",
        d_p == d_p2,
    ))

    # -- Anti-vacuity witnesses: prove the model can actually DENY and ALLOW --
    # (Guards against a degenerate model where everything trivially holds.)
    s = Solver()
    s.add(decision(p, cg, file_policy_empty=fpe, audit=aud, protect_files=pf, verified=ve) == DENY)
    deny_reachable = s.check() == sat
    print(f"  [{'PASS' if deny_reachable else 'FAIL'}] W1 DENY is reachable (model not vacuous)")
    results.append(deny_reachable)

    s = Solver()
    s.add(decision(p, cg, file_policy_empty=fpe, audit=aud, protect_files=pf, verified=ve) == ALLOW)
    allow_reachable = s.check() == sat
    print(f"  [{'PASS' if allow_reachable else 'FAIL'}] W2 ALLOW is reachable (model not vacuous)")
    results.append(allow_reachable)

    print()
    passed = sum(1 for r in results if r)
    total = len(results)
    print(f"{passed}/{total} obligations discharged")
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
