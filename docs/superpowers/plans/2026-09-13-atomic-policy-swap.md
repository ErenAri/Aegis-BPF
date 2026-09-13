# Atomic Policy Swap Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Eliminate the audit-only window that every policy reload currently opens, by replacing the copy-based shadow→live sync with a single atomic inner-map slot flip.

**Architecture:** Each of 16 policy maps becomes an outer `BPF_MAP_TYPE_ARRAY_OF_MAPS` with two slots holding right-sized inner maps. A shared single-entry `active_slot` map names the live slot. Userspace populates the inactive slot (unobserved), then flips `active_slot` with one `u32` write that commits every policy domain simultaneously. Old inner maps are RCU-freed after the flip.

**Tech Stack:** BPF C (libbpf CO-RE, BTF-defined maps), C++20 userspace, CMake + ctest, veristat for verifier budget.

**Spec:** `docs/superpowers/specs/2026-09-13-atomic-policy-swap-design.md`

## Global Constraints

- Kernel floor is **5.8+ with BTF** (`README.md:551`). CI matrix: 5.14, 5.15, 6.1, 6.5, 6.6, 6.8.
- Inner `max_entries` may differ from the template only on **5.11+**; below that, create inner maps at the template's `max_entries`. The swap stays atomic either way.
- `active_slot` is read **once per hook invocation** and passed as an explicit parameter. Never re-read mid-hook.
- A failed reload must leave the previous policy enforcing. Never degrade to audit.
- Do not convert stats/state maps or `survival_allowlist` (see spec).
- Existing style: BTF-defined maps in `bpf/aegis_common.h`, `Result<T>` error handling, `TRY(...)` macro, `clang-format` per `.clang-format`.
- Build: `cmake -B build -DCMAKE_BUILD_TYPE=Debug && cmake --build build -j`. Test: `ctest --test-dir build --output-on-failure`.

---

### Task 1: Kernel capability probe for variable-size inner maps

**Files:**
- Modify: `src/bpf_maps.hpp` (add declaration), `src/bpf_maps.cpp` (add implementation)
- Test: `tests/test_bpf_state.cpp`

**Interfaces:**
- Consumes: nothing.
- Produces: `bool aegis::supports_variable_inner_max_entries();` — returns true when the kernel accepts an inner map whose `max_entries` differs from the outer map's template (5.11+). Result is computed once and cached in a function-local static.

- [ ] **Step 1: Write the failing test**

Add to `tests/test_bpf_state.cpp`:

```cpp
TEST_CASE("variable inner max_entries probe is stable and cached")
{
    // The probe must not crash, must be callable repeatedly, and must
    // return the same answer every time (it is cached).
    const bool first = aegis::supports_variable_inner_max_entries();
    const bool second = aegis::supports_variable_inner_max_entries();
    REQUIRE(first == second);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cmake --build build -j 2>&1 | tail -20`
Expected: compile error — `supports_variable_inner_max_entries` is not a member of `aegis`.

- [ ] **Step 3: Write minimal implementation**

Add to `src/bpf_maps.hpp` after the `sync_from_shadow` declaration:

```cpp
/// True when the kernel accepts an inner map whose max_entries differs from
/// the outer map's template (relaxed in 5.11). When false, inner maps must be
/// created at the template's max_entries. Probed once, then cached.
bool supports_variable_inner_max_entries();
```

Add to `src/bpf_maps.cpp`:

```cpp
namespace {

bool probe_variable_inner_max_entries()
{
    struct bpf_map_create_opts opts = {};
    opts.sz = sizeof(opts);

    // Template the outer map will be created against.
    int tmpl = bpf_map_create(BPF_MAP_TYPE_HASH, "aegis_tmpl", 4, 1, 16, &opts);
    if (tmpl < 0) {
        return false;
    }

    struct bpf_map_create_opts outer_opts = {};
    outer_opts.sz = sizeof(outer_opts);
    outer_opts.inner_map_fd = static_cast<__u32>(tmpl);
    int outer = bpf_map_create(BPF_MAP_TYPE_ARRAY_OF_MAPS, "aegis_probe", 4, 4, 1, &outer_opts);
    if (outer < 0) {
        close(tmpl);
        return false;
    }

    // Deliberately a different max_entries than the template.
    int big = bpf_map_create(BPF_MAP_TYPE_HASH, "aegis_big", 4, 1, 64, &opts);
    if (big < 0) {
        close(outer);
        close(tmpl);
        return false;
    }

    __u32 key = 0;
    __u32 value = static_cast<__u32>(big);
    const bool ok = bpf_map_update_elem(outer, &key, &value, BPF_ANY) == 0;

    close(big);
    close(outer);
    close(tmpl);
    return ok;
}

} // namespace

bool supports_variable_inner_max_entries()
{
    static const bool cached = probe_variable_inner_max_entries();
    return cached;
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cmake --build build -j && ctest --test-dir build -R bpf_state --output-on-failure`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/bpf_maps.hpp src/bpf_maps.cpp tests/test_bpf_state.cpp
git commit -m "feat(bpf): probe kernel support for variable-size inner maps"
```

---

### Task 2: Right-size support in `create_shadow_map`

**Files:**
- Modify: `src/bpf_maps.hpp:54`, `src/bpf_maps.cpp:87`
- Test: `tests/test_bpf_state.cpp`

**Interfaces:**
- Consumes: `supports_variable_inner_max_entries()` from Task 1.
- Produces: `Result<ShadowMap> create_shadow_map(bpf_map* live_map, uint32_t max_entries_override = 0);` — when the override is non-zero **and** the kernel supports variable inner sizes, the created map uses the override; otherwise it uses the live map's `max_entries`. All other attributes are cloned unchanged.

- [ ] **Step 1: Write the failing test**

Add to `tests/test_bpf_state.cpp`:

```cpp
TEST_CASE("create_shadow_map honours a max_entries override")
{
    // Build a small live-like map to clone from.
    struct bpf_map_create_opts opts = {};
    opts.sz = sizeof(opts);
    int live = bpf_map_create(BPF_MAP_TYPE_HASH, "aegis_live", 4, 1, 4096, &opts);
    REQUIRE(live >= 0);

    // Override to a much smaller size; verify via map info.
    auto shadow = aegis::create_shadow_map_from_fd(live, 64);
    REQUIRE(static_cast<bool>(shadow));

    struct bpf_map_info info = {};
    __u32 len = sizeof(info);
    REQUIRE(bpf_obj_get_info_by_fd(shadow->fd(), &info, &len) == 0);

    if (aegis::supports_variable_inner_max_entries()) {
        REQUIRE(info.max_entries == 64);
    } else {
        REQUIRE(info.max_entries == 4096);
    }
    close(live);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cmake --build build -j 2>&1 | tail -20`
Expected: compile error — `create_shadow_map_from_fd` not declared.

- [ ] **Step 3: Write minimal implementation**

In `src/bpf_maps.hpp`, replace the `create_shadow_map` declaration with:

```cpp
Result<ShadowMap> create_shadow_map(bpf_map* live_map, uint32_t max_entries_override = 0);
/// Same as create_shadow_map but clones from a raw fd. Used by tests and by
/// the slot builder, which works from fds rather than libbpf map handles.
Result<ShadowMap> create_shadow_map_from_fd(int live_fd, uint32_t max_entries_override = 0);
```

In `src/bpf_maps.cpp`, replace the body of `create_shadow_map` and add the fd variant:

```cpp
namespace {

Result<ShadowMap> create_shadow_like(enum bpf_map_type type, uint32_t key_size, uint32_t value_size,
                                     uint32_t max_entries, uint32_t flags, uint32_t max_entries_override)
{
    uint32_t entries = max_entries;
    if (max_entries_override > 0 && supports_variable_inner_max_entries()) {
        entries = max_entries_override;
    }

    struct bpf_map_create_opts opts = {};
    opts.sz = sizeof(opts);
    opts.map_flags = flags;
    int fd = bpf_map_create(type, "shadow", key_size, value_size, entries, &opts);
    if (fd < 0) {
        return Error::system(errno, "Failed to create shadow map");
    }
    return ShadowMap(fd);
}

} // namespace

Result<ShadowMap> create_shadow_map(bpf_map* live_map, uint32_t max_entries_override)
{
    if (!live_map) {
        return Error(ErrorCode::InvalidArgument, "Cannot create shadow for null map");
    }
    return create_shadow_like(static_cast<enum bpf_map_type>(bpf_map__type(live_map)), bpf_map__key_size(live_map),
                              bpf_map__value_size(live_map), bpf_map__max_entries(live_map),
                              bpf_map__map_flags(live_map), max_entries_override);
}

Result<ShadowMap> create_shadow_map_from_fd(int live_fd, uint32_t max_entries_override)
{
    struct bpf_map_info info = {};
    __u32 len = sizeof(info);
    if (bpf_obj_get_info_by_fd(live_fd, &info, &len) != 0) {
        return Error::system(errno, "Failed to read map info for shadow clone");
    }
    return create_shadow_like(static_cast<enum bpf_map_type>(info.type), info.key_size, info.value_size,
                              info.max_entries, info.map_flags, max_entries_override);
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cmake --build build -j && ctest --test-dir build -R bpf_state --output-on-failure`
Expected: PASS. The existing `create_shadow_map(m)` call sites are unchanged because the new parameter defaults to 0.

- [ ] **Step 5: Commit**

```bash
git add src/bpf_maps.hpp src/bpf_maps.cpp tests/test_bpf_state.cpp
git commit -m "feat(bpf): allow right-sizing shadow maps via max_entries override"
```

---

### Task 3: BPF-side slot infrastructure (`active_slot` + helpers)

**Files:**
- Modify: `bpf/aegis_common.h` (add map + helpers near the existing `policy_generation` map at `:582-599`)
- Test: `tests/test_bpf_integrity.cpp`

**Interfaces:**
- Consumes: nothing.
- Produces (BPF-side, used by Tasks 4 and 6):
  - map `active_slot` — `BPF_MAP_TYPE_ARRAY`, 1 entry, key `__u32`, value `__u32`.
  - `static __always_inline __u32 policy_active_slot(void)` — reads the live slot, masked to `0..1`.
  - `static __always_inline void *policy_inner(void *outer, __u32 slot)` — resolves an outer map slot to its inner map, or `NULL`.

- [ ] **Step 1: Write the failing test**

Add to `tests/test_bpf_integrity.cpp`:

```cpp
TEST_CASE("BPF object declares active_slot policy map")
{
    // The skeleton must expose active_slot so userspace can flip generations.
    // Guards against the map being dropped or renamed.
    const std::string src = read_file("bpf/aegis_common.h");
    REQUIRE(src.find("} active_slot SEC(\".maps\");") != std::string::npos);
    REQUIRE(src.find("policy_active_slot") != std::string::npos);
    REQUIRE(src.find("policy_inner") != std::string::npos);
}
```

If `read_file` does not exist in that test file, add it:

```cpp
static std::string read_file(const std::string& path)
{
    std::ifstream in(path);
    std::stringstream ss;
    ss << in.rdbuf();
    return ss.str();
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cmake --build build -j && ctest --test-dir build -R bpf_integrity --output-on-failure`
Expected: FAIL — `active_slot` not found.

- [ ] **Step 3: Write minimal implementation**

Add to `bpf/aegis_common.h` immediately after the `policy_generation` map definition (after line 599):

```c
/* Active policy slot selector.
 *
 * Every slotted policy map is an ARRAY_OF_MAPS with two slots.  Userspace
 * populates the inactive slot, then writes the new index here.  That single
 * u32 write is the only observable transition, so all policy domains switch
 * generations together.
 *
 * Key 0 = index of the live slot (0 or 1).
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} active_slot SEC(".maps");

/* Read the live policy slot.  MUST be called exactly once per hook
 * invocation and the result threaded through every helper in that
 * invocation -- re-reading mid-hook can straddle a flip and mix rules from
 * two different generations. */
static __always_inline __u32 policy_active_slot(void)
{
    __u32 key = 0;
    __u32 *slot = bpf_map_lookup_elem(&active_slot, &key);
    /* Mask to the slot count so the verifier can bound the array access. */
    return slot ? (*slot & 1u) : 0;
}

/* Resolve an outer ARRAY_OF_MAPS slot to its inner policy map.
 * Returns NULL when the slot is unpopulated, which callers must treat
 * exactly as they treat an empty map. */
static __always_inline void *policy_inner(void *outer, __u32 slot)
{
    return bpf_map_lookup_elem(outer, &slot);
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cmake --build build -j && ctest --test-dir build -R bpf_integrity --output-on-failure`
Expected: PASS.

- [ ] **Step 5: Verify the BPF object still loads**

Run: `cmake --build build --target aegis_bpf 2>&1 | tail -20`
Expected: BPF object compiles. The new map is unused so far, which is fine.

- [ ] **Step 6: Commit**

```bash
git add bpf/aegis_common.h tests/test_bpf_integrity.cpp
git commit -m "feat(bpf): add active_slot map and policy slot helpers"
```

---

### Task 4: Vertical slice — convert `deny_inode_map` to a slotted map

Convert exactly one map end-to-end before touching the other fifteen. This proves the whole mechanism (declaration, hot path, population, flip) against a real hook with real enforcement.

**Files:**
- Modify: `bpf/aegis_common.h:461-466` (map declaration), `bpf/aegis_file.bpf.h:43`, `:184` (the two read sites)
- Test: `tests/test_bpf_integrity.cpp`

**Interfaces:**
- Consumes: `policy_active_slot()`, `policy_inner()` from Task 3.
- Produces: outer map `deny_inode_outer`; the inner template type `struct deny_inode_inner`. Userspace (Task 5) looks the outer map up by the name `deny_inode_outer`.

- [ ] **Step 1: Write the failing test**

Add to `tests/test_bpf_integrity.cpp`:

```cpp
TEST_CASE("deny_inode is a slotted outer map with two slots")
{
    const std::string src = read_file("bpf/aegis_common.h");
    REQUIRE(src.find("} deny_inode_outer SEC(\".maps\");") != std::string::npos);
    REQUIRE(src.find("struct deny_inode_inner") != std::string::npos);

    // The hook must resolve through the slot, not the bare map.
    const std::string hook = read_file("bpf/aegis_file.bpf.h");
    REQUIRE(hook.find("&deny_inode_map") == std::string::npos);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cmake --build build -j && ctest --test-dir build -R bpf_integrity --output-on-failure`
Expected: FAIL — `deny_inode_outer` not found.

- [ ] **Step 3: Replace the map declaration**

In `bpf/aegis_common.h`, replace lines 461-466:

```c
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_DENY_INODE_ENTRIES);
    __type(key, struct inode_id);
    __type(value, __u8);
} deny_inode_map SEC(".maps");
```

with:

```c
/* Inner map template for the slotted deny-inode policy map. */
struct deny_inode_inner {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_DENY_INODE_ENTRIES);
    __type(key, struct inode_id);
    __type(value, __u8);
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
    __uint(max_entries, 2);
    __type(key, __u32);
    __array(values, struct deny_inode_inner);
} deny_inode_outer SEC(".maps");
```

- [ ] **Step 4: Update the two hook read sites**

In `bpf/aegis_file.bpf.h`, at both `:43` and `:184`, replace:

```c
    __u8 *rule = bpf_map_lookup_elem(&deny_inode_map, &key);
```

with:

```c
    void *deny_inode = policy_inner(&deny_inode_outer, slot);
    __u8 *rule = deny_inode ? bpf_map_lookup_elem(deny_inode, &key) : NULL;
```

In each of the two enclosing hook functions, add the slot read as the first
statement of the function body (before any policy map access):

```c
    const __u32 slot = policy_active_slot();
```

- [ ] **Step 5: Verify the BPF object compiles and the verifier accepts it**

Run: `cmake --build build --target aegis_bpf 2>&1 | tail -30`
Expected: compiles clean. If the verifier rejects the inner lookup, confirm
`policy_inner`'s return is NULL-checked before use — it always must be.

- [ ] **Step 6: Run test to verify it passes**

Run: `ctest --test-dir build -R bpf_integrity --output-on-failure`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add bpf/aegis_common.h bpf/aegis_file.bpf.h tests/test_bpf_integrity.cpp
git commit -m "feat(bpf): convert deny_inode to a slotted outer map"
```

---

### Task 5: Userspace slot builder and atomic flip

**Files:**
- Create: `src/policy_slots.hpp`, `src/policy_slots.cpp`
- Modify: `CMakeLists.txt` (add the new source to the agent target and the test target)
- Test: `tests/test_policy_slots.cpp` (create), registered in `CMakeLists.txt`

**Interfaces:**
- Consumes: `create_shadow_map_from_fd()` (Task 2), `ShadowMap` (`src/bpf_maps.hpp:19`).
- Produces:
  - `struct SlotBuilder` with `Result<void> add_map(const std::string& name, int outer_fd, uint32_t rule_count, int live_inner_fd);`
  - `Result<int> SlotBuilder::inner_fd(const std::string& name) const;` — the fd to populate for that map.
  - `Result<void> SlotBuilder::commit(int active_slot_fd);` — inserts every built inner map into the inactive slot, then flips `active_slot`. Returns an error **without flipping** if any insert fails.
  - `uint32_t inner_size_for(uint32_t rule_count)` — returns `std::max(64u, rule_count * 2)`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_policy_slots.cpp`:

```cpp
#include "policy_slots.hpp"

#include <bpf/bpf.h>

#include "catch_amalgamated.hpp"

using namespace aegis;

namespace {

int make_hash_map(uint32_t entries)
{
    struct bpf_map_create_opts opts = {};
    opts.sz = sizeof(opts);
    return bpf_map_create(BPF_MAP_TYPE_HASH, "t_inner", 4, 1, entries, &opts);
}

int make_outer(int tmpl_fd)
{
    struct bpf_map_create_opts opts = {};
    opts.sz = sizeof(opts);
    opts.inner_map_fd = static_cast<__u32>(tmpl_fd);
    return bpf_map_create(BPF_MAP_TYPE_ARRAY_OF_MAPS, "t_outer", 4, 4, 2, &opts);
}

int make_active_slot()
{
    struct bpf_map_create_opts opts = {};
    opts.sz = sizeof(opts);
    return bpf_map_create(BPF_MAP_TYPE_ARRAY, "t_slot", 4, 4, 1, &opts);
}

} // namespace

TEST_CASE("inner_size_for applies a floor and doubles the rule count")
{
    REQUIRE(inner_size_for(0) == 64);
    REQUIRE(inner_size_for(10) == 64);
    REQUIRE(inner_size_for(100) == 200);
}

TEST_CASE("commit flips active_slot exactly once and populates the new slot")
{
    int tmpl = make_hash_map(64);
    REQUIRE(tmpl >= 0);
    int outer = make_outer(tmpl);
    REQUIRE(outer >= 0);
    int slot_fd = make_active_slot();
    REQUIRE(slot_fd >= 0);

    // Slot starts at 0, so the builder must target slot 1.
    SlotBuilder builder;
    REQUIRE(builder.add_map("deny_inode", outer, 10, tmpl));
    auto fd = builder.inner_fd("deny_inode");
    REQUIRE(fd);

    // Put a rule in the new inner map before committing.
    uint32_t key = 42;
    uint8_t val = 1;
    REQUIRE(bpf_map_update_elem(*fd, &key, &val, BPF_ANY) == 0);

    REQUIRE(builder.commit(slot_fd));

    uint32_t zero = 0;
    uint32_t live = 0;
    REQUIRE(bpf_map_lookup_elem(slot_fd, &zero, &live) == 0);
    REQUIRE(live == 1);
}

TEST_CASE("commit does not flip when an inner map is missing")
{
    int tmpl = make_hash_map(64);
    int outer = make_outer(tmpl);
    int slot_fd = make_active_slot();
    REQUIRE(tmpl >= 0);
    REQUIRE(outer >= 0);
    REQUIRE(slot_fd >= 0);

    // An outer fd of -1 makes the slot insert fail.
    SlotBuilder builder;
    REQUIRE(builder.add_map("bad", -1, 10, tmpl));
    REQUIRE_FALSE(builder.commit(slot_fd));

    // The live slot must still be the original one: fail-safe.
    uint32_t zero = 0;
    uint32_t live = 99;
    REQUIRE(bpf_map_lookup_elem(slot_fd, &zero, &live) == 0);
    REQUIRE(live == 0);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cmake --build build -j 2>&1 | tail -20`
Expected: compile error — `policy_slots.hpp` does not exist.

- [ ] **Step 3: Write the implementation**

Create `src/policy_slots.hpp`:

```cpp
// cppcheck-suppress-file missingIncludeSystem
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "bpf_maps.hpp"
#include "result.hpp"

namespace aegis {

/// Size an inner policy map for a given rule count, leaving headroom so that
/// runtime single-element inserts (dynamic/TTL denies) do not hit max_entries
/// between reloads.
uint32_t inner_size_for(uint32_t rule_count);

/// Builds a complete new policy generation in the inactive slot of every
/// outer map, then commits it with a single atomic write to active_slot.
///
/// Failure before commit() leaves the live policy entirely untouched.
class SlotBuilder {
  public:
    /// Create a right-sized inner map for `name`, cloned from `live_inner_fd`.
    Result<void> add_map(const std::string& name, int outer_fd, uint32_t rule_count, int live_inner_fd);

    /// The fd of the new inner map for `name`, for population.
    Result<int> inner_fd(const std::string& name) const;

    /// Insert every built inner map into the inactive slot, then flip
    /// active_slot. Returns an error without flipping if any insert fails.
    Result<void> commit(int active_slot_fd);

  private:
    struct Entry {
        std::string name;
        int outer_fd = -1;
        ShadowMap inner;
    };
    std::vector<Entry> entries_;
};

} // namespace aegis
```

Create `src/policy_slots.cpp`:

```cpp
#include "policy_slots.hpp"

#include <bpf/bpf.h>

#include <algorithm>

namespace aegis {

uint32_t inner_size_for(uint32_t rule_count)
{
    return std::max(64u, rule_count * 2u);
}

Result<void> SlotBuilder::add_map(const std::string& name, int outer_fd, uint32_t rule_count, int live_inner_fd)
{
    auto inner = create_shadow_map_from_fd(live_inner_fd, inner_size_for(rule_count));
    if (!inner) {
        return inner.error();
    }
    Entry e;
    e.name = name;
    e.outer_fd = outer_fd;
    e.inner = std::move(*inner);
    entries_.push_back(std::move(e));
    return {};
}

Result<int> SlotBuilder::inner_fd(const std::string& name) const
{
    for (const auto& e : entries_) {
        if (e.name == name) {
            return e.inner.fd();
        }
    }
    return Error(ErrorCode::InvalidArgument, "No staged inner map named " + name);
}

Result<void> SlotBuilder::commit(int active_slot_fd)
{
    uint32_t key = 0;
    uint32_t live = 0;
    if (bpf_map_lookup_elem(active_slot_fd, &key, &live) != 0) {
        return Error::system(errno, "Failed to read active_slot");
    }
    const uint32_t target = live ^ 1u;

    // Populate the inactive slot. These writes are individually non-atomic but
    // no hook observes them, because active_slot still names the other slot.
    for (const auto& e : entries_) {
        uint32_t inner_fd_value = static_cast<uint32_t>(e.inner.fd());
        if (bpf_map_update_elem(e.outer_fd, &target, &inner_fd_value, BPF_ANY) != 0) {
            // Fail-safe: no flip. The live policy is untouched.
            return Error::system(errno, "Failed to stage inner map " + e.name);
        }
    }

    // The single atomic commit: every domain switches generation here.
    if (bpf_map_update_elem(active_slot_fd, &key, &target, BPF_ANY) != 0) {
        return Error::system(errno, "Failed to flip active_slot");
    }

    // Release the previous generation so the kernel can RCU-free it.
    for (const auto& e : entries_) {
        bpf_map_delete_elem(e.outer_fd, &live);
    }
    return {};
}

} // namespace aegis
```

- [ ] **Step 4: Register the new files in CMakeLists.txt**

Add `src/policy_slots.cpp` to the agent target's source list (alongside `src/bpf_maps.cpp`), and add `tests/test_policy_slots.cpp` to the unit-test target's source list (alongside `tests/test_policy.cpp` near `CMakeLists.txt:699`).

- [ ] **Step 5: Run tests to verify they pass**

Run: `cmake --build build -j && ctest --test-dir build -R policy_slots --output-on-failure`
Expected: all three tests PASS.

- [ ] **Step 6: Commit**

```bash
git add src/policy_slots.hpp src/policy_slots.cpp tests/test_policy_slots.cpp CMakeLists.txt
git commit -m "feat(policy): add slot builder with atomic commit and fail-safe abort"
```

---

### Task 6: Wire the slot builder into the reload path for `deny_inode`

**Files:**
- Modify: `src/policy_runtime.cpp:293-560` (replace the shadow→live sync for `deny_inode`), `src/bpf_ops.cpp:355` (resolve `deny_inode_outer` and `active_slot` handles), `src/bpf_ops.hpp:64` (add fields)
- Test: `tests/test_policy.cpp`

**Interfaces:**
- Consumes: `SlotBuilder` (Task 5), `deny_inode_outer` / `active_slot` (Tasks 3-4).
- Produces: `BpfState::deny_inode_outer` and `BpfState::active_slot_map` (`bpf_map*`), populated at load time.

- [ ] **Step 1: Write the failing test**

Add to `tests/test_policy.cpp`:

```cpp
TEST_CASE("a failed policy apply leaves the previous generation live")
{
    // Fail-safe contract: if staging fails, active_slot must not move.
    // Regression guard for the removed direct-apply fallback.
    SlotBuilder builder;
    int slot_fd = make_active_slot_for_test();
    REQUIRE(slot_fd >= 0);

    REQUIRE(builder.add_map("broken", -1, 4, make_hash_map_for_test(64)));
    REQUIRE_FALSE(builder.commit(slot_fd));

    uint32_t zero = 0;
    uint32_t live = 123;
    REQUIRE(bpf_map_lookup_elem(slot_fd, &zero, &live) == 0);
    REQUIRE(live == 0);
}
```

Add the two helpers at the top of that file if absent, mirroring the ones in `tests/test_policy_slots.cpp`.

- [ ] **Step 2: Run test to verify it fails**

Run: `cmake --build build -j && ctest --test-dir build -R test_policy --output-on-failure`
Expected: FAIL to compile until `policy_slots.hpp` is included in `tests/test_policy.cpp`.

- [ ] **Step 3: Add the state handles**

In `src/bpf_ops.hpp`, next to `policy_generation_map` (line 64), add:

```cpp
    bpf_map* deny_inode_outer = nullptr;
    bpf_map* active_slot_map = nullptr;
```

In `src/bpf_ops.cpp`, alongside the existing `policy_generation` resolution at line 355, add:

```cpp
        state.deny_inode_outer = bpf_object__find_map_by_name(state.obj, "deny_inode_outer");
        state.active_slot_map = bpf_object__find_map_by_name(state.obj, "active_slot");
```

- [ ] **Step 4: Replace the deny_inode sync with a slot commit**

In `src/policy_runtime.cpp`, inside the shadow branch, remove the
`sync_from_shadow(state.deny_inode, ...)` call and instead stage the inner map
through a `SlotBuilder` created before population, then call `commit()` after
verification. The builder's `inner_fd("deny_inode")` replaces
`shadows.deny_inode.fd()` as the population target.

Delete the `bump_policy_generation(state)` call that precedes the sync
(`policy_runtime.cpp:518`) — there is no longer a window to guard.

- [ ] **Step 5: Run the full test suite**

Run: `cmake --build build -j && ctest --test-dir build --output-on-failure`
Expected: PASS. Investigate any policy test that assumed an audit window.

- [ ] **Step 6: Commit**

```bash
git add src/policy_runtime.cpp src/bpf_ops.cpp src/bpf_ops.hpp tests/test_policy.cpp
git commit -m "feat(policy): commit deny_inode through the atomic slot flip"
```

---

### Task 7: The decisive test — deny never leaks during reload

This is the regression proof for the entire effort. It must fail against the
pre-change code and pass after.

**Files:**
- Create: `tests/enforcement/reload_under_load.sh`
- Modify: `CMakeLists.txt` (register under the kernel-matrix test group near `:773`)

**Interfaces:**
- Consumes: a built agent binary and a policy denying a known path.
- Produces: exit 0 when zero denied operations were allowed; exit 1 otherwise.

- [ ] **Step 1: Write the failing test**

Create `tests/enforcement/reload_under_load.sh`:

```bash
#!/usr/bin/env bash
# Proves a policy reload never drops enforcement.
#
# Hammers a denied open() from several workers while the policy is reloaded in
# a loop. Any successful open is a leak: before the atomic-swap change this
# reproduces the audit-only window at bpf/aegis_common.h:1063.
set -euo pipefail

AGENT="${1:?path to aegis agent binary}"
POLICY="${2:?path to policy file}"
TARGET="/tmp/aegis_reload_target"
WORKERS=8
DURATION=20

echo "test content" > "$TARGET"

"$AGENT" daemon --policy "$POLICY" &
AGENT_PID=$!
trap 'kill $AGENT_PID 2>/dev/null || true; rm -f "$TARGET"' EXIT
sleep 2

leaks_file="$(mktemp)"
echo 0 > "$leaks_file"

for _ in $(seq "$WORKERS"); do
    (
        end=$((SECONDS + DURATION))
        leaks=0
        while [ "$SECONDS" -lt "$end" ]; do
            if cat "$TARGET" >/dev/null 2>&1; then
                leaks=$((leaks + 1))
            fi
        done
        # Accumulate atomically enough for a pass/fail signal.
        flock "$leaks_file" -c "echo \$(( \$(cat $leaks_file) + $leaks )) > $leaks_file"
    ) &
done

# Reload continuously for the duration of the load.
(
    end=$((SECONDS + DURATION))
    while [ "$SECONDS" -lt "$end" ]; do
        "$AGENT" policy reload --policy "$POLICY" >/dev/null 2>&1 || true
    done
) &

wait
leaks="$(cat "$leaks_file")"
rm -f "$leaks_file"

echo "leaked allows during reload: $leaks"
if [ "$leaks" -ne 0 ]; then
    echo "FAIL: enforcement dropped during policy reload"
    exit 1
fi
echo "PASS: enforcement held across every reload"
```

Make it executable: `chmod +x tests/enforcement/reload_under_load.sh`

- [ ] **Step 2: Run it against the PRE-change code to confirm it catches the bug**

```bash
git stash
cmake --build build -j
sudo ./tests/enforcement/reload_under_load.sh ./build/aegisbpfd ./rules/example.policy
git stash pop
```

Expected: FAIL with a non-zero leak count. If it reports zero leaks, the test
is not exercising the window — increase `WORKERS` or `DURATION` until it
reproduces, because a test that cannot fail proves nothing.

- [ ] **Step 3: Run it against the post-change code**

```bash
cmake --build build -j
sudo ./tests/enforcement/reload_under_load.sh ./build/aegisbpfd ./rules/example.policy
```

Expected: PASS, zero leaks.

- [ ] **Step 4: Register it in the kernel-matrix test group**

In `CMakeLists.txt`, alongside the existing kernel-matrix tests near line 773:

```cmake
    add_test(
        NAME enforcement_reload_under_load
        COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/tests/enforcement/reload_under_load.sh
                $<TARGET_FILE:aegisbpfd> ${CMAKE_CURRENT_SOURCE_DIR}/rules/example.policy)
    set_tests_properties(enforcement_reload_under_load PROPERTIES LABELS "kernel")
```

- [ ] **Step 5: Commit**

```bash
git add tests/enforcement/reload_under_load.sh CMakeLists.txt
git commit -m "test(enforcement): prove reloads never drop enforcement"
```

---

### Task 8: Convert the remaining file/exec policy maps

**Files:**
- Modify: `bpf/aegis_common.h`, `bpf/aegis_file.bpf.h`, `bpf/aegis_exec.bpf.h`, `bpf/aegis_ima.bpf.h`, `src/policy_runtime.cpp`, `src/bpf_ops.cpp`, `src/bpf_ops.hpp`
- Test: `tests/test_bpf_integrity.cpp`

**Maps:** `deny_path_map`, `deny_comm_map`, `allow_cgroup_map`, `allow_exec_inode_map`, `trusted_exec_hash`.

Note `trusted_exec_hash` currently bypasses the shadow path entirely and is
written directly to the live map; bringing it into the slot mechanism is
required by the cross-domain atomicity goal.

**Interfaces:**
- Consumes: everything from Tasks 3-6.
- Produces: outer maps `deny_path_outer`, `deny_comm_outer`, `allow_cgroup_outer`, `allow_exec_inode_outer`, `trusted_exec_hash_outer`, plus matching `BpfState` fields.

- [ ] **Step 1: Write the failing test**

Add to `tests/test_bpf_integrity.cpp`:

```cpp
TEST_CASE("all file and exec policy maps are slotted")
{
    const std::string src = read_file("bpf/aegis_common.h");
    for (const char* name : {"deny_path_outer", "deny_comm_outer", "allow_cgroup_outer",
                             "allow_exec_inode_outer", "trusted_exec_hash_outer"}) {
        INFO("missing outer map: " << name);
        REQUIRE(src.find(std::string("} ") + name + " SEC(\".maps\");") != std::string::npos);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cmake --build build -j && ctest --test-dir build -R bpf_integrity --output-on-failure`
Expected: FAIL on the first missing outer map.

- [ ] **Step 3: Convert each map**

For each of the five maps, apply the exact pattern established in Task 4:
declare `struct <name>_inner { ... }` with the original attributes, replace the
map with an `ARRAY_OF_MAPS` named `<name>_outer` holding `__array(values, struct <name>_inner)` and `max_entries = 2`, then update every hook read site to resolve through `policy_inner(&<name>_outer, slot)` with a NULL check.

Each hook function reads `const __u32 slot = policy_active_slot();` once at the
top and passes `slot` to any helper that touches a policy map. Where a helper
such as `cgroup_inode_denied()` accesses a policy map, add a `__u32 slot`
parameter rather than letting it call `policy_active_slot()` itself.

- [ ] **Step 4: Stage each map in the reload path**

In `src/policy_runtime.cpp`, add a `builder.add_map(...)` call for each and
replace its `sync_from_shadow` call with population via `builder.inner_fd(...)`.
Resolve each `<name>_outer` handle in `src/bpf_ops.cpp` and add the matching
`bpf_map*` field to `src/bpf_ops.hpp`.

- [ ] **Step 5: Run the full suite plus the enforcement proof**

```bash
cmake --build build -j && ctest --test-dir build --output-on-failure
sudo ./tests/enforcement/reload_under_load.sh ./build/aegisbpfd ./rules/example.policy
```
Expected: all PASS, zero leaks.

- [ ] **Step 6: Commit**

```bash
git add bpf/ src/ tests/
git commit -m "feat(bpf): slot the remaining file and exec policy maps"
```

---

### Task 9: Convert the network and cgroup policy maps

**Files:**
- Modify: `bpf/aegis_common.h`, `bpf/aegis_net.bpf.h`, `src/policy_runtime.cpp`, `src/bpf_ops.cpp`, `src/bpf_ops.hpp`
- Test: `tests/test_bpf_integrity.cpp`, `tests/test_network.cpp`

**Maps:** `deny_ipv4`, `deny_ipv6`, `deny_port`, `deny_ip_port_v4`, `deny_ip_port_v6`, `deny_cidr_v4`, `deny_cidr_v6`, `deny_cgroup_inode`, `deny_cgroup_ipv4`, `deny_cgroup_port`.

`deny_cidr_v4` and `deny_cidr_v6` are `BPF_MAP_TYPE_LPM_TRIE`. Verified on
kernel 7.0 that LPM_TRIE works as an inner map; confirm on the 5.14/5.15 matrix
in Task 12.

**Interfaces:**
- Consumes: Tasks 3-6.
- Produces: the ten matching `<name>_outer` maps and `BpfState` fields.

- [ ] **Step 1: Write the failing test**

Add to `tests/test_bpf_integrity.cpp`:

```cpp
TEST_CASE("all network and cgroup policy maps are slotted")
{
    const std::string src = read_file("bpf/aegis_common.h");
    for (const char* name : {"deny_ipv4_outer", "deny_ipv6_outer", "deny_port_outer",
                             "deny_ip_port_v4_outer", "deny_ip_port_v6_outer",
                             "deny_cidr_v4_outer", "deny_cidr_v6_outer",
                             "deny_cgroup_inode_outer", "deny_cgroup_ipv4_outer",
                             "deny_cgroup_port_outer"}) {
        INFO("missing outer map: " << name);
        REQUIRE(src.find(std::string("} ") + name + " SEC(\".maps\");") != std::string::npos);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `ctest --test-dir build -R bpf_integrity --output-on-failure`
Expected: FAIL.

- [ ] **Step 3: Convert each map using the Task 4 pattern**

`aegis_net.bpf.h` has the densest read sites (`deny_ipv4` and `deny_cidr_v4`
each appear five times). Read the slot once per hook function and thread it
through; do not add a `policy_active_slot()` call per lookup.

- [ ] **Step 4: Stage each in the reload path and resolve handles**

As in Task 8.

- [ ] **Step 5: Run the full suite plus the enforcement proof**

```bash
cmake --build build -j && ctest --test-dir build --output-on-failure
sudo ./tests/enforcement/reload_under_load.sh ./build/aegisbpfd ./rules/example.policy
```
Expected: all PASS.

- [ ] **Step 6: Commit**

```bash
git add bpf/ src/ tests/
git commit -m "feat(bpf): slot the network and cgroup policy maps"
```

---

### Task 10: Cross-domain atomicity test

**Files:**
- Create: `tests/enforcement/cross_domain_atomicity.sh`
- Modify: `CMakeLists.txt`

**Interfaces:**
- Consumes: a fully slotted build (Tasks 8-9).
- Produces: exit 0 when file and network rules are never observed from different generations.

- [ ] **Step 1: Write the test**

Create `tests/enforcement/cross_domain_atomicity.sh`:

```bash
#!/usr/bin/env bash
# Proves file and network rules switch generations together.
#
# Generation A denies path X and port P. Generation B denies neither.
# An observer that ever sees "X denied but P allowed" (or the reverse) has
# caught a torn flip, which means the single-slot-read invariant is broken.
set -euo pipefail

AGENT="${1:?path to aegis agent binary}"
POLICY_A="${2:?policy A}"
POLICY_B="${3:?policy B}"
DURATION=20

"$AGENT" daemon --policy "$POLICY_A" &
AGENT_PID=$!
trap 'kill $AGENT_PID 2>/dev/null || true' EXIT
sleep 2

( end=$((SECONDS + DURATION))
  while [ "$SECONDS" -lt "$end" ]; do
      "$AGENT" policy reload --policy "$POLICY_A" >/dev/null 2>&1 || true
      "$AGENT" policy reload --policy "$POLICY_B" >/dev/null 2>&1 || true
  done ) &

torn=0
end=$((SECONDS + DURATION))
while [ "$SECONDS" -lt "$end" ]; do
    cat /tmp/aegis_cross_target >/dev/null 2>&1 && file_allowed=1 || file_allowed=0
    (exec 3<>/dev/tcp/127.0.0.1/9999) 2>/dev/null && net_allowed=1 || net_allowed=0
    if [ "$file_allowed" -ne "$net_allowed" ]; then
        torn=$((torn + 1))
    fi
done
wait

echo "torn observations: $torn"
[ "$torn" -eq 0 ] || { echo "FAIL: file and network rules straddled a flip"; exit 1; }
echo "PASS: domains always switched together"
```

Make executable: `chmod +x tests/enforcement/cross_domain_atomicity.sh`

Create the two policies it needs under `rules/`: one denying both the path and
the port, one denying neither.

- [ ] **Step 2: Run it**

```bash
sudo ./tests/enforcement/cross_domain_atomicity.sh ./build/aegisbpfd \
     rules/cross_domain_a.policy rules/cross_domain_b.policy
```
Expected: PASS, zero torn observations. A non-zero count means some hook
re-reads the slot mid-invocation — find it and thread `slot` through instead.

- [ ] **Step 3: Register and commit**

```cmake
    add_test(
        NAME enforcement_cross_domain_atomicity
        COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/tests/enforcement/cross_domain_atomicity.sh
                $<TARGET_FILE:aegisbpfd>
                ${CMAKE_CURRENT_SOURCE_DIR}/rules/cross_domain_a.policy
                ${CMAKE_CURRENT_SOURCE_DIR}/rules/cross_domain_b.policy)
    set_tests_properties(enforcement_cross_domain_atomicity PROPERTIES LABELS "kernel")
```

```bash
git add tests/enforcement/cross_domain_atomicity.sh rules/cross_domain_*.policy CMakeLists.txt
git commit -m "test(enforcement): prove policy domains switch generations together"
```

---

### Task 11: Remove the audit window and the direct-apply fallback

Only now, with every map slotted and the proofs in place, delete the old
machinery.

**Files:**
- Modify: `bpf/aegis_common.h:1023-1037`, `:1063-1066`, `src/policy_runtime.cpp:293-306`, `:558+`, `src/bpf_config.cpp:301`
- Test: `tests/test_bpf_integrity.cpp`, `tests/test_policy.cpp`

**Interfaces:**
- Consumes: Tasks 8-10.
- Produces: `get_effective_audit_mode()` with no generation branch; a single apply path.

- [ ] **Step 1: Write the failing test**

Add to `tests/test_bpf_integrity.cpp`:

```cpp
TEST_CASE("no policy-generation audit fallback remains")
{
    // The reload audit window is gone; enforcing must never depend on a
    // generation match. Regression guard against reintroducing the hole.
    const std::string src = read_file("bpf/aegis_common.h");
    REQUIRE(src.find("is_policy_consistent") == std::string::npos);
}

TEST_CASE("no bulk direct-apply fallback remains")
{
    const std::string src = read_file("src/policy_runtime.cpp");
    REQUIRE(src.find("falling back to direct apply") == std::string::npos);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `ctest --test-dir build -R bpf_integrity --output-on-failure`
Expected: FAIL — both strings still present.

- [ ] **Step 3: Delete the BPF-side audit fallback**

In `bpf/aegis_common.h`, delete the whole `is_policy_consistent()` function
(lines 1023-1037) and this branch in `get_effective_audit_mode()`:

```c
    /* Policy generation mismatch: maps are mid-update -- force audit to
     * avoid enforcing a partially-synced ruleset. */
    if (!is_policy_consistent())
        return 1;
```

Leave every other audit trigger (emergency disable, break-glass, explicit audit
mode, deadman) exactly as-is.

- [ ] **Step 4: Delete the direct-apply fallback**

In `src/policy_runtime.cpp`, remove the `use_shadow` flag and the entire `else`
branch that mutates live maps in place. A failure to build the new generation
now returns an error directly:

```cpp
    auto builder_result = build_policy_slot(state, policy, entries);
    if (!builder_result) {
        // Fail-safe: the previous generation stays live and enforcing.
        return fail(builder_result.error());
    }
```

Also delete the stale comment block at `policy_runtime.cpp:285-290` describing
the generation guard.

- [ ] **Step 5: Demote `bump_policy_generation` to observability**

In `src/bpf_config.cpp:301`, keep the function but move its call site to
*after* a successful flip, and update the doc comment in `src/bpf_config.hpp:33`
to state that it advances a reporting counter and does not gate enforcement.

- [ ] **Step 6: Run everything**

```bash
cmake --build build -j && ctest --test-dir build --output-on-failure
sudo ./tests/enforcement/reload_under_load.sh ./build/aegisbpfd ./rules/example.policy
```
Expected: all PASS.

- [ ] **Step 7: Commit**

```bash
git add bpf/aegis_common.h src/policy_runtime.cpp src/bpf_config.cpp src/bpf_config.hpp tests/
git commit -m "refactor(policy): remove reload audit window and direct-apply fallback"
```

---

### Task 12: Verifier budget, kernel matrix, and memory verification

**Files:**
- Modify: `docs/superpowers/specs/2026-09-13-atomic-policy-swap-design.md` (record measured results)
- Test: existing veristat and kernel-matrix CI jobs

**Interfaces:**
- Consumes: the complete change (Tasks 1-11).
- Produces: recorded verifier-instruction deltas, matrix results, and a memory comparison.

- [ ] **Step 1: Measure the verifier budget**

```bash
cmake --build build --target aegis_bpf
veristat -o csv build/aegis.bpf.o > /tmp/after.csv
git stash && cmake --build build --target aegis_bpf
veristat -o csv build/aegis.bpf.o > /tmp/before.csv
git stash pop
veristat -C /tmp/before.csv /tmp/after.csv
```
Expected: every program still verifies. Record the instruction delta; a large
increase on a hot hook means the slot read is being repeated — fix it rather
than accept it.

- [ ] **Step 2: Confirm LPM_TRIE inner maps at the kernel floor**

Run the kernel-matrix CI job (5.14, 5.15, 6.1, 6.5, 6.6, 6.8) and confirm the
BPF object loads and `enforcement_reload_under_load` passes on each. 5.14/5.15
are the ones that matter: they are the oldest kernels in the matrix and the
closest to the 5.11 `max_entries` boundary.

- [ ] **Step 3: Verify the memory claim**

With a small policy loaded (roughly ten rules), compare locked memory before
and after:

```bash
sudo bpftool map show | grep -E 'deny_|allow_' | awk '{s+=$NF} END {print s}'
```
Expected: steady-state total is **below** the pre-change baseline, because
inner maps are right-sized rather than preallocated at `max_entries`.

- [ ] **Step 4: Record results in the spec**

Append a "Measured results" section to the design doc with the verifier deltas,
the matrix pass list, and the before/after memory numbers.

- [ ] **Step 5: Commit**

```bash
git add docs/superpowers/specs/2026-09-13-atomic-policy-swap-design.md
git commit -m "docs(spec): record measured verifier, matrix, and memory results"
```

---

## Self-Review

**Spec coverage.** Map layout → Tasks 3, 4, 8, 9. Memory/right-sizing → Tasks 1, 2, 12. Hot path and the single-slot-read invariant → Tasks 4, 8, 9, 10. Commit protocol → Task 5. Removals → Task 11. Direct-apply removal → Task 11. Pinning/restart → *gap found, see below*. Compatibility/5.11 fallback → Tasks 1, 2, 12. Testing → Tasks 7, 10, 12. Risks → each has a task.

**Gap found and closed:** the spec's "Pinning and restart" section had no task. Add:

### Task 13: Pin outer maps and verify policy survives restart

**Files:**
- Modify: `src/types.hpp:30` (add pin paths), `src/bpf_ops.cpp:543-549`, `:763`
- Test: `tests/test_bpf_link_pin.cpp`

**Interfaces:**
- Consumes: Tasks 8-9.
- Produces: pin paths `kActiveSlotPin` and `k<Name>OuterPin`, following `kPolicyGenerationPin`.

- [ ] **Step 1: Write the failing test**

```cpp
TEST_CASE("outer policy maps and active_slot are pinned")
{
    // Policy must survive an agent restart: the pinned outer maps keep the
    // inner maps alive via refcount, so enforcement continues uninterrupted.
    REQUIRE(std::string(aegis::kActiveSlotPin) == "/sys/fs/bpf/aegisbpf/active_slot");
    REQUIRE(std::string(aegis::kDenyInodeOuterPin) == "/sys/fs/bpf/aegisbpf/deny_inode_outer");
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `ctest --test-dir build -R link_pin --output-on-failure`
Expected: FAIL — constants undefined.

- [ ] **Step 3: Add the pin constants and wire them**

In `src/types.hpp` next to `kPolicyGenerationPin` (line 30), add
`kActiveSlotPin` and one `k<Name>OuterPin` per converted map. In
`src/bpf_ops.cpp`, add each to the `try_reuse_optional` block at 543-549 and
the `try_pin` block at 763, following the `policy_generation` pattern exactly.

- [ ] **Step 4: Verify restart behaviour manually**

```bash
sudo ./build/aegisbpfd daemon --policy rules/example.policy &
sleep 3 && sudo pkill -f aegisbpfd && sleep 1
cat /tmp/aegis_reload_target    # must still be denied
```
Expected: the denied path stays denied while no agent is running, because the
pinned outer maps still reference populated inner maps.

- [ ] **Step 5: Commit**

```bash
git add src/types.hpp src/bpf_ops.cpp tests/test_bpf_link_pin.cpp
git commit -m "feat(bpf): pin outer policy maps so policy survives restart"
```

**Placeholder scan.** No TBD/TODO; every code step carries real code. Task 8 and
Task 9 describe a repeated mechanical pattern rather than repeating sixteen
near-identical blocks — the pattern is written out in full in Task 4, which
those tasks reference by name.

**Type consistency.** `SlotBuilder::add_map` / `inner_fd` / `commit` and
`inner_size_for` are used with identical signatures in Tasks 5, 6, 8, 9, 11.
`create_shadow_map_from_fd` is defined in Task 2 and used in Task 5.
`policy_active_slot` / `policy_inner` are defined in Task 3 and used in Tasks 4,
8, 9. Map naming is uniformly `<name>_outer` / `struct <name>_inner`.
