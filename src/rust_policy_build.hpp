// cppcheck-suppress-file missingIncludeSystem
#pragma once

#include <string>

#include "types.hpp" // Policy

namespace aegis {

// Parse `policy_bytes` with the memory-safe Rust parser (via the
// `aegis_policy_build` FFI seam) and reconstruct the full structured `Policy` into
// `out`. Returns true if the policy parsed cleanly and was built; false if it had
// parse errors (nothing built) — mirroring the C++ apply path, which discards a
// policy on error.
//
// This is the **content** seam for the eventual swap: the wiring that would make
// the memory-safe Rust parser authoritative for the applied policy. It is NOT yet
// wired into the apply path — it is exercised only by the in-process equivalence
// test, which proves the reconstructed `Policy` matches the C++-parsed one. A
// no-op returning false unless built with AEGIS_RUST_SHADOW.
bool rust_build_policy(const std::string& policy_bytes, Policy& out);

// Path-based convenience: read `policy_path` and `rust_build_policy` its bytes.
// Used by the apply path's `authoritative` mode. Returns false on read failure or
// a parse error (nothing built). A no-op returning false unless AEGIS_RUST_SHADOW.
bool rust_build_policy_from_path(const std::string& policy_path, Policy& out);

} // namespace aegis
