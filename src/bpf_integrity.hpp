// cppcheck-suppress-file missingIncludeSystem
#pragma once

#include <string>

#include "result.hpp"

namespace aegis {

struct BpfIntegrityStatus {
    std::string object_path;
    std::string hash_path;
    bool object_exists = false;
    bool hash_exists = false;
    bool hash_verified = false;
    bool allow_unsigned = false;
    bool require_hash = false;
    std::string reason;
};

std::string resolve_bpf_obj_path();
bool allow_unsigned_bpf_enabled();
bool require_bpf_hash_enabled();
bool require_bpf_sig_enabled();
Result<BpfIntegrityStatus> evaluate_bpf_integrity(bool require_hash, bool allow_unsigned);
Result<void> verify_bpf_integrity(const std::string& obj_path);

} // namespace aegis
