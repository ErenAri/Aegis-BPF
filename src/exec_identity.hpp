// cppcheck-suppress-file missingIncludeSystem
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_set>
#include <vector>

#include "result.hpp"
#include "types.hpp"

namespace aegis {

Result<std::vector<std::string>> load_allow_binary_hashes_from_policy(const std::string& policy_path);

class ExecIdentityEnforcer {
  public:
    ExecIdentityEnforcer(std::vector<std::string> allow_hashes, bool audit_only, bool allow_unknown,
                         uint8_t enforce_signal);

    [[nodiscard]] bool enabled() const { return !allow_hashes_.empty(); }
    [[nodiscard]] size_t allowlist_size() const { return allow_hashes_.size(); }

    void on_exec(const ExecEvent& ev) const;

  private:
    std::unordered_set<std::string> allow_hashes_;
    bool audit_only_;
    bool allow_unknown_;
    uint8_t enforce_signal_;
};

} // namespace aegis
