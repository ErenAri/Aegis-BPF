// cppcheck-suppress-file missingIncludeSystem
#pragma once

#include <string>
#include <vector>

#include "policy_parse.hpp"
#include "policy_runtime.hpp"

namespace aegis {
Result<void> policy_export(const std::string& path);
Result<void> write_policy_file(const std::string& path, std::vector<std::string> deny_paths,
                               std::vector<std::string> deny_inodes, std::vector<std::string> allow_cgroups);

} // namespace aegis
