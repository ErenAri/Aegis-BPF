// cppcheck-suppress-file missingIncludeSystem
#pragma once

#include <string>

#include "result.hpp"
#include "types.hpp"

namespace aegis {

Result<Policy> parse_policy_file(const std::string& path, PolicyIssues& issues);
void report_policy_issues(const PolicyIssues& issues);
void detect_policy_conflicts(const Policy& policy, PolicyIssues& issues);
Result<void> policy_lint(const std::string& path);

} // namespace aegis
