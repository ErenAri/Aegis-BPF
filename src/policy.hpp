#pragma once

#include "result.hpp"
#include "types.hpp"

#include <string>

namespace aegis {

struct BpfState;

// Policy parsing
Result<Policy> parse_policy_file(const std::string &path, PolicyIssues &issues);
void report_policy_issues(const PolicyIssues &issues);

// Policy commands
Result<void> policy_lint(const std::string &path);
Result<void> policy_apply(const std::string &path, bool reset, const std::string &cli_hash,
                          const std::string &cli_hash_file, bool rollback_on_failure);
Result<void> policy_export(const std::string &path);
Result<void> policy_show();
Result<void> policy_rollback();

// Internal helpers
Result<void> apply_policy_internal(const std::string &path, const std::string &computed_hash, bool reset, bool record);
Result<void> reset_policy_maps(BpfState &state);
Result<void> record_applied_policy(const std::string &path, const std::string &hash);
Result<void> write_policy_file(const std::string &path, std::vector<std::string> deny_paths,
                               std::vector<std::string> deny_inodes, std::vector<std::string> allow_cgroups);

} // namespace aegis
