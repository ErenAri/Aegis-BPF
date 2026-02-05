// cppcheck-suppress-file missingIncludeSystem
#pragma once

#include <string>

namespace aegis {

// Policy commands
int cmd_policy_lint(const std::string& path);
int cmd_policy_lint_fix(const std::string& path, const std::string& out_path);
int cmd_policy_validate(const std::string& path, bool verbose);
int cmd_policy_apply(const std::string& path, bool reset, const std::string& sha256,
                     const std::string& sha256_file, bool rollback_on_failure);
int cmd_policy_apply_signed(const std::string& bundle_path, bool require_signature);
int cmd_policy_sign(const std::string& policy_path, const std::string& key_path, const std::string& output_path);
int cmd_policy_export(const std::string& path);
int cmd_policy_show();
int cmd_policy_rollback();

}  // namespace aegis
