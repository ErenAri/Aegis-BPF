// cppcheck-suppress-file missingIncludeSystem
#pragma once

#include <string>

#include "result.hpp"

namespace aegis {

class BpfState;

using ApplyPolicyInternalFn = Result<void> (*)(const std::string& path, const std::string& computed_hash, bool reset,
                                               bool record);

Result<void> policy_apply(const std::string& path, bool reset, const std::string& cli_hash,
                          const std::string& cli_hash_file, bool rollback_on_failure,
                          const std::string& trace_id_override = "");
Result<void> policy_show();
Result<void> policy_rollback();

Result<void> apply_policy_internal(const std::string& path, const std::string& computed_hash, bool reset, bool record);
Result<void> reset_policy_maps(BpfState& state);
Result<void> record_applied_policy(const std::string& path, const std::string& hash);

void set_apply_policy_internal_for_test(ApplyPolicyInternalFn fn);
void reset_apply_policy_internal_for_test();

} // namespace aegis
