// cppcheck-suppress-file missingIncludeSystem
#pragma once

#include <string>

namespace aegis {

int cmd_explain(const std::string& event_path, const std::string& policy_path, bool json_output = false);

} // namespace aegis
