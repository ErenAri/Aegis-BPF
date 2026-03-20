// cppcheck-suppress-file missingIncludeSystem
#pragma once

#include <string>

namespace aegis {

struct EmergencyToggleOptions {
    std::string reason;
    std::string reason_pattern; // optional regex (std::regex) applied to raw --reason
    bool json_output = false;
};

int cmd_emergency_disable(const EmergencyToggleOptions& options);
int cmd_emergency_enable(const EmergencyToggleOptions& options);
int cmd_emergency_status(bool json_output = false);

} // namespace aegis
