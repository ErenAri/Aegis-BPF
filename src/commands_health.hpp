// cppcheck-suppress-file missingIncludeSystem
#pragma once

namespace aegis {

int cmd_health(bool json_output = false, bool require_enforce = false);
int cmd_doctor(bool json_output = false);

} // namespace aegis
