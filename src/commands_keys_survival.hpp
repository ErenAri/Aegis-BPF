// cppcheck-suppress-file missingIncludeSystem
#pragma once

#include <string>

namespace aegis {

// Key management commands
int cmd_keys_list();
int cmd_keys_add(const std::string& key_file);

// Survival commands
int cmd_survival_list();
int cmd_survival_verify();

} // namespace aegis
