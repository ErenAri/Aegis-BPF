// cppcheck-suppress-file missingIncludeSystem
#pragma once

#include <string>

namespace aegis {

// Block commands
int cmd_block_add(const std::string& path);
int cmd_block_del(const std::string& path);
int cmd_block_list();
int cmd_block_clear();

// Allow commands
int cmd_allow_add(const std::string& path);
int cmd_allow_del(const std::string& path);
int cmd_allow_list();

} // namespace aegis
