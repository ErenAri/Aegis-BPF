// cppcheck-suppress-file missingIncludeSystem
#pragma once

#include <string>

#include "logging.hpp"

namespace aegis {

int usage(const char* prog);
LogLevel parse_log_level(const std::string& value);
void configure_logging_from_args(int argc, char** argv);

} // namespace aegis
