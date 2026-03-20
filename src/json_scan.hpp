// cppcheck-suppress-file missingIncludeSystem
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace aegis::json_scan {

bool find_value_start(const std::string& json, const std::string& key, size_t& pos);
bool extract_string(const std::string& json, const std::string& key, std::string& out);
bool extract_uint64(const std::string& json, const std::string& key, uint64_t& out);
bool extract_int64(const std::string& json, const std::string& key, int64_t& out);
bool extract_bool(const std::string& json, const std::string& key, bool& out);
bool extract_int64_array(const std::string& json, const std::string& key, std::vector<int64_t>& out);

} // namespace aegis::json_scan
