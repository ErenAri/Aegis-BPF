// cppcheck-suppress-file missingIncludeSystem
#include "json_scan.hpp"

#include <cctype>
#include <limits>

namespace aegis::json_scan {

namespace {

void skip_ws(const std::string& json, size_t& pos)
{
    while (pos < json.size() && std::isspace(static_cast<unsigned char>(json[pos]))) {
        ++pos;
    }
}

bool parse_hex_digit(char c, unsigned int& value)
{
    if (c >= '0' && c <= '9') {
        value = static_cast<unsigned int>(c - '0');
        return true;
    }
    if (c >= 'a' && c <= 'f') {
        value = static_cast<unsigned int>(10 + (c - 'a'));
        return true;
    }
    if (c >= 'A' && c <= 'F') {
        value = static_cast<unsigned int>(10 + (c - 'A'));
        return true;
    }
    return false;
}

bool parse_string_at(const std::string& json, size_t pos, std::string& out)
{
    if (pos >= json.size() || json[pos] != '"') {
        return false;
    }
    ++pos;

    std::string result;
    while (pos < json.size()) {
        char c = json[pos++];
        if (c == '"') {
            out = result;
            return true;
        }
        if (c != '\\') {
            result.push_back(c);
            continue;
        }
        if (pos >= json.size()) {
            return false;
        }
        char esc = json[pos++];
        switch (esc) {
            case '"':
            case '\\':
            case '/':
                result.push_back(esc);
                break;
            case 'n':
                result.push_back('\n');
                break;
            case 'r':
                result.push_back('\r');
                break;
            case 't':
                result.push_back('\t');
                break;
            case 'b':
                result.push_back('\b');
                break;
            case 'f':
                result.push_back('\f');
                break;
            case 'u': {
                if (pos + 4 > json.size()) {
                    return false;
                }
                unsigned int code = 0;
                for (int i = 0; i < 4; ++i) {
                    unsigned int digit = 0;
                    if (!parse_hex_digit(json[pos++], digit)) {
                        return false;
                    }
                    code = (code << 4) | digit;
                }
                result.push_back((code <= 0x7f) ? static_cast<char>(code) : '?');
                break;
            }
            default:
                result.push_back(esc);
                break;
        }
    }
    return false;
}

bool parse_uint64_at(const std::string& json, size_t pos, uint64_t& out)
{
    if (pos >= json.size() || !std::isdigit(static_cast<unsigned char>(json[pos]))) {
        return false;
    }
    uint64_t value = 0;
    while (pos < json.size() && std::isdigit(static_cast<unsigned char>(json[pos]))) {
        const uint64_t digit = static_cast<uint64_t>(json[pos++] - '0');
        if (value > (std::numeric_limits<uint64_t>::max() - digit) / 10) {
            return false;
        }
        value = value * 10 + digit;
    }
    out = value;
    return true;
}

bool parse_int64_at(const std::string& json, size_t pos, int64_t& out)
{
    bool negative = false;
    if (pos < json.size() && json[pos] == '-') {
        negative = true;
        ++pos;
    }
    if (pos >= json.size() || !std::isdigit(static_cast<unsigned char>(json[pos]))) {
        return false;
    }

    constexpr uint64_t kPositiveLimit = static_cast<uint64_t>(std::numeric_limits<int64_t>::max());
    constexpr uint64_t kNegativeLimit = kPositiveLimit + 1;
    const uint64_t limit = negative ? kNegativeLimit : kPositiveLimit;

    uint64_t value = 0;
    while (pos < json.size() && std::isdigit(static_cast<unsigned char>(json[pos]))) {
        const uint64_t digit = static_cast<uint64_t>(json[pos++] - '0');
        if (value > (limit - digit) / 10) {
            return false;
        }
        value = value * 10 + digit;
    }

    if (!negative) {
        out = static_cast<int64_t>(value);
        return true;
    }
    if (value == kNegativeLimit) {
        out = std::numeric_limits<int64_t>::min();
        return true;
    }
    out = -static_cast<int64_t>(value);
    return true;
}

} // namespace

bool find_value_start(const std::string& json, const std::string& key, size_t& pos)
{
    const std::string needle = "\"" + key + "\"";
    const size_t key_pos = json.find(needle);
    if (key_pos == std::string::npos) {
        return false;
    }
    const size_t colon = json.find(':', key_pos + needle.size());
    if (colon == std::string::npos) {
        return false;
    }
    pos = colon + 1;
    skip_ws(json, pos);
    return pos < json.size();
}

bool extract_string(const std::string& json, const std::string& key, std::string& out)
{
    size_t pos = 0;
    if (!find_value_start(json, key, pos)) {
        return false;
    }
    return parse_string_at(json, pos, out);
}

bool extract_uint64(const std::string& json, const std::string& key, uint64_t& out)
{
    size_t pos = 0;
    if (!find_value_start(json, key, pos)) {
        return false;
    }
    return parse_uint64_at(json, pos, out);
}

bool extract_int64(const std::string& json, const std::string& key, int64_t& out)
{
    size_t pos = 0;
    if (!find_value_start(json, key, pos)) {
        return false;
    }
    return parse_int64_at(json, pos, out);
}

bool extract_bool(const std::string& json, const std::string& key, bool& out)
{
    size_t pos = 0;
    if (!find_value_start(json, key, pos)) {
        return false;
    }
    if (json.compare(pos, 4, "true") == 0) {
        out = true;
        return true;
    }
    if (json.compare(pos, 5, "false") == 0) {
        out = false;
        return true;
    }
    return false;
}

bool extract_int64_array(const std::string& json, const std::string& key, std::vector<int64_t>& out)
{
    size_t pos = 0;
    if (!find_value_start(json, key, pos)) {
        return false;
    }
    if (pos >= json.size() || json[pos] != '[') {
        return false;
    }
    ++pos;

    std::vector<int64_t> values;
    while (pos < json.size()) {
        skip_ws(json, pos);
        if (pos < json.size() && json[pos] == ']') {
            out = values;
            return true;
        }

        int64_t value = 0;
        if (!parse_int64_at(json, pos, value)) {
            return false;
        }

        bool negative = (json[pos] == '-');
        if (negative) {
            ++pos;
        }
        while (pos < json.size() && std::isdigit(static_cast<unsigned char>(json[pos]))) {
            ++pos;
        }

        values.push_back(value);
        skip_ws(json, pos);
        if (pos < json.size() && json[pos] == ',') {
            ++pos;
            continue;
        }
        if (pos < json.size() && json[pos] == ']') {
            out = values;
            return true;
        }
    }
    return false;
}

} // namespace aegis::json_scan
