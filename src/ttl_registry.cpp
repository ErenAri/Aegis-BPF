// cppcheck-suppress-file missingIncludeSystem
#include "ttl_registry.hpp"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <sstream>

namespace aegis {

std::optional<uint32_t> parse_ttl_suffix(std::string& arg)
{
    // Only the final whitespace-delimited token may be a ttl marker; a path can
    // legitimately contain spaces, so we never scan earlier tokens.
    const size_t sp = arg.find_last_of(" \t");
    if (sp == std::string::npos) {
        return std::nullopt;
    }
    const std::string token = arg.substr(sp + 1);
    const std::string prefix = "ttl=";
    if (token.size() <= prefix.size() || token.compare(0, prefix.size(), prefix) != 0) {
        return std::nullopt;
    }
    const std::string digits = token.substr(prefix.size());
    for (char c : digits) {
        if (std::isdigit(static_cast<unsigned char>(c)) == 0) {
            return std::nullopt;
        }
    }
    unsigned long long value = 0;
    try {
        value = std::stoull(digits);
    } catch (...) {
        return std::nullopt;
    }
    if (value == 0 || value > 0xFFFFFFFFULL) {
        return std::nullopt;
    }
    // Strip the token and any whitespace that preceded it.
    size_t end = sp;
    while (end > 0 && (arg[end - 1] == ' ' || arg[end - 1] == '\t')) {
        --end;
    }
    arg.erase(end);
    return static_cast<uint32_t>(value);
}

std::vector<TtlEntry> read_ttl_db(const std::string& path)
{
    std::vector<TtlEntry> entries;
    std::ifstream in(path);
    if (!in.is_open()) {
        return entries;
    }
    std::string line;
    while (std::getline(in, line)) {
        std::istringstream iss(line);
        uint64_t expiry = 0;
        std::string verb;
        if (!(iss >> expiry >> verb)) {
            continue;
        }
        // The remainder of the line is the arg, which may contain spaces.
        std::string arg;
        std::getline(iss, arg);
        size_t start = arg.find_first_not_of(" \t");
        if (start != std::string::npos) {
            arg = arg.substr(start);
        } else {
            arg.clear();
        }
        if (verb.empty() || arg.empty()) {
            continue;
        }
        entries.push_back(TtlEntry{expiry, verb, arg});
    }
    return entries;
}

bool write_ttl_db(const std::vector<TtlEntry>& entries, const std::string& path)
{
    std::error_code ec;
    std::filesystem::path p(path);
    if (p.has_parent_path()) {
        std::filesystem::create_directories(p.parent_path(), ec);
    }
    const std::string tmp = path + ".tmp";
    {
        std::ofstream out(tmp, std::ios::trunc);
        if (!out.is_open()) {
            return false;
        }
        for (const auto& e : entries) {
            out << e.expiry_epoch << " " << e.verb << " " << e.arg << "\n";
        }
        out.flush();
        if (!out.good()) {
            out.close();
            std::remove(tmp.c_str());
            return false;
        }
    }
    if (std::rename(tmp.c_str(), path.c_str()) != 0) {
        std::remove(tmp.c_str());
        return false;
    }
    return true;
}

void upsert_ttl_entry(std::vector<TtlEntry>& entries, uint64_t expiry, const std::string& verb, const std::string& arg)
{
    for (auto& e : entries) {
        if (e.verb == verb && e.arg == arg) {
            e.expiry_epoch = expiry;
            return;
        }
    }
    entries.push_back(TtlEntry{expiry, verb, arg});
}

void remove_ttl_entry(std::vector<TtlEntry>& entries, const std::string& verb, const std::string& arg)
{
    entries.erase(std::remove_if(entries.begin(), entries.end(),
                                 [&](const TtlEntry& e) { return e.verb == verb && e.arg == arg; }),
                  entries.end());
}

void remove_ttl_entries_by_verb(std::vector<TtlEntry>& entries, const std::string& verb)
{
    entries.erase(std::remove_if(entries.begin(), entries.end(), [&](const TtlEntry& e) { return e.verb == verb; }),
                  entries.end());
}

TtlPartition partition_expired(const std::vector<TtlEntry>& entries, uint64_t now_epoch)
{
    TtlPartition out;
    for (const auto& e : entries) {
        if (e.expiry_epoch <= now_epoch) {
            out.expired.push_back(e);
        } else {
            out.live.push_back(e);
        }
    }
    return out;
}

size_t reap_expired_ttls(uint64_t now_epoch, const std::function<void(const std::string&, const std::string&)>& del_fn,
                         const std::string& path)
{
    std::vector<TtlEntry> entries = read_ttl_db(path);
    if (entries.empty()) {
        return 0;
    }
    TtlPartition part = partition_expired(entries, now_epoch);
    if (part.expired.empty()) {
        return 0;
    }
    for (const auto& e : part.expired) {
        if (del_fn) {
            del_fn(e.verb, e.arg);
        }
    }
    write_ttl_db(part.live, path);
    return part.expired.size();
}

} // namespace aegis
