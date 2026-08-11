// cppcheck-suppress-file missingIncludeSystem
#pragma once

// TTL registry for dynamically-added denies.
//
// A deny installed over the control API (POST /block/add, /network/deny/*) can
// carry an optional TTL. Without expiry, a transient alert — e.g. a Falco
// detection relayed by aegis-responder — would wedge a path or IP permanently
// until an operator manually cleared it. The registry records each timed deny's
// wall-clock expiry; the daemon's reaper removes entries whose deadline has
// passed by invoking the same del command the CLI uses.
//
// The parse/partition/persistence helpers here are deliberately free of any
// kernel or socket dependency so they are fully unit-testable.

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace aegis {

// One timed deny: remove `verb arg` once wall-clock epoch seconds reaches expiry.
struct TtlEntry {
    uint64_t expiry_epoch = 0; // CLOCK_REALTIME seconds after which the deny is reaped
    std::string verb;          // control verb that installed it (e.g. "/block/add")
    std::string arg;           // the target (path / ip / cidr)
};

// Strip a trailing " ttl=<seconds>" token from `arg` in place. Returns the parsed
// seconds if a well-formed positive token was present (and removes it from arg),
// or std::nullopt otherwise (leaving arg untouched). A path may itself contain
// spaces, so only the final whitespace-delimited token is considered.
std::optional<uint32_t> parse_ttl_suffix(std::string& arg);

// Read/write the on-disk registry. Format is one entry per line:
//   <expiry_epoch> <verb> <arg-with-spaces>
// Missing file reads as empty. Writes are atomic (temp + rename).
std::vector<TtlEntry> read_ttl_db(const std::string& path);
bool write_ttl_db(const std::vector<TtlEntry>& entries, const std::string& path);

// Insert or replace the timed deny for (verb, arg) with a new expiry. Re-adding a
// deny with a fresh TTL extends it rather than duplicating.
void upsert_ttl_entry(std::vector<TtlEntry>& entries, uint64_t expiry, const std::string& verb, const std::string& arg);

// Remove any timed deny matching (verb, arg). Used when a deny is re-added with no
// TTL (it becomes permanent) or when it is explicitly deleted/cleared.
void remove_ttl_entry(std::vector<TtlEntry>& entries, const std::string& verb, const std::string& arg);

// Remove every timed deny whose verb equals `verb` (e.g. on /block/clear).
void remove_ttl_entries_by_verb(std::vector<TtlEntry>& entries, const std::string& verb);

// Split entries into those due for reaping (expiry <= now) and those still live.
struct TtlPartition {
    std::vector<TtlEntry> expired;
    std::vector<TtlEntry> live;
};
TtlPartition partition_expired(const std::vector<TtlEntry>& entries, uint64_t now_epoch);

// Reap pass: read the registry at `path`, remove entries whose deadline has passed
// (invoking `del_fn(verb, arg)` for each), and persist the survivors. Returns the
// number of denies reaped. Pure w.r.t. enforcement: the caller supplies del_fn.
size_t reap_expired_ttls(uint64_t now_epoch, const std::function<void(const std::string&, const std::string&)>& del_fn,
                         const std::string& path);

} // namespace aegis
