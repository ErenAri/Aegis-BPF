// cppcheck-suppress-file missingIncludeSystem
#pragma once

#include <string>

#include "types.hpp"

namespace aegis {

/// Format an AegisBPF block event as an OCSF 1.1.0 File Activity
/// (class_uid 1001) JSON object. Returns the JSON as a single-line
/// string with no trailing newline.
///
/// Mapping summary:
///   class_uid    = 1001 (File Activity)
///   category_uid = 1    (System Activity)
///   activity_id  = 14   (Open) -- AegisBPF blocks file_open / inode_permission
///   action_id    = `audit_only ? 1 (Allowed) : 2 (Denied)`
///   disposition_id = `audit_only ? omitted : 2 (Blocked)`
///   status_id    = 1 (Success -- the policy decision was applied)
///   severity_id  = `audit_only ? 2 (Low) : 4 (High)`
///   actor.process = the blocking subject (pid, ppid, name from comm)
///   file.path / file.name / file.parent_folder = derived from ev.path
///   metadata.product.{name, version} = "AegisBPF" / AEGIS_VERSION_STRING
///
/// Pre-resolved strings are passed in to keep the formatter pure
/// (no syscalls) so it can be unit-tested.
std::string format_block_event_ocsf(const BlockEvent& ev, const std::string& cgpath, const std::string& path,
                                    const std::string& resolved_path, const std::string& action,
                                    const std::string& comm, const std::string& exec_id,
                                    const std::string& parent_exec_id, const std::string& hostname);

/// Format an AegisBPF network block event as an OCSF 1.1.0 Network
/// Activity (class_uid 4001) JSON object.
///
/// Mapping summary:
///   class_uid    = 4001 (Network Activity)
///   category_uid = 4    (Network Activity)
///   activity_id  = derived from `direction`:
///                    egress(0)  -> 1 (Open)
///                    bind(1)    -> 1 (Open)
///                    listen(2)  -> 1 (Open)
///                    accept(3)  -> 1 (Open)
///                    send(4)    -> 6 (Traffic)
///                    recv(5)    -> 6 (Traffic)
///   action_id      = `audit_only ? 1 : 2`
///   disposition_id = `audit_only ? omitted : 2 (Blocked)`
///   status_id      = 1
///   severity_id    = `audit_only ? 2 : 4`
///   src_endpoint / dst_endpoint = depending on direction
///   connection_info.protocol_num = 6 (TCP) or 17 (UDP)
///   actor.process = the calling subject
std::string format_net_block_event_ocsf(const NetBlockEvent& ev, const std::string& cgpath, const std::string& comm,
                                        const std::string& exec_id, const std::string& parent_exec_id,
                                        const std::string& event_type, const std::string& remote_ip,
                                        const std::string& hostname);

/// Returns true if `value` selects the OCSF format and false for
/// the default Aegis format. Returns std::nullopt for unrecognized
/// values via the wrapper below.
bool is_ocsf_format_keyword(const std::string& value);

} // namespace aegis
