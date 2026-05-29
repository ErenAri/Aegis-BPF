// cppcheck-suppress-file missingIncludeSystem
#pragma once

#include <string>

#include "types.hpp"

namespace aegis {

/// Format an AegisBPF block event as an ArcSight Common Event Format
/// (CEF) record. Returns a single-line string with no trailing
/// newline, suitable for direct emit to syslog / journald / stdout.
///
/// Header layout (ArcSight CEF Implementation Standard):
///   CEF:0|AegisBPF Project|AegisBPF|<version>|<sigID>|<name>|<sev>|<ext>
///
/// Mapping summary:
///   sigID    = "aegis:file:open"
///   name     = "AegisBPF File Open Denied" or "...Audit Observed"
///   severity = `audit_only ? 4 (Medium) : 8 (High)`
///   act      = action string (BLOCK / AUDIT / TERM / KILL)
///   outcome  = "success" (the policy decision was applied)
///   msg      = human-readable summary
///   fname    = basename(path)
///   filePath = effective path (resolved when available)
///   spid     = ev.pid
///   sproc    = comm
///   dvchost  = hostname
///   rt       = epoch ms (event receipt time)
///   externalId = exec_id (so SIEMs can pivot across AegisBPF events)
///   cs1/cs1Label = cgroup_path / AegisCgroupPath
///   cs2/cs2Label = parent_exec_id / AegisParentExecId
///   cn1/cn1Label = cgid / AegisCgroupId
///   cn2/cn2Label = inode / AegisInode
///   cn3/cn3Label = device / AegisDevice
///
/// Pre-resolved strings are passed in so the formatter is pure
/// (no syscalls) and unit-testable.
std::string format_block_event_cef(const BlockEvent& ev, const std::string& cgpath, const std::string& path,
                                   const std::string& resolved_path, const std::string& action, const std::string& comm,
                                   const std::string& exec_id, const std::string& parent_exec_id,
                                   const std::string& hostname);

/// Format an AegisBPF network block event as an ArcSight CEF record.
///
/// Mapping summary:
///   sigID    = "aegis:net:<direction>"  (connect, bind, listen, accept, send, recv)
///   name     = "AegisBPF Network <Direction> Denied" or "...Audit Observed"
///   severity = `audit_only ? 4 : 8`
///   proto    = tcp / udp / <num>
///   src / spt = local side (direction-dependent)
///   dst / dpt = remote side (direction-dependent)
///   act      = action string
///   outcome  = "success"
///   msg      = human-readable summary
///   spid     = ev.pid
///   sproc    = comm
///   dvchost  = hostname
///   rt       = epoch ms
///   externalId = exec_id
///   cs1/cs1Label = cgroup_path / AegisCgroupPath
///   cs2/cs2Label = parent_exec_id / AegisParentExecId
///   cs3/cs3Label = rule_type / AegisRuleType
///   cs4/cs4Label = event_type / AegisEventType
///   cn1/cn1Label = cgid / AegisCgroupId
///   cn2/cn2Label = direction / AegisDirection
std::string format_net_block_event_cef(const NetBlockEvent& ev, const std::string& cgpath, const std::string& comm,
                                       const std::string& exec_id, const std::string& parent_exec_id,
                                       const std::string& event_type, const std::string& remote_ip,
                                       const std::string& hostname);

/// Returns true if `value` selects the CEF format. Recognises:
/// "cef", "CEF", "cef-1.0".
bool is_cef_format_keyword(const std::string& value);

} // namespace aegis
