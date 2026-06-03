//! Memory-safe policy-file parser — a faithful Rust port of `src/policy_parse.cpp`.
//!
//! This is the **oxidation target**: the C++ agent's policy parser walks
//! untrusted operator/CI-supplied bytes. The C++ implementation is already
//! `std::string`-based (bounds-safe), so this port's value is defense-in-depth +
//! a path to a single, fuzzable, unsafe-free parser. It is NOT yet wired into the
//! production load path; that swap is gated on the differential parity harness
//! going green and a human review — see `rust/aegis-parser/README.md`.
//!
//! Fidelity contract: this module reproduces the observable behavior of
//! `parse_policy_file` + `detect_policy_conflicts` — the same per-line errors and
//! warnings (verbatim text incl. line numbers), the same section/flag/version
//! handling, the same de-duplication, and the same post-parse version gating.
//! Field validation the C++ delegates to `network_ops`/`utils` is reproduced here
//! with Rust's standard `Ipv4Addr`/`Ipv6Addr` (which closely track
//! `inet_pton`/`inet_ntop`); residual divergence on adversarial inputs is
//! quantified by the parity harness over the policy corpus.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::net::{Ipv4Addr, Ipv6Addr};

/// Boolean policy flags toggled by a bare `[section]` header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Flag {
    ProtectConnect,
    ProtectRuntimeDeps,
    RequireImaAppraisal,
    ImaFailClosed,
    DenyPtrace,
    DenyModuleLoad,
    DenyBpf,
}

impl Flag {
    pub fn as_str(self) -> &'static str {
        match self {
            Flag::ProtectConnect => "protect_connect",
            Flag::ProtectRuntimeDeps => "protect_runtime_deps",
            Flag::RequireImaAppraisal => "require_ima_appraisal",
            Flag::ImaFailClosed => "ima_fail_closed",
            Flag::DenyPtrace => "deny_ptrace",
            Flag::DenyModuleLoad => "deny_module_load",
            Flag::DenyBpf => "deny_bpf",
        }
    }
}

/// Parsed policy result. Counts/sets mirror what `policy validate` reports and
/// what the de-dup logic produces, so the harness can compare structurally.
#[derive(Debug, Default)]
pub struct Policy {
    pub version: u64,
    pub flags: BTreeSet<Flag>,
    pub deny_paths: Vec<Vec<u8>>,
    pub protect_paths: Vec<Vec<u8>>,
    pub deny_inodes: Vec<String>, // canonical "dev:ino"
    pub allow_cgroup_ids: Vec<u64>,
    pub allow_cgroup_paths: Vec<Vec<u8>>,
    pub deny_ips: Vec<Vec<u8>>,
    pub deny_cidrs: Vec<Vec<u8>>,
    pub deny_ports: Vec<(u16, u8, u8)>, // parsed (port, proto, dir); dedup by raw text
    pub deny_ip_ports: Vec<String>,     // dedup by canonical key
    pub deny_binary_hashes: Vec<String>, // lowercased hex
    pub allow_binary_hashes: Vec<String>,
    pub trusted_exec_hashes: Vec<String>,
    pub deny_comm: Vec<Vec<u8>>,
    pub scan_paths: Vec<Vec<u8>>,
    pub cgroup_deny_inodes: Vec<String>, // dedup key "cgroup|dev:ino"
    pub cgroup_deny_ips: Vec<String>,    // dedup key "cgroup|ip"
    pub cgroup_deny_ports: Vec<(Vec<u8>, (u16, u8, u8))>, // (cgroup, parsed port); dedup key "cgroup|raw"
    pub network_enabled: bool,
    pub cgroup_enabled: bool,
}

#[derive(Debug, Default)]
pub struct PolicyIssues {
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

impl PolicyIssues {
    pub fn has_errors(&self) -> bool {
        !self.errors.is_empty()
    }
}

const VALID_SECTIONS: &[&str] = &[
    "deny_path",
    "deny_inode",
    "protect_path",
    "protect_connect",
    "protect_runtime_deps",
    "require_ima_appraisal",
    "trusted_exec_hash",
    "ima_fail_closed",
    "allow_cgroup",
    "deny_ip",
    "deny_cidr",
    "deny_port",
    "deny_ip_port",
    "deny_binary_hash",
    "allow_binary_hash",
    "scan_paths",
    "cgroup_deny_inode",
    "cgroup_deny_ip",
    "cgroup_deny_port",
    "deny_ptrace",
    "deny_module_load",
    "deny_bpf",
    "deny_comm",
];

// mirrors src/policy_parse.cpp kDenyPathMax.
const DENY_PATH_MAX: usize = 4096;

fn is_space(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

/// Byte-exact analogue of `aegis::trim` (std::isspace on unsigned char).
fn trim(s: &[u8]) -> &[u8] {
    let mut start = 0;
    while start < s.len() && is_space(s[start]) {
        start += 1;
    }
    let mut end = s.len();
    while end > start && is_space(s[end - 1]) {
        end -= 1;
    }
    &s[start..end]
}

/// `std::getline`-faithful line split: split on '\n'; if the input ends with a
/// trailing '\n', drop the empty final element. Empty input yields no lines.
fn split_lines(bytes: &[u8]) -> Vec<&[u8]> {
    if bytes.is_empty() {
        return Vec::new();
    }
    let mut lines: Vec<&[u8]> = bytes.split(|&b| b == b'\n').collect();
    if bytes.last() == Some(&b'\n') {
        lines.pop();
    }
    lines
}

/// Faithful `parse_uint64`: base-10, reject leading '-', allow leading '+' (as
/// strtoull does), reject any trailing non-digit, reject overflow.
fn parse_uint64(s: &[u8]) -> Option<u64> {
    if s.is_empty() || s[0] == b'-' {
        return None;
    }
    let digits = if s[0] == b'+' { &s[1..] } else { s };
    if digits.is_empty() {
        return None;
    }
    let mut acc: u64 = 0;
    for &b in digits {
        if !b.is_ascii_digit() {
            return None;
        }
        acc = acc.checked_mul(10)?.checked_add((b - b'0') as u64)?;
    }
    Some(acc)
}

/// `std::stoi`-style lenient leading integer (skips ws, optional sign, stops at
/// first non-digit; needs >=1 digit). Used for CIDR prefix lengths.
fn parse_leading_int(s: &[u8]) -> Option<i64> {
    let mut i = 0;
    while i < s.len() && is_space(s[i]) {
        i += 1;
    }
    let neg = if i < s.len() && (s[i] == b'+' || s[i] == b'-') {
        let n = s[i] == b'-';
        i += 1;
        n
    } else {
        false
    };
    let start = i;
    let mut acc: i64 = 0;
    while i < s.len() && s[i].is_ascii_digit() {
        acc = acc.checked_mul(10)?.checked_add((s[i] - b'0') as i64)?;
        i += 1;
    }
    if i == start {
        return None; // no digits -> std::invalid_argument
    }
    Some(if neg { -acc } else { acc })
}

/// Faithful `parse_key_value`: split on first '=', trim both, require non-empty key.
fn parse_key_value(line: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let pos = line.iter().position(|&b| b == b'=')?;
    let key = trim(&line[..pos]).to_vec();
    let value = trim(&line[pos + 1..]).to_vec();
    if key.is_empty() {
        return None;
    }
    Some((key, value))
}

fn show(bytes: &[u8]) -> std::borrow::Cow<'_, str> {
    String::from_utf8_lossy(bytes)
}

/// dev:ino canonical string (mirrors inode_to_string: decimal dev ':' decimal ino).
fn parse_inode_id(text: &[u8]) -> Option<String> {
    let pos = text.iter().position(|&b| b == b':')?;
    let dev = parse_uint64(trim(&text[..pos]))?;
    let ino = parse_uint64(trim(&text[pos + 1..]))?;
    if dev > u32::MAX as u64 {
        return None;
    }
    Some(format!("{dev}:{ino}"))
}

fn parse_ipv4(s: &[u8]) -> Option<Ipv4Addr> {
    std::str::from_utf8(s).ok()?.parse::<Ipv4Addr>().ok()
}

fn parse_ipv6(s: &[u8]) -> Option<Ipv6Addr> {
    std::str::from_utf8(s).ok()?.parse::<Ipv6Addr>().ok()
}

/// ip:port `[proto]` value: ""/"any" -> 0, tcp -> 6, udp -> 17.
fn parse_protocol_value(s: &[u8]) -> Option<u8> {
    match s {
        b"" | b"any" => Some(0),
        b"tcp" => Some(6),
        b"udp" => Some(17),
        _ => None,
    }
}

/// Faithful `parse_cidr_v4`/`parse_cidr_v6`: split on '/', validate IP, prefix in range.
fn valid_cidr(s: &[u8]) -> bool {
    let Some(slash) = s.iter().position(|&b| b == b'/') else {
        return false;
    };
    let ip_part = &s[..slash];
    let prefix_part = &s[slash + 1..];
    if parse_ipv4(ip_part).is_some() {
        if let Some(p) = parse_leading_int(prefix_part) {
            return (0..=32).contains(&p);
        }
        return false;
    }
    if parse_ipv6(ip_part).is_some() {
        if let Some(p) = parse_leading_int(prefix_part) {
            return (0..=128).contains(&p);
        }
    }
    false
}

/// Faithful `parse_port_rule`: `port[:proto[:dir]]` -> (port, protocol, direction).
/// Mirrors C++ `parse_port_rule` exactly, including its defaults (protocol 0 =
/// any, direction 2 = both) and its tolerance of extra `:`-separated trailing
/// fields. Returns `None` on any invalid field — same accept/reject set as C++.
fn parse_port_rule(s: &[u8]) -> Option<(u16, u8, u8)> {
    let parts: Vec<&[u8]> = s.split(|&b| b == b':').collect();
    if parts[0].is_empty() {
        return None;
    }
    let port = match parse_uint64(parts[0]) {
        Some(p) if (1..=65535).contains(&p) => p as u16,
        _ => return None,
    };
    let mut protocol: u8 = 0; // default "any" (C++ zero-inits the rule)
    if parts.len() > 1 && !parts[1].is_empty() {
        protocol = match parts[1] {
            b"tcp" => 6,
            b"udp" => 17,
            b"any" => 0,
            _ => return None,
        };
    }
    let mut direction: u8 = 2; // default "both" (C++ sets rule.direction = 2)
    if parts.len() > 2 && !parts[2].is_empty() {
        direction = match parts[2] {
            b"egress" | b"connect" => 0,
            b"bind" => 1,
            b"both" => 2,
            _ => return None,
        };
    }
    Some((port, protocol, direction))
}

/// Faithful `parse_ip_port_rule` + `canonical_ip_port_rule_key`. Returns the
/// canonical dedup key `<ip>|<port>|<protocol>` on success.
fn parse_ip_port_canonical(text: &[u8]) -> Option<String> {
    if text.is_empty() {
        return None;
    }
    let (ip_part, port_part, protocol_part): (Vec<u8>, Vec<u8>, Vec<u8>);
    if text[0] == b'[' {
        let close = text.iter().position(|&b| b == b']')?;
        if close + 1 >= text.len() || text[close + 1] != b':' {
            return None;
        }
        ip_part = text[1..close].to_vec();
        let remainder = &text[close + 2..];
        match remainder.iter().position(|&b| b == b':') {
            None => {
                port_part = remainder.to_vec();
                protocol_part = Vec::new();
            }
            Some(colon) => {
                port_part = remainder[..colon].to_vec();
                let proto = &remainder[colon + 1..];
                if proto.contains(&b':') {
                    return None;
                }
                protocol_part = proto.to_vec();
            }
        }
    } else {
        let last_colon = text.iter().rposition(|&b| b == b':')?;
        let tail = &text[last_colon + 1..];
        if parse_protocol_value(tail).is_some() {
            protocol_part = tail.to_vec();
            let head = &text[..last_colon];
            let port_colon = head.iter().rposition(|&b| b == b':')?;
            ip_part = head[..port_colon].to_vec();
            port_part = head[port_colon + 1..].to_vec();
        } else {
            ip_part = text[..last_colon].to_vec();
            port_part = tail.to_vec();
            protocol_part = Vec::new();
        }
    }
    if ip_part.is_empty() || port_part.is_empty() {
        return None;
    }
    let port = match parse_uint64(&port_part) {
        Some(p) if (1..=65535).contains(&p) => p as u16,
        _ => return None,
    };
    let protocol = parse_protocol_value(&protocol_part)?;
    let ip_canon = if let Some(v4) = parse_ipv4(&ip_part) {
        v4.to_string()
    } else if let Some(v6) = parse_ipv6(&ip_part) {
        v6.to_string()
    } else {
        return None;
    };
    Some(format!("{ip_canon}|{port}|{protocol}"))
}

fn valid_hex64(s: &[u8]) -> bool {
    s.len() == 64 && s.iter().all(|b| b.is_ascii_hexdigit())
}

fn lower_hex(s: &[u8]) -> String {
    s.iter().map(|b| b.to_ascii_lowercase() as char).collect()
}

/// Parse policy bytes. Mirrors `parse_policy_file`. `with_conflicts` adds the
/// `detect_policy_conflicts` advisory warnings (as `policy lint` does).
pub fn parse_policy(bytes: &[u8], with_conflicts: bool) -> (Policy, PolicyIssues) {
    let mut p = Policy::default();
    let mut issues = PolicyIssues::default();
    let mut section: Vec<u8> = Vec::new();

    let mut seen_deny_path = BTreeSet::new();
    let mut seen_protect_path = BTreeSet::new();
    let mut seen_deny_inode = BTreeSet::new();
    let mut seen_allow_path = BTreeSet::new();
    let mut seen_allow_id = BTreeSet::new();
    let mut seen_deny_ip = BTreeSet::new();
    let mut seen_deny_cidr = BTreeSet::new();
    let mut seen_deny_port = BTreeSet::new();
    let mut seen_deny_ip_port = BTreeSet::new();
    let mut seen_deny_hash = BTreeSet::new();
    let mut seen_allow_hash = BTreeSet::new();
    let mut seen_trusted_hash = BTreeSet::new();
    let mut seen_deny_comm = BTreeSet::new();
    let mut seen_cg_inode = BTreeSet::new();
    let mut seen_cg_ip = BTreeSet::new();
    let mut seen_cg_port = BTreeSet::new();

    fn err(issues: &mut PolicyIssues, ln: usize, msg: String) {
        issues.errors.push(format!("line {ln}: {msg}"));
    }
    fn warn(issues: &mut PolicyIssues, ln: usize, msg: String) {
        issues.warnings.push(format!("line {ln}: {msg}"));
    }

    for (idx, raw) in split_lines(bytes).iter().enumerate() {
        let line_no = idx + 1;
        let t = trim(raw);
        if t.is_empty() || t[0] == b'#' {
            continue;
        }

        if t[0] == b'[' && *t.last().unwrap() == b']' {
            let inner = trim(&t[1..t.len() - 1]);
            let sec_str = String::from_utf8_lossy(inner).to_string();
            if !VALID_SECTIONS.contains(&sec_str.as_str()) {
                err(&mut issues, line_no, format!("unknown section '{sec_str}'"));
                section.clear();
            } else {
                section = inner.to_vec();
            }
            match sec_str.as_str() {
                "protect_connect" => p.flags.insert(Flag::ProtectConnect),
                "protect_runtime_deps" => p.flags.insert(Flag::ProtectRuntimeDeps),
                "require_ima_appraisal" => p.flags.insert(Flag::RequireImaAppraisal),
                "deny_ptrace" => p.flags.insert(Flag::DenyPtrace),
                "deny_module_load" => p.flags.insert(Flag::DenyModuleLoad),
                "deny_bpf" => p.flags.insert(Flag::DenyBpf),
                "ima_fail_closed" => p.flags.insert(Flag::ImaFailClosed),
                _ => false,
            };
            continue;
        }

        if section.is_empty() {
            match parse_key_value(t) {
                None => err(
                    &mut issues,
                    line_no,
                    "expected key=value in header".to_string(),
                ),
                Some((key, value)) => {
                    if key == b"version" {
                        match parse_uint64(&value) {
                            Some(v) if v != 0 && v <= i32::MAX as u64 => p.version = v,
                            _ => err(&mut issues, line_no, "invalid version".to_string()),
                        }
                    } else {
                        err(
                            &mut issues,
                            line_no,
                            format!("unknown header key '{}'", show(&key)),
                        );
                    }
                }
            }
            continue;
        }

        match section.as_slice() {
            b"deny_path" => {
                if t.len() >= DENY_PATH_MAX {
                    err(&mut issues, line_no, "deny_path is too long".to_string());
                } else if t[0] != b'/' {
                    err(
                        &mut issues,
                        line_no,
                        format!("deny_path must be an absolute path (got '{}')", show(t)),
                    );
                } else if seen_deny_path.insert(t.to_vec()) {
                    p.deny_paths.push(t.to_vec());
                }
            }
            b"protect_path" => {
                if t.len() >= DENY_PATH_MAX {
                    err(&mut issues, line_no, "protect_path is too long".to_string());
                } else if t[0] != b'/' {
                    err(
                        &mut issues,
                        line_no,
                        format!("protect_path must be an absolute path (got '{}')", show(t)),
                    );
                } else if seen_protect_path.insert(t.to_vec()) {
                    p.protect_paths.push(t.to_vec());
                }
            }
            sec @ (b"protect_connect"
            | b"protect_runtime_deps"
            | b"require_ima_appraisal"
            | b"ima_fail_closed"
            | b"deny_ptrace"
            | b"deny_module_load"
            | b"deny_bpf") => {
                warn(
                    &mut issues,
                    line_no,
                    format!(
                        "[{}] does not take entries; ignoring '{}'",
                        show(sec),
                        show(t)
                    ),
                );
            }
            b"deny_inode" => match parse_inode_id(t) {
                None => err(
                    &mut issues,
                    line_no,
                    "invalid inode format (dev:ino)".to_string(),
                ),
                Some(key) => {
                    if seen_deny_inode.insert(key.clone()) {
                        p.deny_inodes.push(key);
                    }
                }
            },
            b"allow_cgroup" => {
                if t.starts_with(b"cgid:") {
                    match parse_uint64(trim(&t[5..])) {
                        None => err(&mut issues, line_no, "invalid cgid value".to_string()),
                        Some(cgid) => {
                            if seen_allow_id.insert(cgid) {
                                p.allow_cgroup_ids.push(cgid);
                            }
                        }
                    }
                } else {
                    if t[0] != b'/' {
                        warn(
                            &mut issues,
                            line_no,
                            "allow_cgroup path is relative".to_string(),
                        );
                    }
                    if seen_allow_path.insert(t.to_vec()) {
                        p.allow_cgroup_paths.push(t.to_vec());
                    }
                }
            }
            b"deny_ip" => {
                if parse_ipv4(t).is_none() && parse_ipv6(t).is_none() {
                    err(
                        &mut issues,
                        line_no,
                        format!("invalid IP address '{}'", show(t)),
                    );
                } else if seen_deny_ip.insert(t.to_vec()) {
                    p.deny_ips.push(t.to_vec());
                    p.network_enabled = true;
                }
            }
            b"deny_cidr" => {
                if !valid_cidr(t) {
                    err(
                        &mut issues,
                        line_no,
                        format!("invalid CIDR notation '{}'", show(t)),
                    );
                } else if seen_deny_cidr.insert(t.to_vec()) {
                    p.deny_cidrs.push(t.to_vec());
                    p.network_enabled = true;
                }
            }
            b"deny_port" => match parse_port_rule(t) {
                None => err(
                    &mut issues,
                    line_no,
                    format!("invalid port rule '{}'", show(t)),
                ),
                // dedup by raw text (matches C++ deny_port_seen), store parsed tuple
                Some(rule) => {
                    if seen_deny_port.insert(t.to_vec()) {
                        p.deny_ports.push(rule);
                        p.network_enabled = true;
                    }
                }
            },
            b"deny_ip_port" => match parse_ip_port_canonical(t) {
                None => err(
                    &mut issues,
                    line_no,
                    format!("invalid IP:port rule '{}'", show(t)),
                ),
                Some(key) => {
                    if seen_deny_ip_port.insert(key.clone()) {
                        p.deny_ip_ports.push(key);
                        p.network_enabled = true;
                    }
                }
            },
            sec @ (b"deny_binary_hash" | b"allow_binary_hash" | b"trusted_exec_hash") => {
                let label = show(sec).to_string();
                if !t.starts_with(b"sha256:") {
                    err(
                        &mut issues,
                        line_no,
                        format!("{label} entry must start with 'sha256:'"),
                    );
                } else {
                    let hash = &t[7..];
                    if hash.len() != 64 {
                        err(
                            &mut issues,
                            line_no,
                            "sha256 hash must be 64 hex characters".to_string(),
                        );
                    } else if !valid_hex64(hash) {
                        err(
                            &mut issues,
                            line_no,
                            "sha256 hash contains non-hex characters".to_string(),
                        );
                    } else {
                        let h = lower_hex(hash);
                        match sec {
                            b"deny_binary_hash" => {
                                if seen_deny_hash.insert(h.clone()) {
                                    p.deny_binary_hashes.push(h);
                                }
                            }
                            b"allow_binary_hash" => {
                                if seen_allow_hash.insert(h.clone()) {
                                    p.allow_binary_hashes.push(h);
                                }
                            }
                            _ => {
                                if seen_trusted_hash.insert(h.clone()) {
                                    p.trusted_exec_hashes.push(h);
                                }
                            }
                        }
                    }
                }
            }
            b"deny_comm" => {
                if t.len() > 15 {
                    err(
                        &mut issues,
                        line_no,
                        "deny_comm entry exceeds 15 chars (kernel TASK_COMM_LEN - 1)".to_string(),
                    );
                } else if seen_deny_comm.insert(t.to_vec()) {
                    p.deny_comm.push(t.to_vec());
                }
            }
            b"cgroup_deny_inode" => match t.iter().position(|&b| b == b' ') {
                None => err(
                    &mut issues,
                    line_no,
                    "cgroup_deny_inode expects '<cgroup> <dev>:<ino>'".to_string(),
                ),
                Some(sep) => {
                    let cgroup = trim(&t[..sep]);
                    match parse_inode_id(trim(&t[sep + 1..])) {
                        None => err(
                            &mut issues,
                            line_no,
                            "invalid inode format in cgroup_deny_inode (dev:ino)".to_string(),
                        ),
                        Some(idk) => {
                            let key = format!("{}|{}", show(cgroup), idk);
                            if seen_cg_inode.insert(key.clone()) {
                                p.cgroup_deny_inodes.push(key);
                                p.cgroup_enabled = true;
                            }
                        }
                    }
                }
            },
            b"cgroup_deny_ip" => match t.iter().position(|&b| b == b' ') {
                None => err(
                    &mut issues,
                    line_no,
                    "cgroup_deny_ip expects '<cgroup> <ipv4>'".to_string(),
                ),
                Some(sep) => {
                    let cgroup = trim(&t[..sep]);
                    let ip = trim(&t[sep + 1..]);
                    if parse_ipv4(ip).is_none() {
                        err(
                            &mut issues,
                            line_no,
                            format!(
                                "cgroup_deny_ip only supports IPv4; invalid address '{}'",
                                show(ip)
                            ),
                        );
                    } else {
                        let key = format!("{}|{}", show(cgroup), show(ip));
                        if seen_cg_ip.insert(key.clone()) {
                            p.cgroup_deny_ips.push(key);
                            p.cgroup_enabled = true;
                        }
                    }
                }
            },
            b"cgroup_deny_port" => match t.iter().position(|&b| b == b' ') {
                None => err(
                    &mut issues,
                    line_no,
                    "cgroup_deny_port expects '<cgroup> <port>[:<proto>[:<dir>]]'".to_string(),
                ),
                Some(sep) => {
                    let cgroup = trim(&t[..sep]);
                    let port = trim(&t[sep + 1..]);
                    match parse_port_rule(port) {
                        None => err(
                            &mut issues,
                            line_no,
                            format!("invalid port rule '{}'", show(port)),
                        ),
                        // dedup by "cgroup|raw" (matches C++), store (cgroup, parsed)
                        Some(rule) => {
                            let key = format!("{}|{}", show(cgroup), show(port));
                            if seen_cg_port.insert(key) {
                                p.cgroup_deny_ports.push((cgroup.to_vec(), rule));
                                p.cgroup_enabled = true;
                            }
                        }
                    }
                }
            },
            b"scan_paths" => {
                if t.is_empty() || t[0] != b'/' {
                    warn(
                        &mut issues,
                        line_no,
                        "scan_paths entry should be absolute".to_string(),
                    );
                }
                p.scan_paths.push(t.to_vec());
            }
            _ => {}
        }
    }

    // ---- post-parse validation (mirrors policy_parse.cpp lines 561-596) ----
    if p.version == 0 {
        issues
            .errors
            .push("missing header key: version".to_string());
    }
    if p.version < 1 || p.version > 6 {
        issues
            .errors
            .push(format!("unsupported policy version: {}", p.version));
    }
    if !p.deny_binary_hashes.is_empty() && p.version < 3 {
        issues
            .errors
            .push("[deny_binary_hash] requires version=3 or higher".to_string());
    }
    if !p.allow_binary_hashes.is_empty() && p.version < 3 {
        issues
            .errors
            .push("[allow_binary_hash] requires version=3 or higher".to_string());
    }
    if (!p.protect_paths.is_empty()
        || p.flags.contains(&Flag::ProtectConnect)
        || p.flags.contains(&Flag::ProtectRuntimeDeps))
        && p.version < 4
    {
        issues.errors.push(
            "[protect_path]/[protect_connect]/[protect_runtime_deps] requires version=4 or higher"
                .to_string(),
        );
    }
    if p.flags.contains(&Flag::RequireImaAppraisal) && p.version < 5 {
        issues
            .errors
            .push("[require_ima_appraisal] requires version=5 or higher".to_string());
    }
    if !p.trusted_exec_hashes.is_empty() && p.version < 5 {
        issues
            .errors
            .push("[trusted_exec_hash] requires version=5 or higher".to_string());
    }
    if p.flags.contains(&Flag::ImaFailClosed) && p.trusted_exec_hashes.is_empty() {
        issues.errors.push(
            "[ima_fail_closed] requires a non-empty [trusted_exec_hash] allowlist".to_string(),
        );
    }
    if p.flags.contains(&Flag::ProtectRuntimeDeps)
        && !p.flags.contains(&Flag::ProtectConnect)
        && p.protect_paths.is_empty()
    {
        issues.errors.push(
            "[protect_runtime_deps] requires [protect_connect] or [protect_path]".to_string(),
        );
    }
    if p.cgroup_enabled && p.version < 6 {
        issues
            .errors
            .push("[cgroup_deny_*] sections require version=6 or higher".to_string());
    }

    if with_conflicts && !issues.has_errors() {
        detect_conflicts(&p, &mut issues);
    }

    (p, issues)
}

/// Mirrors `detect_policy_conflicts` (lint-only advisory warnings).
fn detect_conflicts(p: &Policy, issues: &mut PolicyIssues) {
    if !p.deny_paths.is_empty() && !p.protect_paths.is_empty() {
        let deny: BTreeSet<&Vec<u8>> = p.deny_paths.iter().collect();
        for pp in &p.protect_paths {
            if deny.contains(pp) {
                issues.warnings.push(format!(
                    "conflict: '{}' appears in both [deny_path] and [protect_path]. The deny rule takes precedence.",
                    show(pp)
                ));
            }
        }
    }
    if p.network_enabled && !p.deny_ips.is_empty() && !p.deny_cidrs.is_empty() {
        issues.warnings.push(
            "advisory: policy has both IP and CIDR deny rules. Verify that individual IPs are not already covered by CIDR ranges (redundant rules waste map capacity).".to_string(),
        );
    }
    if p.flags.contains(&Flag::DenyBpf) && !p.flags.contains(&Flag::DenyModuleLoad) {
        issues.warnings.push(
            "advisory: [deny_bpf] is enabled but [deny_module_load] is not. Kernel module loading remains unrestricted, which may allow alternative attack paths (T1547.006).".to_string(),
        );
    }
    if (p.flags.contains(&Flag::DenyPtrace)
        || p.flags.contains(&Flag::DenyModuleLoad)
        || p.flags.contains(&Flag::DenyBpf))
        && p.deny_paths.is_empty()
        && p.deny_inodes.is_empty()
    {
        issues.warnings.push(
            "advisory: kernel security hooks are enabled but no file deny rules are configured. Consider adding [deny_path] or [deny_inode] sections for file access control.".to_string(),
        );
    }
    if (p.flags.contains(&Flag::ProtectConnect) || !p.protect_paths.is_empty())
        && p.allow_binary_hashes.is_empty()
        && p.deny_binary_hashes.is_empty()
    {
        issues.warnings.push(
            "advisory: [protect_path] or [protect_connect] is enabled but no binary hash allowlist is configured. Exec identity will have no basis for trust decisions.".to_string(),
        );
    }
}

/// Complete, canonical, machine-comparable dump of the parse result, for the
/// differential parity harness (`scripts/rust_policy_parity.sh`). The C++
/// `aegisbpf policy canonical` subcommand emits this byte-for-byte over the
/// UTF-8 input domain, so the two parsers can be proven *structurally*
/// equivalent — every stored entry, not just counts and issues.
///
/// Layout (fixed section order; entries in stored insertion order):
///   * no errors: `version`, `flag` lines, then every entry in every category,
///     then sorted `WARN` lines.
///   * `>= 1` error: the C++ parser discards its partial policy on error, so we
///     emit no policy lines — only sorted `ERROR` then sorted `WARN` lines.
///
/// Flags iterate in `Flag`-enum declaration order (`BTreeSet<Flag>` order); the
/// C++ side mirrors that exact order. Ports render as the parsed numeric tuple
/// `port:proto:dir`; `deny_ip_port` / `cgroup_deny_inode` / `cgroup_deny_ip`
/// render as their canonical dedup keys.
pub fn canonical_report(p: &Policy, issues: &PolicyIssues) -> String {
    let mut out = String::new();
    if !issues.has_errors() {
        let _ = writeln!(out, "version {}", p.version);
        for f in &p.flags {
            let _ = writeln!(out, "flag {}", f.as_str());
        }
        for v in &p.deny_paths {
            let _ = writeln!(out, "deny_path {}", show(v));
        }
        for v in &p.protect_paths {
            let _ = writeln!(out, "protect_path {}", show(v));
        }
        for v in &p.deny_inodes {
            let _ = writeln!(out, "deny_inode {v}");
        }
        for id in &p.allow_cgroup_ids {
            let _ = writeln!(out, "allow_cgroup_id {id}");
        }
        for v in &p.allow_cgroup_paths {
            let _ = writeln!(out, "allow_cgroup_path {}", show(v));
        }
        for v in &p.deny_ips {
            let _ = writeln!(out, "deny_ip {}", show(v));
        }
        for v in &p.deny_cidrs {
            let _ = writeln!(out, "deny_cidr {}", show(v));
        }
        for &(port, proto, dir) in &p.deny_ports {
            let _ = writeln!(out, "deny_port {port}:{proto}:{dir}");
        }
        for v in &p.deny_ip_ports {
            let _ = writeln!(out, "deny_ip_port {v}");
        }
        for v in &p.deny_binary_hashes {
            let _ = writeln!(out, "deny_binary_hash {v}");
        }
        for v in &p.allow_binary_hashes {
            let _ = writeln!(out, "allow_binary_hash {v}");
        }
        for v in &p.trusted_exec_hashes {
            let _ = writeln!(out, "trusted_exec_hash {v}");
        }
        for v in &p.deny_comm {
            let _ = writeln!(out, "deny_comm {}", show(v));
        }
        for v in &p.scan_paths {
            let _ = writeln!(out, "scan_paths {}", show(v));
        }
        for v in &p.cgroup_deny_inodes {
            let _ = writeln!(out, "cgroup_deny_inode {v}");
        }
        for v in &p.cgroup_deny_ips {
            let _ = writeln!(out, "cgroup_deny_ip {v}");
        }
        for (cg, (port, proto, dir)) in &p.cgroup_deny_ports {
            let _ = writeln!(out, "cgroup_deny_port {}|{port}:{proto}:{dir}", show(cg));
        }
    }
    let mut errs: Vec<&String> = issues.errors.iter().collect();
    let mut warns: Vec<&String> = issues.warnings.iter().collect();
    errs.sort();
    warns.sort();
    for e in errs {
        let _ = writeln!(out, "ERROR {e}");
    }
    for w in warns {
        let _ = writeln!(out, "WARN {w}");
    }
    out
}

#[cfg(test)]
mod tests;
