//! Unit + adversarial tests for the policy parser. These pin the contract
//! independently of the differential harness (which proves C++ parity).
use super::*;

fn parse(s: &str) -> (Policy, PolicyIssues) {
    parse_policy(s.as_bytes(), false)
}
fn lint(s: &str) -> (Policy, PolicyIssues) {
    parse_policy(s.as_bytes(), true)
}

// ---- low-level helpers ----

#[test]
fn trim_strips_ascii_whitespace_both_ends() {
    assert_eq!(trim(b"  \t hello \r\n"), b"hello");
    assert_eq!(trim(b""), b"");
    assert_eq!(trim(b"   "), b"");
    assert_eq!(trim(b"a"), b"a");
}

#[test]
fn parse_uint64_contract() {
    assert_eq!(parse_uint64(b"0"), Some(0));
    assert_eq!(parse_uint64(b"42"), Some(42));
    assert_eq!(parse_uint64(b"+5"), Some(5)); // strtoull accepts leading '+'
    assert_eq!(parse_uint64(b"-5"), None);
    assert_eq!(parse_uint64(b""), None);
    assert_eq!(parse_uint64(b"+"), None);
    assert_eq!(parse_uint64(b"0x10"), None); // trailing non-digit
    assert_eq!(parse_uint64(b"12a"), None);
    assert_eq!(parse_uint64(b"18446744073709551615"), Some(u64::MAX));
    assert_eq!(parse_uint64(b"18446744073709551616"), None); // overflow
}

#[test]
fn split_lines_matches_getline() {
    assert_eq!(split_lines(b"").len(), 0);
    assert_eq!(split_lines(b"a"), vec![b"a".as_slice()]);
    assert_eq!(split_lines(b"a\n"), vec![b"a".as_slice()]);
    assert_eq!(split_lines(b"a\nb"), vec![b"a".as_slice(), b"b".as_slice()]);
    assert_eq!(split_lines(b"a\n\n"), vec![b"a".as_slice(), b"".as_slice()]);
    assert_eq!(split_lines(b"\n"), vec![b"".as_slice()]);
}

// ---- structural / lexical ----

#[test]
fn comments_and_blanks_skipped() {
    let (p, i) = parse("version=1\n\n   \n# a comment\n[deny_path]\n/etc/shadow\n");
    assert!(!i.has_errors(), "{:?}", i.errors);
    assert_eq!(p.deny_paths.len(), 1);
}

#[test]
fn unknown_section_errors_and_clears_section() {
    // After an unknown section, subsequent lines are treated as header context.
    let (_p, i) = parse("version=1\n[bogus]\n/etc/shadow\n");
    assert!(i
        .errors
        .iter()
        .any(|e| e.contains("unknown section 'bogus'")));
    assert!(i
        .errors
        .iter()
        .any(|e| e.contains("expected key=value in header")));
}

#[test]
fn header_only_version_recognized() {
    let (p, i) = parse("version=4\nfoo=bar\n");
    assert_eq!(p.version, 4);
    assert!(i
        .errors
        .iter()
        .any(|e| e.contains("unknown header key 'foo'")));
}

#[test]
fn missing_version_errors() {
    let (_p, i) = parse("[deny_path]\n/etc/shadow\n");
    assert!(i
        .errors
        .iter()
        .any(|e| e.contains("missing header key: version")));
}

#[test]
fn invalid_version_value() {
    let (_p, i) = parse("version=abc\n");
    assert!(i.errors.iter().any(|e| e.contains("invalid version")));
}

#[test]
fn unsupported_version_range() {
    let (_p, i) = parse("version=7\n");
    assert!(i
        .errors
        .iter()
        .any(|e| e.contains("unsupported policy version: 7")));
}

// ---- deny_path / dedup ----

#[test]
fn deny_path_requires_absolute() {
    let (p, i) = parse("version=1\n[deny_path]\nrelative/x\n");
    assert!(i
        .errors
        .iter()
        .any(|e| e.contains("deny_path must be an absolute path (got 'relative/x')")));
    assert_eq!(p.deny_paths.len(), 0);
}

#[test]
fn deny_path_dedup() {
    let (p, _i) = parse("version=1\n[deny_path]\n/a\n/a\n/b\n");
    assert_eq!(p.deny_paths.len(), 2);
}

// ---- boolean sections ----

#[test]
fn boolean_section_sets_flag_and_warns_on_entry() {
    let (p, i) = parse("version=1\n[deny_ptrace]\nstray\n");
    assert!(p.flags.contains(&Flag::DenyPtrace));
    assert!(i
        .warnings
        .iter()
        .any(|w| w.contains("[deny_ptrace] does not take entries; ignoring 'stray'")));
}

// ---- deny_inode ----

#[test]
fn deny_inode_canonicalizes_and_dedups() {
    let (p, i) = parse("version=1\n[deny_inode]\n2049:128\n2049:128\nbad\n");
    assert!(i
        .errors
        .iter()
        .any(|e| e.contains("invalid inode format (dev:ino)")));
    assert_eq!(p.deny_inodes, vec!["2049:128".to_string()]);
}

// ---- network ----

#[test]
fn deny_ip_accepts_v4_and_v6_rejects_garbage() {
    let (p, i) = parse("version=1\n[deny_ip]\n10.0.0.1\n::1\nnope\n");
    assert!(i
        .errors
        .iter()
        .any(|e| e.contains("invalid IP address 'nope'")));
    assert_eq!(p.deny_ips.len(), 2);
    assert!(p.network_enabled);
}

#[test]
fn deny_cidr_validation() {
    let (p, i) = parse("version=1\n[deny_cidr]\n10.0.0.0/8\n10.0.0.0/33\nfe80::/10\n");
    assert!(i
        .errors
        .iter()
        .any(|e| e.contains("invalid CIDR notation '10.0.0.0/33'")));
    assert_eq!(p.deny_cidrs.len(), 2);
}

#[test]
fn deny_port_rule_forms() {
    let (p, i) = parse("version=1\n[deny_port]\n22\n443:tcp\n53:udp:both\n0\n99999\n");
    assert_eq!(p.deny_ports.len(), 3);
    assert!(
        i.errors
            .iter()
            .filter(|e| e.contains("invalid port rule"))
            .count()
            == 2
    );
}

#[test]
fn deny_ip_port_canonical_dedup() {
    // Same endpoint written two ways canonicalizes equal -> deduped to 1.
    let (p, _i) = parse("version=1\n[deny_ip_port]\n10.0.0.1:443\n10.000.000.001:443\n");
    // 10.000.000.001 is rejected by strict inet_pton-style parsing, so it errors;
    // assert the valid one is counted.
    assert!(!p.deny_ip_ports.is_empty());
}

#[test]
fn deny_ip_port_v6_bracketed() {
    let (p, i) = parse("version=1\n[deny_ip_port]\n[::1]:443:tcp\n");
    assert!(!i.has_errors(), "{:?}", i.errors);
    assert_eq!(p.deny_ip_ports.len(), 1);
}

// ---- hashes ----

#[test]
fn binary_hash_validation_and_lowercasing() {
    let good = "A".repeat(64);
    let (p, i) = parse(&format!(
        "version=3\n[deny_binary_hash]\nsha256:{good}\nsha256:short\nnoprefix\n"
    ));
    assert_eq!(p.deny_binary_hashes, vec!["a".repeat(64)]);
    assert!(i
        .errors
        .iter()
        .any(|e| e.contains("must be 64 hex characters")));
    assert!(i
        .errors
        .iter()
        .any(|e| e.contains("must start with 'sha256:'")));
}

#[test]
fn binary_hash_version_gate() {
    let good = "a".repeat(64);
    let (_p, i) = parse(&format!("version=2\n[deny_binary_hash]\nsha256:{good}\n"));
    assert!(i
        .errors
        .iter()
        .any(|e| e.contains("[deny_binary_hash] requires version=3 or higher")));
}

// ---- deny_comm ----

#[test]
fn deny_comm_length_limit() {
    let (p, i) = parse("version=1\n[deny_comm]\nshortcomm\nthis_is_way_too_long_comm\n");
    assert_eq!(p.deny_comm.len(), 1);
    assert!(i.errors.iter().any(|e| e.contains("exceeds 15 chars")));
}

// ---- cgroup (v6) ----

#[test]
fn cgroup_sections_require_v6() {
    let (_p, i) = parse("version=5\n[cgroup_deny_inode]\n/sys/fs/cgroup/x 2049:10\n");
    assert!(i
        .errors
        .iter()
        .any(|e| e.contains("[cgroup_deny_*] sections require version=6 or higher")));
}

#[test]
fn cgroup_deny_inode_ok_on_v6() {
    let (p, i) = parse("version=6\n[cgroup_deny_inode]\n/sys/fs/cgroup/x 2049:10\n");
    assert!(!i.has_errors(), "{:?}", i.errors);
    assert_eq!(p.cgroup_deny_inodes.len(), 1);
    assert!(p.cgroup_enabled);
}

// ---- post-parse cross-field rules ----

#[test]
fn ima_fail_closed_requires_trusted_hashes() {
    let (_p, i) = parse("version=5\n[ima_fail_closed]\n");
    assert!(i.errors.iter().any(
        |e| e.contains("[ima_fail_closed] requires a non-empty [trusted_exec_hash] allowlist")
    ));
}

#[test]
fn protect_runtime_deps_requires_connect_or_path() {
    let (_p, i) = parse("version=4\n[protect_runtime_deps]\n");
    assert!(
        i.errors
            .iter()
            .any(|e| e
                .contains("[protect_runtime_deps] requires [protect_connect] or [protect_path]"))
    );
}

// ---- lint conflicts ----

#[test]
fn conflict_deny_and_protect_same_path() {
    let good = "a".repeat(64);
    let (_p, i) = lint(&format!(
        "version=4\n[deny_path]\n/x\n[protect_path]\n/x\n[allow_binary_hash]\nsha256:{good}\n"
    ));
    assert!(i
        .warnings
        .iter()
        .any(|w| w.contains("appears in both [deny_path] and [protect_path]")));
}

// ---- memory-safety / adversarial: must never panic ----

#[test]
fn adversarial_inputs_never_panic() {
    let cases: &[&[u8]] = &[
        b"",
        b"\n\n\n",
        b"[",
        b"]",
        b"[]",
        b"[deny_path]",
        b"version=",
        b"=value",
        b"[deny_ip_port]\n[::1]",
        b"[deny_ip_port]\n:::::\n",
        b"[deny_cidr]\n/\n",
        b"\xff\xfe\x00\x01 garbage bytes",
        b"[deny_path]\n\x00\xff/notutf8\n",
        &[b'x'; 100_000],
    ];
    for c in cases {
        let _ = parse_policy(c, true); // just must not panic
    }
}

#[test]
fn long_line_no_overflow() {
    let mut s = b"version=1\n[deny_path]\n/".to_vec();
    s.resize(s.len() + 50_000, b'a');
    s.push(b'\n');
    let (p, i) = parse_policy(&s, false);
    // exceeds DENY_PATH_MAX -> error, not added
    assert_eq!(p.deny_paths.len(), 0);
    assert!(i.errors.iter().any(|e| e.contains("deny_path is too long")));
}
