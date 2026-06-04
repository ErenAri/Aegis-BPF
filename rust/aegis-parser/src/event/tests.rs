//! Unit + adversarial tests for the event decoder. The authoritative proof of
//! equivalence is the differential parity harness (`scripts/rust_event_parity.sh`)
//! against the C++ `handle_event`; these tests pin individual decode behaviors
//! (offsets, NUL-terminated `char[]` extraction, label derivation) and guarantee
//! the decoder never panics on adversarial input — the memory-safety property the
//! C++ `static_cast` + size-discarding consumer lacks.

use super::*;

const PB: usize = PAYLOAD;

/// A zeroed `Event`-shaped record (`type` at 0, union payload at `PAYLOAD`).
fn rec(ty: u32) -> Vec<u8> {
    let mut b = vec![0u8; EVENT_SIZE];
    b[0..4].copy_from_slice(&ty.to_le_bytes());
    b
}

fn put_u32(b: &mut [u8], off: usize, v: u32) {
    b[off..off + 4].copy_from_slice(&v.to_le_bytes());
}
fn put_u64(b: &mut [u8], off: usize, v: u64) {
    b[off..off + 8].copy_from_slice(&v.to_le_bytes());
}
fn put_u16(b: &mut [u8], off: usize, v: u16) {
    b[off..off + 2].copy_from_slice(&v.to_le_bytes());
}
fn put_bytes(b: &mut [u8], off: usize, v: &[u8]) {
    b[off..off + v.len()].copy_from_slice(v);
}

fn line<'a>(report: &'a str, key: &str) -> &'a str {
    report
        .lines()
        .find(|l| l.split(' ').next() == Some(key))
        .unwrap_or_else(|| panic!("missing line {key:?} in:\n{report}"))
}

#[test]
fn event_size_matches_cpp_probe() {
    // sizeof(aegis::Event) / sizeof(aegis::ForensicEvent) per the layout probe
    // against src/types.hpp.
    assert_eq!(EVENT_SIZE, 344);
    assert_eq!(PAYLOAD, 8);
    assert_eq!(FORENSIC_SIZE, 104);
}

#[test]
fn exec_event_fields() {
    let mut b = rec(TYPE_EXEC);
    put_u32(&mut b, PB, 4242); // pid
    put_u32(&mut b, PB + 4, 7); // ppid
    put_u64(&mut b, PB + 8, 0x1122_3344_5566_7788); // start_time
    put_u64(&mut b, PB + 16, 99); // cgid
    put_bytes(&mut b, PB + 24, b"bash\0"); // comm
    b[PB + 72] = 3; // ancestor_count
    put_u32(&mut b, PB + 40, 100);
    put_u32(&mut b, PB + 44, 200);
    put_u32(&mut b, PB + 48, 300);
    put_u32(&mut b, PB + 52, 400); // beyond count=3, must be ignored

    let r = canonical_report(&b);
    assert_eq!(line(&r, "type"), "type exec");
    assert_eq!(line(&r, "pid"), "pid 4242");
    assert_eq!(line(&r, "ppid"), "ppid 7");
    assert_eq!(line(&r, "start_time"), "start_time 1234605616436508552");
    assert_eq!(line(&r, "cgid"), "cgid 99");
    assert_eq!(line(&r, "comm_hex"), "comm_hex 62617368"); // "bash"
    assert_eq!(line(&r, "ancestor_count"), "ancestor_count 3");
    assert_eq!(line(&r, "ancestors"), "ancestors 100,200,300");
}

#[test]
fn exec_ancestors_clamped_to_depth() {
    let mut b = rec(TYPE_EXEC);
    b[PB + 72] = 250; // absurd count
    for i in 0..ANCESTOR_MAX_DEPTH {
        put_u32(&mut b, PB + 40 + i * 4, (i as u32) + 1);
    }
    let r = canonical_report(&b);
    // Only kAncestorMaxDepth (8) ancestors are emitted, never more.
    assert_eq!(line(&r, "ancestors"), "ancestors 1,2,3,4,5,6,7,8");
    assert_eq!(line(&r, "ancestor_count"), "ancestor_count 250");
}

#[test]
fn block_event_fields_and_offsets() {
    let mut b = rec(TYPE_BLOCK);
    put_u32(&mut b, PB, 11); // ppid @0
    put_u64(&mut b, PB + 8, 500); // start_time
    put_u64(&mut b, PB + 16, 400); // parent_start_time
    put_u32(&mut b, PB + 24, 12345); // pid @24
    put_u64(&mut b, PB + 32, 88); // cgid
    put_bytes(&mut b, PB + 40, b"evil\0"); // comm
    put_u64(&mut b, PB + 56, 0xdead); // ino
    put_u32(&mut b, PB + 64, 2050); // dev
    put_bytes(&mut b, PB + 68, b"/etc/shadow\0"); // path
    put_bytes(&mut b, PB + 324, b"KILL\0"); // action

    let r = canonical_report(&b);
    assert_eq!(line(&r, "type"), "type block");
    assert_eq!(line(&r, "pid"), "pid 12345");
    assert_eq!(line(&r, "ppid"), "ppid 11");
    assert_eq!(line(&r, "ino"), "ino 57005");
    assert_eq!(line(&r, "dev"), "dev 2050");
    // "/etc/shadow" hex
    assert_eq!(line(&r, "path_hex"), "path_hex 2f6574632f736861646f77");
    assert_eq!(line(&r, "action_hex"), "action_hex 4b494c4c"); // KILL
}

#[test]
fn net_block_direction_labels() {
    let cases = [
        (0u8, "net_connect_block"),
        (1, "net_bind_block"),
        (2, "net_listen_block"),
        (3, "net_accept_block"),
        (4, "net_sendmsg_block"),
        (5, "net_recvmsg_block"),
        (99, "net_recvmsg_block"), // anything else -> recvmsg, like C++ else-branch
    ];
    for (dir, label) in cases {
        let mut b = rec(TYPE_NET_CONNECT_BLOCK);
        b[PB + 54] = dir; // direction
        let r = canonical_report(&b);
        assert_eq!(line(&r, "type"), format!("type {label}"), "dir={dir}");
        assert_eq!(line(&r, "direction"), format!("direction {dir}"));
    }
}

#[test]
fn net_block_protocol_and_family_and_addrs() {
    let mut b = rec(TYPE_NET_BIND_BLOCK);
    b[PB + 48] = FAMILY_IPV4; // family
    b[PB + 49] = PROTO_TCP; // protocol
    put_u16(&mut b, PB + 50, 8080); // local_port
    put_u16(&mut b, PB + 52, 443); // remote_port
    b[PB + 54] = 1; // direction = bind
    put_bytes(&mut b, PB + 56, &[10, 0, 0, 1]); // remote_ipv4 = 10.0.0.1 bytes
    put_bytes(&mut b, PB + 84, b"ip\0"); // rule_type
    put_bytes(&mut b, PB + 76, b"BLOCK\0"); // action

    let r = canonical_report(&b);
    assert_eq!(line(&r, "family"), "family ipv4");
    assert_eq!(line(&r, "family_raw"), "family_raw 2");
    assert_eq!(line(&r, "protocol"), "protocol tcp");
    assert_eq!(line(&r, "local_port"), "local_port 8080");
    assert_eq!(line(&r, "remote_port"), "remote_port 443");
    assert_eq!(line(&r, "remote_ipv4_hex"), "remote_ipv4_hex 0a000001");
    assert_eq!(
        line(&r, "remote_ipv6_hex"),
        "remote_ipv6_hex 00000000000000000000000000000000"
    );
    assert_eq!(line(&r, "rule_type_hex"), "rule_type_hex 6970"); // "ip"
    assert_eq!(line(&r, "action_hex"), "action_hex 424c4f434b"); // BLOCK
}

#[test]
fn net_block_protocol_udp_and_numeric() {
    let mut b = rec(TYPE_NET_CONNECT_BLOCK);
    b[PB + 49] = PROTO_UDP;
    assert_eq!(line(&canonical_report(&b), "protocol"), "protocol udp");
    b[PB + 49] = 132; // SCTP -> numeric
    assert_eq!(line(&canonical_report(&b), "protocol"), "protocol 132");
}

#[test]
fn net_block_family_ipv6_label() {
    let mut b = rec(TYPE_NET_CONNECT_BLOCK);
    b[PB + 48] = 10; // AF_INET6
    let v6: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    put_bytes(&mut b, PB + 60, &v6);
    let r = canonical_report(&b);
    assert_eq!(line(&r, "family"), "family ipv6");
    assert_eq!(
        line(&r, "remote_ipv6_hex"),
        "remote_ipv6_hex 20010db8000000000000000000000001"
    );
}

#[test]
fn kernel_block_fields() {
    let mut b = rec(TYPE_KERNEL_PTRACE_BLOCK);
    put_u32(&mut b, PB, 321); // pid
    put_u32(&mut b, PB + 48, 654); // target_pid
    put_bytes(&mut b, PB + 64, b"ptrace\0"); // rule_type
    put_bytes(&mut b, PB + 56, b"AUDIT\0"); // action
    let r = canonical_report(&b);
    assert_eq!(line(&r, "type"), "type kernel_block");
    assert_eq!(line(&r, "pid"), "pid 321");
    assert_eq!(line(&r, "target_pid"), "target_pid 654");
    assert_eq!(line(&r, "rule_type_hex"), "rule_type_hex 707472616365"); // ptrace
    assert_eq!(line(&r, "action_hex"), "action_hex 4155444954"); // AUDIT
                                                                 // derived event_type = "kernel_ptrace_block", emitted as hex
    assert_eq!(
        line(&r, "event_type_hex"),
        format!("event_type_hex {}", to_hex(b"kernel_ptrace_block"))
    );
}

#[test]
fn kernel_event_type_label_derivation_empty_rule_type() {
    // rule_type empty (leading NUL) -> derived "kernel__block"; the derivation is
    // a pure function of the rule_type bytes, pinned via hex.
    let b = rec(TYPE_KERNEL_BPF_BLOCK); // rule_type left zeroed
    let r = canonical_report(&b);
    assert_eq!(line(&r, "rule_type_hex"), "rule_type_hex ");
    assert_eq!(
        line(&r, "event_type_hex"),
        format!("event_type_hex {}", to_hex(b"kernel__block"))
    );
}

/// A zeroed *bare* forensic record: `forensic_event` at offset 0 (its own `type`
/// at offset 0), `FORENSIC_SIZE` bytes — NOT the 344-byte `Event` envelope.
fn forensic_rec() -> Vec<u8> {
    let mut b = vec![0u8; FORENSIC_SIZE];
    b[0..4].copy_from_slice(&TYPE_FORENSIC_BLOCK.to_le_bytes());
    b
}

#[test]
fn forensic_fields_bare_offset0() {
    // Bare forensic_event: fields at struct offsets from the RECORD BASE (offset 0),
    // not the Event payload offset. This is the fixed offset-0 decode.
    let mut b = forensic_rec();
    put_u32(&mut b, 4, 777); // pid
    put_u32(&mut b, 8, 778); // ppid
    put_u64(&mut b, 16, 1000); // start_time
    put_bytes(&mut b, 40, b"sshd\0"); // comm
    put_u32(&mut b, 68, 1001); // uid
    put_u32(&mut b, 72, 1002); // gid
    b[92] = 2; // exec_stage
    b[93] = 1; // verified_exec
    b[94] = 1; // exec_identity_known
    put_bytes(&mut b, 96, b"DENY\0"); // action
    let r = canonical_report(&b);
    assert_eq!(line(&r, "type"), "type forensic_block");
    assert_eq!(line(&r, "pid"), "pid 777");
    assert_eq!(line(&r, "ppid"), "ppid 778");
    assert_eq!(line(&r, "start_time"), "start_time 1000");
    assert_eq!(line(&r, "comm_hex"), "comm_hex 73736864"); // sshd
    assert_eq!(line(&r, "uid"), "uid 1001");
    assert_eq!(line(&r, "gid"), "gid 1002");
    assert_eq!(line(&r, "exec_stage"), "exec_stage 2");
    assert_eq!(line(&r, "verified_exec"), "verified_exec 1");
    assert_eq!(line(&r, "action_hex"), "action_hex 44454e59"); // DENY
}

#[test]
fn forensic_short_record_rejected() {
    // A forensic record shorter than FORENSIC_SIZE is rejected (bounds-checked),
    // where the old code would have over-read it.
    for len in [4usize, 50, FORENSIC_SIZE - 1] {
        let mut b = vec![0u8; len];
        b[0..4].copy_from_slice(&TYPE_FORENSIC_BLOCK.to_le_bytes());
        assert_eq!(canonical_report(&b), format!("err short_buffer {len}\n"));
    }
    // exactly FORENSIC_SIZE decodes; a non-forensic type would need EVENT_SIZE.
    assert!(canonical_report(&forensic_rec()).starts_with("type forensic_block\n"));
    // a 104-byte buffer with a NON-forensic known type is still too short.
    let mut block = vec![0u8; FORENSIC_SIZE];
    block[0..4].copy_from_slice(&TYPE_BLOCK.to_le_bytes());
    assert_eq!(
        canonical_report(&block),
        format!("err short_buffer {FORENSIC_SIZE}\n")
    );
}

#[test]
fn overlay_fields() {
    let mut b = rec(TYPE_OVERLAY_COPY_UP);
    put_u32(&mut b, PB, 55); // pid
    put_u64(&mut b, PB + 8, 66); // cgid
    put_u64(&mut b, PB + 16, 0xabcd); // src_ino
    put_u32(&mut b, PB + 24, 777); // src_dev
    b[PB + 32] = 9; // deny_flags
    let r = canonical_report(&b);
    assert_eq!(line(&r, "type"), "type overlay_copy_up");
    assert_eq!(line(&r, "pid"), "pid 55");
    assert_eq!(line(&r, "cgid"), "cgid 66");
    assert_eq!(line(&r, "src_ino"), "src_ino 43981");
    assert_eq!(line(&r, "src_dev"), "src_dev 777");
    assert_eq!(line(&r, "deny_flags"), "deny_flags 9");
}

#[test]
fn exec_argv_slots() {
    let mut b = rec(TYPE_EXEC_ARGV);
    put_u32(&mut b, PB, 1234); // pid
    put_u16(&mut b, PB + 16, 3); // argc
    put_u16(&mut b, PB + 18, 12); // total_len
    let argv = PB + 24;
    put_bytes(&mut b, argv, b"ls\0"); // slot 0
    put_bytes(&mut b, argv + ARGV_SLOT, b"-la\0"); // slot 1
    put_bytes(&mut b, argv + 2 * ARGV_SLOT, b"/root\0"); // slot 2
    put_bytes(&mut b, argv + 3 * ARGV_SLOT, b"ignored\0"); // beyond argc
    let r = canonical_report(&b);
    assert_eq!(line(&r, "type"), "type exec_argv");
    assert_eq!(line(&r, "argc"), "argc 3");
    assert_eq!(line(&r, "total_len"), "total_len 12");
    assert_eq!(line(&r, "argv_count"), "argv_count 3");
    assert_eq!(line(&r, "arg0_hex"), "arg0_hex 6c73"); // ls
    assert_eq!(line(&r, "arg1_hex"), "arg1_hex 2d6c61"); // -la
    assert_eq!(line(&r, "arg2_hex"), "arg2_hex 2f726f6f74"); // /root
    assert!(!r.contains("arg3_hex"));
}

#[test]
fn exec_argv_clamped_to_max_entries() {
    let mut b = rec(TYPE_EXEC_ARGV);
    put_u16(&mut b, PB + 16, 9999); // argc absurd
    let r = canonical_report(&b);
    assert_eq!(line(&r, "argv_count"), "argv_count 8"); // kMaxArgvEntries
    assert!(r.contains("arg7_hex"));
    assert!(!r.contains("arg8_hex"));
}

#[test]
fn comm_no_nul_uses_full_width() {
    let mut b = rec(TYPE_EXEC);
    put_bytes(&mut b, PB + 24, &[0x41u8; COMM_LEN]); // 16 'A', no NUL
    let r = canonical_report(&b);
    assert_eq!(
        line(&r, "comm_hex"),
        format!("comm_hex {}", "41".repeat(16))
    );
}

#[test]
fn comm_embedded_nul_truncates() {
    let mut b = rec(TYPE_EXEC);
    put_bytes(&mut b, PB + 24, b"ab\0XYZ"); // strnlen stops at first NUL
    let r = canonical_report(&b);
    assert_eq!(line(&r, "comm_hex"), "comm_hex 6162"); // "ab"
}

#[test]
fn short_buffer_reports_length() {
    // Below 4 bytes the type discriminant can't even be read.
    for len in [0usize, 1, 2, 3] {
        let b = vec![0u8; len];
        assert_eq!(canonical_report(&b), format!("err short_buffer {len}\n"));
    }
    // A known non-forensic type needs a full Event (344); shorter -> short_buffer.
    for len in [4usize, 8, 100, EVENT_SIZE - 1] {
        let mut b = vec![0u8; len];
        b[0..4].copy_from_slice(&TYPE_BLOCK.to_le_bytes());
        assert_eq!(canonical_report(&b), format!("err short_buffer {len}\n"));
    }
    // exactly EVENT_SIZE with an unknown type (0) -> unknown marker, not short.
    assert_eq!(canonical_report(&vec![0u8; EVENT_SIZE]), "unknown_type 0\n");
    // an unknown type only needs the 4-byte discriminant — never short above it.
    let mut u = vec![0u8; 10];
    u[0..4].copy_from_slice(&999u32.to_le_bytes());
    assert_eq!(canonical_report(&u), "unknown_type 999\n");
}

#[test]
fn unknown_type_marker() {
    for ty in [0u32, 5, 9, 16, 23, 31, 1000, u32::MAX] {
        let b = rec(ty);
        let known = matches!(
            ty,
            1..=4 | 10..=15 | 20..=22 | 30
        );
        if !known {
            assert_eq!(canonical_report(&b), format!("unknown_type {ty}\n"));
        }
    }
}

#[test]
fn extra_trailing_bytes_ignored() {
    // handle_event ignores `size`; a longer buffer decodes its first EVENT_SIZE
    // bytes identically.
    let mut b = rec(TYPE_EXEC);
    put_u32(&mut b, PB, 42);
    let exact = canonical_report(&b);
    b.extend_from_slice(&[0xff; 64]);
    assert_eq!(canonical_report(&b), exact);
}

#[test]
fn adversarial_inputs_never_panic() {
    // Deterministic LCG over many lengths and byte patterns; the decoder must
    // return a String for every input and never panic / over-read.
    let mut state: u64 = 0x9e37_79b9_7f4a_7c15;
    let mut next = || {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (state >> 33) as u32
    };
    for _ in 0..20_000 {
        let len = (next() as usize) % (EVENT_SIZE + 80);
        let mut b = vec![0u8; len];
        for byte in b.iter_mut() {
            *byte = next() as u8;
        }
        // Bias the type field toward recognized values to exercise every arm.
        if len >= 4 {
            let ty = [1u32, 2, 3, 4, 10, 13, 15, 20, 22, 30, 999][(next() as usize) % 11];
            b[0..4].copy_from_slice(&ty.to_le_bytes());
        }
        let _ = canonical_report(&b);
    }
}
