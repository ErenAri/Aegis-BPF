//! Memory-safe decoder for the BPF ring-buffer event records — a faithful Rust
//! port of the C++ event consumer (`handle_event` + the `print_*_event` field
//! extraction in `src/events.cpp`).
//!
//! This is the third oxidation target on the untrusted-input boundary (after the
//! policy file and the signed bundle). Of the three it carries the most raw
//! memory-safety value: the C++ consumer does
//! `static_cast<const Event*>(data)` on a ring-buffer record and then reads
//! fixed-offset fields and walks fixed-size `char` arrays — and crucially it
//! **discards the `size` argument** (`int handle_event(void*, void* data, size_t)`),
//! so a short or malformed record is read out of bounds. The kernel BPF program
//! is the normal producer, but a memory-safe decoder that bounds-checks every
//! read is defense-in-depth on exactly the byte boundary where a producer/consumer
//! struct-layout drift would otherwise become an out-of-bounds read.
//!
//! Like `policy` and `bundle`, it is NOT wired into the production path — it is
//! proven against the C++ implementation by a differential parity harness
//! (`scripts/rust_event_parity.sh`). The eventual swap is a wiring change through
//! a C ABI seam still to be added for this decoder, mirroring the policy `ffi`
//! module — not a rewrite.
//!
//! # Fidelity contract
//!
//! This reproduces the observable behavior of `handle_event` **as written**:
//!
//! * Dispatch on the `u32` `type` at byte offset 0 of the record.
//! * Every typed payload is read through the C++ `Event` union, whose members
//!   begin at byte offset 8 (4-byte `type` + 4 bytes of alignment padding;
//!   verified by a layout probe against `src/types.hpp`). So a payload field at
//!   struct-offset `k` lives at record offset `8 + k`.
//! * `char[]` fields decode like C++ `to_string(buf, n)` = `string(buf,
//!   strnlen(buf, n))` — bytes up to the first NUL within the fixed width.
//! * Multi-byte integers are little-endian (native order on the x86-64 / aarch64
//!   hosts that run the daemon, matching the in-kernel writes).
//! * The net-block event label is derived from `direction` and the kernel-block
//!   label from the `rule_type` string, exactly as `print_net_block_event` /
//!   `print_kernel_block_event` compute them.
//!
//! ## Faithful to a latent C++ quirk (documented, not fixed here)
//!
//! `handle_event` reads forensic events through `e->forensic` at offset 8, but
//! the BPF side emits a *bare* `forensic_event` (its own `type` at offset 0,
//! `sizeof == 104`). For a real bare wire record that is an 8-byte field shift
//! and an 8-byte over-read. This port faithfully mirrors the offset-8 read
//! because a drop-in replacement must preserve `handle_event`'s behavior; the
//! parity harness feeds `Event`-shaped (offset-8 payload) records, for which the
//! read is well-formed and meaningful. The producer/consumer size mismatch is a
//! separate, human-reviewed concern, not something a fidelity-preserving
//! oxidation should silently change.
//!
//! # Honest scope
//!
//! The canonical dump compared by the harness pins the *decode* — the part that
//! is memory-unsafe in C++: field offsets, integer endianness, NUL-terminated
//! `char[]` extraction, and the direction/rule_type → label logic. `char[]` and
//! address fields are emitted as length-exact lowercase hex so arbitrary bytes
//! compare unambiguously. Address *text* formatting (`inet_ntop` vs Rust's
//! `Ipv6Addr` Display) is presentation, not decode, and is intentionally out of
//! scope (see the existing `inet_ntop` caveat in the crate README); the raw
//! address bytes are pinned by hex.

use std::fmt::Write as _;

/// Wire size of a C++ `Event` record (`sizeof(aegis::Event)`), verified by a
/// layout probe against `src/types.hpp`. The union payload begins at
/// [`PAYLOAD`]; the largest payload (`BlockEvent`, 336 B) ends exactly here.
pub const EVENT_SIZE: usize = 344;

/// Byte offset of the union payload within an `Event` (4-byte `type` + 4 pad).
const PAYLOAD: usize = 8;

// Event type discriminants (`enum EventType`, src/types.hpp).
const TYPE_EXEC: u32 = 1;
const TYPE_BLOCK: u32 = 2;
const TYPE_EXEC_ARGV: u32 = 3;
const TYPE_FORENSIC_BLOCK: u32 = 4;
const TYPE_NET_CONNECT_BLOCK: u32 = 10;
const TYPE_NET_BIND_BLOCK: u32 = 11;
const TYPE_NET_LISTEN_BLOCK: u32 = 12;
const TYPE_NET_ACCEPT_BLOCK: u32 = 13;
const TYPE_NET_SENDMSG_BLOCK: u32 = 14;
const TYPE_NET_RECVMSG_BLOCK: u32 = 15;
const TYPE_KERNEL_PTRACE_BLOCK: u32 = 20;
const TYPE_KERNEL_MODULE_BLOCK: u32 = 21;
const TYPE_KERNEL_BPF_BLOCK: u32 = 22;
const TYPE_OVERLAY_COPY_UP: u32 = 30;

// Field-width constants (src/types.hpp).
const COMM_LEN: usize = 16;
const ACTION_LEN: usize = 8;
const RULE_TYPE_LEN: usize = 16;
const DENY_PATH_MAX: usize = 256;
const ANCESTOR_MAX_DEPTH: usize = 8;
const MAX_ARGV_ENTRIES: usize = 8;
const ARGV_SLOT: usize = 32; // kMaxArgvSize(256) / kMaxArgvEntries(8)

const FAMILY_IPV4: u8 = 2;
const PROTO_TCP: u8 = 6;
const PROTO_UDP: u8 = 17;

// ---- bounds-checked little-endian readers --------------------------------
// Every read is guarded by the up-front `buf.len() >= EVENT_SIZE` check in
// `canonical_report`; these helpers slice within that window. They take the
// already-resolved absolute record offset (`PAYLOAD + struct_offset`).

fn rd_u8(buf: &[u8], off: usize) -> u8 {
    buf[off]
}

fn rd_u16(buf: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([buf[off], buf[off + 1]])
}

fn rd_u32(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

fn rd_u64(buf: &[u8], off: usize) -> u64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&buf[off..off + 8]);
    u64::from_le_bytes(b)
}

/// Lowercase hex of `bytes`.
fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// The `to_string(buf, max)` extraction at record offset `off`: the bytes up to
/// the first NUL within the `max`-wide field (C++ `string(buf, strnlen(buf, max))`).
fn cstr(buf: &[u8], off: usize, max: usize) -> &[u8] {
    let field = &buf[off..off + max];
    let len = field.iter().position(|&b| b == 0).unwrap_or(max);
    &field[..len]
}

/// Hex of the [`cstr`] extraction — the form the canonical dump emits for
/// `char[]` fields so arbitrary bytes compare unambiguously.
fn cstr_hex(buf: &[u8], off: usize, max: usize) -> String {
    to_hex(cstr(buf, off, max))
}

/// Canonical, machine-comparable dump of the decoded record, for the differential
/// parity harness. The C++ `aegisbpf policy event-canonical` subcommand emits this
/// byte-for-byte.
///
/// * `buf.len() < EVENT_SIZE` → `err short_buffer <len>` (the bounds check the C++
///   `handle_event` lacks; both sides agree, so truncated records can be fuzzed).
/// * an unrecognized `type` → `unknown_type <n>` (C++ `handle_event` prints
///   nothing; both sides emit this deterministic marker so they agree).
/// * otherwise `type <label>` + every decoded field (ints decimal, `char[]` and
///   address bytes as length-exact lowercase hex).
pub fn canonical_report(buf: &[u8]) -> String {
    if buf.len() < EVENT_SIZE {
        return format!("err short_buffer {}\n", buf.len());
    }
    let ty = rd_u32(buf, 0);
    match ty {
        TYPE_EXEC => dump_exec_event(buf),
        TYPE_BLOCK => dump_block(buf),
        TYPE_EXEC_ARGV => dump_exec_argv(buf),
        TYPE_FORENSIC_BLOCK => dump_forensic(buf),
        TYPE_NET_CONNECT_BLOCK
        | TYPE_NET_BIND_BLOCK
        | TYPE_NET_LISTEN_BLOCK
        | TYPE_NET_ACCEPT_BLOCK
        | TYPE_NET_SENDMSG_BLOCK
        | TYPE_NET_RECVMSG_BLOCK => dump_net_block(buf),
        TYPE_KERNEL_PTRACE_BLOCK | TYPE_KERNEL_MODULE_BLOCK | TYPE_KERNEL_BPF_BLOCK => {
            dump_kernel_block(buf)
        }
        TYPE_OVERLAY_COPY_UP => dump_overlay(buf),
        other => format!("unknown_type {other}\n"),
    }
}

// ExecEvent @ PAYLOAD: pid@0 ppid@4 start_time@8 cgid@16 comm@24[16]
//                      ancestor_pids@40[8*u32] ancestor_count@72
fn dump_exec_event(buf: &[u8]) -> String {
    let mut o = String::new();
    let _ = writeln!(o, "type exec");
    let _ = writeln!(o, "pid {}", rd_u32(buf, PAYLOAD));
    let _ = writeln!(o, "ppid {}", rd_u32(buf, PAYLOAD + 4));
    let _ = writeln!(o, "start_time {}", rd_u64(buf, PAYLOAD + 8));
    let _ = writeln!(o, "cgid {}", rd_u64(buf, PAYLOAD + 16));
    let _ = writeln!(o, "comm_hex {}", cstr_hex(buf, PAYLOAD + 24, COMM_LEN));
    let count = rd_u8(buf, PAYLOAD + 72);
    let _ = writeln!(o, "ancestor_count {count}");
    let used = (count as usize).min(ANCESTOR_MAX_DEPTH);
    let mut ancestors = String::new();
    for i in 0..used {
        if i > 0 {
            ancestors.push(',');
        }
        let _ = write!(ancestors, "{}", rd_u32(buf, PAYLOAD + 40 + i * 4));
    }
    let _ = writeln!(o, "ancestors {ancestors}");
    o
}

// BlockEvent @ PAYLOAD: ppid@0 start_time@8 parent_start_time@16 pid@24 cgid@32
//                       comm@40[16] ino@56 dev@64 path@68[256] action@324[8]
fn dump_block(buf: &[u8]) -> String {
    let mut o = String::new();
    let _ = writeln!(o, "type block");
    let _ = writeln!(o, "pid {}", rd_u32(buf, PAYLOAD + 24));
    let _ = writeln!(o, "ppid {}", rd_u32(buf, PAYLOAD));
    let _ = writeln!(o, "start_time {}", rd_u64(buf, PAYLOAD + 8));
    let _ = writeln!(o, "parent_start_time {}", rd_u64(buf, PAYLOAD + 16));
    let _ = writeln!(o, "cgid {}", rd_u64(buf, PAYLOAD + 32));
    let _ = writeln!(o, "comm_hex {}", cstr_hex(buf, PAYLOAD + 40, COMM_LEN));
    let _ = writeln!(o, "ino {}", rd_u64(buf, PAYLOAD + 56));
    let _ = writeln!(o, "dev {}", rd_u32(buf, PAYLOAD + 64));
    let _ = writeln!(o, "path_hex {}", cstr_hex(buf, PAYLOAD + 68, DENY_PATH_MAX));
    let _ = writeln!(o, "action_hex {}", cstr_hex(buf, PAYLOAD + 324, ACTION_LEN));
    o
}

// ExecArgvEvent @ PAYLOAD: pid@0 start_time@8 argc@16 total_len@18 argv@24[256]
fn dump_exec_argv(buf: &[u8]) -> String {
    let mut o = String::new();
    let _ = writeln!(o, "type exec_argv");
    let _ = writeln!(o, "pid {}", rd_u32(buf, PAYLOAD));
    let _ = writeln!(o, "start_time {}", rd_u64(buf, PAYLOAD + 8));
    let argc = rd_u16(buf, PAYLOAD + 16);
    let _ = writeln!(o, "argc {argc}");
    let _ = writeln!(o, "total_len {}", rd_u16(buf, PAYLOAD + 18));
    let used = (argc as usize).min(MAX_ARGV_ENTRIES);
    let _ = writeln!(o, "argv_count {used}");
    let argv_base = PAYLOAD + 24;
    for i in 0..used {
        let _ = writeln!(
            o,
            "arg{i}_hex {}",
            cstr_hex(buf, argv_base + i * ARGV_SLOT, ARGV_SLOT)
        );
    }
    o
}

// ForensicEvent @ PAYLOAD (faithful to handle_event's offset-8 union read):
//   type@0 pid@4 ppid@8 start_time@16 parent_start_time@24 cgid@32 comm@40[16]
//   ino@56 dev@64 uid@68 gid@72 exec_ino@80 exec_dev@88 exec_stage@92
//   verified_exec@93 exec_identity_known@94 action@96[8]
fn dump_forensic(buf: &[u8]) -> String {
    let mut o = String::new();
    let _ = writeln!(o, "type forensic_block");
    let _ = writeln!(o, "pid {}", rd_u32(buf, PAYLOAD + 4));
    let _ = writeln!(o, "ppid {}", rd_u32(buf, PAYLOAD + 8));
    let _ = writeln!(o, "start_time {}", rd_u64(buf, PAYLOAD + 16));
    let _ = writeln!(o, "parent_start_time {}", rd_u64(buf, PAYLOAD + 24));
    let _ = writeln!(o, "cgid {}", rd_u64(buf, PAYLOAD + 32));
    let _ = writeln!(o, "comm_hex {}", cstr_hex(buf, PAYLOAD + 40, COMM_LEN));
    let _ = writeln!(o, "ino {}", rd_u64(buf, PAYLOAD + 56));
    let _ = writeln!(o, "dev {}", rd_u32(buf, PAYLOAD + 64));
    let _ = writeln!(o, "uid {}", rd_u32(buf, PAYLOAD + 68));
    let _ = writeln!(o, "gid {}", rd_u32(buf, PAYLOAD + 72));
    let _ = writeln!(o, "exec_ino {}", rd_u64(buf, PAYLOAD + 80));
    let _ = writeln!(o, "exec_dev {}", rd_u32(buf, PAYLOAD + 88));
    let _ = writeln!(o, "exec_stage {}", rd_u8(buf, PAYLOAD + 92));
    let _ = writeln!(o, "verified_exec {}", rd_u8(buf, PAYLOAD + 93));
    let _ = writeln!(o, "exec_identity_known {}", rd_u8(buf, PAYLOAD + 94));
    let _ = writeln!(o, "action_hex {}", cstr_hex(buf, PAYLOAD + 96, ACTION_LEN));
    o
}

fn net_event_label(direction: u8) -> &'static str {
    match direction {
        0 => "net_connect_block",
        1 => "net_bind_block",
        2 => "net_listen_block",
        3 => "net_accept_block",
        4 => "net_sendmsg_block",
        _ => "net_recvmsg_block",
    }
}

fn protocol_str(p: u8) -> String {
    match p {
        PROTO_TCP => "tcp".to_string(),
        PROTO_UDP => "udp".to_string(),
        other => other.to_string(),
    }
}

// NetBlockEvent @ PAYLOAD: pid@0 ppid@4 start_time@8 parent_start_time@16 cgid@24
//   comm@32[16] family@48 protocol@49 local_port@50 remote_port@52 direction@54
//   remote_ipv4@56[4] remote_ipv6@60[16] action@76[8] rule_type@84[16]
fn dump_net_block(buf: &[u8]) -> String {
    let mut o = String::new();
    let direction = rd_u8(buf, PAYLOAD + 54);
    let family = rd_u8(buf, PAYLOAD + 48);
    let _ = writeln!(o, "type {}", net_event_label(direction));
    let _ = writeln!(o, "pid {}", rd_u32(buf, PAYLOAD));
    let _ = writeln!(o, "ppid {}", rd_u32(buf, PAYLOAD + 4));
    let _ = writeln!(o, "start_time {}", rd_u64(buf, PAYLOAD + 8));
    let _ = writeln!(o, "parent_start_time {}", rd_u64(buf, PAYLOAD + 16));
    let _ = writeln!(o, "cgid {}", rd_u64(buf, PAYLOAD + 24));
    let _ = writeln!(o, "comm_hex {}", cstr_hex(buf, PAYLOAD + 32, COMM_LEN));
    // family rendered the way the JSON does: ipv4 when ==2, else ipv6.
    let _ = writeln!(
        o,
        "family {}",
        if family == FAMILY_IPV4 {
            "ipv4"
        } else {
            "ipv6"
        }
    );
    let _ = writeln!(o, "family_raw {family}");
    let _ = writeln!(o, "protocol {}", protocol_str(rd_u8(buf, PAYLOAD + 49)));
    let _ = writeln!(o, "local_port {}", rd_u16(buf, PAYLOAD + 50));
    let _ = writeln!(o, "remote_port {}", rd_u16(buf, PAYLOAD + 52));
    let _ = writeln!(o, "direction {direction}");
    let _ = writeln!(
        o,
        "remote_ipv4_hex {}",
        to_hex(&buf[PAYLOAD + 56..PAYLOAD + 60])
    );
    let _ = writeln!(
        o,
        "remote_ipv6_hex {}",
        to_hex(&buf[PAYLOAD + 60..PAYLOAD + 76])
    );
    let _ = writeln!(o, "action_hex {}", cstr_hex(buf, PAYLOAD + 76, ACTION_LEN));
    let _ = writeln!(
        o,
        "rule_type_hex {}",
        cstr_hex(buf, PAYLOAD + 84, RULE_TYPE_LEN)
    );
    o
}

// KernelBlockEvent @ PAYLOAD: pid@0 ppid@4 start_time@8 parent_start_time@16
//   cgid@24 comm@32[16] target_pid@48 action@56[8] rule_type@64[16]
fn dump_kernel_block(buf: &[u8]) -> String {
    let mut o = String::new();
    let _ = writeln!(o, "type kernel_block");
    let _ = writeln!(o, "pid {}", rd_u32(buf, PAYLOAD));
    let _ = writeln!(o, "ppid {}", rd_u32(buf, PAYLOAD + 4));
    let _ = writeln!(o, "start_time {}", rd_u64(buf, PAYLOAD + 8));
    let _ = writeln!(o, "parent_start_time {}", rd_u64(buf, PAYLOAD + 16));
    let _ = writeln!(o, "cgid {}", rd_u64(buf, PAYLOAD + 24));
    let _ = writeln!(o, "comm_hex {}", cstr_hex(buf, PAYLOAD + 32, COMM_LEN));
    let _ = writeln!(o, "target_pid {}", rd_u32(buf, PAYLOAD + 48));
    let _ = writeln!(o, "action_hex {}", cstr_hex(buf, PAYLOAD + 56, ACTION_LEN));
    let rule_type = cstr(buf, PAYLOAD + 64, RULE_TYPE_LEN);
    let _ = writeln!(o, "rule_type_hex {}", to_hex(rule_type));
    // print_kernel_block_event derives event_type = "kernel_" + to_string(rule_type)
    // + "_block"; emit that derived label as hex so the derivation itself is pinned
    // (and stays byte-safe when rule_type holds arbitrary bytes).
    let mut label = b"kernel_".to_vec();
    label.extend_from_slice(rule_type);
    label.extend_from_slice(b"_block");
    let _ = writeln!(o, "event_type_hex {}", to_hex(&label));
    o
}

// OverlayCopyUpEvent @ PAYLOAD: pid@0 cgid@8 src_ino@16 src_dev@24 deny_flags@32
fn dump_overlay(buf: &[u8]) -> String {
    let mut o = String::new();
    let _ = writeln!(o, "type overlay_copy_up");
    let _ = writeln!(o, "pid {}", rd_u32(buf, PAYLOAD));
    let _ = writeln!(o, "cgid {}", rd_u64(buf, PAYLOAD + 8));
    let _ = writeln!(o, "src_ino {}", rd_u64(buf, PAYLOAD + 16));
    let _ = writeln!(o, "src_dev {}", rd_u32(buf, PAYLOAD + 24));
    let _ = writeln!(o, "deny_flags {}", rd_u8(buf, PAYLOAD + 32));
    o
}

#[cfg(test)]
mod tests;
