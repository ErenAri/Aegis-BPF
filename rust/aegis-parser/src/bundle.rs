//! Memory-safe parser for the signed-policy-bundle header — a faithful Rust port
//! of `parse_signed_bundle` (`src/crypto.cpp`).
//!
//! This is the second oxidation target on the untrusted-input boundary (after
//! the policy file). A signed bundle is operator/CI-supplied and is the input to
//! signature verification, so its decoder walks attacker-influenceable bytes;
//! getting the *split point* and field parsing exactly right is security-relevant
//! (a divergence could change which bytes are treated as the signed policy body).
//!
//! Like `policy`, it is NOT wired into the production path — it is proven against
//! the C++ implementation by a differential parity harness
//! (`scripts/rust_bundle_parity.sh`) and the eventual swap is a wiring change
//! through the crate's FFI seam.
//!
//! Fidelity contract: this reproduces the observable behavior of
//! `parse_signed_bundle` — the same separator rule (the first `"---"` substring,
//! anywhere), the same header-line handling, the same recognized keys, the same
//! first-error-wins ordering and error classes, and — crucially — the same
//! *lenient* integer parsing as C++ `std::stoul`/`std::stoull` (skip leading
//! whitespace, accept a leading sign with `-` wrapping for unsigned, ignore
//! trailing non-digits, treat overflow as an error). Residual divergence is
//! quantified by the parity harness over a corpus + generated bundles.

use std::fmt::Write as _;

const BUNDLE_HEADER: &[u8] = b"AEGIS-POLICY-BUNDLE-V1";
const BUNDLE_SEPARATOR: &[u8] = b"---";

/// Parsed bundle. Mirrors the parse-relevant fields of C++ `SignedPolicyBundle`,
/// which is value-initialized (`bundle{}`), so absent byte fields are all-zero
/// here too (we do not distinguish "absent" from "all-zero hex", matching C++).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bundle {
    pub format_version: u32,
    pub policy_version: u64,
    pub timestamp: u64,
    pub expires: u64,
    pub signer_key: [u8; 32],
    pub signature: [u8; 64],
    pub policy_sha256: String,
    pub policy_content: Vec<u8>,
}

impl Default for Bundle {
    fn default() -> Self {
        Bundle {
            format_version: 0,
            policy_version: 0,
            timestamp: 0,
            expires: 0,
            signer_key: [0u8; 32],
            signature: [0u8; 64],
            policy_sha256: String::new(),
            policy_content: Vec::new(),
        }
    }
}

fn is_space(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

/// Byte-exact analogue of `aegis::trim_string` (std::isspace on unsigned char).
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

/// Faithful `std::stoull` (base 10, via strtoull): skip leading whitespace,
/// accept an optional `+`/`-` (with `-` wrapping for unsigned, as strtoull does),
/// require >=1 digit, ignore trailing non-digits, and treat magnitude overflow
/// as an error. Returns `None` for "no digits" and "overflow" alike — the C++
/// caller catches `std::exception` for both and yields the same "Invalid X".
fn c_stoull(s: &[u8]) -> Option<u64> {
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
    let mut acc: u64 = 0;
    let mut overflow = false;
    while i < s.len() && s[i].is_ascii_digit() {
        let d = (s[i] - b'0') as u64;
        match acc.checked_mul(10).and_then(|v| v.checked_add(d)) {
            Some(v) => acc = v,
            None => overflow = true, // keep consuming digits, like strtoull
        }
        i += 1;
    }
    if i == start || overflow {
        return None;
    }
    Some(if neg { acc.wrapping_neg() } else { acc })
}

fn hex_digit_value(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(10 + (c - b'a')),
        b'A'..=b'F' => Some(10 + (c - b'A')),
        _ => None,
    }
}

/// Faithful `hex_to_bytes`: requires exactly `out.len() * 2` hex chars.
fn hex_to_bytes(hex: &[u8], out: &mut [u8]) -> bool {
    if hex.len() != out.len() * 2 {
        return false;
    }
    for (i, slot) in out.iter_mut().enumerate() {
        match (hex_digit_value(hex[2 * i]), hex_digit_value(hex[2 * i + 1])) {
            (Some(hi), Some(lo)) => *slot = (hi << 4) | lo,
            _ => return false,
        }
    }
    true
}

/// Faithful `parse_header_line`: split on the FIRST ':', trim both sides, require
/// a non-empty key. Returns None when there is no ':' or the key is empty.
fn parse_header_line(line: &[u8]) -> Option<(&[u8], &[u8])> {
    let pos = line.iter().position(|&b| b == b':')?;
    let key = trim(&line[..pos]);
    let value = trim(&line[pos + 1..]);
    if key.is_empty() {
        return None;
    }
    Some((key, value))
}

/// Parse a signed-policy-bundle. Mirrors `parse_signed_bundle`: returns the
/// parsed bundle, or the verbatim primary error message on the first failure.
pub fn parse_signed_bundle(content: &[u8]) -> Result<Bundle, String> {
    let mut bundle = Bundle::default();

    // Separator = first "---" substring anywhere (C++ content.find("---")).
    let sep_pos = content
        .windows(BUNDLE_SEPARATOR.len())
        .position(|w| w == BUNDLE_SEPARATOR)
        .ok_or("Bundle missing separator line (---)")?;

    let header_section = &content[..sep_pos];
    let mut policy_section = &content[sep_pos + BUNDLE_SEPARATOR.len()..];

    // Trim leading newlines from the policy section (C++ erases leading \n/\r).
    while let Some((&first, rest)) = policy_section.split_first() {
        if first == b'\n' || first == b'\r' {
            policy_section = rest;
        } else {
            break;
        }
    }
    bundle.policy_content = policy_section.to_vec();

    let mut found_header = false;
    // std::getline over the header section: split on '\n'; '\r' is left for trim.
    for raw in header_section.split(|&b| b == b'\n') {
        let line = trim(raw);
        if line.is_empty() {
            continue;
        }

        if !found_header {
            if line != BUNDLE_HEADER {
                return Err("Invalid bundle header".to_string());
            }
            found_header = true;
            continue;
        }

        let Some((key, value)) = parse_header_line(line) else {
            continue;
        };

        match key {
            b"format_version" => match c_stoull(value) {
                Some(v) => bundle.format_version = v as u32, // C++ casts stoul -> uint32_t
                None => return Err("Invalid format_version".to_string()),
            },
            b"policy_version" => match c_stoull(value) {
                Some(v) => bundle.policy_version = v,
                None => return Err("Invalid policy_version".to_string()),
            },
            b"timestamp" => match c_stoull(value) {
                Some(v) => bundle.timestamp = v,
                None => return Err("Invalid timestamp".to_string()),
            },
            b"expires" => match c_stoull(value) {
                Some(v) => bundle.expires = v,
                None => return Err("Invalid expires".to_string()),
            },
            b"signer_key" => {
                // decode_public_key trims again, then requires exactly 64 hex.
                if !hex_to_bytes(trim(value), &mut bundle.signer_key) {
                    return Err("Invalid signer_key".to_string());
                }
            }
            b"signature" => {
                if !hex_to_bytes(trim(value), &mut bundle.signature) {
                    return Err("Invalid signature".to_string());
                }
            }
            b"policy_sha256" => {
                bundle.policy_sha256 = String::from_utf8_lossy(value).to_string();
            }
            _ => {} // unknown keys ignored
        }
    }

    if !found_header {
        return Err("Bundle header not found".to_string());
    }
    if bundle.format_version == 0 {
        return Err("Missing format_version in bundle".to_string());
    }

    Ok(bundle)
}

/// FNV-1a 64-bit over `data`. Dependency-free content fingerprint for the parity
/// harness (the C++ side computes the identical hash), so the harness can compare
/// the extracted policy body exactly without dumping raw (possibly large) bytes.
pub fn fnv1a64(data: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in data {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Canonical, machine-comparable dump of the parse result, for the differential
/// parity harness. The C++ `aegisbpf policy bundle-canonical` subcommand emits
/// this byte-for-byte. On success: `ok` + every parsed field (byte arrays as
/// lowercase hex, policy body as length + FNV-1a). On failure: `err <message>`
/// with the verbatim primary error.
pub fn canonical_report(result: &Result<Bundle, String>) -> String {
    let mut out = String::new();
    match result {
        Err(msg) => {
            let _ = writeln!(out, "err {msg}");
        }
        Ok(b) => {
            let _ = writeln!(out, "ok");
            let _ = writeln!(out, "format_version {}", b.format_version);
            let _ = writeln!(out, "policy_version {}", b.policy_version);
            let _ = writeln!(out, "timestamp {}", b.timestamp);
            let _ = writeln!(out, "expires {}", b.expires);
            let _ = writeln!(out, "signer_key {}", to_hex(&b.signer_key));
            let _ = writeln!(out, "signature {}", to_hex(&b.signature));
            let _ = writeln!(out, "policy_sha256 {}", b.policy_sha256);
            let _ = writeln!(out, "policy_content_len {}", b.policy_content.len());
            let _ = writeln!(
                out,
                "policy_content_fnv1a64 {:016x}",
                fnv1a64(&b.policy_content)
            );
        }
    }
    out
}

#[cfg(test)]
mod tests;
