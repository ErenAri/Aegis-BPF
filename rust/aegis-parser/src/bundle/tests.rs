//! Unit + adversarial tests for the signed-bundle parser. These pin the contract
//! independently of the differential harness (which proves C++ parity).
use super::*;

fn parse(s: &str) -> Result<Bundle, String> {
    parse_signed_bundle(s.as_bytes())
}

const HK: &str = "AEGIS-POLICY-BUNDLE-V1";

// ---- low-level helpers ----

#[test]
fn c_stoull_matches_strtoull_leniency() {
    assert_eq!(c_stoull(b"0"), Some(0));
    assert_eq!(c_stoull(b"42"), Some(42));
    assert_eq!(c_stoull(b"  42"), Some(42)); // leading whitespace skipped
    assert_eq!(c_stoull(b"+7"), Some(7));
    assert_eq!(c_stoull(b"5abc"), Some(5)); // trailing junk ignored
    assert_eq!(c_stoull(b"abc"), None); // no digits -> invalid_argument
    assert_eq!(c_stoull(b""), None);
    assert_eq!(c_stoull(b"+"), None);
    assert_eq!(c_stoull(b"-1"), Some(u64::MAX)); // strtoull wraps unsigned negation
    assert_eq!(c_stoull(b"-2"), Some(u64::MAX - 1));
    assert_eq!(c_stoull(b"18446744073709551615"), Some(u64::MAX));
    assert_eq!(c_stoull(b"18446744073709551616"), None); // overflow -> out_of_range
}

#[test]
fn format_version_truncates_to_u32_like_static_cast() {
    // std::stoul returns 64-bit unsigned long on Linux, cast to uint32_t truncates.
    let b = parse(&format!("{HK}\nformat_version: 4294967297\n---\nbody")).unwrap();
    assert_eq!(b.format_version, 1); // 2^32 + 1 truncated
                                     // 2^32 exactly -> 0 -> "Missing format_version".
    let e = parse(&format!("{HK}\nformat_version: 4294967296\n---\nbody")).unwrap_err();
    assert_eq!(e, "Missing format_version in bundle");
}

// ---- structure ----

#[test]
fn missing_separator_errors() {
    assert_eq!(
        parse("AEGIS-POLICY-BUNDLE-V1\nformat_version: 1\n").unwrap_err(),
        "Bundle missing separator line (---)"
    );
}

#[test]
fn invalid_header_errors() {
    assert_eq!(
        parse("WRONG-HEADER\nformat_version: 1\n---\nbody").unwrap_err(),
        "Invalid bundle header"
    );
}

#[test]
fn header_not_found_when_header_section_blank() {
    // content begins with the separator -> empty header section -> no lines.
    assert_eq!(parse("---\nbody").unwrap_err(), "Bundle header not found");
}

#[test]
fn missing_format_version_errors() {
    assert_eq!(
        parse(&format!("{HK}\npolicy_version: 5\n---\nbody")).unwrap_err(),
        "Missing format_version in bundle"
    );
}

// ---- fields ----

#[test]
fn full_valid_bundle_parses_all_fields() {
    let sk = "a".repeat(64); // 32 bytes
    let sig = "b".repeat(128); // 64 bytes
    let src = format!(
        "{HK}\n\
         format_version: 1\n\
         policy_version: 7\n\
         timestamp: 1000\n\
         expires: 2000\n\
         signer_key: {sk}\n\
         signature: {sig}\n\
         policy_sha256: deadbeef\n\
         ---\n\
         version=1\n[deny_path]\n/etc/shadow\n"
    );
    let b = parse(&src).unwrap();
    assert_eq!(b.format_version, 1);
    assert_eq!(b.policy_version, 7);
    assert_eq!(b.timestamp, 1000);
    assert_eq!(b.expires, 2000);
    assert_eq!(b.signer_key, [0xaa; 32]);
    assert_eq!(b.signature, [0xbb; 64]);
    assert_eq!(b.policy_sha256, "deadbeef");
    assert_eq!(b.policy_content, b"version=1\n[deny_path]\n/etc/shadow\n");
}

#[test]
fn signer_key_and_signature_length_checked() {
    let short = parse(&format!(
        "{HK}\nformat_version: 1\nsigner_key: aabb\n---\nx"
    ))
    .unwrap_err();
    assert_eq!(short, "Invalid signer_key");
    let badsig = parse(&format!(
        "{HK}\nformat_version: 1\nsignature: notlongenough\n---\nx"
    ))
    .unwrap_err();
    assert_eq!(badsig, "Invalid signature");
}

#[test]
fn non_hex_signer_key_rejected() {
    let sk = "g".repeat(64); // right length, non-hex
    assert_eq!(
        parse(&format!(
            "{HK}\nformat_version: 1\nsigner_key: {sk}\n---\nx"
        ))
        .unwrap_err(),
        "Invalid signer_key"
    );
}

#[test]
fn unknown_keys_and_colonless_lines_ignored() {
    let b = parse(&format!(
        "{HK}\nformat_version: 1\nthis line has no colon\nunknown_key: whatever\n---\nbody"
    ))
    .unwrap();
    assert_eq!(b.format_version, 1);
    assert_eq!(b.policy_content, b"body");
}

#[test]
fn first_error_wins_in_line_order() {
    // invalid policy_version appears before invalid signature -> version error first.
    let e = parse(&format!(
        "{HK}\nformat_version: 1\npolicy_version: notanumber\nsignature: short\n---\nx"
    ))
    .unwrap_err();
    assert_eq!(e, "Invalid policy_version");
}

#[test]
fn separator_is_first_triple_dash_anywhere() {
    // The "---" inside the signer_key value is the split point (matches C++ find).
    let e = parse(&format!("{HK}\nsigner_key: ---\n---\nbody")).unwrap_err();
    // header_section = "AEGIS-...-V1\nsigner_key: " -> empty signer_key value -> invalid.
    assert_eq!(e, "Invalid signer_key");
}

#[test]
fn leading_newlines_trimmed_from_policy_body() {
    let b = parse(&format!("{HK}\nformat_version: 1\n---\n\r\n\nbody\n")).unwrap();
    assert_eq!(b.policy_content, b"body\n");
}

#[test]
fn crlf_header_lines_tolerated() {
    let b = parse(&format!("{HK}\r\nformat_version: 1\r\n---\r\nbody")).unwrap();
    assert_eq!(b.format_version, 1);
}

// ---- memory-safety / adversarial: must never panic ----

#[test]
fn adversarial_inputs_never_panic() {
    let cases: &[&[u8]] = &[
        b"",
        b"-",
        b"--",
        b"---",
        b"---\n",
        b"\x00\xff---\x00",
        b"AEGIS-POLICY-BUNDLE-V1",
        b"AEGIS-POLICY-BUNDLE-V1\nsigner_key:",
        b"AEGIS-POLICY-BUNDLE-V1\nformat_version: \n---",
        b"AEGIS-POLICY-BUNDLE-V1\n:novalue\n---\nx",
        "AEGIS-POLICY-BUNDLE-V1\nformat_version: 999999999999999999999999\n---\nx".as_bytes(),
        &[b'-'; 100_000],
    ];
    for c in cases {
        let _ = parse_signed_bundle(c); // just must not panic
    }
}

#[test]
fn fnv1a64_is_deterministic_and_distinguishes() {
    assert_eq!(fnv1a64(b""), 0xcbf29ce484222325);
    assert_eq!(fnv1a64(b"a"), fnv1a64(b"a"));
    assert_ne!(fnv1a64(b"a"), fnv1a64(b"b"));
    assert_ne!(fnv1a64(b"ab"), fnv1a64(b"ba"));
}
