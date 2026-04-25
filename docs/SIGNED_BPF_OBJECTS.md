# Signed BPF objects (Ed25519)

AegisBPF verifies the integrity of the kernel BPF object (`aegis.bpf.o`)
before handing it to libbpf. The verification has two layers:

1. **SHA-256 integrity** — the on-disk object must hash to a value
   recorded in `aegis.bpf.sha256` (or, equivalently, in the `sha256:`
   line of a sidecar `aegis.bpf.o.sig` file). This catches accidental
   corruption and naïve tampering. It has been in place since v0.1.
2. **Ed25519 signature** — the `aegis.bpf.o.sig` file may carry a
   detached Ed25519 signature over the 32-byte SHA-256 hash, signed by
   a key whose public half lives in the trusted keys directory. This
   catches tampering by an attacker who can also rewrite
   `aegis.bpf.sha256`.

This document covers layer 2: the runtime side of the Ed25519 signature
check.

## Sidecar `.sig` file format

Plain text, key/value, one per line:

```
format_version:1
sha256:<64 hex chars>            # SHA-256 of aegis.bpf.o (required)
signer_pubkey:<64 hex chars>     # Ed25519 public key (32 bytes, optional)
signature:<128 hex chars>        # Ed25519 signature over the 32-byte hash (optional)
signer:<freeform display name>   # informational
timestamp:<unix epoch>           # informational
key_id:<hex>                     # informational
```

`signer_pubkey` and `signature` are optional. A `.sig` file with only
`sha256:` is treated as the legacy hash-only format and accepted unless
`AEGIS_REQUIRE_BPF_SIG=1` is set.

The signature payload is the **raw 32-byte SHA-256 hash bytes**, not
the hex string. Sign with:

```bash
sha256sum aegis.bpf.o | head -c 64 | xxd -r -p \
  | openssl pkeyutl -sign -inkey signer.key -rawin > sig.bin
```

(or any Ed25519 implementation; the daemon uses TweetNaCl via
`crypto::verify_bytes`).

## Trust anchor

The signer's Ed25519 public key must appear as a `*.pub` file inside
the trusted keys directory:

- `AEGIS_KEYS_DIR` (env), if set, otherwise
- `/etc/aegisbpf/keys/`

Each `.pub` file holds a single 64-character hex-encoded public key.
The same directory is used for policy-bundle signing keys, so a single
key set can authorise both BPF objects and policies.

If `signer_pubkey` from the `.sig` file does not appear in
`load_trusted_keys()`, verification fails (unless
`AEGIS_ALLOW_UNSIGNED_BPF=1` is set as a break-glass).

## Environment variables

| Variable | Default | Effect |
|----------|---------|--------|
| `AEGIS_REQUIRE_BPF_SIG` | unset (off) | When truthy, missing or hash-only `.sig` files cause `verify_bpf_integrity` to fail. |
| `AEGIS_REQUIRE_BPF_HASH` | unset (off) | Independently requires the `.sha256` file to exist. |
| `AEGIS_ALLOW_UNSIGNED_BPF` | unset (off) | Break-glass. Downgrades any signature failure to a `WARN` log line. Use only for triage on isolated hosts. |
| `AEGIS_KEYS_DIR` | `/etc/aegisbpf/keys` | Trusted keys directory consulted for both BPF objects and policy bundles. |
| `AEGIS_BPF_OBJ` | resolved automatically | Path to the BPF object (`.bpf.o`); the `.sig` is found at `<path>.sig`. |

The integrity flow is:

1. Compute SHA-256 of the resolved BPF object.
2. Compare against `aegis.bpf.sha256` (primary, secondary, adjacent
   paths checked in order).
3. If a `aegis.bpf.o.sig` file exists, validate it:
   - `sha256:` line must equal step (1).
   - If `signer_pubkey` + `signature` are present, decode them, verify
     `signer_pubkey` is in the trusted keys directory, and verify the
     Ed25519 signature against the 32-byte hash bytes.
4. Hard-fail on any failure unless `AEGIS_ALLOW_UNSIGNED_BPF` is set.

Steps 3 and 4 are new in this release.

## Build-time signing (not yet automated)

This release ships the verification code only. The release pipeline
does not yet emit `aegis.bpf.o.sig` automatically — that will land in a
follow-up PR using Sigstore Cosign keyless signing (matching the
existing `.tar.gz` / `.deb` / `.rpm` signature posture in
[`.github/workflows/release.yml`](../.github/workflows/release.yml)).

To produce a `.sig` file out-of-band today:

```bash
# Generate a long-lived signer keypair (keep aegis-signer.key offline).
aegisbpf keygen --out aegis-signer

# Compute the hash and sign it.
SHA=$(sha256sum aegis.bpf.o | cut -d' ' -f1)
SIG=$(printf '%s' "$SHA" | xxd -r -p | \
       openssl pkeyutl -sign -inkey aegis-signer.key -rawin | xxd -p -c0)
PUB=$(cat aegis-signer.pub)

cat > aegis.bpf.o.sig <<EOF
format_version:1
sha256:${SHA}
signer_pubkey:${PUB}
signature:${SIG}
signer:release
timestamp:$(date +%s)
EOF

install -m0644 aegis-signer.pub /etc/aegisbpf/keys/release.pub
```

## Failure modes

| Condition | Default behaviour | With `AEGIS_REQUIRE_BPF_SIG=1` | With `AEGIS_ALLOW_UNSIGNED_BPF=1` |
|-----------|-------------------|-------------------------------|----------------------------------|
| `.sig` file missing | pass (warn) | **fail** | pass (warn) |
| `.sig` has only `sha256:` | pass (info log) | **fail** | pass (warn) |
| `signature` byte tampered | **fail** | **fail** | pass (warn) |
| `signer_pubkey` not trusted | **fail** | **fail** | pass (warn) |
| Object hash mismatch | **fail** | **fail** | pass (warn) |
| `signer_pubkey` malformed | **fail** | **fail** | pass (warn) |

## Implementation

- [`src/bpf_signing.cpp`](../src/bpf_signing.cpp) — `verify_bpf_signature()`.
- [`src/bpf_integrity.cpp`](../src/bpf_integrity.cpp) — calls
  `verify_bpf_signature()` after hash verification succeeds.
- [`src/crypto.cpp`](../src/crypto.cpp) — Ed25519 primitives via
  TweetNaCl, plus `load_trusted_keys()` reading `*.pub` files.
- [`tests/test_bpf_integrity.cpp`](../tests/test_bpf_integrity.cpp) —
  `BpfSignatureTest` cases cover valid / tampered / untrusted /
  missing / legacy / break-glass paths.

## See also

- [`docs/KEY_MANAGEMENT.md`](KEY_MANAGEMENT.md) — long-lived signer keys.
- [`SECURITY.md`](../SECURITY.md) — disclosure process, threat model summary.
- [`docs/THREAT_MODEL.md`](THREAT_MODEL.md) — attacker capabilities the BPF
  signature is intended to defeat.
