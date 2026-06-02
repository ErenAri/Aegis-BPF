# BPF Object Integrity

AegisBPF verifies the compiled BPF object before loading it into the kernel, in
two complementary layers:

1. **Integrity (SHA-256 sidecar)** — detects accidental corruption / partial
   writes. Implemented in `src/bpf_integrity.cpp`.
2. **Authenticity (Ed25519 signature sidecar)** — detects deliberate tampering.
   A hash sidecar alone is *not* tamper-evident: an attacker who can overwrite
   `aegis.bpf.o` can also overwrite `aegis.bpf.sha256`. A detached Ed25519
   signature verified against a **trusted keystore** the attacker cannot rewrite
   closes that gap. Implemented in `src/bpf_signing.cpp`
   (`verify_bpf_signature()`), wired into the load path in `src/bpf_ops.cpp`
   immediately after the hash check.

Both run at daemon startup before `bpf_object__load()`. Both fail closed only
when the operator opts in (see below); a deployment with no sidecars and no
`AEGIS_REQUIRE_*` flags loads as before.

## Runtime Contract

### Integrity (hash)

- Object path: `AEGIS_BPF_OBJ` overrides auto-detection.
- Hash sidecar lookup: `AEGIS_BPF_OBJ_HASH_PATH`,
  `AEGIS_BPF_OBJ_HASH_INSTALL_PATH`, then `aegis.bpf.sha256` next to the object.
- Strict hash mode: `AEGIS_REQUIRE_BPF_HASH=1`.
- Enforce-mode daemon startup sets `AEGIS_REQUIRE_BPF_HASH=1` internally.

### Authenticity (signature)

- Signature sidecar: `<object>.sig` next to the object (e.g. `aegis.bpf.o.sig`).
- Trusted keys: the daemon loads `*.pub` (64-hex Ed25519 public keys) from the
  trusted keystore — `AEGIS_KEYS_DIR`, default the packaged keys directory — the
  **same** keystore used to verify signed policy bundles. The directory and key
  files are permission-validated and symlinks are rejected (`load_trusted_keys`).
- Strict signature mode: `AEGIS_REQUIRE_BPF_SIGNATURE=1` makes the load **fail
  closed** unless `<object>.sig` carries an Ed25519 signature over the object's
  SHA-256 digest that verifies against a trusted public key. This flag is now
  honoured at load time (it was previously parsed only by an unwired helper).
- If a `.sig` is present but `AEGIS_REQUIRE_BPF_SIGNATURE` is unset, the daemon
  verifies it *advisorily*: a match is logged, a mismatch logs a warning but does
  not block (so signatures can be rolled out before being required).

### Break-glass

- `AEGIS_ALLOW_UNSIGNED_BPF=1` permits a missing or mismatched hash **and** a
  missing/invalid signature, logging a warning each time. Use only to recover a
  host whose signing material is unavailable.

## Signing workflow

```sh
# 1. Generate an Ed25519 signer keypair: writes signer.key (128-hex secret,
#    mode 0600) and signer.pub (64-hex public).
aegisbpf bpf keygen --out signer

# 2. Install the public key in the trusted keystore.
aegisbpf keys add signer.pub

# 3. Sign the built object -> writes aegis.bpf.o.sig (sha256 + Ed25519 signature).
aegisbpf bpf sign --obj /usr/lib/aegisbpf/aegis.bpf.o --key signer.key --signer release

# 4. Require signatures at load time.
AEGIS_REQUIRE_BPF_SIGNATURE=1 aegisbpf run --enforce
```

Keep `signer.key` offline; only `signer.pub` needs to reach the host. The same
keypair format is used by `policy sign --key`.

## Expected Sidecars

- **Hash** (`aegis.bpf.sha256`): the first token must be the expected 64-hex
  SHA-256 digest for `aegis.bpf.o`. The packaged build writes only that digest;
  a `sha256sum`-style line with a filename is also accepted (first token read).
- **Signature** (`aegis.bpf.o.sig`): a small key/value text file. The daemon
  reads `sha256:<64-hex>` (the digest that was signed) and
  `signature:<128-hex>` (the Ed25519 signature over those digest bytes);
  `signer:`, `timestamp:`, `key_id:`, and `format_version:` are informational.

## Release signing (follow-up)

`aegis.bpf.sha256` is produced by the build (`CMakeLists.txt`) and shipped by the
packaging workflow. Producing and shipping `aegis.bpf.o.sig` in the release
pipeline requires a release **signing key** (a deployment/secret decision), so it
is left to operators: generate a keypair once, store the secret in the release
signer (e.g. a CI secret), add `bpf sign` after the build, and publish the
`.pub` for hosts to install. The load-time gate, signing tool, and on-disk
formats above are all in place.
