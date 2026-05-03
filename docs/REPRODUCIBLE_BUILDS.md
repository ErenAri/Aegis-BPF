# Reproducible Builds

AegisBPF aims for **bit-for-bit reproducible builds**: two builds of the
same source tree, with the same compiler version and `SOURCE_DATE_EPOCH`,
produce a byte-identical `aegisbpf` binary regardless of:

- the absolute path of the source / build directory,
- the build host's hostname,
- the user (uid/gid) running the build,
- the wall-clock time at which the build runs.

This matters for supply-chain integrity. A reproducible build lets a
third party verify, from public source, that a published binary
contains exactly what the source says — without trusting the build
host. It is one of the [SLSA Level 3](https://slsa.dev/spec/v1.0/levels)
requirements and is a requirement for several distros (Debian, Arch,
NixOS) to ship official packages.

## How it's achieved

The reproducibility flags are centralised in
[`cmake/Reproducibility.cmake`](../cmake/Reproducibility.cmake) and
included once from the top-level [`CMakeLists.txt`](../CMakeLists.txt)
*after* all other compiler-flag manipulation. The module is enabled by
default; pass `-DAEGIS_REPRODUCIBLE_BUILD=OFF` to opt out (e.g. when
debugging path-dependent issues).

Knobs we apply:

| Flag                                  | What it removes                            |
|---------------------------------------|--------------------------------------------|
| `-ffile-prefix-map=<src>=.`           | absolute paths from `__FILE__` and assertions |
| `-ffile-prefix-map=<build>=.`         | absolute paths from generated headers       |
| `-fdebug-prefix-map=<src>=.`          | absolute paths from DWARF debug info        |
| `-fdebug-prefix-map=<build>=.`        | absolute paths from generated objects       |
| `-Wl,--build-id=sha1`                 | replaces random/uuid build-id with content hash |
| `ar -D` / `ranlib -D`                 | zeros mtime / uid / gid / mode in `.a` files |
| `SOURCE_DATE_EPOCH` (env)             | propagated to any tool that bakes timestamps |

We deliberately do **not**:

- strip the build-id (a content-addressed build-id is more useful than
  none — debuginfod and coredump tooling rely on it),
- post-process the BPF object's BTF section (clang's CO-RE pipeline is
  already deterministic given the same input source).

## CI verification

Every PR runs [`scripts/check_reproducible_build.sh`](../scripts/check_reproducible_build.sh)
via the [Reproducibility workflow](../.github/workflows/reproducibility.yml).
The script:

1. Stages two copies of the working tree at distinct absolute paths
   (`/tmp/aegis-repro-XXX/aaaaaa/src` vs `…/bbbbbbbbbbbbbb/src`).
2. Configures and builds each independently (`SKIP_BPF_BUILD=ON`,
   `BUILD_TESTING=OFF`, Release).
3. Compares `sha256sum` of the **full** `aegisbpf` ELF — not a stripped
   or section-extracted variant. If they don't match, the check fails.
4. On failure, runs `diffoscope` if available and retains the scratch
   trees for inspection (`KEEP_TMP=1`).

The use of two *different* absolute paths is deliberate: it forces any
remaining `__FILE__`-style leakage to surface as a diff. A naive
"build twice in the same dir" check would silently miss most
real-world reproducibility regressions.

## Running the check locally

```bash
scripts/check_reproducible_build.sh
```

Override knobs:

```bash
SOURCE_DATE_EPOCH=1700000000 \
CMAKE_GENERATOR=Ninja \
KEEP_TMP=1 \
scripts/check_reproducible_build.sh
```

`KEEP_TMP=1` retains the two scratch source/build trees for manual
inspection (for example with `diffoscope build-A/aegisbpf build-B/aegisbpf`).

## Toolchain prerequisites

- **GCC ≥ 8 / Clang ≥ 7** for `-ffile-prefix-map` support. Older
  toolchains will fall back to `-fdebug-prefix-map` (still applied) but
  may leak source paths into `__FILE__`.
- **GNU binutils ≥ 2.30** for `ar -D` / `ranlib -D` (deterministic
  archives). Released 2018; present on every supported distro.
- **GNU ld ≥ 2.27** for `--build-id=sha1`. Present everywhere.
- **rsync** (for the local check script).

## What this does *not* cover

- **The final container image.** The Dockerfile is not yet bit-for-bit
  reproducible (image layer timestamps, `apt` index ordering). Tracked
  separately; the binary inside the image is reproducible.
- **Cross-architecture builds.** The check runs on the same host arch
  it was built on; cross-builds for arm64 from x86_64 are reproducible
  per-target but the per-target hashes are obviously different.
- **Third-party static dependencies.** When `-DSTATIC_LIBBPF=ON`, libbpf
  is fetched and built from source. Its build is reproducible *if*
  `SOURCE_DATE_EPOCH` is set; otherwise libbpf's `make install` step
  may bake the wall-clock into archive members. The CI check uses
  system libbpf to keep the surface small.

## Verifying a release binary

To verify a released `aegisbpf` matches the public source at a given
tag:

```bash
git checkout v0.X.Y
export SOURCE_DATE_EPOCH=$(git log -1 --pretty=%ct)
scripts/check_reproducible_build.sh
sha256sum /tmp/aegis-repro-*/aaaaaa/build/aegisbpf
# Compare against the sha256 published in the release notes.
```

If the hashes match, the released binary is provably built from the
tagged source.
