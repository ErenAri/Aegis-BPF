{
  lib,
  stdenv,
  cmake,
  pkg-config,
  clang,
  bpftools,
  libbpf,
  elfutils,
  zlib,
  zstd,
  linuxHeaders,
  # Pre-generated vmlinux.h. CO-RE keeps the resulting object portable regardless
  # of which kernel's BTF it was generated from, so a checked-in header makes the
  # BPF build hermetic (no /sys/kernel/btf dependency). Same approach upstream CO-RE
  # projects (e.g. cloudflare/ebpf_exporter) use for reproducible packaging.
  vmlinuxHeader ? ./vmlinux.x86_64.h,
}:

stdenv.mkDerivation (finalAttrs: {
  pname = "aegisbpf";
  version = "0.10.0";

  # Local source, filtered to the inputs the build needs (the repo carries many
  # throwaway build-*/ trees that must not enter the store).
  src = lib.cleanSourceWith {
    src = ../..;
    filter =
      path: type:
      let
        rel = lib.removePrefix (toString ../.. + "/") (toString path);
        top = lib.head (lib.splitString "/" rel);
      in
      builtins.elem top [
        "CMakeLists.txt"
        "cmake"
        "src"
        "bpf"
        "config"
        "packaging"
        "LICENSE"
      ];
  };

  nativeBuildInputs = [
    cmake
    pkg-config
    clang
    bpftools
  ];

  buildInputs = [
    libbpf
    elfutils
    zlib
    zstd # elfutils' libelf.pc requires libzstd
    linuxHeaders # asm-generic/* UAPI headers for the BPF object
  ];

  cmakeFlags = [
    (lib.cmakeFeature "VMLINUX_H" (toString vmlinuxHeader))
    (lib.cmakeBool "BUILD_TESTING" false)
    (lib.cmakeBool "ENABLE_RUST_PARSER_LINK" false)
    (lib.cmakeBool "STATIC_LIBBPF" false)
  ];

  # `clang` here is the unwrapped compiler (see below) so the BPF object is built
  # with exactly `-target bpf` and none of the stdenv cc-wrapper's hardening flags
  # (e.g. -fzero-call-used-regs), which the bpf target rejects. Unwrapped clang has
  # no default system-header search path, so hand it the kernel UAPI headers
  # (asm-generic/*) via CPATH. The userspace C++ build uses the normal stdenv cc.
  CPATH = "${linuxHeaders}/include";

  # The upstream install() ships two system-config files to absolute /etc paths,
  # which a hermetic build cannot write. Redirect them under $out/etc.
  postPatch = ''
    substituteInPlace CMakeLists.txt \
      --replace-warn 'DESTINATION /etc/default' 'DESTINATION ${placeholder "out"}/etc/default' \
      --replace-warn 'DESTINATION /etc/aegisbpf' 'DESTINATION ${placeholder "out"}/etc/aegisbpf'
  '';

  meta = {
    description = "BPF-LSM runtime security agent with race-free in-kernel enforcement";
    homepage = "https://github.com/ErenAri/Aegis-BPF";
    license = lib.licenses.asl20;
    platforms = lib.platforms.linux;
    mainProgram = "aegisbpf";
  };
})
