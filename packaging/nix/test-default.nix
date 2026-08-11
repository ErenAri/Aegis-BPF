# Test entry point for building the aegisbpf Nix package in a hermetic sandbox
# (e.g. `nix-build packaging/nix/test-default.nix` inside a nixos/nix container).
# The final nixpkgs submission generates vmlinux.h in-build; here we feed a
# pre-generated one so the derisk build is self-contained.
let
  nixpkgs = fetchTarball {
    url = "https://github.com/NixOS/nixpkgs/archive/nixos-unstable.tar.gz";
  };
  pkgs = import nixpkgs { };
in
pkgs.callPackage ./package.nix {
  # vmlinuxHeader defaults to the checked-in ./vmlinux.x86_64.h.
  # Unwrapped clang for the BPF object: the stdenv cc-wrapper injects hardening
  # flags (e.g. -fzero-call-used-regs) that `-target bpf` rejects. Pinned to LLVM
  # 18 (the newest in the project's tested clang-15/17/18 matrix); newer LLVM
  # regresses BPF stack usage past the 512-byte verifier limit.
  clang = pkgs.llvmPackages_18.clang-unwrapped;
}
