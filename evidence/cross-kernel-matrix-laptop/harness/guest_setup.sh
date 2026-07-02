#!/usr/bin/env bash
# Unified guest setup (Ubuntu/Debian). Installs deps, extracts the fixed source,
# builds userspace with SKIP_BPF_BUILD=ON against the host's clang-18 CO-RE object
# (kernel-independent), leaving a runnable agent for the batteries.
set -uo pipefail
exec > ~/setup.log 2>&1
echo "=== setup @ $(date -u +%FT%TZ) kernel $(uname -r) / $(. /etc/os-release; echo "$PRETTY_NAME") ==="
export DEBIAN_FRONTEND=noninteractive
sudo apt-get update -qq
# clang is required by CMake even with SKIP_BPF_BUILD=ON (top-level find_program).
sudo apt-get install -y -qq build-essential cmake ninja-build pkg-config libelf-dev \
  zlib1g-dev git ca-certificates python3 clang || { echo "APT_FAILED"; exit 10; }

CM="$(command -v cmake)"
CMV="$($CM --version | head -1 | grep -oE '[0-9]+\.[0-9]+')"
# STATIC_LIBBPF needs cmake >= 3.24 (DOWNLOAD_EXTRACT_TIMESTAMP). Pip-upgrade if older.
if [ "$(printf '%s\n3.24\n' "$CMV" | sort -V | head -1)" != "3.24" ]; then
  echo "cmake $CMV < 3.24 -> pip upgrade"
  sudo apt-get install -y -qq python3-pip >/dev/null 2>&1
  sudo pip3 install -q --upgrade cmake >/dev/null 2>&1 || true
  hash -r; CM="$(command -v cmake)"
fi
echo "cmake: $($CM --version | head -1)"

mkdir -p ~/aegis && tar xzf ~/aegis-fix.tgz -C ~/aegis
cd ~/aegis
rm -rf build
"$CM" -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release \
  -DSKIP_BPF_BUILD=ON -DSTATIC_LIBBPF=ON 2>&1 | tail -6 || { echo "CMAKE_CONFIG_FAILED"; exit 11; }
cp ~/hostbpf/aegis.bpf.o ~/hostbpf/aegis.skel.h ~/hostbpf/aegis.bpf.sha256 build/
"$CM" --build build --target aegisbpf -j"$(nproc)" 2>&1 | tail -20 || { echo "BUILD_FAILED"; exit 12; }
[[ -f build/aegis.bpf.o ]] || cp ~/hostbpf/aegis.bpf.o build/
[[ -f build/aegis.bpf.sha256 ]] || cp ~/hostbpf/aegis.bpf.sha256 build/
echo "=== ready ==="
ls -la build/aegisbpf build/aegis.bpf.o
./build/aegisbpf --version | head -1
echo "BUILD_OK"
