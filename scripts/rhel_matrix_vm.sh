#!/usr/bin/env bash
# Run the atomic-swap validation on a RHEL-family vendor kernel.
#
# Why this exists separately from scripts/kernel_matrix_vm.sh
# ----------------------------------------------------------
# That harness uses virtme-ng, which shares the host rootfs over 9p. RHEL-family
# kernels build no 9p at all, so virtme-ng cannot boot them -- it fails to mount
# a root filesystem and the guest dies before init. That is a fact about
# virtme-ng, NOT about RHEL: "we could not test it that way" is not evidence
# that Aegis does not work there, and the support matrix must never be narrowed
# on the strength of a harness limitation.
#
# So RHEL gets a real VM instead: a vendor cloud image booted on its own
# installed kernel under plain qemu, reached over ssh.
#
# Two details are load-bearing:
#   * -cpu host. RHEL 9 is built for the x86-64-v2 baseline; qemu's default CPU
#     model does not provide it and init dies with exitcode=0x00007f00.
#   * cloud-init runs grubby to add bpf to lsm=, then reboots once. BPF-LSM is
#     not in AlmaLinux's default LSM list.
#
# The BPF object is built natively inside the guest. This is deliberate: the
# RHEL-family row now proves both source-build portability with the distro clang
# and CO-RE runtime portability on the vendor kernel. BUILD_ONLY=1 stops after
# the native build so CI can gate the compiler/toolchain contract without paying
# for the full stress/crash/leak validation.
#
# Env:
#   IMAGE_URL   cloud image (default: AlmaLinux 9 GenericCloud x86_64)
#   WORK        working directory (default: ~/aegis-rhel)
#   OUT         result directory  (default: $WORK/out)
#   KEEP_VM     1 to leave the VM running for inspection
#   BUILD_ONLY  1 to stop after the native guest build
#
# Exit: 0 if every phase passed, 1 on a failure, 2 on missing prerequisites.
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="${WORK:-$HOME/aegis-rhel}"
OUT="${OUT:-$WORK/out}"
IMAGE_URL="${IMAGE_URL:-https://repo.almalinux.org/almalinux/9/cloud/x86_64/images/AlmaLinux-9-GenericCloud-latest.x86_64.qcow2}"
SSH_PORT="${SSH_PORT:-2222}"
BOOT_TIMEOUT="${BOOT_TIMEOUT:-600}"
mkdir -p "$WORK" "$OUT"

for t in qemu-system-x86_64 cloud-localds ssh scp qemu-img curl; do
    command -v "$t" >/dev/null 2>&1 || { echo "missing prerequisite: $t"; exit 2; }
done
[ -e /dev/kvm ] || { echo "/dev/kvm not available"; exit 2; }

KEY="$WORK/id_alma"
BASE="$WORK/alma9.qcow2"
DISK="$WORK/alma9-run.qcow2"
SEED="$WORK/seed.iso"
VM_PID=""

cleanup() {
    if [ -n "$VM_PID" ] && [ "${KEEP_VM:-0}" != 1 ]; then
        kill "$VM_PID" 2>/dev/null
        wait "$VM_PID" 2>/dev/null
    fi
    return 0
}
trap cleanup EXIT INT TERM

ssh_vm() { ssh -q -i "$KEY" -p "$SSH_PORT" \
    -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o ConnectTimeout=5 aegis@127.0.0.1 "$@"; }
scp_vm() { scp -q -i "$KEY" -P "$SSH_PORT" \
    -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "$@"; }

# --- one-time assets ------------------------------------------------------
[ -f "$KEY" ] || ssh-keygen -t ed25519 -N '' -f "$KEY" -C aegis-rhel >/dev/null

if [ ! -f "$BASE" ]; then
    echo "fetching $IMAGE_URL"
    curl -fsSL -o "$BASE.part" "$IMAGE_URL" || { echo "image download failed"; exit 2; }
    mv "$BASE.part" "$BASE"
fi

if [ ! -f "$SEED" ]; then
    cat > "$WORK/meta-data" <<META
instance-id: aegis-alma
local-hostname: aegis-alma
META
    cat > "$WORK/user-data" <<USERDATA
#cloud-config
users:
  - name: aegis
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    ssh_authorized_keys:
      - $(cat "$KEY.pub")
ssh_pwauth: false
runcmd:
  # BPF-LSM is not in AlmaLinux's default lsm= list; enable it and reboot once.
  - grubby --update-kernel=ALL --args="lsm=lockdown,capability,bpf"
  - [ sh, -c, "echo AEGIS_CLOUDINIT_DONE > /var/log/aegis-ready" ]
  - [ reboot ]
USERDATA
    cloud-localds "$SEED" "$WORK/user-data" "$WORK/meta-data" || exit 2
fi

# A fresh overlay per run: the validation is destructive inside the guest.
rm -f "$DISK"
qemu-img create -q -f qcow2 -F qcow2 -b "$BASE" "$DISK" 20G || exit 2

# --- boot -----------------------------------------------------------------
# -cpu host is required: see the header.
qemu-system-x86_64 \
    -name aegis-rhel -machine accel=kvm -cpu host -smp 4 -m 4G \
    -drive file="$DISK",if=virtio,format=qcow2 \
    -drive file="$SEED",if=virtio,format=raw,readonly=on \
    -netdev user,id=n0,hostfwd=tcp::"$SSH_PORT"-:22 -device virtio-net-pci,netdev=n0 \
    -display none -serial file:"$WORK/console.log" \
    > "$WORK/qemu.log" 2>&1 &
VM_PID=$!

echo "booting AlmaLinux (qemu pid $VM_PID); cloud-init reboots once for lsm="
waited=0
until ssh_vm true 2>/dev/null; do
    sleep 5; waited=$((waited+5))
    if ! kill -0 "$VM_PID" 2>/dev/null; then
        echo "VM exited during boot; console tail:"; tail -20 "$WORK/console.log"; exit 1
    fi
    if [ "$waited" -ge "$BOOT_TIMEOUT" ]; then
        echo "VM never became reachable after ${waited}s; console tail:"
        tail -20 "$WORK/console.log"; exit 1
    fi
done

# cloud-init's reboot can land after the first ssh succeeds. Wait for the
# marker, then for ssh to come back on the rebooted (BPF-LSM) kernel.
for _ in $(seq 1 60); do
    ssh_vm "test -f /var/log/aegis-ready" 2>/dev/null && break
    sleep 5
done
sleep 10
waited=0
until ssh_vm true 2>/dev/null; do
    sleep 5; waited=$((waited+5))
    [ "$waited" -ge 300 ] && { echo "VM did not return after cloud-init reboot"; exit 1; }
done

lsm=$(ssh_vm "cat /sys/kernel/security/lsm" 2>/dev/null)
case "$lsm" in
    *bpf*) ;;
    *) echo "BPF-LSM is not active in the guest (lsm=$lsm); refusing to report a result"
       exit 1 ;;
esac
echo "guest kernel: $(ssh_vm uname -r)   lsm=$lsm"

# --- ship the tree --------------------------------------------------------
# git archive, not tar: the working tree carries build directories and a Rust
# target dir that make the tarball three orders of magnitude larger.
git -C "$REPO" archive --format=tar.gz -o "$WORK/aegis.tgz" HEAD || exit 1
scp_vm "$WORK/aegis.tgz" aegis@127.0.0.1:/tmp/aegis.tgz || exit 1

# crb carries libbpf-devel on AlmaLinux 9; it is disabled by default.
ssh_vm "sudo dnf -y config-manager --set-enabled crb >/dev/null 2>&1
        sudo dnf -y install gcc gcc-c++ clang llvm cmake ninja-build libbpf-devel \
             systemd-devel pkgconf-pkg-config python3 elfutils-libelf-devel \
             >/dev/null 2>&1
        rm -rf ~/aegis && mkdir -p ~/aegis && tar -C ~/aegis -xzf /tmp/aegis.tgz" || exit 1

echo "building userspace + BPF object natively in the guest"
ssh_vm "cd ~/aegis && clang --version >/tmp/clang-version.txt 2>&1 &&
        cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release \
          -DBUILD_TESTING=OFF -DSKIP_BPF_BUILD=OFF >/tmp/cmake.log 2>&1 &&
        cmake --build build >>/tmp/cmake.log 2>&1 &&
        test -s build/aegis.bpf.o" || {
    echo "guest native build failed; compiler:"; ssh_vm "head -3 /tmp/clang-version.txt 2>/dev/null || true"
    echo "build log:"; ssh_vm "tail -50 /tmp/cmake.log"; exit 1; }

ssh_vm "head -3 /tmp/clang-version.txt" > "$OUT/clang-version.txt" 2>/dev/null || true
ssh_vm "tail -100 /tmp/cmake.log" > "$OUT/native-build.log" 2>/dev/null || true

if [ "${BUILD_ONLY:-0}" = 1 ]; then
    echo "native BPF build: PASS"
    echo "compiler: $(head -1 "$OUT/clang-version.txt" 2>/dev/null)"
    exit 0
fi

# --- run the same phases the kernel matrix runs ---------------------------
scp_vm "$REPO/scripts/kernel_matrix_guest.sh" aegis@127.0.0.1:/tmp/guest.sh || exit 1
ssh_vm "chmod +x /tmp/guest.sh && sudo env AEGIS_REPO=\$HOME/aegis \
          T_VALIDATE=900 T_STRESS=600 T_CRASH=600 T_LEAK=900 \
          /tmp/guest.sh /tmp/aegisout" 
scp_vm -r aegis@127.0.0.1:/tmp/aegisout/. "$OUT/" 2>/dev/null

if [ ! -f "$OUT/result.json" ]; then
    echo "no result.json came back; guest log tail:"
    tail -30 "$OUT/log.txt" 2>/dev/null || echo "(no log either)"
    exit 1
fi

# Record what the result is a result ABOUT. A row that does not name its vendor
# kernel package is indistinguishable from a mainline kernel of the same
# version, and a mainline 5.14 result must never stand in for a RHEL one.
ssh_vm "rpm -q kernel-core | tail -1" > "$OUT/kernel-package.txt" 2>/dev/null
ssh_vm "cat /etc/redhat-release" > "$OUT/distro.txt" 2>/dev/null
ssh_vm "uname -a" > "$OUT/uname.txt" 2>/dev/null

echo
echo "kernel package : $(cat "$OUT/kernel-package.txt" 2>/dev/null)"
echo "distro         : $(cat "$OUT/distro.txt" 2>/dev/null)"
echo "results        : $OUT"
grep -E '"validation"|"leak"|"status"|"torn"|"violations"' "$OUT/result.json"

grep -q '"validation": "pass"' "$OUT/result.json" || exit 1
grep -q '"violations": 0'      "$OUT/result.json" || exit 1
grep -q '"leak": "pass"'       "$OUT/result.json" || exit 1
echo "PASS"
