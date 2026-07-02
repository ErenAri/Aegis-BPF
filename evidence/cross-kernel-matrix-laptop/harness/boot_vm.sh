#!/usr/bin/env bash
# boot_vm.sh <name> <base_qcow2> <ssh_port> [ram_mb] [vcpus]
# Boots a cloud image as an overlay VM (base stays pristine), headless, KVM,
# user-net with ssh hostfwd. Backgrounds qemu via setsid; logs to the vm dir.
set -euo pipefail
KM=~/aegis-km
NAME="$1"; BASE="$2"; PORT="$3"; RAM="${4:-4096}"; VCPUS="${5:-4}"
VMDIR="$KM/vms/$NAME"
mkdir -p "$VMDIR"

OVERLAY="$VMDIR/disk.qcow2"
qemu-img create -f qcow2 -F qcow2 -b "$BASE" "$OVERLAY" 20G >/dev/null
qemu-img resize "$OVERLAY" 20G >/dev/null 2>&1 || true

SEED="$VMDIR/seed.img"
cloud-localds "$SEED" "$KM/cloud-init/user-data"

echo "$PORT" > "$VMDIR/ssh_port"
setsid qemu-system-x86_64 \
  -name "$NAME" \
  -machine accel=kvm -cpu host -smp "$VCPUS" -m "$RAM" \
  -drive file="$OVERLAY",if=virtio,format=qcow2 \
  -drive file="$SEED",if=virtio,format=raw \
  -netdev user,id=n0,hostfwd=tcp:127.0.0.1:${PORT}-:22 \
  -device virtio-net-pci,netdev=n0 \
  -nographic -serial file:"$VMDIR/console.log" \
  > "$VMDIR/qemu.log" 2>&1 &
echo $! > "$VMDIR/qemu.pid"
echo "booted $NAME (qemu pid $(cat "$VMDIR/qemu.pid"), ssh 127.0.0.1:$PORT, dir $VMDIR)"
