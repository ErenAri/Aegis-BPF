#!/usr/bin/env bash
set -euo pipefail

lsm_path="/sys/kernel/security/lsm"

if [[ ! -r "$lsm_path" ]]; then
    echo "[!] Cannot read $lsm_path"
    exit 1
fi

lsm_contents=$(cat "$lsm_path")
echo "[*] /sys/kernel/security/lsm: $lsm_contents"

if echo "$lsm_contents" | grep -qw bpf; then
    echo "[+] BPF LSM is enabled."
else
    echo "[!] BPF LSM is NOT enabled (missing 'bpf')."
    echo "    Add bpf to your kernel LSM list, e.g. in GRUB:"
    echo "    GRUB_CMDLINE_LINUX=\"... lsm=landlock,lockdown,yama,bpf,integrity,apparmor\""
    echo "    Then run: sudo update-grub && sudo reboot"
fi

config_file="/boot/config-$(uname -r)"
if [[ -r "$config_file" ]]; then
    grep -E '^CONFIG_BPF_LSM=' "$config_file" || echo "[!] CONFIG_BPF_LSM not found in $config_file"
elif [[ -r /proc/config.gz ]]; then
    zgrep -E '^CONFIG_BPF_LSM=' /proc/config.gz || echo "[!] CONFIG_BPF_LSM not found in /proc/config.gz"
else
    echo "[!] Kernel config file not found to verify CONFIG_BPF_LSM"
fi
