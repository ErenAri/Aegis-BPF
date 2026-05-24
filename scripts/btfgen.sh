#!/usr/bin/env bash
# btfgen.sh — Download a pre-built BTF blob from BTFhub-archive for a
#              given kernel release.
#
# This is the recommended way to get BTF on kernels that lack built-in
# /sys/kernel/btf/vmlinux (same approach Falco, Tetragon, and Tracee
# use).
#
# Usage:
#   btfgen.sh <kernel-release>              # e.g. 5.15.0-91-generic
#   btfgen.sh --list <distro>/<version>     # e.g. ubuntu/22.04
#   btfgen.sh --auto                        # detect running kernel
#
# Options:
#   --output-dir <dir>    Override output directory
#                         (default: /var/lib/aegisbpf/btfs)
#   --arch <arch>         Override architecture (default: auto-detected)
#   --distro <d/v>        Override distro/version (default: auto-detected)
#   --list <distro/ver>   List available kernels for a distro/version
#   --auto                Use running kernel's release (uname -r)
#   --force               Re-download even if cached
#   -q, --quiet           Suppress progress output
#
# Requires: curl, tar
#
# BTFhub-archive layout:
#   https://github.com/aquasecurity/btfhub-archive/raw/main/
#     <distro>/<version>/<arch>/<kernel_release>.btf.tar.xz

set -euo pipefail

# ── Defaults ────────────────────────────────────────────────────────
BTFHUB_BASE_URL="https://github.com/aquasecurity/btfhub-archive/raw/main"
DEFAULT_OUTPUT_DIR="/var/lib/aegisbpf/btfs"
OUTPUT_DIR=""
ARCH=""
DISTRO=""       # e.g. "ubuntu/22.04"
KERNEL_RELEASE=""
FORCE=0
QUIET=0
LIST_MODE=0
AUTO_MODE=0

# Supported distros and their known versions.
SUPPORTED_DISTROS="ubuntu debian fedora centos rhel amzn oracle sles opensuse arch"

# ── Helpers ─────────────────────────────────────────────────────────
die()  { echo "btfgen: error: $*" >&2; exit 1; }
info() { [[ $QUIET -eq 1 ]] || echo "btfgen: $*" >&2; }
warn() { echo "btfgen: warning: $*" >&2; }

detect_arch() {
    local machine
    machine="$(uname -m)"
    case "$machine" in
        x86_64)  echo "x86_64" ;;
        aarch64) echo "arm64"  ;;
        arm*)    echo "arm64"  ;;
        s390x)   echo "s390x"  ;;
        ppc64le) echo "ppc64le";;
        *)       echo "$machine" ;;
    esac
}

# Try to detect distro and version from os-release.
detect_distro() {
    local id version_id
    if [[ -f /etc/os-release ]]; then
        id=$(. /etc/os-release && echo "${ID:-}")
        version_id=$(. /etc/os-release && echo "${VERSION_ID:-}")
    else
        return 1
    fi

    # Normalise ID to BTFhub naming.
    case "$id" in
        ubuntu)    echo "ubuntu/${version_id}" ;;
        debian)    echo "debian/${version_id%%.*}" ;;   # 11.x → 11
        fedora)    echo "fedora/${version_id}" ;;
        centos)    echo "centos/${version_id%%.*}" ;;
        rhel)      echo "rhel/${version_id%%.*}" ;;
        amzn)      echo "amzn/${version_id}" ;;
        ol)        echo "oracle/${version_id%%.*}" ;;
        sles)      echo "sles/${version_id%%.*}" ;;
        opensuse*) echo "opensuse/${version_id%%.*}" ;;
        arch)      echo "arch/rolling" ;;
        *)         return 1 ;;
    esac
}

# Download a single file from BTFhub-archive via curl.
# Returns 0 on success, 1 on failure.
download() {
    local url="$1" dest="$2"
    local http_code
    http_code=$(curl -sfL -w '%{http_code}' -o "$dest" "$url" 2>/dev/null) || true
    if [[ "$http_code" == "200" && -s "$dest" ]]; then
        return 0
    fi
    rm -f "$dest"
    return 1
}

# ── Argument parsing ───────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --output-dir)
            [[ -n "${2:-}" ]] || die "--output-dir requires a value"
            OUTPUT_DIR="$2"; shift 2 ;;
        --arch)
            [[ -n "${2:-}" ]] || die "--arch requires a value"
            ARCH="$2"; shift 2 ;;
        --distro)
            [[ -n "${2:-}" ]] || die "--distro requires a value (e.g. ubuntu/22.04)"
            DISTRO="$2"; shift 2 ;;
        --list)
            LIST_MODE=1
            [[ -n "${2:-}" ]] || die "--list requires a distro/version (e.g. ubuntu/22.04)"
            DISTRO="$2"; shift 2 ;;
        --auto)
            AUTO_MODE=1; shift ;;
        --force)
            FORCE=1; shift ;;
        -q|--quiet)
            QUIET=1; shift ;;
        -h|--help)
            sed -n '2,/^$/s/^# \?//p' "$0"
            exit 0 ;;
        -*)
            die "unknown option: $1" ;;
        *)
            KERNEL_RELEASE="$1"; shift ;;
    esac
done

# Apply defaults.
[[ -n "$OUTPUT_DIR" ]] || OUTPUT_DIR="$DEFAULT_OUTPUT_DIR"
[[ -n "$ARCH" ]]       || ARCH="$(detect_arch)"

# --auto: use uname -r
if [[ $AUTO_MODE -eq 1 ]]; then
    KERNEL_RELEASE="$(uname -r)"
fi

# ── List mode ──────────────────────────────────────────────────────
if [[ $LIST_MODE -eq 1 ]]; then
    [[ -n "$DISTRO" ]] || die "specify distro/version for --list"
    info "Listing available kernels for ${DISTRO}/${ARCH} ..."
    info "(fetching directory listing from BTFhub-archive, this may take a moment)"

    # BTFhub-archive is a git repo. We use the GitHub API to list
    # directory contents rather than cloning the whole repo.
    api_url="https://api.github.com/repos/aquasecurity/btfhub-archive/contents/${DISTRO}/${ARCH}"
    listing=$(curl -sfL "$api_url" 2>/dev/null) || die "could not fetch listing from $api_url"

    # Parse JSON array of objects with "name" fields.
    echo "$listing" | grep '"name"' | sed 's/.*"name": *"\([^"]*\)".*/\1/' | sed 's/\.btf\.tar\.xz$//' | sort -V
    exit 0
fi

# ── Download mode ──────────────────────────────────────────────────
[[ -n "$KERNEL_RELEASE" ]] || die "specify a kernel release (e.g. 5.15.0-91-generic) or use --auto"

# Check for curl.
command -v curl >/dev/null 2>&1 || die "curl is required but not found"
command -v tar  >/dev/null 2>&1 || die "tar is required but not found"

# Already cached?
dest_file="${OUTPUT_DIR}/${KERNEL_RELEASE}.btf"
if [[ -f "$dest_file" && $FORCE -eq 0 ]]; then
    info "Already cached: $dest_file (use --force to re-download)"
    echo "$dest_file"
    exit 0
fi

# Auto-detect distro if not specified.
if [[ -z "$DISTRO" ]]; then
    DISTRO="$(detect_distro 2>/dev/null)" || true
fi

# Build the list of distro/version combos to try. If we detected one
# put it first; then try all supported ones as fallbacks.
declare -a DISTRO_CANDIDATES=()
if [[ -n "$DISTRO" ]]; then
    DISTRO_CANDIDATES+=("$DISTRO")
fi

# Build a broader fallback list from common distro/version combos.
FALLBACK_COMBOS=(
    "ubuntu/22.04" "ubuntu/24.04" "ubuntu/20.04" "ubuntu/18.04"
    "debian/12" "debian/11" "debian/10"
    "centos/8" "centos/9" "centos/7"
    "rhel/8" "rhel/9" "rhel/7"
    "fedora/39" "fedora/38" "fedora/40"
    "amzn/2" "amzn/2023"
    "oracle/8" "oracle/9" "oracle/7"
    "sles/15" "sles/12"
    "opensuse/15"
    "arch/rolling"
)

for combo in "${FALLBACK_COMBOS[@]}"; do
    # Don't duplicate the detected distro.
    [[ "$combo" == "$DISTRO" ]] && continue
    DISTRO_CANDIDATES+=("$combo")
done

# Create output directory.
mkdir -p "$OUTPUT_DIR" 2>/dev/null || die "cannot create output directory: $OUTPUT_DIR"

TMPDIR_DL=$(mktemp -d)
trap 'rm -rf "$TMPDIR_DL"' EXIT

info "Downloading BTF for kernel ${KERNEL_RELEASE} (arch=${ARCH}) ..."

for candidate in "${DISTRO_CANDIDATES[@]}"; do
    url="${BTFHUB_BASE_URL}/${candidate}/${ARCH}/${KERNEL_RELEASE}.btf.tar.xz"
    tmp_archive="${TMPDIR_DL}/${KERNEL_RELEASE}.btf.tar.xz"

    if download "$url" "$tmp_archive"; then
        # Extract the BTF blob.
        tmp_btf="${TMPDIR_DL}/${KERNEL_RELEASE}.btf"
        if tar -xJf "$tmp_archive" -C "$TMPDIR_DL" 2>/dev/null; then
            # The archive may contain just the .btf file or a path
            # like <kernel>.btf. Find it.
            found_btf=""
            while IFS= read -r -d '' f; do
                found_btf="$f"
                break
            done < <(find "$TMPDIR_DL" -name "*.btf" -print0 2>/dev/null)

            if [[ -n "$found_btf" ]]; then
                install -m 0644 "$found_btf" "$dest_file"
                info "Saved: $dest_file (from ${candidate}/${ARCH})"
                echo "$dest_file"
                exit 0
            fi
        fi
        warn "Archive downloaded but extraction failed for ${candidate}"
    fi
done

die "no BTF blob found for kernel ${KERNEL_RELEASE} in BTFhub-archive (tried ${#DISTRO_CANDIDATES[@]} distro/version combos)"
