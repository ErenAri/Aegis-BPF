#!/usr/bin/env bash
# btfgen.sh - Generate minimized BTF files for kernels without built-in BTF
#
# Uses BTFHub archive + bpftool gen min_core_btf to produce tiny BTF files
# specific to AegisBPF's CO-RE relocations.
#
# Usage:
#   ./scripts/btfgen.sh <bpf_object> [--output-dir <dir>]
#
# Output: A directory of minimized BTF files at <output-dir>/<kernel-version>.btf
#
# Requirements:
#   - bpftool with gen min_core_btf support (>= 7.0)
#   - wget or curl for downloading BTFHub archive
#   - tar for extraction

set -euo pipefail

BPF_OBJ="${1:-}"
OUTPUT_DIR="${2:-packaging/btfhub/btfs}"
BTFHUB_ARCHIVE_URL="https://github.com/aquasecurity/btfhub-archive/releases/latest/download"

# Target distributions and kernel versions
BTFHUB_DISTROS=(
    "ubuntu/22.04/x86_64"
    "ubuntu/24.04/x86_64"
    "debian/11/x86_64"
    "debian/12/x86_64"
    "centos/8/x86_64"
    "centos/9/x86_64"
    "fedora/38/x86_64"
    "fedora/39/x86_64"
    "amzn/2/x86_64"
    "amzn/2023/x86_64"
)

if [[ -z "$BPF_OBJ" ]]; then
    echo "Usage: $0 <bpf_object> [--output-dir <dir>]" >&2
    exit 1
fi

if [[ ! -f "$BPF_OBJ" ]]; then
    echo "Error: BPF object not found: $BPF_OBJ" >&2
    exit 1
fi

if ! command -v bpftool >/dev/null 2>&1; then
    echo "Error: bpftool not found" >&2
    exit 1
fi

# Check bpftool supports gen min_core_btf
if ! bpftool gen min_core_btf --help 2>/dev/null | grep -q "min_core_btf"; then
    echo "Warning: bpftool does not support gen min_core_btf (requires >= 7.0)"
    echo "Skipping BTF generation"
    exit 0
fi

mkdir -p "$OUTPUT_DIR"
TMPDIR=$(mktemp -d)
trap "rm -rf $TMPDIR" EXIT

echo "=== BTFGen: Generating minimized BTF files ==="
echo "BPF object: $BPF_OBJ"
echo "Output dir: $OUTPUT_DIR"
echo ""

TOTAL=0
GENERATED=0
ERRORS=0

for distro_path in "${BTFHUB_DISTROS[@]}"; do
    distro_name=$(echo "$distro_path" | tr '/' '-')
    echo "Processing $distro_path..."

    # Download the BTF archive for this distro
    archive_url="${BTFHUB_ARCHIVE_URL}/${distro_name}.tar.xz"
    archive_file="${TMPDIR}/${distro_name}.tar.xz"

    if ! wget -q -O "$archive_file" "$archive_url" 2>/dev/null && \
       ! curl -sfL -o "$archive_file" "$archive_url" 2>/dev/null; then
        echo "  Warning: Could not download BTF archive for $distro_path"
        continue
    fi

    # Extract BTF files
    btf_dir="${TMPDIR}/${distro_name}"
    mkdir -p "$btf_dir"
    tar -xf "$archive_file" -C "$btf_dir" 2>/dev/null || {
        echo "  Warning: Could not extract BTF archive for $distro_path"
        continue
    }

    # Generate minimized BTF for each kernel
    while IFS= read -r -d '' btf_file; do
        kernel_version=$(basename "$btf_file" .btf)
        output_file="${OUTPUT_DIR}/${distro_name}_${kernel_version}.btf"
        TOTAL=$((TOTAL + 1))

        if bpftool gen min_core_btf "$btf_file" "$BPF_OBJ" "$output_file" 2>/dev/null; then
            size=$(stat -c%s "$output_file" 2>/dev/null || echo "?")
            echo "  Generated: ${kernel_version} (${size} bytes)"
            GENERATED=$((GENERATED + 1))
        else
            ERRORS=$((ERRORS + 1))
            rm -f "$output_file"
        fi
    done < <(find "$btf_dir" -name "*.btf" -print0 2>/dev/null)
done

echo ""
echo "=== BTFGen Summary ==="
echo "Total kernels processed: $TOTAL"
echo "BTFs generated: $GENERATED"
echo "Errors: $ERRORS"
echo "Output directory: $OUTPUT_DIR"

if [[ $GENERATED -gt 0 ]]; then
    total_size=$(du -sh "$OUTPUT_DIR" 2>/dev/null | cut -f1)
    echo "Total size: $total_size"
fi
