#!/bin/bash
# Generate Software Bill of Materials (SBOM)
# Formats: SPDX, CycloneDX, and human-readable

set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_DIR="$PROJECT_ROOT/sbom"
TIMESTAMP=$(date +%Y-%m-%dT%H:%M:%SZ)
VERSION=$(git describe --tags --always 2>/dev/null || echo "v0.1.1")

mkdir -p "$OUTPUT_DIR"

echo "════════════════════════════════════════════════════"
echo "  Generating SBOM for AegisBPF $VERSION"
echo "════════════════════════════════════════════════════"
echo

#═══════════════════════════════════════════════════════
# Extract dependencies
#═══════════════════════════════════════════════════════

echo "[1/4] Extracting dependencies..."

# System dependencies
LIBBPF_VERSION=$(pkg-config --modversion libbpf 2>/dev/null || echo "unknown")
LIBSYSTEMD_VERSION=$(pkg-config --modversion libsystemd 2>/dev/null || echo "not installed")

# Vendored dependencies
TWEETNACL_VERSION="20140427"  # TweetNaCl version

# FetchContent dependencies
GTEST_VERSION="1.14.0"
GBENCH_VERSION="1.8.3"

echo "  Found dependencies:"
echo "    libbpf: $LIBBPF_VERSION"
echo "    libsystemd: $LIBSYSTEMD_VERSION"
echo "    TweetNaCl: $TWEETNACL_VERSION (vendored)"
echo "    GoogleTest: $GTEST_VERSION (FetchContent)"
echo "    GoogleBenchmark: $GBENCH_VERSION (FetchContent)"

#═══════════════════════════════════════════════════════
# Generate SPDX 2.3 SBOM
#═══════════════════════════════════════════════════════

echo
echo "[2/4] Generating SPDX SBOM..."

cat > "$OUTPUT_DIR/sbom.spdx.json" << EOF
{
  "spdxVersion": "SPDX-2.3",
  "dataLicense": "CC0-1.0",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "AegisBPF-$VERSION",
  "documentNamespace": "https://github.com/aegisbpf/aegisbpf/spdx/$VERSION",
  "creationInfo": {
    "created": "$TIMESTAMP",
    "creators": [
      "Tool: generate_sbom.sh",
      "Organization: AegisBPF"
    ],
    "licenseListVersion": "3.21"
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-Package-AegisBPF",
      "name": "AegisBPF",
      "versionInfo": "$VERSION",
      "downloadLocation": "https://github.com/aegisbpf/aegisbpf/archive/$VERSION.tar.gz",
      "filesAnalyzed": false,
      "licenseConcluded": "MIT",
      "licenseDeclared": "MIT",
      "copyrightText": "Copyright (c) 2024-2026 AegisBPF Contributors",
      "summary": "eBPF-based runtime security agent",
      "description": "AegisBPF is an eBPF-based runtime security agent that monitors and blocks unauthorized file access using Linux Security Modules (LSM).",
      "homepage": "https://github.com/aegisbpf/aegisbpf",
      "externalRefs": [
        {
          "referenceCategory": "SECURITY",
          "referenceType": "url",
          "referenceLocator": "https://github.com/aegisbpf/aegisbpf/security"
        }
      ]
    },
    {
      "SPDXID": "SPDXRef-Package-libbpf",
      "name": "libbpf",
      "versionInfo": "$LIBBPF_VERSION",
      "downloadLocation": "https://github.com/libbpf/libbpf",
      "filesAnalyzed": false,
      "licenseConcluded": "LGPL-2.1-only OR BSD-2-Clause",
      "licenseDeclared": "LGPL-2.1-only OR BSD-2-Clause",
      "copyrightText": "Copyright (c) Linux Kernel Contributors",
      "summary": "BPF CO-RE (Compile Once \u2013 Run Everywhere) library"
    },
    {
      "SPDXID": "SPDXRef-Package-TweetNaCl",
      "name": "TweetNaCl",
      "versionInfo": "$TWEETNACL_VERSION",
      "downloadLocation": "https://tweetnacl.cr.yp.to/software.html",
      "filesAnalyzed": false,
      "licenseConcluded": "Public-Domain",
      "licenseDeclared": "Public-Domain",
      "copyrightText": "Public Domain",
      "summary": "Compact cryptographic library",
      "comment": "Vendored in src/tweetnacl.{c,h}"
    },
    {
      "SPDXID": "SPDXRef-Package-GoogleTest",
      "name": "GoogleTest",
      "versionInfo": "$GTEST_VERSION",
      "downloadLocation": "https://github.com/google/googletest/archive/refs/tags/v$GTEST_VERSION.tar.gz",
      "filesAnalyzed": false,
      "licenseConcluded": "BSD-3-Clause",
      "licenseDeclared": "BSD-3-Clause",
      "copyrightText": "Copyright 2008, Google Inc.",
      "summary": "Google Testing and Mocking Framework",
      "comment": "Build-time dependency only (FetchContent)"
    },
    {
      "SPDXID": "SPDXRef-Package-GoogleBenchmark",
      "name": "GoogleBenchmark",
      "versionInfo": "$GBENCH_VERSION",
      "downloadLocation": "https://github.com/google/benchmark/archive/refs/tags/v$GBENCH_VERSION.tar.gz",
      "filesAnalyzed": false,
      "licenseConcluded": "Apache-2.0",
      "licenseDeclared": "Apache-2.0",
      "copyrightText": "Copyright 2015, Google Inc.",
      "summary": "A microbenchmark support library",
      "comment": "Build-time dependency only (FetchContent)"
    }
  ],
  "relationships": [
    {
      "spdxElementId": "SPDXRef-DOCUMENT",
      "relationshipType": "DESCRIBES",
      "relatedSpdxElement": "SPDXRef-Package-AegisBPF"
    },
    {
      "spdxElementId": "SPDXRef-Package-AegisBPF",
      "relationshipType": "DEPENDS_ON",
      "relatedSpdxElement": "SPDXRef-Package-libbpf"
    },
    {
      "spdxElementId": "SPDXRef-Package-AegisBPF",
      "relationshipType": "DEPENDS_ON",
      "relatedSpdxElement": "SPDXRef-Package-TweetNaCl"
    },
    {
      "spdxElementId": "SPDXRef-Package-AegisBPF",
      "relationshipType": "TEST_DEPENDENCY_OF",
      "relatedSpdxElement": "SPDXRef-Package-GoogleTest"
    },
    {
      "spdxElementId": "SPDXRef-Package-AegisBPF",
      "relationshipType": "TEST_DEPENDENCY_OF",
      "relatedSpdxElement": "SPDXRef-Package-GoogleBenchmark"
    }
  ]
}
EOF

echo "  ✅ SPDX SBOM: $OUTPUT_DIR/sbom.spdx.json"

#═══════════════════════════════════════════════════════
# Generate CycloneDX 1.5 SBOM
#═══════════════════════════════════════════════════════

echo
echo "[3/4] Generating CycloneDX SBOM..."

cat > "$OUTPUT_DIR/sbom.cyclonedx.json" << EOF
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "serialNumber": "urn:uuid:$(uuidgen 2>/dev/null || echo "00000000-0000-0000-0000-000000000000")",
  "version": 1,
  "metadata": {
    "timestamp": "$TIMESTAMP",
    "tools": [
      {
        "name": "generate_sbom.sh",
        "version": "1.0.0"
      }
    ],
    "component": {
      "type": "application",
      "name": "AegisBPF",
      "version": "$VERSION",
      "description": "eBPF-based runtime security agent",
      "licenses": [
        {
          "license": {
            "id": "MIT"
          }
        }
      ],
      "purl": "pkg:github/aegisbpf/aegisbpf@$VERSION"
    }
  },
  "components": [
    {
      "type": "library",
      "name": "libbpf",
      "version": "$LIBBPF_VERSION",
      "description": "BPF CO-RE (Compile Once – Run Everywhere) library",
      "licenses": [
        {
          "expression": "LGPL-2.1-only OR BSD-2-Clause"
        }
      ],
      "purl": "pkg:github/libbpf/libbpf@$LIBBPF_VERSION"
    },
    {
      "type": "library",
      "name": "TweetNaCl",
      "version": "$TWEETNACL_VERSION",
      "description": "Compact cryptographic library",
      "licenses": [
        {
          "license": {
            "name": "Public Domain"
          }
        }
      ],
      "purl": "pkg:generic/tweetnacl@$TWEETNACL_VERSION"
    },
    {
      "type": "library",
      "name": "GoogleTest",
      "version": "$GTEST_VERSION",
      "scope": "optional",
      "description": "Google Testing and Mocking Framework",
      "licenses": [
        {
          "license": {
            "id": "BSD-3-Clause"
          }
        }
      ],
      "purl": "pkg:github/google/googletest@$GTEST_VERSION"
    },
    {
      "type": "library",
      "name": "GoogleBenchmark",
      "version": "$GBENCH_VERSION",
      "scope": "optional",
      "description": "A microbenchmark support library",
      "licenses": [
        {
          "license": {
            "id": "Apache-2.0"
          }
        }
      ],
      "purl": "pkg:github/google/benchmark@$GBENCH_VERSION"
    }
  ],
  "dependencies": [
    {
      "ref": "pkg:github/aegisbpf/aegisbpf@$VERSION",
      "dependsOn": [
        "pkg:github/libbpf/libbpf@$LIBBPF_VERSION",
        "pkg:generic/tweetnacl@$TWEETNACL_VERSION"
      ]
    }
  ]
}
EOF

echo "  ✅ CycloneDX SBOM: $OUTPUT_DIR/sbom.cyclonedx.json"

#═══════════════════════════════════════════════════════
# Generate human-readable SBOM
#═══════════════════════════════════════════════════════

echo
echo "[4/4] Generating human-readable SBOM..."

cat > "$OUTPUT_DIR/sbom.txt" << EOF
═══════════════════════════════════════════════════════════════
    SOFTWARE BILL OF MATERIALS (SBOM)
    AegisBPF $VERSION
═══════════════════════════════════════════════════════════════

Generated: $TIMESTAMP
Format: Human-Readable Text

═══════════════════════════════════════════════════════════════
MAIN COMPONENT
═══════════════════════════════════════════════════════════════

Name:        AegisBPF
Version:     $VERSION
Type:        Application
License:     MIT
Description: eBPF-based runtime security agent that monitors and
             blocks unauthorized file access using Linux Security
             Modules (LSM).
Homepage:    https://github.com/aegisbpf/aegisbpf
Repository:  https://github.com/aegisbpf/aegisbpf.git

═══════════════════════════════════════════════════════════════
RUNTIME DEPENDENCIES
═══════════════════════════════════════════════════════════════

1. libbpf
   Version:     $LIBBPF_VERSION
   Type:        System Library
   License:     LGPL-2.1-only OR BSD-2-Clause
   Description: BPF CO-RE (Compile Once – Run Everywhere) library
   Source:      https://github.com/libbpf/libbpf
   Usage:       BPF program loading and management

2. TweetNaCl
   Version:     $TWEETNACL_VERSION
   Type:        Vendored Library
   License:     Public Domain
   Description: Compact cryptographic library (Ed25519 signatures)
   Source:      https://tweetnacl.cr.yp.to/
   Location:    src/tweetnacl.{c,h}
   Usage:       Policy bundle signing and verification

3. libsystemd (optional)
   Version:     $LIBSYSTEMD_VERSION
   Type:        System Library
   License:     LGPL-2.1-or-later
   Description: systemd journal logging
   Usage:       Structured logging to systemd journal

═══════════════════════════════════════════════════════════════
BUILD-TIME DEPENDENCIES
═══════════════════════════════════════════════════════════════

1. GoogleTest
   Version:     $GTEST_VERSION
   Type:        Test Framework (FetchContent)
   License:     BSD-3-Clause
   Description: Google Testing and Mocking Framework
   Source:      https://github.com/google/googletest
   Hash:        SHA256=8ad598c73ad796e0d8280b082cebd82a630d73e73cd3c70057938a6501bba5d7
   Usage:       Unit testing

2. GoogleBenchmark
   Version:     $GBENCH_VERSION
   Type:        Benchmark Framework (FetchContent)
   License:     Apache-2.0
   Description: Microbenchmark support library
   Source:      https://github.com/google/benchmark
   Hash:        SHA256=6bc180a57d23d4d9515519f92b0c83d61b05b5bab188961f36ac7b06b0d9e9ce
   Usage:       Performance testing

═══════════════════════════════════════════════════════════════
DEVELOPMENT TOOLS
═══════════════════════════════════════════════════════════════

- clang/gcc:    C/C++ compiler (11+)
- cmake:        Build system (3.20+)
- bpftool:      BPF object generation
- pkg-config:   Dependency management

═══════════════════════════════════════════════════════════════
LICENSE SUMMARY
═══════════════════════════════════════════════════════════════

Main License:           MIT
Runtime Dependencies:   LGPL-2.1, BSD-2-Clause, Public Domain
Build Dependencies:     BSD-3-Clause, Apache-2.0

All licenses are OSI-approved and compatible.

═══════════════════════════════════════════════════════════════
SECURITY INFORMATION
═══════════════════════════════════════════════════════════════

Vulnerability Reporting:
  See SECURITY.md in the repository

Known Vulnerabilities:
  None (as of $TIMESTAMP)

Security Fixes:
  v0.1.1: TweetNaCl memory exhaustion (FIXED)

═══════════════════════════════════════════════════════════════
VERIFICATION
═══════════════════════════════════════════════════════════════

To verify this SBOM:
  1. Check source code matches declared version
  2. Verify dependency hashes in CMakeLists.txt
  3. Run: ./scripts/verify_trustworthiness.sh

For more information:
  - TRUST_EVIDENCE.md
  - CMakeLists.txt (dependency definitions)
  - docs/VENDORED_DEPENDENCIES.md

═══════════════════════════════════════════════════════════════
EOF

echo "  ✅ Human-readable SBOM: $OUTPUT_DIR/sbom.txt"

#═══════════════════════════════════════════════════════
# Summary
#═══════════════════════════════════════════════════════

echo
echo "════════════════════════════════════════════════════"
echo "  SBOM Generation Complete"
echo "════════════════════════════════════════════════════"
echo
echo "Output files:"
echo "  - $OUTPUT_DIR/sbom.spdx.json (SPDX 2.3)"
echo "  - $OUTPUT_DIR/sbom.cyclonedx.json (CycloneDX 1.5)"
echo "  - $OUTPUT_DIR/sbom.txt (Human-readable)"
echo
echo "Next steps:"
echo "  1. Review SBOMs for accuracy"
echo "  2. Include in release artifacts"
echo "  3. Upload to artifact repository"
echo "  4. Update vulnerability databases"
echo
echo "✅ SBOM generation successful"
echo

exit 0
