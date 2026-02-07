# AegisBPF Error Handling Guidelines

**Purpose:** Guide for writing user-friendly, secure error messages
**Audience:** AegisBPF contributors
**Last Updated:** 2026-02-07

---

## Principles

### 1. User-Friendly by Default

**Bad:**
```
Error: ENOENT (errno 2) at /var/run/aegisbpf/bpf/deny_inode_map
```

**Good:**
```
Security enforcement not active. Start the daemon first: sudo aegisbpf run
```

### 2. Avoid Information Disclosure

**Bad:**
```
Failed to open /home/alice/.ssh/id_rsa: Permission denied
Policy file at /etc/aegisbpf/secret-policy.yml
Database password incorrect for user 'admin' at 192.168.1.50:3306
```

**Good:**
```
Failed to access required file. Check permissions.
Policy file not found. Specify with --policy flag.
Database authentication failed. Check credentials.
```

**Rationale:** Error messages can leak:
- Internal file paths
- User names
- IP addresses
- System architecture
- Security policy details

### 3. Provide Actionable Remediation

Every error should suggest next steps:

```
Error: BPF map capacity reached

What happened: The deny rules map is full (65,536 entries)
What to do:   Run 'sudo aegisbpf block clear' to remove old entries
              OR increase map size in bpf/aegis.bpf.c
Documentation: docs/CAPACITY_PLANNING.md#map-limits
```

### 4. Use Structured Error Codes

```cpp
#include "error_codes.hpp"

// Instead of:
return Error("File not found");

// Use:
return Error(AegisErrorCode::FileNotFound, "Policy file missing");
```

Benefits:
- Programmatic error handling
- Stable error identification
- Multi-language support
- Automated monitoring

---

## Error Code System

All errors use `src/error_codes.hpp`:

```cpp
enum class AegisErrorCode {
    // Kernel compatibility (1000-1099)
    KernelTooOld = 1000,
    BpfLsmNotAvailable = 1001,

    // BPF operations (1100-1199)
    BpfLoadFailed = 1100,
    BpfMapFull = 1102,

    // Policy errors (1200-1299)
    PolicyFileNotFound = 1200,
    PolicyParseError = 1201,

    // ... see error_codes.hpp for full list
};
```

### Usage Example

```cpp
// Get user-friendly message
std::string msg = error_message(AegisErrorCode::BpfMapFull, verbose);

// Get remediation steps
std::string fix = error_remediation(AegisErrorCode::BpfMapFull);

// Log with context
logger().log(SLOG_ERROR("Map full")
    .code(AegisErrorCode::BpfMapFull)
    .field("map", "deny_inode")
    .field("capacity", "65536"));
```

---

## Verbose Mode

Add `--verbose` flag to commands for detailed errors:

```bash
# Default: User-friendly
$ aegisbpf policy apply broken.yml
Error: Policy validation failed
Fix: Review policy rules and check syntax

# Verbose: Technical details
$ aegisbpf policy apply broken.yml --verbose
Error: Policy validation failed [code: 1202]
Cause: YAML parse error at line 15: unexpected token
File: /home/user/broken.yml
Stack: policy.cpp:validatePolicy:342
Fix: Run 'yamllint broken.yml' to identify syntax errors
```

### Implementation

```cpp
bool verbose = args.verbose;

if (!result) {
    if (verbose) {
        // Include technical details
        logger().error("Detailed error info")
            .field("errno", errno)
            .field("file_path", path)
            .field("line", __LINE__);
    } else {
        // User-friendly only
        logger().error(error_message(code, false));
    }
}
```

---

## Path Sanitization

Sanitize file paths before logging:

```cpp
std::string sanitize_path(const std::string& path) {
    // Remove /home/<user>/ prefix
    if (path.starts_with("/home/")) {
        size_t pos = path.find('/', 6);
        if (pos != std::string::npos) {
            return "~/" + path.substr(pos + 1);
        }
    }

    // Replace internal paths with placeholders
    if (path.starts_with("/var/run/aegisbpf")) {
        return "${AEGIS_RUNTIME}/" + path.substr(18);
    }

    // Keep only filename for temp files
    if (path.starts_with("/tmp/")) {
        return "/tmp/" + std::filesystem::path(path).filename().string();
    }

    return path;
}
```

**Example:**
```
Before: /home/alice/.ssh/id_rsa
After:  ~/.ssh/id_rsa

Before: /var/run/aegisbpf/bpf/deny_inode_map
After:  ${AEGIS_RUNTIME}/bpf/deny_inode_map

Before: /tmp/aegisbpf-12345-policy.yml.tmp
After:  /tmp/policy.yml.tmp
```

---

## Error Severity Levels

Use appropriate log levels:

```cpp
// Fatal: Unrecoverable errors
SLOG_FATAL("BPF program load failed")  // Daemon cannot start

// Error: Operation failed, but daemon continues
SLOG_ERROR("Failed to add deny rule")  // Rule not added, but daemon runs

// Warn: Unexpected but handled
SLOG_WARN("Map utilization at 85%")  // Approaching limits

// Info: Normal operations
SLOG_INFO("Policy applied successfully")

// Debug: Verbose operational details (--verbose only)
SLOG_DEBUG("BPF map lookup: key=123 found=true")
```

---

## Examples: Before & After

### Example 1: File Not Found

**Before:**
```cpp
if (!std::filesystem::exists(path)) {
    logger().error("ENOENT: " + path);
    return 1;
}
```

**After:**
```cpp
if (!std::filesystem::exists(path)) {
    if (args.verbose) {
        logger().error("File not found")
            .code(AegisErrorCode::FileNotFound)
            .field("path", sanitize_path(path))
            .field("cwd", std::filesystem::current_path());
    } else {
        logger().error(error_message(AegisErrorCode::FileNotFound))
            .hint(error_remediation(AegisErrorCode::FileNotFound));
    }
    return static_cast<int>(AegisErrorCode::FileNotFound);
}
```

### Example 2: Permission Denied

**Before:**
```cpp
if (fd < 0) {
    logger().error("Failed to open " + file + ": " + strerror(errno));
}
```

**After:**
```cpp
if (fd < 0) {
    if (errno == EACCES || errno == EPERM) {
        logger().error(error_message(AegisErrorCode::FilePermissionDenied))
            .hint(error_remediation(AegisErrorCode::FilePermissionDenied));
    } else {
        logger().error(error_message(AegisErrorCode::FileReadError, args.verbose))
            .code_if_verbose(errno, args.verbose);
    }
}
```

### Example 3: BPF Map Full

**Before:**
```cpp
if (ret == -E2BIG) {
    logger().error("Map full: " + std::to_string(current_entries) + "/" +
                   std::to_string(max_entries));
}
```

**After:**
```cpp
if (ret == -E2BIG) {
    logger().error(error_message(AegisErrorCode::BpfMapFull))
        .field("map", map_name)
        .field("capacity", max_entries)
        .hint(error_remediation(AegisErrorCode::BpfMapFull));
}
```

---

## Migration Checklist

### High Priority (User-Facing Commands)
- [ ] CLI command parsing errors
- [ ] Policy validation errors
- [ ] Daemon startup errors
- [ ] BPF load failures
- [ ] File permission errors

### Medium Priority (Operations)
- [ ] Block/allow rule operations
- [ ] Metrics collection errors
- [ ] Health check errors
- [ ] Network rule errors

### Low Priority (Internal)
- [ ] Debug logging
- [ ] Trace spans
- [ ] Internal assertions

---

## Testing Error Messages

```cpp
TEST(ErrorHandling, UserFriendlyMessages) {
    std::string msg = error_message(AegisErrorCode::BpfMapFull, false);

    // Should NOT contain:
    EXPECT_THAT(msg, Not(HasSubstr("errno")));
    EXPECT_THAT(msg, Not(HasSubstr("E2BIG")));
    EXPECT_THAT(msg, Not(HasSubstr("/var/run")));

    // Should contain:
    EXPECT_THAT(msg, HasSubstr("capacity"));
    EXPECT_THAT(msg, HasSubstr("remove"));
}

TEST(ErrorHandling, VerboseIncludesTechnical) {
    std::string verbose = error_message(AegisErrorCode::BpfMapFull, true);
    std::string normal = error_message(AegisErrorCode::BpfMapFull, false);

    // Verbose should have more detail
    EXPECT_GT(verbose.length(), normal.length());
    EXPECT_THAT(verbose, HasSubstr("BPF"));
}
```

---

## Resources

- `src/error_codes.hpp` - Error code definitions
- `src/logging.hpp` - Logging infrastructure
- `docs/TROUBLESHOOTING.md` - User-facing error solutions
- Error code ranges:
  - 1000-1099: Kernel compatibility
  - 1100-1199: BPF operations
  - 1200-1299: Policy errors
  - 1300-1399: File operations
  - 1400-1499: Network errors
  - 1500-1599: Daemon errors
  - 1600-1699: Resource errors
  - 1900-1999: Generic errors

---

**Last Updated:** 2026-02-07
**Next Review:** After implementing in 3 high-priority command modules
**Owner:** Development Team
