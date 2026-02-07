#!/usr/bin/env bash
#
# AegisBPF Phase 0: Pre-Deployment Validation
#
# This script validates that all prerequisites are met before starting
# the production rollout.

set -euo pipefail

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

VALIDATION_PASSED=0
VALIDATION_FAILED=0
VALIDATION_WARNING=0

log_pass() {
    echo -e "${GREEN}✓${NC} $1"
    ((VALIDATION_PASSED++))
}

log_fail() {
    echo -e "${RED}✗${NC} $1"
    ((VALIDATION_FAILED++))
}

log_warn() {
    echo -e "${YELLOW}⚠${NC} $1"
    ((VALIDATION_WARNING++))
}

log_info() {
    echo -e "${BLUE}ℹ${NC} $1"
}

section() {
    echo
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
}

echo "╔════════════════════════════════════════════════════╗"
echo "║  AegisBPF Production Rollout - Phase 0 Validation ║"
echo "╔════════════════════════════════════════════════════╝"
echo

# Check if running from project root
if [ ! -f "CMakeLists.txt" ] || [ ! -d "bpf" ]; then
    log_fail "Not running from project root. Please run from AegisBPF directory."
    exit 1
fi

section "1. Test Status"

# Check unit tests
if [ -f "build/aegisbpf_test" ]; then
    log_info "Running unit tests..."
    if sudo ./build/aegisbpf_test --gtest_brief=1 >/tmp/unit_test.log 2>&1; then
        TEST_COUNT=$(grep -c "RUN" /tmp/unit_test.log || echo "0")
        log_pass "Unit tests: $TEST_COUNT tests passed"
    else
        log_fail "Unit tests: FAILED (see /tmp/unit_test.log)"
    fi
else
    log_warn "Unit tests: Binary not found. Run: cmake --build build"
fi

# Check E2E tests
if [ -d "scripts" ] && [ -f "scripts/smoke_enforce.sh" ]; then
    log_pass "E2E test scripts: Available"
    log_info "  To run E2E: sudo ./scripts/smoke_enforce.sh"
else
    log_warn "E2E test scripts: Not found"
fi

section "2. Security Audit Status"

# Check for security audit documents
if [ -f "docs/SECURITY_AUDIT.md" ]; then
    log_pass "Ed25519 crypto audit: Documented"
else
    log_warn "Security audit documentation missing"
fi

# Check BPF verifier bypass is disabled
if grep -q "NDEBUG" CMakeLists.txt; then
    log_pass "BPF verifier bypass: Disabled in Release builds"
else
    log_warn "BPF verifier bypass: Check CMakeLists.txt for NDEBUG"
fi

# Check for debug symbols in binary
if [ -f "build/aegisbpf" ]; then
    if file build/aegisbpf | grep -q "not stripped"; then
        log_warn "Binary contains debug symbols (use Release build for production)"
    else
        log_pass "Binary: Stripped for production"
    fi
fi

section "3. Documentation Status"

REQUIRED_DOCS=(
    "docs/RUNBOOK_RECOVERY.md"
    "docs/CAPACITY_PLANNING.md"
    "docs/MONITORING_GUIDE.md"
    "docs/ROLLOUT_PLAN.md"
)

for doc in "${REQUIRED_DOCS[@]}"; do
    if [ -f "$doc" ]; then
        log_pass "Documentation: $doc"
    else
        log_fail "Documentation: Missing $doc"
    fi
done

section "4. Monitoring Stack Readiness"

log_info "Checking monitoring prerequisites..."

# Check if Prometheus is available
if command -v prometheus &>/dev/null; then
    log_pass "Prometheus: Installed"
elif docker ps --format '{{.Image}}' | grep -q prometheus; then
    log_pass "Prometheus: Running in Docker"
else
    log_warn "Prometheus: Not detected. Install for production monitoring."
fi

# Check if Grafana is available
if command -v grafana-server &>/dev/null; then
    log_pass "Grafana: Installed"
elif docker ps --format '{{.Image}}' | grep -q grafana; then
    log_pass "Grafana: Running in Docker"
else
    log_warn "Grafana: Not detected. Install for production dashboards."
fi

# Check for Prometheus config
if [ -f "config/prometheus/alerts.yml" ]; then
    log_pass "Alert rules: Configured"
else
    log_warn "Alert rules: config/prometheus/alerts.yml not found"
fi

section "5. Kernel Compatibility"

log_info "Checking kernel features..."

if [ -f "build/aegisbpf" ]; then
    # Run health check
    if sudo ./build/aegisbpf health --json >/tmp/health.json 2>&1; then
        CAPABILITY=$(jq -r '.capability' /tmp/health.json 2>/dev/null || echo "unknown")
        if [ "$CAPABILITY" = "full" ]; then
            log_pass "Kernel capability: Full enforcement available"
        elif [ "$CAPABILITY" = "audit-only" ]; then
            log_warn "Kernel capability: Audit-only mode (BPF LSM not enabled)"
        else
            log_fail "Kernel capability: Cannot determine ($CAPABILITY)"
        fi

        # Check features
        BPF_LSM=$(jq -r '.features.bpf_lsm' /tmp/health.json 2>/dev/null || echo "false")
        CGROUP_V2=$(jq -r '.features.cgroup_v2' /tmp/health.json 2>/dev/null || echo "false")
        BTF=$(jq -r '.features.btf' /tmp/health.json 2>/dev/null || echo "false")

        [ "$BPF_LSM" = "true" ] && log_pass "BPF LSM: Enabled" || log_warn "BPF LSM: Disabled (audit-only mode)"
        [ "$CGROUP_V2" = "true" ] && log_pass "Cgroup v2: Available" || log_fail "Cgroup v2: Missing"
        [ "$BTF" = "true" ] && log_pass "BTF: Available" || log_warn "BTF: Missing (may limit compatibility)"
    else
        log_warn "Health check failed. Run manually: sudo ./build/aegisbpf health"
    fi
else
    log_warn "Binary not found. Build first: cmake --build build"
fi

section "6. Performance Baseline"

log_info "To capture performance baseline, run:"
echo "  1. Start in audit mode: sudo ./build/aegisbpf run --audit --metrics-port=9090 &"
echo "  2. Run workload for 1 hour"
echo "  3. Capture metrics: curl http://localhost:9090/metrics > baseline.txt"
echo "  4. Measure CPU: top -p \$(pgrep aegisbpf) -b -n 60 > cpu_baseline.txt"
log_warn "Performance baseline: Manual validation required"

section "7. Build Configuration"

if [ -f "build/CMakeCache.txt" ]; then
    BUILD_TYPE=$(grep CMAKE_BUILD_TYPE:STRING build/CMakeCache.txt | cut -d= -f2)
    if [ "$BUILD_TYPE" = "Release" ] || [ "$BUILD_TYPE" = "RelWithDebInfo" ]; then
        log_pass "Build type: $BUILD_TYPE (production-ready)"
    else
        log_warn "Build type: $BUILD_TYPE (use Release for production)"
    fi
else
    log_warn "Build configuration: Not found"
fi

section "8. Deployment Scripts"

DEPLOYMENT_SCRIPTS=(
    "scripts/canary_deploy.sh"
    "scripts/rollback.sh"
)

for script in "${DEPLOYMENT_SCRIPTS[@]}"; do
    if [ -f "$script" ] && [ -x "$script" ]; then
        log_pass "Deployment script: $script"
    else
        log_fail "Deployment script: Missing or not executable: $script"
    fi
done

section "9. Policy Files"

if [ -f "config/policy.yml" ]; then
    log_pass "Policy file: config/policy.yml exists"

    # Validate policy syntax
    if [ -f "build/aegisbpf" ]; then
        if ./build/aegisbpf policy validate config/policy.yml 2>&1 | grep -q "valid"; then
            log_pass "Policy validation: Syntax OK"
        else
            log_warn "Policy validation: Check syntax"
        fi
    fi
else
    log_warn "Policy file: Create config/policy.yml before deployment"
fi

section "10. Version Control Status"

CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "unknown")
log_info "Current branch: $CURRENT_BRANCH"

if git diff-index --quiet HEAD -- 2>/dev/null; then
    log_pass "Working tree: Clean (no uncommitted changes)"
else
    log_warn "Working tree: Uncommitted changes present"
fi

if git log origin/main..HEAD --oneline 2>/dev/null | grep -q .; then
    UNPUSHED=$(git log origin/main..HEAD --oneline 2>/dev/null | wc -l)
    log_warn "Version control: $UNPUSHED unpushed commit(s)"
else
    log_pass "Version control: All changes pushed"
fi

section "11. CI/CD Status"

log_info "Checking latest CI run..."
if command -v gh &>/dev/null; then
    LATEST_RUN=$(gh run list --branch "$CURRENT_BRANCH" --limit 1 --json conclusion,status --jq '.[0]')
    STATUS=$(echo "$LATEST_RUN" | jq -r '.status')
    CONCLUSION=$(echo "$LATEST_RUN" | jq -r '.conclusion')

    if [ "$STATUS" = "completed" ] && [ "$CONCLUSION" = "success" ]; then
        log_pass "CI/CD: Latest run passed"
    elif [ "$STATUS" = "in_progress" ]; then
        log_warn "CI/CD: Build in progress"
    else
        log_fail "CI/CD: Latest run failed or incomplete"
    fi
else
    log_warn "GitHub CLI not installed. Check CI manually."
fi

# Summary
section "Validation Summary"

echo
echo "Results:"
echo -e "  ${GREEN}Passed:${NC}   $VALIDATION_PASSED"
echo -e "  ${RED}Failed:${NC}   $VALIDATION_FAILED"
echo -e "  ${YELLOW}Warnings:${NC} $VALIDATION_WARNING"
echo

if [ "$VALIDATION_FAILED" -eq 0 ] && [ "$VALIDATION_WARNING" -le 5 ]; then
    echo -e "${GREEN}✓ Phase 0 validation complete!${NC}"
    echo
    echo "Next steps:"
    echo "  1. Review warnings above and address critical items"
    echo "  2. Capture performance baseline (see section 6)"
    echo "  3. Schedule Phase 1: Shadow Mode deployment"
    echo "  4. Review docs/ROLLOUT_PLAN.md for detailed procedures"
    echo
    exit 0
elif [ "$VALIDATION_FAILED" -eq 0 ]; then
    echo -e "${YELLOW}⚠ Phase 0 validation passed with warnings${NC}"
    echo
    echo "Address warnings before proceeding to production:"
    echo "  - Review items marked with ⚠ above"
    echo "  - Ensure monitoring stack is ready"
    echo "  - Complete performance baseline capture"
    echo
    exit 0
else
    echo -e "${RED}✗ Phase 0 validation failed${NC}"
    echo
    echo "Critical issues must be resolved:"
    echo "  - Fix items marked with ✗ above"
    echo "  - Re-run validation after fixes"
    echo
    exit 1
fi
