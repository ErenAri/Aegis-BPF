#!/usr/bin/env bash
#
# AegisBPF Emergency Rollback Script
#
# Usage:
#   ./rollback.sh --scope=all|canary|policy [--reason="description"]
#
# This script provides emergency rollback capabilities for AegisBPF deployments.
# It can rollback the entire deployment, just canary hosts, or just the policy.

set -euo pipefail

# Configuration
SCOPE="help"
REASON="Emergency rollback initiated"
BACKUP_DIR="/var/lib/aegisbpf/backup"
REMOTE_POLICY_PATH="/etc/aegisbpf/policy.yml"
METRICS_PORT=${METRICS_PORT:-9090}

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Parse arguments
while [[ $# -gt 0 ]]; do
  case $1 in
    --scope=*)
      SCOPE="${1#*=}"
      shift
      ;;
    --reason=*)
      REASON="${1#*=}"
      shift
      ;;
    --help)
      SCOPE="help"
      shift
      ;;
    *)
      echo "Unknown option: $1"
      SCOPE="help"
      shift
      ;;
  esac
done

usage() {
  cat <<EOF
${RED}AegisBPF Emergency Rollback Script${NC}

${YELLOW}⚠️  WARNING: This script performs emergency rollback operations.
Use only when necessary and with proper authorization.${NC}

Usage:
  $0 --scope=SCOPE [--reason="DESCRIPTION"]

Scopes:
  all       - Disable AegisBPF on ALL hosts (emergency)
  canary    - Disable AegisBPF on canary hosts only
  policy    - Rollback policy to previous version (keep daemon running)

Options:
  --scope=SCOPE         Rollback scope (required)
  --reason="TEXT"       Reason for rollback (for audit log)

Examples:
  # Emergency: disable on all hosts
  $0 --scope=all --reason="Critical production incident #12345"

  # Rollback canary deployment
  $0 --scope=canary --reason="High error rate detected in canary"

  # Rollback policy only
  $0 --scope=policy --reason="Policy causing false positives"

Requirements:
  - Ansible or SSH access to target hosts
  - sudo privileges on remote hosts
  - Proper authorization for rollback operations

${RED}⚠️  IMPORTANT: This action will be logged for audit purposes.${NC}

EOF
}

log_rollback() {
  local message=$1
  local timestamp
  timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

  # Log to local file
  mkdir -p /var/log/aegisbpf
  echo "[$timestamp] $message" | tee -a /var/log/aegisbpf/rollback.log

  # Log to syslog if available
  if command -v logger &>/dev/null; then
    logger -t aegisbpf-rollback "$message"
  fi
}

confirm_rollback() {
  local scope=$1

  echo -e "${RED}═══════════════════════════════════════${NC}"
  echo -e "${RED}  AEGISBPF EMERGENCY ROLLBACK${NC}"
  echo -e "${RED}═══════════════════════════════════════${NC}"
  echo
  echo -e "Scope:  ${YELLOW}$scope${NC}"
  echo -e "Reason: ${YELLOW}$REASON${NC}"
  echo -e "Time:   $(date)"
  echo
  echo -e "${YELLOW}This action will:${NC}"

  case "$scope" in
    all)
      echo "  - Stop AegisBPF daemon on ALL production hosts"
      echo "  - Disable automatic restart"
      echo "  - Remove enforcement immediately"
      echo
      echo -e "${RED}⚠️  This affects ENTIRE production environment!${NC}"
      ;;
    canary)
      echo "  - Stop AegisBPF daemon on canary hosts"
      echo "  - Disable automatic restart on canary hosts"
      echo "  - Keep non-canary hosts running normally"
      ;;
    policy)
      echo "  - Clear current policy enforcement rules"
      echo "  - Restore previous policy from backup"
      echo "  - Keep daemon running (audit mode only)"
      ;;
  esac

  echo
  echo -n "Type 'ROLLBACK' to confirm: "
  read -r confirmation

  if [ "$confirmation" != "ROLLBACK" ]; then
    echo "Rollback cancelled."
    exit 0
  fi

  echo
  log_rollback "ROLLBACK INITIATED: scope=$scope reason='$REASON' user=$USER"
}

get_all_hosts() {
  # Try ansible-inventory first
  if command -v ansible-inventory &>/dev/null; then
    ansible-inventory --list 2>/dev/null | jq -r '.all.hosts[]' 2>/dev/null || echo ""
  fi

  # Fall back to kubectl for Kubernetes
  if command -v kubectl &>/dev/null; then
    kubectl get nodes -o jsonpath='{.items[*].status.addresses[?(@.type=="InternalIP")].address}' 2>/dev/null || echo ""
  fi

  # Fall back to hosts file
  if [ -f "./hosts.txt" ]; then
    cat ./hosts.txt
  fi
}

get_canary_hosts() {
  if [ -f ".canary_hosts" ]; then
    cat .canary_hosts
  else
    echo ""
  fi
}

disable_host() {
  local host=$1
  local label=$2

  echo -n "  $host ... "

  if ! ssh -o ConnectTimeout=5 "$host" true 2>/dev/null; then
    echo -e "${YELLOW}UNREACHABLE${NC}"
    return 1
  fi

  # Stop and disable service
  ssh "$host" "sudo systemctl stop aegisbpf 2>/dev/null || true"
  ssh "$host" "sudo systemctl disable aegisbpf 2>/dev/null || true"

  echo -e "${GREEN}DISABLED${NC}"
  log_rollback "DISABLED: host=$host label=$label"
  return 0
}

rollback_all() {
  echo -e "${RED}Rolling back ALL hosts...${NC}"
  echo

  local all_hosts
  all_hosts=$(get_all_hosts)

  if [ -z "$all_hosts" ]; then
    echo "ERROR: No hosts found" >&2
    exit 1
  fi

  local success=0
  local failed=0

  for host in $all_hosts; do
    if disable_host "$host" "all"; then
      ((success++))
    else
      ((failed++))
    fi
  done

  echo
  echo "═══════════════════════════════════════"
  echo -e "Rollback complete:"
  echo -e "  ${GREEN}Disabled: $success${NC}"
  echo -e "  ${YELLOW}Failed: $failed${NC}"
  echo "═══════════════════════════════════════"

  log_rollback "ROLLBACK COMPLETE: scope=all success=$success failed=$failed"

  if [ "$failed" -gt 0 ]; then
    echo
    echo -e "${YELLOW}WARNING: Some hosts failed to rollback. Manual intervention required.${NC}"
    exit 1
  fi
}

rollback_canary() {
  echo -e "${YELLOW}Rolling back canary hosts...${NC}"
  echo

  local canary_hosts
  canary_hosts=$(get_canary_hosts)

  if [ -z "$canary_hosts" ]; then
    echo "No canary hosts found. Was canary deployment run?"
    exit 1
  fi

  local success=0
  local failed=0

  for host in $canary_hosts; do
    if disable_host "$host" "canary"; then
      ((success++))
    else
      ((failed++))
    fi
  done

  echo
  echo "═══════════════════════════════════════"
  echo -e "Canary rollback complete:"
  echo -e "  ${GREEN}Disabled: $success${NC}"
  echo -e "  ${YELLOW}Failed: $failed${NC}"
  echo "═══════════════════════════════════════"

  log_rollback "ROLLBACK COMPLETE: scope=canary success=$success failed=$failed"

  # Remove canary hosts file
  rm -f .canary_hosts
}

rollback_policy() {
  echo -e "${YELLOW}Rolling back policy...${NC}"
  echo

  local all_hosts
  all_hosts=$(get_all_hosts)

  if [ -z "$all_hosts" ]; then
    echo "ERROR: No hosts found" >&2
    exit 1
  fi

  # Find most recent backup policy
  local backup_policy
  for host in $all_hosts; do
    backup_policy=$(ssh "$host" "ls -t $BACKUP_DIR/policy-*.yml 2>/dev/null | head -1" || echo "")
    if [ -n "$backup_policy" ]; then
      break
    fi
  done

  if [ -z "$backup_policy" ]; then
    echo "No backup policy found. Clearing all enforcement rules instead..."

    # Clear all rules (audit-only mode)
    for host in $all_hosts; do
      echo -n "  $host ... "
      if ssh "$host" "$REMOTE_BINARY_PATH block clear 2>/dev/null"; then
        echo -e "${GREEN}CLEARED${NC}"
      else
        echo -e "${YELLOW}FAILED${NC}"
      fi
    done

    log_rollback "POLICY ROLLBACK: No backup found, cleared all rules"
    return
  fi

  echo "Found backup: $backup_policy"

  local success=0
  local failed=0

  for host in $all_hosts; do
    echo -n "  $host ... "

    if ssh "$host" "sudo cp $backup_policy $REMOTE_POLICY_PATH && $REMOTE_BINARY_PATH apply $REMOTE_POLICY_PATH 2>/dev/null"; then
      echo -e "${GREEN}RESTORED${NC}"
      ((success++))
    else
      echo -e "${YELLOW}FAILED${NC}"
      ((failed++))
    fi
  done

  echo
  echo "═══════════════════════════════════════"
  echo -e "Policy rollback complete:"
  echo -e "  ${GREEN}Restored: $success${NC}"
  echo -e "  ${YELLOW}Failed: $failed${NC}"
  echo "═══════════════════════════════════════"

  log_rollback "POLICY ROLLBACK COMPLETE: backup=$backup_policy success=$success failed=$failed"
}

# Main execution
case "$SCOPE" in
  all)
    confirm_rollback "all"
    rollback_all
    echo
    echo -e "${RED}All hosts have been rolled back.${NC}"
    echo "To re-enable, follow the deployment procedure from ROLLOUT_PLAN.md"
    ;;
  canary)
    confirm_rollback "canary"
    rollback_canary
    echo
    echo -e "${GREEN}Canary hosts have been rolled back.${NC}"
    echo "Non-canary hosts continue running normally."
    ;;
  policy)
    confirm_rollback "policy"
    rollback_policy
    echo
    echo -e "${GREEN}Policy has been rolled back.${NC}"
    echo "Daemons continue running with previous policy."
    ;;
  help|*)
    usage
    exit 0
    ;;
esac

log_rollback "ROLLBACK SCRIPT COMPLETED: scope=$SCOPE"
echo
echo "Rollback logged to: /var/log/aegisbpf/rollback.log"
