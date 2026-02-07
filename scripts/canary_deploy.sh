#!/usr/bin/env bash
#
# AegisBPF Canary Deployment Script
#
# Usage:
#   ./canary_deploy.sh --percentage=5 --enable
#   ./canary_deploy.sh --disable
#
# This script deploys AegisBPF to a percentage of hosts for canary testing.
# It selects hosts at random and manages the deployment lifecycle.

set -euo pipefail

# Configuration
CANARY_PERCENTAGE=${CANARY_PERCENTAGE:-5}
BINARY_PATH=${BINARY_PATH:-"./aegisbpf"}
POLICY_PATH=${POLICY_PATH:-"./config/policy.yml"}
REMOTE_BINARY_PATH="/usr/bin/aegisbpf"
REMOTE_POLICY_PATH="/etc/aegisbpf/policy.yml"
METRICS_PORT=${METRICS_PORT:-9090}
MODE=${MODE:-"enforce"}  # "enforce" or "audit"

# Parse arguments
ACTION="help"
while [[ $# -gt 0 ]]; do
  case $1 in
    --enable)
      ACTION="enable"
      shift
      ;;
    --disable)
      ACTION="disable"
      shift
      ;;
    --status)
      ACTION="status"
      shift
      ;;
    --percentage=*)
      CANARY_PERCENTAGE="${1#*=}"
      shift
      ;;
    --mode=*)
      MODE="${1#*=}"
      shift
      ;;
    --help)
      ACTION="help"
      shift
      ;;
    *)
      echo "Unknown option: $1"
      ACTION="help"
      shift
      ;;
  esac
done

usage() {
  cat <<EOF
AegisBPF Canary Deployment Script

Usage:
  $0 --enable [--percentage=N] [--mode=MODE]
  $0 --disable
  $0 --status
  $0 --help

Options:
  --enable              Deploy AegisBPF to canary hosts
  --disable             Remove AegisBPF from canary hosts
  --status              Show current canary deployment status
  --percentage=N        Percentage of hosts to deploy to (default: 5)
  --mode=MODE           Deployment mode: enforce or audit (default: enforce)

Environment Variables:
  CANARY_PERCENTAGE     Percentage of hosts (default: 5)
  BINARY_PATH           Path to aegisbpf binary (default: ./aegisbpf)
  POLICY_PATH           Path to policy file (default: ./config/policy.yml)
  METRICS_PORT          Metrics port (default: 9090)
  MODE                  Deployment mode (default: enforce)

Examples:
  # Deploy to 5% of hosts in enforce mode
  $0 --enable

  # Deploy to 10% of hosts in audit mode
  $0 --enable --percentage=10 --mode=audit

  # Disable canary deployment
  $0 --disable

  # Check canary status
  $0 --status

Requirements:
  - Ansible or SSH access to target hosts
  - sudo privileges on remote hosts
  - aegisbpf binary and policy file

EOF
}

get_all_hosts() {
  # Try ansible-inventory first, fall back to /etc/hosts
  if command -v ansible-inventory &>/dev/null; then
    ansible-inventory --list 2>/dev/null | jq -r '.all.hosts[]' 2>/dev/null || echo ""
  fi

  # If ansible didn't work, try kubectl for Kubernetes
  if command -v kubectl &>/dev/null; then
    kubectl get nodes -o jsonpath='{.items[*].status.addresses[?(@.type=="InternalIP")].address}' 2>/dev/null || echo ""
  fi

  # If neither worked, check for a hosts file
  if [ -f "./hosts.txt" ]; then
    cat ./hosts.txt
  fi
}

select_canary_hosts() {
  local percentage=$1
  local all_hosts
  all_hosts=$(get_all_hosts)

  if [ -z "$all_hosts" ]; then
    echo "ERROR: No hosts found. Configure ansible-inventory, kubectl, or create hosts.txt" >&2
    exit 1
  fi

  local total_hosts
  total_hosts=$(echo "$all_hosts" | wc -w)
  local canary_count
  canary_count=$(( (total_hosts * percentage + 50) / 100 ))  # Round to nearest

  if [ "$canary_count" -lt 1 ]; then
    canary_count=1
  fi

  echo "Total hosts: $total_hosts" >&2
  echo "Canary hosts: $canary_count ($percentage%)" >&2

  # Select random hosts
  echo "$all_hosts" | tr ' ' '\n' | shuf | head -n "$canary_count"
}

deploy_to_host() {
  local host=$1
  local mode=$2

  echo "Deploying to $host (mode: $mode)..."

  # Check if host is reachable
  if ! ssh -o ConnectTimeout=5 "$host" true 2>/dev/null; then
    echo "  ERROR: Cannot reach $host" >&2
    return 1
  fi

  # Stop existing daemon
  ssh "$host" "sudo systemctl stop aegisbpf 2>/dev/null || true"

  # Copy binary
  if ! scp -q "$BINARY_PATH" "$host:/tmp/aegisbpf"; then
    echo "  ERROR: Failed to copy binary to $host" >&2
    return 1
  fi

  # Copy policy
  if ! scp -q "$POLICY_PATH" "$host:/tmp/policy.yml"; then
    echo "  ERROR: Failed to copy policy to $host" >&2
    return 1
  fi

  # Install binary and policy
  ssh "$host" "sudo mv /tmp/aegisbpf $REMOTE_BINARY_PATH && sudo chmod +x $REMOTE_BINARY_PATH"
  ssh "$host" "sudo mkdir -p /etc/aegisbpf && sudo mv /tmp/policy.yml $REMOTE_POLICY_PATH"

  # Create systemd service if not exists
  ssh "$host" "sudo tee /etc/systemd/system/aegisbpf.service >/dev/null" <<EOF
[Unit]
Description=AegisBPF Runtime Security Agent
After=network.target

[Service]
Type=simple
ExecStart=$REMOTE_BINARY_PATH run --$mode --metrics-port=$METRICS_PORT
Restart=always
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF

  # Enable and start service
  ssh "$host" "sudo systemctl daemon-reload"
  ssh "$host" "sudo systemctl enable aegisbpf"
  ssh "$host" "sudo systemctl start aegisbpf"

  # Wait for health check
  sleep 2
  if ssh "$host" "curl -sf http://localhost:$METRICS_PORT/health >/dev/null"; then
    echo "  ✓ $host deployed successfully"
    return 0
  else
    echo "  ✗ $host health check failed" >&2
    return 1
  fi
}

disable_on_host() {
  local host=$1

  echo "Disabling on $host..."

  if ! ssh -o ConnectTimeout=5 "$host" true 2>/dev/null; then
    echo "  ERROR: Cannot reach $host" >&2
    return 1
  fi

  ssh "$host" "sudo systemctl stop aegisbpf"
  ssh "$host" "sudo systemctl disable aegisbpf"

  echo "  ✓ $host disabled"
}

check_host_status() {
  local host=$1

  if ! ssh -o ConnectTimeout=5 "$host" true 2>/dev/null; then
    echo "$host: UNREACHABLE"
    return
  fi

  if ssh "$host" "systemctl is-active aegisbpf >/dev/null 2>&1"; then
    local health_status
    if ssh "$host" "curl -sf http://localhost:$METRICS_PORT/health >/dev/null 2>&1"; then
      health_status="HEALTHY"
    else
      health_status="UNHEALTHY"
    fi
    echo "$host: RUNNING ($health_status)"
  else
    echo "$host: STOPPED"
  fi
}

action_enable() {
  if [ ! -f "$BINARY_PATH" ]; then
    echo "ERROR: Binary not found at $BINARY_PATH" >&2
    exit 1
  fi

  if [ ! -f "$POLICY_PATH" ]; then
    echo "ERROR: Policy not found at $POLICY_PATH" >&2
    exit 1
  fi

  echo "=== AegisBPF Canary Deployment ==="
  echo "Binary: $BINARY_PATH"
  echo "Policy: $POLICY_PATH"
  echo "Mode: $MODE"
  echo "Percentage: $CANARY_PERCENTAGE%"
  echo

  local canary_hosts
  canary_hosts=$(select_canary_hosts "$CANARY_PERCENTAGE")

  # Save canary hosts to file for later reference
  echo "$canary_hosts" > .canary_hosts

  local success_count=0
  local fail_count=0

  for host in $canary_hosts; do
    if deploy_to_host "$host" "$MODE"; then
      ((success_count++))
    else
      ((fail_count++))
    fi
  done

  echo
  echo "=== Deployment Summary ==="
  echo "Successful: $success_count"
  echo "Failed: $fail_count"

  if [ "$fail_count" -gt 0 ]; then
    echo
    echo "WARNING: Some deployments failed. Review logs above."
    exit 1
  fi

  echo
  echo "Canary deployment complete. Monitor metrics:"
  echo "  - Check dashboards for canary host performance"
  echo "  - Review block events: aegisbpf stats"
  echo "  - Monitor application health"
  echo
  echo "To rollback: $0 --disable"
}

action_disable() {
  if [ ! -f ".canary_hosts" ]; then
    echo "ERROR: No canary hosts found. Was deployment run?" >&2
    exit 1
  fi

  echo "=== AegisBPF Canary Rollback ==="

  local canary_hosts
  canary_hosts=$(cat .canary_hosts)

  for host in $canary_hosts; do
    disable_on_host "$host"
  done

  echo
  echo "Canary rollback complete."
  rm -f .canary_hosts
}

action_status() {
  if [ ! -f ".canary_hosts" ]; then
    echo "No active canary deployment."
    exit 0
  fi

  echo "=== AegisBPF Canary Status ==="

  local canary_hosts
  canary_hosts=$(cat .canary_hosts)

  for host in $canary_hosts; do
    check_host_status "$host"
  done
}

# Main execution
case "$ACTION" in
  enable)
    action_enable
    ;;
  disable)
    action_disable
    ;;
  status)
    action_status
    ;;
  help|*)
    usage
    exit 0
    ;;
esac
