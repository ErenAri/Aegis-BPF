#!/usr/bin/env bash
# aws_soak_24h.sh — Launch a 24-hour soak test on an AWS EC2 instance.
#
# Launches a t3.micro (or user-specified type) with Ubuntu 24.04, builds
# AegisBPF from HEAD, enables BPF LSM, runs a 24-hour soak, uploads
# results to S3, and terminates.
#
# Cost: t3.micro = ~$0.25/day (us-east-1). The instance self-terminates
# after the soak completes.
#
# Prerequisites:
#   - AWS CLI configured (`aws configure`)
#   - An S3 bucket for results (or the script creates one)
#   - Default VPC with internet access (or specify --subnet-id)
#
# Usage:
#   ./scripts/aws_soak_24h.sh [options]
#
# Options:
#   --instance-type TYPE   EC2 instance type (default: t3.micro)
#   --ami AMI_ID           Ubuntu 24.04 AMI ID (auto-detected if empty)
#   --region REGION        AWS region (default: us-east-1)
#   --s3-bucket BUCKET     S3 bucket for results (default: aegisbpf-soak-results)
#   --branch BRANCH        Git branch to test (default: main)
#   --duration SECONDS     Soak duration (default: 86400 = 24 hours)
#   --mode MODE            audit or enforce (default: audit)
#   --dry-run              Print user-data script but don't launch
#   -h, --help             Show this help
#
# IMPORTANT: t2.micro works but t3.micro is recommended (cheaper, 2 vCPUs,
# newer Nitro platform). Both have 1 GB RAM which is sufficient for
# AegisBPF soak testing (~8-50 MB RSS).
#
# BPF LSM Note: Ubuntu 24.04 AMIs do NOT have BPF LSM enabled by default.
# This script adds lsm=...,bpf to GRUB and reboots the instance before
# starting the soak. The reboot adds ~2 minutes to startup.

set -euo pipefail

INSTANCE_TYPE="${INSTANCE_TYPE:-t3.micro}"
AMI_ID="${AMI_ID:-}"
REGION="${REGION:-us-east-1}"
S3_BUCKET="${S3_BUCKET:-aegisbpf-soak-results}"
GIT_BRANCH="${GIT_BRANCH:-main}"
GIT_REPO="${GIT_REPO:-https://github.com/ErenAri/Aegis-BPF.git}"
DURATION="${DURATION:-86400}"
SOAK_MODE="${SOAK_MODE:-audit}"
DRY_RUN=0

usage() {
    cat <<EOF
Usage: $0 [options]

Launch a 24-hour soak test on AWS EC2.

Options:
  --instance-type TYPE   Instance type (default: $INSTANCE_TYPE)
  --ami AMI_ID           Ubuntu 24.04 AMI (auto-detected per region)
  --region REGION        AWS region (default: $REGION)
  --s3-bucket BUCKET     S3 bucket for results (default: $S3_BUCKET)
  --branch BRANCH        Git branch (default: $GIT_BRANCH)
  --duration SECONDS     Soak duration (default: $DURATION)
  --mode MODE            audit or enforce (default: $SOAK_MODE)
  --dry-run              Print user-data, don't launch
  -h, --help             Show help

Cost estimate (us-east-1):
  t3.micro:  ~\$0.25/day
  t3.small:  ~\$0.50/day
  t3.medium: ~\$1.00/day
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --instance-type) INSTANCE_TYPE="$2"; shift 2 ;;
        --ami) AMI_ID="$2"; shift 2 ;;
        --region) REGION="$2"; shift 2 ;;
        --s3-bucket) S3_BUCKET="$2"; shift 2 ;;
        --branch) GIT_BRANCH="$2"; shift 2 ;;
        --duration) DURATION="$2"; shift 2 ;;
        --mode) SOAK_MODE="$2"; shift 2 ;;
        --dry-run) DRY_RUN=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown option: $1" >&2; usage >&2; exit 1 ;;
    esac
done

# Auto-detect Ubuntu 24.04 AMI if not specified
if [[ -z "${AMI_ID}" ]]; then
    echo "Looking up Ubuntu 24.04 AMI in ${REGION}..."
    AMI_ID="$(aws ec2 describe-images \
        --region "${REGION}" \
        --owners 099720109477 \
        --filters "Name=name,Values=ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*" \
                  "Name=state,Values=available" \
        --query 'sort_by(Images, &CreationDate)[-1].ImageId' \
        --output text 2>/dev/null)" || true
    if [[ -z "${AMI_ID}" || "${AMI_ID}" == "None" ]]; then
        echo "ERROR: Could not find Ubuntu 24.04 AMI in ${REGION}" >&2
        echo "Specify --ami manually." >&2
        exit 1
    fi
    echo "Using AMI: ${AMI_ID}"
fi

TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
RUN_ID="soak-${TIMESTAMP}"

# Generate the cloud-init user-data script
#
# Design notes (these fix real bugs hit on prior runs):
#   - cloud-init user-data only runs ONCE (on first boot). After the reboot
#     needed to activate BPF LSM, user-data is NOT re-run. We therefore
#     install a systemd oneshot unit in Phase 1 that runs Phase 2 on the
#     next boot.
#   - Ubuntu 24.04 (Noble) does NOT have an `awscli` apt package. Installing
#     aws-cli via snap instead. Any failure in apt-get install rolls back the
#     WHOLE transaction, which is what previously left clang/cmake missing.
#   - Use --parallel 1 for cmake build on 1 GB RAM instances (avoid OOM).
#   - Use PIPESTATUS to capture the soak script's exit, not tee's.
USERDATA=$(cat <<'USERDATA_EOF'
#!/bin/bash
set -uxo pipefail  # no -e: let commands fail without killing the script
exec > /var/log/aegisbpf-soak-setup.log 2>&1

echo "=== AegisBPF soak cloud-init Phase 1 started at $(date -u) ==="

# --- Wait for any existing apt/dpkg activity (cloud-init, unattended-upgrades) ---
for i in $(seq 1 60); do
    if ! fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 \
         && ! fuser /var/lib/apt/lists/lock >/dev/null 2>&1; then
        break
    fi
    echo "Waiting for dpkg/apt lock ($i/60)..."
    sleep 10
done

# --- Install build deps (apt) ---
# IMPORTANT: do NOT include `awscli` here — that package does not exist on
# Ubuntu 24.04 and its absence causes the entire apt transaction to fail,
# leaving the other packages uninstalled. AWS CLI is installed separately
# via snap below.
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y clang llvm libbpf-dev libsystemd-dev pkg-config \
    cmake ninja-build python3-jsonschema libelf-dev zlib1g-dev git jq curl \
    python3-pip
APT_RC=$?
echo "apt-get install exit=${APT_RC}"

# Verify critical tools actually landed
for tool in clang cmake ninja pkg-config git; do
    if ! command -v "${tool}" >/dev/null 2>&1; then
        echo "FATAL: ${tool} missing after apt-get install"
        exit 1
    fi
done

# Install bpftool (kernel-matched, with fallbacks)
apt-get install -y linux-tools-common || true
apt-get install -y "linux-tools-$(uname -r)" || \
    apt-get install -y linux-tools-generic || true

# Install AWS CLI v2 via snap (awscli apt package does not exist on Noble)
snap install aws-cli --classic || true
if ! command -v aws >/dev/null 2>&1; then
    # Fallback: official v2 zip installer
    curl -fsSL "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o /tmp/awscliv2.zip
    (cd /tmp && unzip -q awscliv2.zip && ./aws/install)
fi
aws --version || echo "WARN: aws cli still missing"

# --- Enable BPF LSM in GRUB (if not already active) ---
CURRENT_LSM="$(cat /sys/kernel/security/lsm 2>/dev/null || echo 'lockdown,capability,landlock,yama,apparmor')"
NEEDS_REBOOT=0
if ! echo "${CURRENT_LSM}" | grep -q bpf; then
    sed -i "s|^GRUB_CMDLINE_LINUX=\"|GRUB_CMDLINE_LINUX=\"lsm=${CURRENT_LSM},bpf |" /etc/default/grub
    update-grub
    NEEDS_REBOOT=1
fi

# --- Install Phase 2 as a systemd oneshot unit ---
# cloud-init user-data does not re-run after reboot. A systemd unit does.
cat > /usr/local/bin/aegisbpf-soak-phase2.sh <<'PHASE2_EOF'
#!/bin/bash
set -uxo pipefail
exec > /var/log/aegisbpf-soak-phase2.log 2>&1

echo "=== Phase 2 start at $(date -u) ==="

# If already ran to completion, don't run again
if [[ -f /var/lib/aegisbpf-soak-done ]]; then
    echo "Soak already completed. Exiting."
    exit 0
fi

# Verify BPF LSM active
cat /sys/kernel/security/lsm
if ! grep -q bpf /sys/kernel/security/lsm; then
    echo "WARNING: BPF LSM not active"
fi

# Clone and build
mkdir -p /opt
cd /opt
if [[ ! -d aegisbpf ]]; then
    git clone --depth 1 --branch __GIT_BRANCH__ __GIT_REPO__ aegisbpf
fi
cd aegisbpf

cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=OFF
# --parallel 1 to avoid OOM on 1 GB RAM instances (t2.micro, t3.micro)
cmake --build build --parallel 1
BUILD_RC=$?
if [[ ${BUILD_RC} -ne 0 ]] || [[ ! -x build/aegisbpf ]]; then
    echo "FATAL: build failed (rc=${BUILD_RC})"
    touch /var/lib/aegisbpf-soak-done
    # still try to upload logs
    mkdir -p /opt/aegisbpf/artifacts/soak-24h
    cp /var/log/aegisbpf-soak-phase2.log /opt/aegisbpf/artifacts/soak-24h/ || true
    cp /var/log/aegisbpf-soak-setup.log /opt/aegisbpf/artifacts/soak-24h/ || true
    aws s3 cp --recursive /opt/aegisbpf/artifacts/soak-24h/ \
        s3://__S3_BUCKET__/__RUN_ID__/ --region __REGION__ || true
    INSTANCE_ID="$(curl -sS -H "X-aws-ec2-metadata-token: $(curl -sS -X PUT http://169.254.169.254/latest/api/token -H 'X-aws-ec2-metadata-token-ttl-seconds: 60')" http://169.254.169.254/latest/meta-data/instance-id)"
    aws ec2 terminate-instances --instance-ids "${INSTANCE_ID}" --region __REGION__ || true
    exit 1
fi

./build/aegisbpf version || true

# Run soak
mkdir -p /opt/aegisbpf/artifacts/soak-24h
set +e  # don't let soak non-zero kill the wrapper
AEGIS_BIN=./build/aegisbpf \
    SOAK_MODE=__SOAK_MODE__ \
    SOAK_NET_WORKLOAD=1 \
    DURATION_SECONDS=__DURATION__ \
    MAX_RINGBUF_DROPS=2000 \
    MAX_RSS_GROWTH_KB=131072 \
    MAX_EVENT_DROP_RATIO_PCT=0.1 \
    MIN_TOTAL_DECISIONS=100 \
    OUT_JSON=/opt/aegisbpf/artifacts/soak-24h/soak_summary.json \
    scripts/soak_reliability.sh 2>&1 | tee /opt/aegisbpf/artifacts/soak-24h/soak.log
SOAK_EXIT=${PIPESTATUS[0]}
set -u

# Capture environment
uname -a > /opt/aegisbpf/artifacts/soak-24h/kernel.txt
cat /etc/os-release > /opt/aegisbpf/artifacts/soak-24h/os-release.txt || true
lscpu > /opt/aegisbpf/artifacts/soak-24h/cpu.txt || true
free -m > /opt/aegisbpf/artifacts/soak-24h/memory.txt || true
cat /sys/kernel/security/lsm > /opt/aegisbpf/artifacts/soak-24h/lsm.txt || true
echo "${SOAK_EXIT}" > /opt/aegisbpf/artifacts/soak-24h/exit_code.txt
cp /var/log/aegisbpf-soak-setup.log /opt/aegisbpf/artifacts/soak-24h/ || true
cp /var/log/aegisbpf-soak-phase2.log /opt/aegisbpf/artifacts/soak-24h/ || true

# Upload to S3
aws s3 cp --recursive /opt/aegisbpf/artifacts/soak-24h/ \
    s3://__S3_BUCKET__/__RUN_ID__/ --region __REGION__ || echo "S3 upload failed"

touch /var/lib/aegisbpf-soak-done

# Self-terminate (IMDSv2)
IMDS_TOKEN="$(curl -sS -X PUT http://169.254.169.254/latest/api/token -H 'X-aws-ec2-metadata-token-ttl-seconds: 60')"
INSTANCE_ID="$(curl -sS -H "X-aws-ec2-metadata-token: ${IMDS_TOKEN}" http://169.254.169.254/latest/meta-data/instance-id)"
aws ec2 terminate-instances --instance-ids "${INSTANCE_ID}" --region __REGION__ || true
PHASE2_EOF
chmod +x /usr/local/bin/aegisbpf-soak-phase2.sh

cat > /etc/systemd/system/aegisbpf-soak.service <<'UNIT_EOF'
[Unit]
Description=AegisBPF 24h soak test runner (Phase 2)
After=network-online.target cloud-init.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/aegisbpf-soak-phase2.sh
RemainAfterExit=yes
TimeoutStartSec=0

[Install]
WantedBy=multi-user.target
UNIT_EOF

systemctl daemon-reload
systemctl enable aegisbpf-soak.service

echo "=== Phase 1 complete at $(date -u), NEEDS_REBOOT=${NEEDS_REBOOT} ==="

if [[ ${NEEDS_REBOOT} -eq 1 ]]; then
    echo "Rebooting to activate BPF LSM..."
    # Phase 2 will run automatically via systemd unit after reboot.
    reboot
    exit 0
fi

# BPF LSM already active (unusual) — kick off Phase 2 now.
systemctl start aegisbpf-soak.service
USERDATA_EOF
)

# Replace placeholders
USERDATA="${USERDATA//__GIT_BRANCH__/${GIT_BRANCH}}"
USERDATA="${USERDATA//__GIT_REPO__/${GIT_REPO}}"
USERDATA="${USERDATA//__SOAK_MODE__/${SOAK_MODE}}"
USERDATA="${USERDATA//__DURATION__/${DURATION}}"
USERDATA="${USERDATA//__S3_BUCKET__/${S3_BUCKET}}"
USERDATA="${USERDATA//__RUN_ID__/${RUN_ID}}"
USERDATA="${USERDATA//__REGION__/${REGION}}"

# --- Ensure IAM role exists for instance (S3 + self-terminate) ---
ROLE_NAME="aegisbpf-soak-role"
PROFILE_NAME="aegisbpf-soak-profile"

ensure_iam_role() {
    # Check if role already exists
    if aws iam get-role --role-name "${ROLE_NAME}" --region "${REGION}" >/dev/null 2>&1; then
        echo "IAM role ${ROLE_NAME} already exists."
    else
        echo "Creating IAM role ${ROLE_NAME}..."
        aws iam create-role --role-name "${ROLE_NAME}" \
            --assume-role-policy-document '{
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": {"Service": "ec2.amazonaws.com"},
                    "Action": "sts:AssumeRole"
                }]
            }' >/dev/null

        # Attach policies for S3 upload and self-termination
        aws iam put-role-policy --role-name "${ROLE_NAME}" \
            --policy-name "aegisbpf-soak-policy" \
            --policy-document '{
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["s3:PutObject", "s3:GetObject", "s3:ListBucket"],
                        "Resource": ["arn:aws:s3:::'"${S3_BUCKET}"'", "arn:aws:s3:::'"${S3_BUCKET}"'/*"]
                    },
                    {
                        "Effect": "Allow",
                        "Action": "ec2:TerminateInstances",
                        "Resource": "*",
                        "Condition": {
                            "StringEquals": {"ec2:ResourceTag/Purpose": "soak-test"}
                        }
                    },
                    {
                        "Effect": "Allow",
                        "Action": "ec2:DescribeInstances",
                        "Resource": "*"
                    }
                ]
            }' >/dev/null
    fi

    # Create instance profile if it doesn't exist
    if aws iam get-instance-profile --instance-profile-name "${PROFILE_NAME}" >/dev/null 2>&1; then
        echo "Instance profile ${PROFILE_NAME} already exists."
    else
        echo "Creating instance profile ${PROFILE_NAME}..."
        aws iam create-instance-profile --instance-profile-name "${PROFILE_NAME}" >/dev/null
        aws iam add-role-to-instance-profile \
            --instance-profile-name "${PROFILE_NAME}" \
            --role-name "${ROLE_NAME}" >/dev/null
        echo "Waiting for instance profile propagation..."
        sleep 15
    fi
}

# --- Ensure SSH key pair exists ---
KEY_NAME="aegisbpf-soak-key"
KEY_FILE="${HOME}/.ssh/${KEY_NAME}.pem"

ensure_key_pair() {
    if aws ec2 describe-key-pairs --key-names "${KEY_NAME}" --region "${REGION}" >/dev/null 2>&1; then
        echo "Key pair ${KEY_NAME} already exists."
    else
        echo "Creating key pair ${KEY_NAME}..."
        mkdir -p "${HOME}/.ssh"
        aws ec2 create-key-pair --key-name "${KEY_NAME}" --region "${REGION}" \
            --query 'KeyMaterial' --output text > "${KEY_FILE}"
        chmod 600 "${KEY_FILE}"
        echo "SSH key saved to ${KEY_FILE}"
    fi
}

# --- Ensure security group allows SSH ---
SG_NAME="aegisbpf-soak-sg"

ensure_security_group() {
    SG_ID="$(aws ec2 describe-security-groups --group-names "${SG_NAME}" --region "${REGION}" \
        --query 'SecurityGroups[0].GroupId' --output text 2>/dev/null)" || true
    if [[ -n "${SG_ID}" && "${SG_ID}" != "None" ]]; then
        echo "Security group ${SG_NAME} already exists: ${SG_ID}"
    else
        echo "Creating security group ${SG_NAME}..."
        SG_ID="$(aws ec2 create-security-group --group-name "${SG_NAME}" \
            --description "AegisBPF soak test - SSH access" \
            --region "${REGION}" --query 'GroupId' --output text)"
        aws ec2 authorize-security-group-ingress --group-id "${SG_ID}" --region "${REGION}" \
            --protocol tcp --port 22 --cidr 0.0.0.0/0 >/dev/null
        echo "Security group created: ${SG_ID}"
    fi
}

if [[ "${DRY_RUN}" -eq 1 ]]; then
    echo "=== User-data script (dry run) ==="
    echo "${USERDATA}"
    echo
    echo "=== Launch parameters ==="
    echo "Instance type: ${INSTANCE_TYPE}"
    echo "AMI: ${AMI_ID}"
    echo "Region: ${REGION}"
    echo "S3 bucket: s3://${S3_BUCKET}/${RUN_ID}/"
    echo "Duration: ${DURATION}s ($(( DURATION / 3600 )) hours)"
    echo "Mode: ${SOAK_MODE}"
    exit 0
fi

# Ensure S3 bucket exists
aws s3 mb "s3://${S3_BUCKET}" --region "${REGION}" 2>/dev/null || true

# Setup IAM, key pair, and security group
ensure_iam_role
ensure_key_pair
ensure_security_group

# Launch instance
echo "Launching ${INSTANCE_TYPE} in ${REGION}..."
INSTANCE_ID="$(aws ec2 run-instances \
    --region "${REGION}" \
    --image-id "${AMI_ID}" \
    --instance-type "${INSTANCE_TYPE}" \
    --user-data "${USERDATA}" \
    --key-name "${KEY_NAME}" \
    --security-groups "${SG_NAME}" \
    --iam-instance-profile "Name=${PROFILE_NAME}" \
    --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=aegisbpf-soak-${TIMESTAMP}},{Key=Purpose,Value=soak-test}]" \
    --instance-initiated-shutdown-behavior terminate \
    --query 'Instances[0].InstanceId' \
    --output text)"

# Wait for public IP
sleep 5
PUBLIC_IP="$(aws ec2 describe-instances --instance-ids "${INSTANCE_ID}" --region "${REGION}" \
    --query 'Reservations[].Instances[].PublicIpAddress' --output text 2>/dev/null)" || true

echo
echo "=== Soak test launched ==="
echo "Instance:  ${INSTANCE_ID}"
echo "Type:      ${INSTANCE_TYPE}"
echo "Region:    ${REGION}"
echo "IP:        ${PUBLIC_IP:-pending}"
echo "Duration:  ${DURATION}s ($(( DURATION / 3600 )) hours)"
echo "Mode:      ${SOAK_MODE}"
echo "Branch:    ${GIT_BRANCH}"
echo "Results:   s3://${S3_BUCKET}/${RUN_ID}/"
echo
echo "SSH (for debugging):"
echo "  ssh -i ${KEY_FILE} ubuntu@${PUBLIC_IP:-<pending>}"
echo
echo "View setup log:"
echo "  ssh -i ${KEY_FILE} ubuntu@${PUBLIC_IP:-<pending>} 'sudo tail -f /var/log/aegisbpf-soak-setup.log'"
echo
echo "Monitor:"
echo "  aws ec2 describe-instances --instance-ids ${INSTANCE_ID} --region ${REGION} --query 'Reservations[].Instances[].State.Name' --output text"
echo
echo "Fetch results when done:"
echo "  aws s3 cp --recursive s3://${S3_BUCKET}/${RUN_ID}/ ./artifacts/soak-24h/"
echo
echo "Estimated cost: ~\$$(python3 -c "
costs = {'t3.micro': 0.0104, 't3.small': 0.0208, 't3.medium': 0.0416, 't2.micro': 0.0116}
hours = ${DURATION} / 3600
cost = costs.get('${INSTANCE_TYPE}', 0.0104) * hours
print(f'{cost:.2f}')
")"
