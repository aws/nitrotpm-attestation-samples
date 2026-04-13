#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
ARTIFACTS_DIR="$SCRIPT_DIR/../artifacts"
RESOURCES_FILE="$ARTIFACTS_DIR/resources.json"

# Parse flags
SECURE_BOOT_FLAG=""
DEBUG_FLAG=""
TIMEOUT=600

while [[ $# -gt 0 ]]; do
  case $1 in
    --secure-boot) SECURE_BOOT_FLAG="--secure-boot"; shift ;;
    --debug) DEBUG_FLAG="--debug"; shift ;;
    --timeout) TIMEOUT="$2"; shift; shift ;;
    *) echo "Unknown option $1"; exit 1 ;;
  esac
done

# Track phase results
PHASE1_RESULT="SKIP"
PHASE2_RESULT="SKIP"
PHASE3_RESULT="SKIP"
PHASE4_RESULT="SKIP"

# Helper: update resource in resources.json
mkdir -p "$ARTIFACTS_DIR"
echo '{}' > "$RESOURCES_FILE"

update_resource() {
  local KEY=$1
  local VALUE=$2
  jq --arg key "$KEY" --arg value "$VALUE" '.[$key] = $value' "$RESOURCES_FILE" > tmp.json && mv tmp.json "$RESOURCES_FILE"
}

# Helper: wait for SSH connectivity
wait_for_ssh() {
  local HOST=$1
  local TIMEOUT=$2
  local START=$(date +%s)
  echo "Waiting for SSH connectivity on $HOST (timeout: ${TIMEOUT}s)..."
  while true; do
    if ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 root@"$HOST" "echo ok" &>/dev/null; then
      echo "SSH is available on $HOST"
      return 0
    fi
    local ELAPSED=$(( $(date +%s) - START ))
    if [ "$ELAPSED" -ge "$TIMEOUT" ]; then
      echo "Timeout waiting for SSH on $HOST after ${ELAPSED}s"
      return 1
    fi
    sleep 10
  done
}

# Helper: wait for PostgreSQL via SSH
wait_for_postgresql() {
  local HOST=$1
  local TIMEOUT=$2
  local START=$(date +%s)
  echo "Waiting for PostgreSQL on $HOST (timeout: ${TIMEOUT}s)..."
  while true; do
    if ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 root@"$HOST" "sudo -u postgres psql -c 'SELECT 1;' -t -A" &>/dev/null; then
      echo "PostgreSQL is available on $HOST"
      return 0
    fi
    local ELAPSED=$(( $(date +%s) - START ))
    if [ "$ELAPSED" -ge "$TIMEOUT" ]; then
      echo "Timeout waiting for PostgreSQL on $HOST after ${ELAPSED}s"
      return 1
    fi
    sleep 15
  done
}

# Helper: run SQL via SSH
run_sql() {
  local HOST=$1
  local SQL=$2
  ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 root@"$HOST" "sudo -u postgres psql -c \"$SQL\" -t -A"
}

# Cleanup function
cleanup() {
  echo ""
  echo "=== Phase 4: Cleanup ==="

  # Read current resources
  if [ -f "$RESOURCES_FILE" ]; then
    "$SCRIPT_DIR/clean.sh" && PHASE4_RESULT="PASS" || PHASE4_RESULT="FAIL"
  else
    echo "No resources file found, nothing to clean up."
    PHASE4_RESULT="PASS"
  fi
}

# Validate AWS credentials
echo "Validating AWS credentials..."
if ! aws sts get-caller-identity >/dev/null 2>&1; then
  echo "ERROR: AWS credentials are invalid or expired."
  exit 1
fi
echo "AWS credentials are valid."

# ============================================================
# Phase 1: Provision
# ============================================================
echo ""
echo "=== Phase 1: Provision ==="

# We need --debug for SSH access during testing
EFFECTIVE_DEBUG="--debug"

phase1() {
  # Step 1: Create AMI
  echo "Step 1: Creating AMI..."
  OUTPUT=$("$SCRIPT_DIR/steps/00_create_ami.sh" $SECURE_BOOT_FLAG $EFFECTIVE_DEBUG)
  AMI_ID=$(echo "$OUTPUT" | grep -oP 'ami-[a-z0-9]+')
  [ -z "$AMI_ID" ] && { echo "Failed to extract AMI ID"; return 1; }
  update_resource "AMI_ID" "$AMI_ID"
  echo "AMI ID: $AMI_ID"

  # Step 2: Create instance profile
  echo "Step 2: Setting up IAM..."
  ROLE_NAME="TpmAttestationRole"
  INSTANCE_PROFILE_NAME="TpmAttestationProfile"
  "$SCRIPT_DIR/steps/01_create_instance_profile.sh" -r "$ROLE_NAME" -p "$INSTANCE_PROFILE_NAME"
  update_resource "ROLE_NAME" "$ROLE_NAME"
  update_resource "INSTANCE_PROFILE_NAME" "$INSTANCE_PROFILE_NAME"

  # Step 3: Create KMS key
  echo "Step 3: Creating KMS key..."
  INSTANCE_ROLE_ARN=$(aws iam get-role --role-name "$ROLE_NAME" --query 'Role.Arn' --output text)
  ADMIN_ROLE_ARN=$(aws sts get-caller-identity --query 'Arn' --output text)
  OUTPUT=$("$SCRIPT_DIR/steps/02_create_kms_key.sh" -r "$INSTANCE_ROLE_ARN" -a "$ADMIN_ROLE_ARN" -m "$SCRIPT_DIR/../result")
  KMS_KEY_ID=$(echo "$OUTPUT" | grep -oP 'KMS key created with ID: \K.*')
  [ -z "$KMS_KEY_ID" ] && { echo "Failed to extract KMS key ID"; return 1; }
  update_resource "KMS_KEY_ID" "$KMS_KEY_ID"
  echo "KMS Key ID: $KMS_KEY_ID"

  # Step 4: Create symmetric key
  echo "Step 4: Creating symmetric key..."
  "$SCRIPT_DIR/steps/03_create_symmetric_key.sh" -k "$KMS_KEY_ID"

  # Step 5: Create EBS volume
  echo "Step 5: Creating EBS volume..."
  AVAILABILITY_ZONE=$(aws ec2 describe-availability-zones --query 'AvailabilityZones[0].ZoneName' --output text)
  OUTPUT=$("$SCRIPT_DIR/steps/04_create_ebs_volume.sh" -z "$AVAILABILITY_ZONE")
  VOLUME_ID=$(echo "$OUTPUT" | grep -oP 'Volume ID: \K.*')
  [ -z "$VOLUME_ID" ] && { echo "Failed to extract Volume ID"; return 1; }
  update_resource "VOLUME_ID" "$VOLUME_ID"
  echo "Volume ID: $VOLUME_ID"

  # Step 6: Launch instance
  echo "Step 6: Launching instance..."
  OUTPUT=$("$SCRIPT_DIR/steps/05_run_instance.sh" -a "$AMI_ID" -p "$INSTANCE_PROFILE_NAME" -v "$VOLUME_ID" $EFFECTIVE_DEBUG)
  INSTANCE_ID=$(echo "$OUTPUT" | grep -oP 'Instance ID: \K.*')
  PUBLIC_IP=$(echo "$OUTPUT" | grep -oP 'Public IP: \K.*')
  SG_ID=$(echo "$OUTPUT" | grep -oP 'Security Group ID: \K.*')
  [ -z "$INSTANCE_ID" ] || [ -z "$PUBLIC_IP" ] || [ -z "$SG_ID" ] && { echo "Failed to extract instance details"; return 1; }
  update_resource "INSTANCE_ID" "$INSTANCE_ID"
  update_resource "SECURITY_GROUP_ID" "$SG_ID"
  echo "Instance ID: $INSTANCE_ID, Public IP: $PUBLIC_IP"
}

if phase1; then
  PHASE1_RESULT="PASS"
  echo "Phase 1: PASS"
else
  PHASE1_RESULT="FAIL"
  echo "Phase 1: FAIL"
  cleanup
  # Print summary and exit
  echo ""
  echo "=== E2E Test Summary ==="
  echo "Phase 1 (Provision):              $PHASE1_RESULT"
  echo "Phase 2 (First Boot Validation):  $PHASE2_RESULT"
  echo "Phase 3 (Persistence Validation): $PHASE3_RESULT"
  echo "Phase 4 (Cleanup):                $PHASE4_RESULT"
  exit 1
fi

# ============================================================
# Phase 2: First Boot Validation
# ============================================================
echo ""
echo "=== Phase 2: First Boot Validation ==="

phase2() {
  # Wait for SSH
  wait_for_ssh "$PUBLIC_IP" "$TIMEOUT" || return 1

  # Wait for PostgreSQL
  wait_for_postgresql "$PUBLIC_IP" "$TIMEOUT" || return 1

  # Verify SELECT 1
  echo "Verifying PostgreSQL with SELECT 1..."
  RESULT=$(run_sql "$PUBLIC_IP" "SELECT 1;")
  [ "$(echo "$RESULT" | tr -d '[:space:]')" = "1" ] || { echo "SELECT 1 failed: got '$RESULT'"; return 1; }
  echo "SELECT 1: OK"

  # Write test data
  echo "Writing test data..."
  run_sql "$PUBLIC_IP" "CREATE TABLE IF NOT EXISTS e2e_test (id serial PRIMARY KEY, value text);"
  run_sql "$PUBLIC_IP" "INSERT INTO e2e_test (value) VALUES ('persistence-check');"

  # Read back test data
  echo "Reading back test data..."
  RESULT=$(run_sql "$PUBLIC_IP" "SELECT value FROM e2e_test WHERE value='persistence-check';")
  [ "$RESULT" = "persistence-check" ] || { echo "Read back failed: got '$RESULT'"; return 1; }
  echo "Test data verified: OK"
}

if phase2; then
  PHASE2_RESULT="PASS"
  echo "Phase 2: PASS"
else
  PHASE2_RESULT="FAIL"
  echo "Phase 2: FAIL"
  cleanup
  echo ""
  echo "=== E2E Test Summary ==="
  echo "Phase 1 (Provision):              $PHASE1_RESULT"
  echo "Phase 2 (First Boot Validation):  $PHASE2_RESULT"
  echo "Phase 3 (Persistence Validation): $PHASE3_RESULT"
  echo "Phase 4 (Cleanup):                $PHASE4_RESULT"
  exit 1
fi

# ============================================================
# Phase 3: Persistence Validation
# ============================================================
echo ""
echo "=== Phase 3: Persistence Validation ==="

phase3() {
  # Terminate first instance (preserve EBS volume)
  echo "Terminating first instance $INSTANCE_ID..."
  aws ec2 terminate-instances --instance-ids "$INSTANCE_ID"
  aws ec2 wait instance-terminated --instance-ids "$INSTANCE_ID"
  echo "First instance terminated."

  # Wait for volume to become available after detach
  echo "Waiting for EBS volume to become available..."
  aws ec2 wait volume-available --volume-ids "$VOLUME_ID"

  # Launch second instance with same volume
  echo "Launching second instance..."
  OUTPUT=$("$SCRIPT_DIR/steps/05_run_instance.sh" -a "$AMI_ID" -p "$INSTANCE_PROFILE_NAME" -v "$VOLUME_ID" $EFFECTIVE_DEBUG)
  INSTANCE_ID=$(echo "$OUTPUT" | grep -oP 'Instance ID: \K.*')
  PUBLIC_IP=$(echo "$OUTPUT" | grep -oP 'Public IP: \K.*')
  SG_ID2=$(echo "$OUTPUT" | grep -oP 'Security Group ID: \K.*')
  [ -z "$INSTANCE_ID" ] || [ -z "$PUBLIC_IP" ] && { echo "Failed to launch second instance"; return 1; }
  update_resource "INSTANCE_ID" "$INSTANCE_ID"
  # Keep original SG_ID for cleanup (or update if new one created)
  [ -n "$SG_ID2" ] && update_resource "SECURITY_GROUP_ID" "$SG_ID2"
  echo "Second instance: $INSTANCE_ID, Public IP: $PUBLIC_IP"

  # Wait for SSH and PostgreSQL
  wait_for_ssh "$PUBLIC_IP" "$TIMEOUT" || return 1
  wait_for_postgresql "$PUBLIC_IP" "$TIMEOUT" || return 1

  # Verify persisted data
  echo "Verifying persisted test data..."
  RESULT=$(run_sql "$PUBLIC_IP" "SELECT value FROM e2e_test WHERE value='persistence-check';")
  [ "$RESULT" = "persistence-check" ] || { echo "Persistence check failed: got '$RESULT'"; return 1; }
  echo "Persistence verified: OK"
}

if phase3; then
  PHASE3_RESULT="PASS"
  echo "Phase 3: PASS"
else
  PHASE3_RESULT="FAIL"
  echo "Phase 3: FAIL"
fi

# ============================================================
# Phase 4: Cleanup (always runs)
# ============================================================
cleanup

# ============================================================
# Summary
# ============================================================
echo ""
echo "=== E2E Test Summary ==="
echo "Phase 1 (Provision):              $PHASE1_RESULT"
echo "Phase 2 (First Boot Validation):  $PHASE2_RESULT"
echo "Phase 3 (Persistence Validation): $PHASE3_RESULT"
echo "Phase 4 (Cleanup):                $PHASE4_RESULT"

# Exit with failure if any phase failed
if [ "$PHASE1_RESULT" != "PASS" ] || [ "$PHASE2_RESULT" != "PASS" ] || [ "$PHASE3_RESULT" != "PASS" ] || [ "$PHASE4_RESULT" != "PASS" ]; then
  exit 1
fi

echo "All phases PASSED."
