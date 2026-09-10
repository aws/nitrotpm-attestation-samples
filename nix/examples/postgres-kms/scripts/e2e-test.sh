#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
ARTIFACTS_DIR="$SCRIPT_DIR/../artifacts"
RESOURCES_FILE="$ARTIFACTS_DIR/resources.json"

# shellcheck source-path=SCRIPTDIR
# shellcheck source=lib/identity.sh
. "$SCRIPT_DIR/lib/identity.sh"
# shellcheck source-path=SCRIPTDIR
# shellcheck source=lib/roles.sh
. "$SCRIPT_DIR/lib/roles.sh"

SECURE_BOOT_FLAG=""
DEBUG_FLAG=""
TIMEOUT=600
NO_CLEANUP=false
SKIP_SG_UPDATE=false
AUTHORIZE_MY_IP=false
VPC_ID_FLAG=""
SECRET_MANAGER_FLAG=""
IDENTITY_ARN=""
START_PHASE=1
CUSTODIAN_ROLE_ARN=""
PROVISIONER_ROLE_ARN=""
DEPLOYER_ROLE_ARN=""
OPERATOR_ROLE_ARN=""
TEST_CLIENT_ROLE_ARN=""
CREATE_ROLES=false

while [[ $# -gt 0 ]]; do
  case $1 in
    --secure-boot) SECURE_BOOT_FLAG="--secure-boot"; shift ;;
    --debug) DEBUG_FLAG="--debug"; shift ;;
    --timeout) TIMEOUT="$2"; shift; shift ;;
    --no-cleanup) NO_CLEANUP=true; shift ;;
    --skip-sg-update) SKIP_SG_UPDATE=true; shift ;;
    --authorize-my-ip) AUTHORIZE_MY_IP=true; shift ;; # CI/CD: auto-allowlist the runner's public IP on 5432
    # Deprecated alias: the "admin" in 02a/02b is specifically the Custodian.
    --admin-role-arn) CUSTODIAN_ROLE_ARN="$2"; shift; shift ;;
    --custodian-role-arn) CUSTODIAN_ROLE_ARN="$2"; shift; shift ;;
    --provisioner-role-arn) PROVISIONER_ROLE_ARN="$2"; shift; shift ;;
    --deployer-role-arn) DEPLOYER_ROLE_ARN="$2"; shift; shift ;;
    --operator-role-arn) OPERATOR_ROLE_ARN="$2"; shift; shift ;;
    --test-client-role-arn) TEST_CLIENT_ROLE_ARN="$2"; shift; shift ;;
    --create-roles) CREATE_ROLES=true; shift ;;
    --vpc-id) VPC_ID_FLAG="--vpc-id $2"; shift; shift ;;
    --start-phase) START_PHASE="$2"; shift; shift ;; # resume a prior --no-cleanup run
    --secrets-manager)
      SECRET_MANAGER_FLAG="true"
      shift
      if [[ $# -gt 0 ]] && [[ "$1" != --* ]]; then
        IDENTITY_ARN="$1"; shift
        validate_secret_arn "$IDENTITY_ARN"
      fi
      ;;
    *) echo "Unknown option $1"; exit 1 ;;
  esac
done

if [ -n "$SECRET_MANAGER_FLAG" ] && [ -z "$SECURE_BOOT_FLAG" ]; then
  echo "Error: --secrets-manager requires --secure-boot"
  exit 1
fi

if [ "$AUTHORIZE_MY_IP" = true ] && [ "$SKIP_SG_UPDATE" = true ]; then
  echo "Error: --authorize-my-ip and --skip-sg-update are mutually exclusive"
  exit 1
fi

case "$START_PHASE" in
  1|2|3) ;;
  *) echo "Error: --start-phase must be 1, 2, or 3 (got '$START_PHASE')"; exit 1 ;;
esac

PHASE1_RESULT="SKIP"
PHASE2_RESULT="SKIP"
PHASE3_RESULT="SKIP"
PHASE4_RESULT="SKIP"

CLIENT_CA_FILE=""
CLIENT_CERT_FILE=""
CLIENT_KEY_FILE=""

mkdir -p "$ARTIFACTS_DIR"
if [ "$START_PHASE" -eq 1 ]; then
  echo '{}' > "$RESOURCES_FILE"
elif [ ! -f "$RESOURCES_FILE" ]; then
  echo "Error: --start-phase $START_PHASE needs a prior run's $RESOURCES_FILE (from --no-cleanup)."
  exit 1
fi

load_provisioned_state() {
  AMI_ID=$(jq -r '.AMI_ID // empty' "$RESOURCES_FILE")
  ROLE_NAME=$(jq -r '.ROLE_NAME // empty' "$RESOURCES_FILE")
  INSTANCE_PROFILE_NAME=$(jq -r '.INSTANCE_PROFILE_NAME // empty' "$RESOURCES_FILE")
  VOLUME_ID=$(jq -r '.VOLUME_ID // empty' "$RESOURCES_FILE")
  INSTANCE_ID=$(jq -r '.INSTANCE_ID // empty' "$RESOURCES_FILE")
  SG_ID=$(jq -r '.SECURITY_GROUP_ID // empty' "$RESOURCES_FILE")
  if [ -z "$INSTANCE_ID" ]; then
    echo "Error: no INSTANCE_ID in $RESOURCES_FILE; cannot resume at phase $START_PHASE."
    return 1
  fi
  read -r PRIVATE_IP PUBLIC_IP < <(aws ec2 describe-instances --instance-ids "$INSTANCE_ID" \
    --query 'Reservations[0].Instances[0].[PrivateIpAddress,PublicIpAddress]' --output text 2>/dev/null)
  if [ -z "$PUBLIC_IP" ] || [ "$PUBLIC_IP" = "None" ]; then
    echo "Error: instance $INSTANCE_ID has no public IP (gone, or launched without --public)."
    return 1
  fi
  echo "Resuming at phase $START_PHASE with instance $INSTANCE_ID (public $PUBLIC_IP)."
  if [ "$AUTHORIZE_MY_IP" = true ]; then
    authorize_my_ip "$SG_ID" || return 1
  elif [ "$SKIP_SG_UPDATE" = false ]; then
    print_sg_authorization_notice "$SG_ID"
  fi
}

retrieve_client_certs() {
  # Suppress xtrace so the client private key isn't echoed; RETURN trap restores it.
  case "$-" in *x*) trap 'set -x; trap - RETURN' RETURN; set +x ;; esac

  echo "Retrieving client certificate bundle from Secrets Manager..."
  local SECRET_ARN
  SECRET_ARN=$(jq -r '.SECRET_ARN // empty' "$RESOURCES_FILE")
  if [ -z "$SECRET_ARN" ]; then
    echo "ERROR: SECRET_ARN not found in resources.json"
    return 1
  fi

  local SECRET_JSON
  SECRET_JSON=$(assume_role_exec "$TEST_CLIENT_ROLE_ARN" -- \
    aws secretsmanager get-secret-value --secret-id "$SECRET_ARN" \
    --query 'SecretString' --output text) || { echo "ERROR: Failed to retrieve secret from Secrets Manager"; return 1; }

  local CA_B64 CERT_B64 KEY_B64
  CA_B64=$(echo "$SECRET_JSON" | jq -r '.ca_cert // empty')
  CERT_B64=$(echo "$SECRET_JSON" | jq -r '.client_cert // empty')
  KEY_B64=$(echo "$SECRET_JSON" | jq -r '.client_key // empty')

  if [ -z "$CA_B64" ] || [ -z "$CERT_B64" ] || [ -z "$KEY_B64" ]; then
    echo "ERROR: Client certificate bundle is missing required fields (ca_cert, client_cert, client_key)"
    return 1
  fi

  CLIENT_CA_FILE=$(mktemp)
  CLIENT_CERT_FILE=$(mktemp)
  CLIENT_KEY_FILE=$(mktemp)

  echo "$CA_B64" | base64 -d > "$CLIENT_CA_FILE" || { echo "ERROR: Failed to decode ca_cert"; return 1; }
  echo "$CERT_B64" | base64 -d > "$CLIENT_CERT_FILE" || { echo "ERROR: Failed to decode client_cert"; return 1; }
  echo "$KEY_B64" | base64 -d > "$CLIENT_KEY_FILE" || { echo "ERROR: Failed to decode client_key"; return 1; }

  chmod 0600 "$CLIENT_KEY_FILE"
  echo "Client certificates written to temp files."
}

wait_for_ssm() {
  local INSTANCE_ID=$1
  local TIMEOUT=$2
  local START
  START=$(date +%s)
  echo "Waiting for SSM connectivity on $INSTANCE_ID (timeout: ${TIMEOUT}s)..."
  while true; do
    local SSM_STATUS
    SSM_STATUS=$(aws ssm describe-instance-information \
      --filters "Key=InstanceIds,Values=$INSTANCE_ID" \
      --query 'InstanceInformationList[0].PingStatus' \
      --output text 2>/dev/null || echo "None")
    if [ "$SSM_STATUS" = "Online" ]; then
      echo "SSM agent is online on $INSTANCE_ID"
      return 0
    fi
    local ELAPSED=$(( $(date +%s) - START ))
    if [ "$ELAPSED" -ge "$TIMEOUT" ]; then
      echo "Timeout waiting for SSM on $INSTANCE_ID after ${ELAPSED}s"
      return 1
    fi
    sleep 10
  done
}

run_ssm_command() {
  local INSTANCE_ID=$1
  local COMMAND=$2
  local TMPJSON
  TMPJSON=$(mktemp)
  jq -n --arg id "$INSTANCE_ID" --arg cmd "$COMMAND" \
    '{InstanceIds: [$id], DocumentName: "AWS-RunShellScript", Parameters: {commands: [$cmd]}}' > "$TMPJSON"
  local CMD_ID
  CMD_ID=$(aws ssm send-command --cli-input-json "file://$TMPJSON" \
    --query 'Command.CommandId' \
    --output text)
  rm -f "$TMPJSON"

  aws ssm wait command-executed \
    --command-id "$CMD_ID" \
    --instance-id "$INSTANCE_ID" 2>/dev/null || true

  aws ssm get-command-invocation \
    --command-id "$CMD_ID" \
    --instance-id "$INSTANCE_ID" \
    --query 'StandardOutputContent' \
    --output text
}

wait_for_postgresql_ssm() {
  local INSTANCE_ID=$1
  local TIMEOUT=$2
  local START
  START=$(date +%s)
  echo "Waiting for PostgreSQL via SSM on $INSTANCE_ID (timeout: ${TIMEOUT}s)..."
  while true; do
    local RESULT
    RESULT=$(run_ssm_command "$INSTANCE_ID" "sudo -u postgres psql -c \"SELECT 1\" -t -A" 2>/dev/null || echo "")
    if [ "$(echo "$RESULT" | tr -d '[:space:]')" = "1" ]; then
      echo "PostgreSQL is available on $INSTANCE_ID (via SSM)"
      return 0
    fi
    local ELAPSED=$(( $(date +%s) - START ))
    if [ "$ELAPSED" -ge "$TIMEOUT" ]; then
      echo "Timeout waiting for PostgreSQL via SSM on $INSTANCE_ID after ${ELAPSED}s"
      return 1
    fi
    sleep 15
  done
}

run_sql_ssm() {
  local INSTANCE_ID=$1
  local SQL=$2
  run_ssm_command "$INSTANCE_ID" "sudo -u postgres psql -c \"$SQL\" -t -A"
}

wait_for_postgresql_mtls() {
  local HOST=$1
  local TIMEOUT=$2
  local START
  START=$(date +%s)
  echo "Waiting for PostgreSQL via mTLS on $HOST (timeout: ${TIMEOUT}s)..."
  while true; do
    if psql "sslmode=verify-ca sslcert=$CLIENT_CERT_FILE sslkey=$CLIENT_KEY_FILE sslrootcert=$CLIENT_CA_FILE host=$HOST port=5432 dbname=postgres user=postgres-client" -c "SELECT 1" -t -A &>/dev/null; then
      echo "PostgreSQL is available on $HOST (via mTLS)"
      return 0
    fi
    local ELAPSED=$(( $(date +%s) - START ))
    if [ "$ELAPSED" -ge "$TIMEOUT" ]; then
      echo "Timeout waiting for PostgreSQL mTLS on $HOST after ${ELAPSED}s"
      return 1
    fi
    sleep 15
  done
}

run_sql_mtls() {
  local HOST=$1
  local SQL=$2
  psql "sslmode=verify-ca sslcert=$CLIENT_CERT_FILE sslkey=$CLIENT_KEY_FILE sslrootcert=$CLIENT_CA_FILE host=$HOST port=5432 dbname=postgres user=postgres-client" -c "$SQL" -t -A
}

cleanup() {
  echo ""
  echo "=== Phase 4: Cleanup ==="

  local SECRET_ARN
  SECRET_ARN=$(jq -r '.SECRET_ARN // empty' "$RESOURCES_FILE" 2>/dev/null || true)

  if [ -n "$SECRET_ARN" ]; then
    echo "Deleting Secrets Manager secret: $SECRET_ARN"
    # Under the Operator role, not ambient credentials: ambient would succeed even if the
    # Operator's DeleteSecret scope no longer covered this secret, hiding the regression.
    if ! assume_role_exec "$OPERATOR_ROLE_ARN" -- \
        aws secretsmanager delete-secret --secret-id "$SECRET_ARN" --force-delete-without-recovery 2>&1; then
      echo "Warning: Failed to delete Secrets Manager secret (non-critical)"
    fi
  fi

  if [ -n "$CLIENT_CA_FILE" ] && [ -f "$CLIENT_CA_FILE" ]; then
    rm -f "$CLIENT_CA_FILE"
  fi
  if [ -n "$CLIENT_CERT_FILE" ] && [ -f "$CLIENT_CERT_FILE" ]; then
    rm -f "$CLIENT_CERT_FILE"
  fi
  if [ -n "$CLIENT_KEY_FILE" ] && [ -f "$CLIENT_KEY_FILE" ]; then
    rm -f "$CLIENT_KEY_FILE"
  fi

  if [ -f "$RESOURCES_FILE" ]; then
    CLEAN_ARGS=()
    [ -n "$CUSTODIAN_ROLE_ARN" ] && CLEAN_ARGS+=(--custodian-role-arn "$CUSTODIAN_ROLE_ARN")
    [ -n "$OPERATOR_ROLE_ARN" ] && CLEAN_ARGS+=(--operator-role-arn "$OPERATOR_ROLE_ARN")
    [ "$CREATE_ROLES" = true ] && CLEAN_ARGS+=(--delete-provisioning-roles)
    "$SCRIPT_DIR/clean.sh" "${CLEAN_ARGS[@]+"${CLEAN_ARGS[@]}"}" \
      && PHASE4_RESULT="PASS" || PHASE4_RESULT="FAIL"
  else
    echo "No resources file found, nothing to clean up."
    PHASE4_RESULT="PASS"
  fi
}

echo "Validating AWS credentials..."
if ! aws sts get-caller-identity >/dev/null 2>&1; then
  echo "ERROR: AWS credentials are invalid or expired."
  exit 1
fi
echo "AWS credentials are valid."

phase1() {
  # Role must exist before stage 5; see prepare-role.sh for why.
  if [ "$CREATE_ROLES" = true ]; then
    echo "Stage 0: Creating the five provisioning roles..."
    OUTPUT=$("$SCRIPT_DIR/steps/00_create_roles.sh") || { echo "Role creation failed"; return 1; }
    CUSTODIAN_ROLE_ARN=$(echo "$OUTPUT" | sed -n 's/.*CUSTODIAN_ROLE_ARN: //p')
    PROVISIONER_ROLE_ARN=$(echo "$OUTPUT" | sed -n 's/.*PROVISIONER_ROLE_ARN: //p')
    DEPLOYER_ROLE_ARN=$(echo "$OUTPUT" | sed -n 's/.*DEPLOYER_ROLE_ARN: //p')
    OPERATOR_ROLE_ARN=$(echo "$OUTPUT" | sed -n 's/.*OPERATOR_ROLE_ARN: //p')
    TEST_CLIENT_ROLE_ARN=$(echo "$OUTPUT" | sed -n 's/.*TEST_CLIENT_ROLE_ARN: //p')
    for VAR in CUSTODIAN_ROLE_ARN PROVISIONER_ROLE_ARN DEPLOYER_ROLE_ARN OPERATOR_ROLE_ARN TEST_CLIENT_ROLE_ARN; do
      [ -n "${!VAR}" ] || { echo "Failed to extract $VAR"; return 1; }
    done
    # IAM is eventually consistent: a role can exist before it is assumable.
    echo "Waiting 10s for IAM role propagation..."
    sleep 10
  fi

  # CUSTODIAN_ROLE_ARN persisted so clean.sh can assume it for key deletion.
  # Other role ARNs aren't read back on --start-phase resume; empty ARN = ambient creds.
  [ -n "$CUSTODIAN_ROLE_ARN" ] && update_resource "CUSTODIAN_ROLE_ARN" "$CUSTODIAN_ROLE_ARN"
  [ -n "$PROVISIONER_ROLE_ARN" ] && update_resource "PROVISIONER_ROLE_ARN" "$PROVISIONER_ROLE_ARN"
  [ -n "$DEPLOYER_ROLE_ARN" ] && update_resource "DEPLOYER_ROLE_ARN" "$DEPLOYER_ROLE_ARN"
  [ -n "$OPERATOR_ROLE_ARN" ] && update_resource "OPERATOR_ROLE_ARN" "$OPERATOR_ROLE_ARN"
  [ -n "$TEST_CLIENT_ROLE_ARN" ] && update_resource "TEST_CLIENT_ROLE_ARN" "$TEST_CLIENT_ROLE_ARN"

  echo "Stage 1/6 (Operator): instance role and profile..."
  ROLE_NAME="TpmAttestationRole"
  INSTANCE_PROFILE_NAME="TpmAttestationProfile"
  # shellcheck disable=SC2086  # ${VAR:+...} and DEBUG_FLAG unquoted for word-splitting into separate args
  OUTPUT=$("$SCRIPT_DIR/prepare-role.sh" \
    ${OPERATOR_ROLE_ARN:+--operator-role-arn "$OPERATOR_ROLE_ARN"} \
    -r "$ROLE_NAME" -p "$INSTANCE_PROFILE_NAME" $DEBUG_FLAG) \
    || { echo "Stage 1 failed"; return 1; }
  INSTANCE_ROLE_ARN=$(echo "$OUTPUT" | sed -n 's/.*INSTANCE_ROLE_ARN: //p')
  [ -z "$INSTANCE_ROLE_ARN" ] && { echo "Failed to extract INSTANCE_ROLE_ARN"; return 1; }
  update_resource "ROLE_NAME" "$ROLE_NAME"
  update_resource "INSTANCE_PROFILE_NAME" "$INSTANCE_PROFILE_NAME"
  echo "Instance role: $INSTANCE_ROLE_ARN"

  echo "Stage 2/6 (Custodian): KMS key under the bootstrap policy..."
  # shellcheck disable=SC2086  # ${VAR:+...} expansions unquoted for word-splitting into separate args
  OUTPUT=$("$SCRIPT_DIR/create-key.sh" \
    ${CUSTODIAN_ROLE_ARN:+--custodian-role-arn "$CUSTODIAN_ROLE_ARN"} \
    ${PROVISIONER_ROLE_ARN:+--provisioner-role-arn "$PROVISIONER_ROLE_ARN"}) \
    || { echo "Stage 2 failed"; return 1; }
  KMS_KEY_ARN=$(echo "$OUTPUT" | sed -n 's/.*KMS key created with ARN: //p')
  [ -z "$KMS_KEY_ARN" ] && { echo "Failed to extract KMS key ARN"; return 1; }
  update_resource "KMS_KEY_ARN" "$KMS_KEY_ARN"
  echo "KMS Key ARN: $KMS_KEY_ARN"

  echo "Stage 3/6 (Deployer): pin, build, sign, register..."
  BUILD_ARGS=(--key-id "$KMS_KEY_ARN" -y)
  [ -n "$DEPLOYER_ROLE_ARN" ] && BUILD_ARGS+=(--deployer-role-arn "$DEPLOYER_ROLE_ARN")
  [ -n "$SECURE_BOOT_FLAG" ] && BUILD_ARGS+=("$SECURE_BOOT_FLAG")
  [ -n "$DEBUG_FLAG" ] && BUILD_ARGS+=("$DEBUG_FLAG")
  if [ -n "$SECRET_MANAGER_FLAG" ]; then
    if [ -n "$IDENTITY_ARN" ]; then
      BUILD_ARGS+=(--secrets-manager "$IDENTITY_ARN")
    else
      BUILD_ARGS+=(--secrets-manager)
    fi
  fi
  OUTPUT=$("$SCRIPT_DIR/build.sh" "${BUILD_ARGS[@]}") || { echo "Stage 3 failed"; return 1; }
  AMI_ID=$(echo "$OUTPUT" | sed -n 's/.*AMI_ID: //p')
  PCR_DIR=$(echo "$OUTPUT" | sed -n 's/.*PCR_DIR: //p')
  IDENTITY_ARN=$(echo "$OUTPUT" | sed -n 's/.*IDENTITY_ARN: //p' || true)
  [ -z "$AMI_ID" ] && { echo "Failed to extract AMI ID"; return 1; }
  [ -z "$PCR_DIR" ] && { echo "Failed to extract PCR_DIR"; return 1; }
  update_resource "AMI_ID" "$AMI_ID"
  [ -n "$IDENTITY_ARN" ] && update_resource "IDENTITY_ARN" "$IDENTITY_ARN"
  echo "AMI ID: $AMI_ID (PCRs in $PCR_DIR)"

  echo "Stage 4/6 (Provisioner): wrap the DEK, issue certificates..."
  # shellcheck disable=SC2086  # ${VAR:+...} expansion unquoted for word-splitting into separate args
  OUTPUT=$("$SCRIPT_DIR/provision-secrets.sh" --key-id "$KMS_KEY_ARN" \
    ${PROVISIONER_ROLE_ARN:+--provisioner-role-arn "$PROVISIONER_ROLE_ARN"}) \
    || { echo "Stage 4 failed"; return 1; }
  SECRET_ARN=$(echo "$OUTPUT" | sed -n 's/.*SECRET_ARN: //p')
  [ -z "$SECRET_ARN" ] && { echo "Failed to extract SECRET_ARN"; return 1; }
  update_resource "SECRET_ARN" "$SECRET_ARN"

  echo "Stage 5/6 (Custodian): gate Decrypt on the PCRs, revoke Encrypt..."
  # Unsigned runs have no PCR7, and finalize-key.sh refuses that gate unless asked by name.
  FINALIZE_ARGS=(--key-id "$KMS_KEY_ARN" --instance-role-arn "$INSTANCE_ROLE_ARN" --pcr-dir "$PCR_DIR")
  [ -n "$CUSTODIAN_ROLE_ARN" ] && FINALIZE_ARGS+=(--custodian-role-arn "$CUSTODIAN_ROLE_ARN")
  [ -z "$SECURE_BOOT_FLAG" ] && FINALIZE_ARGS+=(--allow-pcr4-only)
  "$SCRIPT_DIR/finalize-key.sh" "${FINALIZE_ARGS[@]}" \
    || { echo "Stage 5 failed"; return 1; }

  echo "Stage 6/6 (Operator): volume, launch, security group..."
  DEPLOY_ARGS=(--ami-id "$AMI_ID" --instance-profile "$INSTANCE_PROFILE_NAME")
  [ -n "$OPERATOR_ROLE_ARN" ] && DEPLOY_ARGS+=(--operator-role-arn "$OPERATOR_ROLE_ARN")
  if [ -n "$VPC_ID_FLAG" ]; then
    # shellcheck disable=SC2206  # VPC_ID_FLAG is "--vpc-id X" and must word-split into two args
    DEPLOY_ARGS+=($VPC_ID_FLAG)
  fi
  [ -n "$DEBUG_FLAG" ] && DEPLOY_ARGS+=("$DEBUG_FLAG")
  [ "$AUTHORIZE_MY_IP" = true ] && DEPLOY_ARGS+=(--authorize-my-ip)
  OUTPUT=$("$SCRIPT_DIR/deploy.sh" "${DEPLOY_ARGS[@]}") || { echo "Stage 6 failed"; return 1; }
  VOLUME_ID=$(echo "$OUTPUT" | sed -n 's/.*VOLUME_ID: //p')
  INSTANCE_ID=$(echo "$OUTPUT" | sed -n 's/.*INSTANCE_ID: //p')
  PRIVATE_IP=$(echo "$OUTPUT" | sed -n 's/.*PRIVATE_IP: //p')
  PUBLIC_IP=$(echo "$OUTPUT" | sed -n 's/.*PUBLIC_IP: //p')
  SG_ID=$(echo "$OUTPUT" | sed -n 's/.*SECURITY_GROUP_ID: //p')
  { [ -z "$INSTANCE_ID" ] || [ -z "$PUBLIC_IP" ] || [ -z "$SG_ID" ] || [ -z "$VOLUME_ID" ]; } \
    && { echo "Failed to extract instance details"; return 1; }
  update_resource "VOLUME_ID" "$VOLUME_ID"
  update_resource "INSTANCE_ID" "$INSTANCE_ID"
  update_resource "SECURITY_GROUP_ID" "$SG_ID"
  echo "Instance ID: $INSTANCE_ID, Private IP: $PRIVATE_IP, Public IP: $PUBLIC_IP"
}

if [ "$START_PHASE" -le 1 ]; then
  echo ""
  echo "=== Phase 1: Provision ==="
  if phase1; then
    PHASE1_RESULT="PASS"
    echo "Phase 1: PASS"
  else
    PHASE1_RESULT="FAIL"
    echo "Phase 1: FAIL"
    if [ "$NO_CLEANUP" = true ]; then
      echo "Skipping cleanup (--no-cleanup). Resources preserved for debugging."
      echo "Resource file: $RESOURCES_FILE"
      PHASE4_RESULT="SKIP"
    else
      cleanup
    fi
    echo ""
    echo "=== E2E Test Summary ==="
    echo "Phase 1 (Provision):              $PHASE1_RESULT"
    echo "Phase 2 (First Boot Validation):  $PHASE2_RESULT"
    echo "Phase 3 (Persistence Validation): $PHASE3_RESULT"
    echo "Phase 4 (Cleanup):                $PHASE4_RESULT"
    exit 1
  fi
else
  if ! load_provisioned_state; then
    exit 1
  fi
fi

phase2() {
  if [ "$SKIP_SG_UPDATE" = false ] && [ "$AUTHORIZE_MY_IP" = false ] && [ -t 0 ]; then
    read -r -p "Add your host to SG $SG_ID:5432 (see above), then press Enter to validate... " _
  fi

  retrieve_client_certs || return 1
  wait_for_postgresql_mtls "$PUBLIC_IP" "$TIMEOUT" || return 1

  echo "Verifying PostgreSQL with SELECT 1 (mTLS)..."
  RESULT=$(run_sql_mtls "$PUBLIC_IP" "SELECT 1;")
  [ "$(echo "$RESULT" | tr -d '[:space:]')" = "1" ] || { echo "SELECT 1 failed (mTLS): got '$RESULT'"; return 1; }
  echo "SELECT 1 (mTLS): OK"

  echo "Writing test data (mTLS)..."
  run_sql_mtls "$PUBLIC_IP" "CREATE TABLE IF NOT EXISTS e2e_test (id serial PRIMARY KEY, value text);"
  run_sql_mtls "$PUBLIC_IP" "INSERT INTO e2e_test (value) VALUES ('persistence-check');"

  echo "Reading back test data (mTLS)..."
  RESULT=$(run_sql_mtls "$PUBLIC_IP" "SELECT value FROM e2e_test WHERE value='persistence-check';")
  [ "$RESULT" = "persistence-check" ] || { echo "Read back failed (mTLS): got '$RESULT'"; return 1; }
  echo "Test data verified (mTLS): OK"

  if [ -n "$DEBUG_FLAG" ]; then
    echo "Debug mode: running SSM-based checks..."
    wait_for_ssm "$INSTANCE_ID" "$TIMEOUT" || return 1
    wait_for_postgresql_ssm "$INSTANCE_ID" "$TIMEOUT" || return 1

    echo "Verifying PostgreSQL with SELECT 1 (SSM)..."
    RESULT=$(run_sql_ssm "$INSTANCE_ID" "SELECT 1;")
    [ "$(echo "$RESULT" | tr -d '[:space:]')" = "1" ] || { echo "SELECT 1 failed (SSM): got '$RESULT'"; return 1; }
    echo "SELECT 1 (SSM): OK"

    echo "Reading back test data (SSM)..."
    RESULT=$(run_sql_ssm "$INSTANCE_ID" "SELECT value FROM e2e_test WHERE value='persistence-check';")
    [ "$(echo "$RESULT" | tr -d '[:space:]')" = "persistence-check" ] || { echo "Read back failed (SSM): got '$RESULT'"; return 1; }
    echo "Test data verified (SSM): OK"
  fi
}

if [ "$START_PHASE" -le 2 ]; then
  echo ""
  echo "=== Phase 2: First Boot Validation ==="
  if phase2; then
    PHASE2_RESULT="PASS"
    echo "Phase 2: PASS"
  else
    PHASE2_RESULT="FAIL"
    echo "Phase 2: FAIL"
    if [ "$NO_CLEANUP" = true ]; then
      echo "Skipping cleanup (--no-cleanup). Resources preserved for debugging."
      echo "Resource file: $RESOURCES_FILE"
      PHASE4_RESULT="SKIP"
    else
      cleanup
    fi
    echo ""
    echo "=== E2E Test Summary ==="
    echo "Phase 1 (Provision):              $PHASE1_RESULT"
    echo "Phase 2 (First Boot Validation):  $PHASE2_RESULT"
    echo "Phase 3 (Persistence Validation): $PHASE3_RESULT"
    echo "Phase 4 (Cleanup):                $PHASE4_RESULT"
    exit 1
  fi
fi

echo ""
echo "=== Phase 3: Persistence Validation ==="

phase3() {
  if [ -z "$CLIENT_CA_FILE" ] || [ ! -f "$CLIENT_CA_FILE" ]; then
    retrieve_client_certs || return 1
  fi

  # Assume the Operator role explicitly; ambient creds would pass even if the policy is too narrow.
  echo "Terminating first instance $INSTANCE_ID..."
  assume_role_exec "$OPERATOR_ROLE_ARN" -- aws ec2 terminate-instances --instance-ids "$INSTANCE_ID"
  assume_role_exec "$OPERATOR_ROLE_ARN" -- aws ec2 wait instance-terminated --instance-ids "$INSTANCE_ID"
  echo "First instance terminated."

  echo "Waiting for EBS volume to become available..."
  assume_role_exec "$OPERATOR_ROLE_ARN" -- aws ec2 wait volume-available --volume-ids "$VOLUME_ID"

  echo "Launching second instance..."
  OUTPUT=$(assume_role_exec "$OPERATOR_ROLE_ARN" -- \
    run_instance_step "$AMI_ID" "$INSTANCE_PROFILE_NAME" "$VOLUME_ID" "$VPC_ID_FLAG" "$DEBUG_FLAG")
  INSTANCE_ID=$(echo "$OUTPUT" | sed -n 's/.*Instance ID: //p')
  PRIVATE_IP=$(echo "$OUTPUT" | sed -n 's/.*Private IP: //p')
  PUBLIC_IP=$(echo "$OUTPUT" | sed -n 's/.*Public IP: //p')
  SG_ID2=$(echo "$OUTPUT" | sed -n 's/.*Security Group ID: //p')
  [ -z "$INSTANCE_ID" ] || [ -z "$PUBLIC_IP" ] && { echo "Failed to launch second instance"; return 1; }
  update_resource "INSTANCE_ID" "$INSTANCE_ID"
  [ -n "$SG_ID2" ] && update_resource "SECURITY_GROUP_ID" "$SG_ID2"
  echo "Second instance: $INSTANCE_ID, Private IP: $PRIVATE_IP, Public IP: $PUBLIC_IP"

  wait_for_postgresql_mtls "$PUBLIC_IP" "$TIMEOUT" || return 1

  echo "Verifying persisted test data (mTLS)..."
  RESULT=$(run_sql_mtls "$PUBLIC_IP" "SELECT value FROM e2e_test WHERE value='persistence-check';")
  [ "$RESULT" = "persistence-check" ] || { echo "Persistence check failed (mTLS): got '$RESULT'"; return 1; }
  echo "Persistence verified (mTLS): OK"

  if [ -n "$DEBUG_FLAG" ]; then
    echo "Debug mode: running SSM-based persistence checks..."
    wait_for_ssm "$INSTANCE_ID" "$TIMEOUT" || return 1
    wait_for_postgresql_ssm "$INSTANCE_ID" "$TIMEOUT" || return 1

    echo "Verifying persisted test data (SSM)..."
    RESULT=$(run_sql_ssm "$INSTANCE_ID" "SELECT value FROM e2e_test WHERE value='persistence-check';")
    [ "$(echo "$RESULT" | tr -d '[:space:]')" = "persistence-check" ] || { echo "Persistence check failed (SSM): got '$RESULT'"; return 1; }
    echo "Persistence verified (SSM): OK"
  fi
}

if phase3; then
  PHASE3_RESULT="PASS"
  echo "Phase 3: PASS"
else
  PHASE3_RESULT="FAIL"
  echo "Phase 3: FAIL"
fi

if [ "$NO_CLEANUP" = true ]; then
  echo ""
  echo "=== Phase 4: Cleanup ==="
  echo "Skipping cleanup (--no-cleanup). Resources preserved for debugging."
  echo "Resource file: $RESOURCES_FILE"
  echo "Run ./scripts/clean.sh manually when done."
  PHASE4_RESULT="SKIP"
else
  cleanup
fi

echo ""
echo "=== E2E Test Summary ==="
echo "Phase 1 (Provision):              $PHASE1_RESULT"
echo "Phase 2 (First Boot Validation):  $PHASE2_RESULT"
echo "Phase 3 (Persistence Validation): $PHASE3_RESULT"
echo "Phase 4 (Cleanup):                $PHASE4_RESULT"

for RESULT in "$PHASE1_RESULT" "$PHASE2_RESULT" "$PHASE3_RESULT" "$PHASE4_RESULT"; do
  if [ "$RESULT" = "FAIL" ]; then
    exit 1
  fi
done

echo "All executed phases PASSED."
