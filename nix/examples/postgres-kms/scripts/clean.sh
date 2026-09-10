#!/bin/bash
# Teardown: no set -e by design — cleanup continues past failures so one stuck resource doesn't
# orphan the rest.

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
ARTIFACTS_DIR="$SCRIPT_DIR/../artifacts"
RESOURCES_FILE="$ARTIFACTS_DIR/resources.json"

# shellcheck source-path=SCRIPTDIR
# shellcheck source=lib/roles.sh
. "$SCRIPT_DIR/lib/roles.sh"

CUSTODIAN_ROLE_ARN=""
OPERATOR_ROLE_ARN=""
DELETE_PROVISIONING_ROLES=false
while [[ "$#" -gt 0 ]]; do
  case $1 in
    --custodian-role-arn) CUSTODIAN_ROLE_ARN="$2"; shift ;;
    --operator-role-arn) OPERATOR_ROLE_ARN="$2"; shift ;;
    --delete-provisioning-roles) DELETE_PROVISIONING_ROLES=true ;;
    *) echo "Unknown option $1" >&2; exit 1 ;;
  esac
  shift
done

if [ ! -f "$RESOURCES_FILE" ]; then
  echo "Resources file not found: $RESOURCES_FILE"
  exit 1
fi

echo "Validating AWS credentials..."
if ! aws sts get-caller-identity >/dev/null 2>&1; then
  echo "ERROR: AWS credentials are invalid or expired."
  echo "Please refresh your credentials and try again."
  echo "Resource file preserved at: $RESOURCES_FILE"
  exit 1
fi
echo "AWS credentials are valid. Proceeding with cleanup..."

AMI_ID=$(jq -r '.AMI_ID // empty' "$RESOURCES_FILE")
ROLE_NAME=$(jq -r '.ROLE_NAME // empty' "$RESOURCES_FILE")
INSTANCE_PROFILE_NAME=$(jq -r '.INSTANCE_PROFILE_NAME // empty' "$RESOURCES_FILE")
# Prefer the ARN; KMS_KEY_ID is the legacy field from pre-pinning runs.
KMS_KEY_ARN=$(jq -r '.KMS_KEY_ARN // .KMS_KEY_ID // empty' "$RESOURCES_FILE")
INSTANCE_ID=$(jq -r '.INSTANCE_ID // empty' "$RESOURCES_FILE")
SECURITY_GROUP_ID=$(jq -r '.SECURITY_GROUP_ID // empty' "$RESOURCES_FILE")
VOLUME_ID=$(jq -r '.VOLUME_ID // empty' "$RESOURCES_FILE")
SECRET_ARN=$(jq -r '.SECRET_ARN // empty' "$RESOURCES_FILE")
IDENTITY_ARN=$(jq -r '.IDENTITY_ARN // empty' "$RESOURCES_FILE")

# Prefer an explicit flag; fall back to what the run recorded.
if [ -z "$CUSTODIAN_ROLE_ARN" ]; then
  CUSTODIAN_ROLE_ARN=$(jq -r '.CUSTODIAN_ROLE_ARN // empty' "$RESOURCES_FILE")
fi
if [ -z "$OPERATOR_ROLE_ARN" ]; then
  OPERATOR_ROLE_ARN=$(jq -r '.OPERATOR_ROLE_ARN // empty' "$RESOURCES_FILE")
fi

CLEANUP_SUCCESS=true

# Everything here was created through the Operator role, so tear it down with the same role;
# an empty ARN falls through to ambient credentials. The Operator policy covers every call below.
run_aws_command() {
  if ! output=$(assume_role_exec "$OPERATOR_ROLE_ARN" -- aws "$@" 2>&1); then
    echo "Error executing: aws $*"
    echo "Output: $output"
    CLEANUP_SUCCESS=false
    return 1
  fi
}

# Only a confirmed not-found is safe to swallow. Any other failure (AccessDenied, throttling,
# DependencyViolation) means the resource may still be live, and leaving CLEANUP_SUCCESS=true
# would delete resources.json — its only record.
run_aws_command_optional() {
  if ! output=$(assume_role_exec "$OPERATOR_ROLE_ARN" -- aws "$@" 2>&1); then
    if printf '%s' "$output" | grep -qE 'NotFound|NoSuchEntity|does not exist'; then
      echo "Already gone: aws $*"
      return 0
    fi
    echo "Error executing: aws $*"
    echo "Output: $output"
    CLEANUP_SUCCESS=false
    return 1
  fi
}

if [ -n "$SECRET_ARN" ]; then
  echo "Deleting Secrets Manager secret: $SECRET_ARN"
  run_aws_command_optional secretsmanager delete-secret --secret-id "$SECRET_ARN" --force-delete-without-recovery
fi

if [ -n "$IDENTITY_ARN" ]; then
  echo "Deleting Secrets Manager secret: $IDENTITY_ARN"
  run_aws_command_optional secretsmanager delete-secret --secret-id "$IDENTITY_ARN" --force-delete-without-recovery
fi

if [ -n "$INSTANCE_ID" ]; then
  echo "Terminating EC2 instance: $INSTANCE_ID"
  run_aws_command ec2 terminate-instances --instance-ids "$INSTANCE_ID"
  run_aws_command ec2 wait instance-terminated --instance-ids "$INSTANCE_ID"
fi

if [ -n "$SECURITY_GROUP_ID" ]; then
  echo "Deleting security group: $SECURITY_GROUP_ID"
  run_aws_command_optional ec2 delete-security-group --group-id "$SECURITY_GROUP_ID"
fi

if [ -n "$AMI_ID" ]; then
  # Snapshot IDs must be read before deregistering (describe-images fails after)
  SNAPSHOT_IDS=$(assume_role_exec "$OPERATOR_ROLE_ARN" -- aws ec2 describe-images --image-ids "$AMI_ID" \
    --query 'Images[0].BlockDeviceMappings[*].Ebs.SnapshotId' --output text 2>/dev/null || true)

  echo "Deregistering AMI: $AMI_ID"
  run_aws_command ec2 deregister-image --image-id "$AMI_ID"

  for SNAP_ID in $SNAPSHOT_IDS; do
    if [ -n "$SNAP_ID" ] && [ "$SNAP_ID" != "None" ]; then
      echo "Deleting AMI backing snapshot: $SNAP_ID"
      run_aws_command_optional ec2 delete-snapshot --snapshot-id "$SNAP_ID"
    fi
  done
fi

if [ -n "$VOLUME_ID" ]; then
  # Wait for detach after termination; delete-volume fails with VolumeInUse otherwise
  echo "Waiting for EBS volume to become available: $VOLUME_ID"
  run_aws_command_optional ec2 wait volume-available --volume-ids "$VOLUME_ID"
  echo "Deleting EBS volume: $VOLUME_ID"
  run_aws_command ec2 delete-volume --volume-id "$VOLUME_ID"
fi

if [ -n "$INSTANCE_PROFILE_NAME" ] && [ -n "$ROLE_NAME" ]; then
  echo "Removing role from instance profile"
  run_aws_command iam remove-role-from-instance-profile --instance-profile-name "$INSTANCE_PROFILE_NAME" --role-name "$ROLE_NAME"

  echo "Deleting instance profile: $INSTANCE_PROFILE_NAME"
  run_aws_command iam delete-instance-profile --instance-profile-name "$INSTANCE_PROFILE_NAME"

  echo "Detaching policies from IAM role: $ROLE_NAME"
  if ATTACHED_POLICIES=$(assume_role_exec "$OPERATOR_ROLE_ARN" -- aws iam list-attached-role-policies --role-name "$ROLE_NAME" --query 'AttachedPolicies[*].PolicyArn' --output text 2>/dev/null); then
    for POLICY_ARN in $ATTACHED_POLICIES; do
      echo "Detaching policy: $POLICY_ARN"
      run_aws_command iam detach-role-policy --role-name "$ROLE_NAME" --policy-arn "$POLICY_ARN"
    done
  else
    echo "Error listing attached policies for role: $ROLE_NAME"
    CLEANUP_SUCCESS=false
  fi

  echo "Deleting inline policies from IAM role: $ROLE_NAME"
  if INLINE_POLICIES=$(assume_role_exec "$OPERATOR_ROLE_ARN" -- aws iam list-role-policies --role-name "$ROLE_NAME" --query 'PolicyNames[]' --output text 2>/dev/null); then
    for POLICY_NAME in $INLINE_POLICIES; do
      echo "Deleting inline policy: $POLICY_NAME"
      run_aws_command iam delete-role-policy --role-name "$ROLE_NAME" --policy-name "$POLICY_NAME"
    done
  else
    echo "Error listing inline policies for role: $ROLE_NAME"
    CLEANUP_SUCCESS=false
  fi

  echo "Deleting IAM role: $ROLE_NAME"
  run_aws_command iam delete-role --role-name "$ROLE_NAME"
fi

if [ -n "$KMS_KEY_ARN" ]; then
  # Key deletion is the Custodian's alone: the final policy scopes ScheduleKeyDeletion to it.
  echo "Scheduling KMS key for deletion: $KMS_KEY_ARN"
  kms_err=""
  # shellcheck disable=SC2069  # 2>&1 >/dev/null is intentional: capture stderr, discard stdout
  if ! kms_err=$(assume_role_exec "$CUSTODIAN_ROLE_ARN" -- aws kms schedule-key-deletion --key-id "$KMS_KEY_ARN" --pending-window-in-days 7 2>&1 >/dev/null); then
    echo "Error executing: kms schedule-key-deletion --key-id $KMS_KEY_ARN"
    echo "Output: $kms_err"
    CLEANUP_SUCCESS=false
  fi
fi

if [ "$DELETE_PROVISIONING_ROLES" = true ]; then
  # Needs IAM permissions the Operator lacks. Names come from recorded ARNs — hardcoding
  # NitroTpm* would orphan other prefixes.
  PROV_ROLES=$(jq -r '[.CUSTODIAN_ROLE_ARN, .PROVISIONER_ROLE_ARN, .DEPLOYER_ROLE_ARN,
                       .OPERATOR_ROLE_ARN, .TEST_CLIENT_ROLE_ARN]
                      | map(select(. != null)) | map(sub(".*/"; "")) | .[]' \
                   "$RESOURCES_FILE")
  # Runs predating the persisted ARNs recorded nothing; fall back to defaults.
  if [ -z "$PROV_ROLES" ]; then
    PROV_ROLES="NitroTpmCustodianRole NitroTpmProvisionerRole NitroTpmDeployerRole
                NitroTpmOperatorRole NitroTpmTestClientRole"
  fi
  # Ambient credentials on purpose: these calls need the out-of-ceremony IAM permissions that
  # created the roles, which the Operator deliberately lacks.
  for PROV_ROLE in $PROV_ROLES; do
    if aws iam get-role --role-name "$PROV_ROLE" >/dev/null 2>&1; then
      for POLICY_NAME in $(aws iam list-role-policies --role-name "$PROV_ROLE" --query 'PolicyNames[]' --output text 2>/dev/null); do
        aws iam delete-role-policy --role-name "$PROV_ROLE" --policy-name "$POLICY_NAME" >/dev/null 2>&1 \
          || { echo "Error deleting inline policy $POLICY_NAME from $PROV_ROLE"; CLEANUP_SUCCESS=false; }
      done
      echo "Deleting provisioning role: $PROV_ROLE"
      aws iam delete-role --role-name "$PROV_ROLE" >/dev/null 2>&1 \
        || { echo "Error deleting provisioning role $PROV_ROLE"; CLEANUP_SUCCESS=false; }
    fi
  done
fi

rm -rf "$SCRIPT_DIR/../sb-keys" "$SCRIPT_DIR/../signed-image"

# Truncate not delete: git+file:// flake refs only see tracked paths; empty = unpinned.
: > "$SCRIPT_DIR/../kms-key-arn.txt"


if [ "$CLEANUP_SUCCESS" = true ]; then
  echo "Cleanup completed successfully. Note that some resources may take time to be fully deleted."
  echo "Removing resource tracking files."
  rm -rf "$ARTIFACTS_DIR"
else
  echo "WARNING: Some cleanup operations failed. Resource file preserved at: $RESOURCES_FILE"
  echo "Please check your AWS credentials and re-run the cleanup script."
  echo "Failed resources may still exist and incur charges."
  exit 1
fi
