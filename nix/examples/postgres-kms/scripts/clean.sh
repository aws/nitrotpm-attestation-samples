#!/bin/bash

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
ARTIFACTS_DIR="$SCRIPT_DIR/../artifacts"
RESOURCES_FILE="$ARTIFACTS_DIR/resources.json"

if [ ! -f "$RESOURCES_FILE" ]; then
  echo "Resources file not found: $RESOURCES_FILE"
  exit 1
fi

# Check if AWS credentials are valid before starting cleanup
echo "Validating AWS credentials..."
if ! aws sts get-caller-identity >/dev/null 2>&1; then
  echo "ERROR: AWS credentials are invalid or expired."
  echo "Please refresh your credentials and try again."
  echo "Resource file preserved at: $RESOURCES_FILE"
  exit 1
fi
echo "AWS credentials are valid. Proceeding with cleanup..."

# Read resource IDs from JSON file
AMI_ID=$(jq -r '.AMI_ID // empty' "$RESOURCES_FILE")
ROLE_NAME=$(jq -r '.ROLE_NAME // empty' "$RESOURCES_FILE")
INSTANCE_PROFILE_NAME=$(jq -r '.INSTANCE_PROFILE_NAME // empty' "$RESOURCES_FILE")
KMS_KEY_ID=$(jq -r '.KMS_KEY_ID // empty' "$RESOURCES_FILE")
INSTANCE_ID=$(jq -r '.INSTANCE_ID // empty' "$RESOURCES_FILE")
SECURITY_GROUP_ID=$(jq -r '.SECURITY_GROUP_ID // empty' "$RESOURCES_FILE")
VOLUME_ID=$(jq -r '.VOLUME_ID // empty' "$RESOURCES_FILE")
SECRET_ARN=$(jq -r '.SECRET_ARN // empty' "$RESOURCES_FILE")
IDENTITY_ARN=$(jq -r '.IDENTITY_ARN // empty' "$RESOURCES_FILE")

# Track cleanup success
CLEANUP_SUCCESS=true

# Function to run AWS CLI commands with error handling
run_aws_command() {
  if ! output=$(aws $@ 2>&1); then
    echo "Error executing: aws $@"
    echo "Output: $output"
    CLEANUP_SUCCESS=false
    return 1
  fi
}

# Function to run non-critical AWS CLI commands (failures don't affect overall success)
run_aws_command_optional() {
  if ! output=$(aws $@ 2>&1); then
    echo "Warning: aws $@"
    echo "Output: $output"
    return 1
  fi
}

# Delete Secrets Manager secret (mTLS client certificates)
if [ -n "$SECRET_ARN" ]; then
  echo "Deleting Secrets Manager secret: $SECRET_ARN"
  run_aws_command_optional secretsmanager delete-secret --secret-id "$SECRET_ARN" --force-delete-without-recovery
fi

# Delete Secrets Manager secret (secure boot golden identity, if used)
if [ -n "$IDENTITY_ARN" ]; then
  echo "Deleting Secrets Manager secret: $IDENTITY_ARN"
  run_aws_command_optional secretsmanager delete-secret --secret-id "$IDENTITY_ARN" --force-delete-without-recovery
fi

# Terminate EC2 instance
if [ -n "$INSTANCE_ID" ]; then
  echo "Terminating EC2 instance: $INSTANCE_ID"
  run_aws_command ec2 terminate-instances --instance-ids "$INSTANCE_ID"
  run_aws_command ec2 wait instance-terminated --instance-ids "$INSTANCE_ID"
fi

# Delete security group
if [ -n "$SECURITY_GROUP_ID" ]; then
  echo "Deleting security group: $SECURITY_GROUP_ID"
  run_aws_command_optional ec2 delete-security-group --group-id "$SECURITY_GROUP_ID"
fi

# Deregister AMI and delete its backing snapshot(s)
if [ -n "$AMI_ID" ]; then
  # Snapshot IDs must be read before deregistering (describe-images fails after)
  SNAPSHOT_IDS=$(aws ec2 describe-images --image-ids "$AMI_ID" \
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

# Delete EBS volume
if [ -n "$VOLUME_ID" ]; then
  # Detach is async after termination; wait so delete-volume doesn't fail with VolumeInUse
  echo "Waiting for EBS volume to become available: $VOLUME_ID"
  run_aws_command_optional ec2 wait volume-available --volume-ids "$VOLUME_ID"
  echo "Deleting EBS volume: $VOLUME_ID"
  run_aws_command ec2 delete-volume --volume-id "$VOLUME_ID"
fi

# Delete IAM instance profile and role
if [ -n "$INSTANCE_PROFILE_NAME" ] && [ -n "$ROLE_NAME" ]; then
  echo "Removing role from instance profile"
  run_aws_command iam remove-role-from-instance-profile --instance-profile-name "$INSTANCE_PROFILE_NAME" --role-name "$ROLE_NAME"

  echo "Deleting instance profile: $INSTANCE_PROFILE_NAME"
  run_aws_command iam delete-instance-profile --instance-profile-name "$INSTANCE_PROFILE_NAME"

  echo "Detaching policies from IAM role: $ROLE_NAME"
  if ATTACHED_POLICIES=$(aws iam list-attached-role-policies --role-name "$ROLE_NAME" --query 'AttachedPolicies[*].PolicyArn' --output text 2>/dev/null); then
    for POLICY_ARN in $ATTACHED_POLICIES; do
      echo "Detaching policy: $POLICY_ARN"
      run_aws_command iam detach-role-policy --role-name "$ROLE_NAME" --policy-arn "$POLICY_ARN"
    done
  else
    echo "Error listing attached policies for role: $ROLE_NAME"
    CLEANUP_SUCCESS=false
  fi

  echo "Deleting inline policies from IAM role: $ROLE_NAME"
  if INLINE_POLICIES=$(aws iam list-role-policies --role-name "$ROLE_NAME" --query 'PolicyNames[]' --output text 2>/dev/null); then
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

# Schedule KMS key for deletion
if [ -n "$KMS_KEY_ID" ]; then
  echo "Scheduling KMS key for deletion: $KMS_KEY_ID"
  run_aws_command kms schedule-key-deletion --key-id "$KMS_KEY_ID" --pending-window-in-days 7
fi

# Remove any local secure boot artifacts left behind by an interrupted build.
rm -rf "$SCRIPT_DIR/../sb-keys" "$SCRIPT_DIR/../signed-image"

# Only remove resource files if all cleanup operations succeeded
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
