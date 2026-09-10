#!/bin/bash
set -euo pipefail

usage() {
  echo "Usage: $0 [-r|--role-name <role_name>] [-p|--profile-name <instance_profile_name>] [--debug]"
  exit 1
}

DEBUG=false

while [[ "$#" -gt 0 ]]; do
  case $1 in
    -r|--role-name) ROLE_NAME="$2"; shift ;;
    -p|--profile-name) INSTANCE_PROFILE_NAME="$2"; shift ;;
    --debug) DEBUG=true ;;
    *) usage ;;
  esac
  shift
done

if [ -z "$ROLE_NAME" ] || [ -z "$INSTANCE_PROFILE_NAME" ]; then
  usage
fi

PROFILE_EXISTS=false
if ATTACHED_ROLE=$(aws iam get-instance-profile --instance-profile-name "$INSTANCE_PROFILE_NAME" \
      --query 'InstanceProfile.Roles[0].RoleName' --output text 2>/dev/null); then
  PROFILE_EXISTS=true
  # Fail closed on a mismatch. Stage 5 pins the role ARN it resolves by NAME into the KMS policy,
  # so a profile carrying a different role only surfaces as a Decrypt denial at boot.
  if [ "$ATTACHED_ROLE" != "$ROLE_NAME" ]; then
    echo "Error: instance profile $INSTANCE_PROFILE_NAME carries role '$ATTACHED_ROLE', expected '$ROLE_NAME'." >&2
    exit 1
  fi
  echo "Instance profile $INSTANCE_PROFILE_NAME already exists with role $ROLE_NAME."
fi

if ! aws iam get-role --role-name "$ROLE_NAME" &> /dev/null; then
  aws iam create-role \
    --role-name "$ROLE_NAME" \
    --assume-role-policy-document '{
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Principal": {
          "Service": "ec2.amazonaws.com"
        },
        "Action": "sts:AssumeRole"
      }
    ]
  }'
  echo "Created role: $ROLE_NAME"
else
  echo "Role $ROLE_NAME already exists."
fi

if [ "$PROFILE_EXISTS" = false ]; then
  aws iam create-instance-profile --instance-profile-name "$INSTANCE_PROFILE_NAME"
  aws iam add-role-to-instance-profile --instance-profile-name "$INSTANCE_PROFILE_NAME" --role-name "$ROLE_NAME"
  echo "$ROLE_NAME role and $INSTANCE_PROFILE_NAME instance profile have been created successfully."
fi

# Outside the block above: attach-role-policy is idempotent, and a --debug rerun against an
# existing profile must still get SSM access.
if [ "$DEBUG" = true ]; then
  echo "Debug mode: attaching AmazonSSMManagedInstanceCore policy for SSM access..."
  aws iam attach-role-policy \
    --role-name "$ROLE_NAME" \
    --policy-arn "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
  echo "SSM managed policy attached to role $ROLE_NAME."
fi
