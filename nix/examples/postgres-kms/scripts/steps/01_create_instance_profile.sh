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

# Check if the instance profile already exists
if aws iam get-instance-profile --instance-profile-name "$INSTANCE_PROFILE_NAME" &> /dev/null; then
  echo "Instance profile $INSTANCE_PROFILE_NAME already exists. Exiting successfully."
  exit 0
fi

# Create the role if it doesn't exist
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

# Create the instance profile and add the role
aws iam create-instance-profile --instance-profile-name "$INSTANCE_PROFILE_NAME"
aws iam add-role-to-instance-profile --instance-profile-name "$INSTANCE_PROFILE_NAME" --role-name "$ROLE_NAME"

echo "$ROLE_NAME role and $INSTANCE_PROFILE_NAME instance profile have been created successfully."

# In debug mode, attach the SSM managed policy for Systems Manager access
if [ "$DEBUG" = true ]; then
  echo "Debug mode: attaching AmazonSSMManagedInstanceCore policy for SSM access..."
  aws iam attach-role-policy \
    --role-name "$ROLE_NAME" \
    --policy-arn "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
  echo "SSM managed policy attached to role $ROLE_NAME."
fi
