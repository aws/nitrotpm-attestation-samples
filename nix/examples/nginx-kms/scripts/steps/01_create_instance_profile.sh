#!/bin/bash

usage() {
  echo "Usage: $0 [-r|--role-name <role_name>] [-p|--profile-name <instance_profile_name>]"
  exit 1
}

while [[ "$#" -gt 0 ]]; do
  case $1 in
    -r|--role-name) ROLE_NAME="$2"; shift ;;
    -p|--profile-name) INSTANCE_PROFILE_NAME="$2"; shift ;;
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

# Attach the TpmEkPub customer inline policy to the role
aws iam put-role-policy \
  --role-name "$ROLE_NAME" \
  --policy-name TpmEkPub \
  --policy-document '{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "ec2:GetInstanceTpmEkPub",
      "Resource": "*"
    }
  ]
}'

# Create the instance profile and add the role
aws iam create-instance-profile --instance-profile-name "$INSTANCE_PROFILE_NAME"
aws iam add-role-to-instance-profile --instance-profile-name "$INSTANCE_PROFILE_NAME" --role-name "$ROLE_NAME"

echo "$ROLE_NAME role, TpmEkPub policy, and $INSTANCE_PROFILE_NAME instance profile have been created successfully."
