#!/bin/bash

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

usage() {
  echo "Usage: $0 -a AMI_ID -p INSTANCE_PROFILE_NAME [-t INSTANCE_TYPE]"
  echo "  -a, --ami-id                 Specify the AMI ID"
  echo "  -p, --profile                Specify the Instance Profile name"
  echo "  -t, --instance-type          Specify the Instance Type (default: m6i.4xlarge)"
  exit 1
}

SECURITY_GROUP_NAME="NitroTPMTestSG"

# Parse command line arguments
while [[ "$#" -gt 0 ]]; do
  case $1 in
    -a|--ami-id) AMI_ID="$2"; shift ;;
    -p|--profile) INSTANCE_PROFILE_NAME="$2"; shift ;;
    -t|--instance-type) INSTANCE_TYPE="$2"; shift ;;
    *) usage ;;
  esac
  shift
done

# Check if required arguments are provided
if [ -z "$AMI_ID" ] || [ -z "$INSTANCE_PROFILE_NAME" ]; then
  echo "Error: AMI ID and Instance Profile name are required."
  usage
fi

# Determine instance type based on AMI architecture if not specified
if [ -z "$INSTANCE_TYPE" ]; then
  echo "Determining instance type based on AMI architecture..."
  AMI_ARCH=$(aws ec2 describe-images --image-ids "$AMI_ID" --query 'Images[0].Architecture' --output text)
  
  if [ "$AMI_ARCH" == "arm64" ]; then
    INSTANCE_TYPE="c6g.2xlarge"  # ARM-based instance (Graviton)
    echo "AMI architecture is ARM64, using instance type: $INSTANCE_TYPE"
  else
    INSTANCE_TYPE="m6i.4xlarge"  # x86_64 instance (Intel)
    echo "AMI architecture is x86_64, using instance type: $INSTANCE_TYPE"
  fi
else
  echo "Using specified instance type: $INSTANCE_TYPE"
fi

# Check if the security group exists, if not create it
if ! SG_ID=$(aws ec2 describe-security-groups --group-names "$SECURITY_GROUP_NAME" --query 'SecurityGroups[0].GroupId' --output text 2>/dev/null); then
  echo "Security group does not exist. Creating a new one..."
  SG_ID=$(aws ec2 create-security-group --group-name "$SECURITY_GROUP_NAME" --description "Security group for Nitro TPM test" --query 'GroupId' --output text)
  aws ec2 authorize-security-group-ingress --group-id "$SG_ID" --protocol tcp --port 80 --cidr 0.0.0.0/0
else
  echo "Security group already exists. Using existing group."
fi

# Launch the EC2 instance
INSTANCE_OUTPUT=$(aws ec2 run-instances \
  --image-id "$AMI_ID" \
  --instance-type "$INSTANCE_TYPE" \
  --iam-instance-profile "Name=$INSTANCE_PROFILE_NAME" \
  --user-data file://"$SCRIPT_DIR/../../artifacts/user_data.json" \
  --associate-public-ip-address \
  --security-group-ids "$SG_ID" \
  --query 'Instances[0].{InstanceId:InstanceId,PublicIpAddress:PublicIpAddress}' \
  --output json)

INSTANCE_ID=$(echo "$INSTANCE_OUTPUT" | jq -r '.InstanceId')
PUBLIC_IP=$(echo "$INSTANCE_OUTPUT" | jq -r '.PublicIpAddress')

if [ -z "$INSTANCE_ID" ]; then
  echo "Error: Failed to launch EC2 instance"
  exit 1
fi

echo "EC2 instance launched successfully. Instance ID: $INSTANCE_ID"

# Wait for the instance to be in running state
echo "Waiting for the instance to be in running state..."
aws ec2 wait instance-running --instance-ids "$INSTANCE_ID"

# If public IP is not available immediately, try to fetch it again
if [ -z "$PUBLIC_IP" ] || [ "$PUBLIC_IP" == "null" ]; then
  PUBLIC_IP=$(aws ec2 describe-instances --instance-ids "$INSTANCE_ID" --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)
fi

echo "Instance ID: $INSTANCE_ID"
echo "Public IP: $PUBLIC_IP"
echo "Security Group ID: $SG_ID"
