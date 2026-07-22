#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

usage() {
  echo "Usage: $0 -a AMI_ID -p INSTANCE_PROFILE_NAME -v VOLUME_ID [-t INSTANCE_TYPE] [--vpc-id VPC_ID] [--public] [--debug]"
  echo "  -a, --ami-id                 Specify the AMI ID"
  echo "  -p, --profile                Specify the Instance Profile name"
  echo "  -v, --volume-id              Specify the EBS Volume ID to attach"
  echo "  -t, --instance-type          Specify the Instance Type (auto-detected from AMI arch if omitted)"
  echo "      --vpc-id                 Specify the VPC ID (uses default VPC if omitted)"
  echo "      --public                 Assign a public IP (for out-of-VPC mTLS access; caller must allowlist its source IP on 5432)"
  echo "      --debug                  Enable debug mode (SSM access, no additional inbound ports needed)"
  exit 1
}

SECURITY_GROUP_NAME="PostgresKMS-TestSG"
DEBUG=false
PUBLIC=false
VPC_ID=""

while [[ "$#" -gt 0 ]]; do
  case $1 in
    -a|--ami-id) AMI_ID="$2"; shift ;;
    -p|--profile) INSTANCE_PROFILE_NAME="$2"; shift ;;
    -v|--volume-id) VOLUME_ID="$2"; shift ;;
    -t|--instance-type) INSTANCE_TYPE="$2"; shift ;;
    --vpc-id) VPC_ID="$2"; shift ;;
    --public) PUBLIC=true ;;
    --debug) DEBUG=true ;;
    *) usage ;;
  esac
  shift
done

if [ -z "${AMI_ID:-}" ] || [ -z "${INSTANCE_PROFILE_NAME:-}" ] || [ -z "${VOLUME_ID:-}" ]; then
  echo "Error: AMI ID, Instance Profile name, and Volume ID are required."
  usage
fi

# Determine instance type based on AMI architecture if not specified
if [ -z "${INSTANCE_TYPE:-}" ]; then
  echo "Determining instance type based on AMI architecture..."
  AMI_ARCH=$(aws ec2 describe-images --image-ids "$AMI_ID" --query 'Images[0].Architecture' --output text)

  if [ "$AMI_ARCH" == "arm64" ]; then
    INSTANCE_TYPE="c6g.2xlarge"
    echo "AMI architecture is ARM64, using instance type: $INSTANCE_TYPE"
  else
    INSTANCE_TYPE="m6i.4xlarge"
    echo "AMI architecture is x86_64, using instance type: $INSTANCE_TYPE"
  fi
else
  echo "Using specified instance type: $INSTANCE_TYPE"
fi

# Resolve VPC ID and CIDR
if [ -z "$VPC_ID" ]; then
  VPC_ID=$(aws ec2 describe-vpcs --filters "Name=isDefault,Values=true" --query 'Vpcs[0].VpcId' --output text)
  echo "Using default VPC: $VPC_ID"
fi

VPC_CIDR=$(aws ec2 describe-vpcs --vpc-ids "$VPC_ID" --query 'Vpcs[0].CidrBlock' --output text)
echo "VPC CIDR: $VPC_CIDR"

# Pick a subnet in the same AZ as the EBS volume
VOLUME_AZ=$(aws ec2 describe-volumes --volume-ids "$VOLUME_ID" --query 'Volumes[0].AvailabilityZone' --output text)
echo "EBS volume is in availability zone: $VOLUME_AZ"

SUBNET_ID=$(aws ec2 describe-subnets \
  --filters "Name=vpc-id,Values=$VPC_ID" "Name=availability-zone,Values=$VOLUME_AZ" \
  --query 'Subnets[0].SubnetId' --output text)
echo "Using subnet: $SUBNET_ID in $VOLUME_AZ"

# Check if the security group exists in this VPC, if not create it
if ! SG_ID=$(aws ec2 describe-security-groups \
    --filters "Name=group-name,Values=$SECURITY_GROUP_NAME" "Name=vpc-id,Values=$VPC_ID" \
    --query 'SecurityGroups[0].GroupId' --output text 2>/dev/null) || [ "$SG_ID" = "None" ]; then
  echo "Security group does not exist. Creating in VPC $VPC_ID..."
  SG_ID=$(aws ec2 create-security-group \
    --group-name "$SECURITY_GROUP_NAME" \
    --description "Security group for PostgresKMS test" \
    --vpc-id "$VPC_ID" \
    --query 'GroupId' --output text)
  echo "Allowing inbound PostgreSQL (port 5432) from VPC CIDR $VPC_CIDR..."
  aws ec2 authorize-security-group-ingress --group-id "$SG_ID" --protocol tcp --port 5432 --cidr "$VPC_CIDR"
else
  echo "Security group already exists. Using existing group: $SG_ID"
fi

# Launch the EC2 instance in the same AZ as the volume. By default no public IP
# (access via SSM and VPC-internal mTLS); --public assigns one for out-of-VPC
# mTLS access (the caller is responsible for allowlisting its source IP on 5432).
PUBLIC_IP_FLAG="--no-associate-public-ip-address"
[ "$PUBLIC" = true ] && PUBLIC_IP_FLAG="--associate-public-ip-address"
INSTANCE_OUTPUT=$(aws ec2 run-instances \
  --image-id "$AMI_ID" \
  --instance-type "$INSTANCE_TYPE" \
  --iam-instance-profile "Name=$INSTANCE_PROFILE_NAME" \
  --user-data file://"$SCRIPT_DIR/../../artifacts/user_data.json" \
  --security-group-ids "$SG_ID" \
  --subnet-id "$SUBNET_ID" \
  $PUBLIC_IP_FLAG \
  --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=PostgresKMS-TEE}]" \
  --query 'Instances[0].{InstanceId:InstanceId,PrivateIpAddress:PrivateIpAddress}' \
  --output json)

INSTANCE_ID=$(echo "$INSTANCE_OUTPUT" | jq -r '.InstanceId')
PRIVATE_IP=$(echo "$INSTANCE_OUTPUT" | jq -r '.PrivateIpAddress')

if [ -z "$INSTANCE_ID" ]; then
  echo "Error: Failed to launch EC2 instance"
  exit 1
fi

echo "EC2 instance launched successfully."

# Wait for the instance to be in running state
echo "Waiting for the instance to be in running state..."
aws ec2 wait instance-running --instance-ids "$INSTANCE_ID"

# Attach the EBS volume to the instance
echo "Attaching EBS volume $VOLUME_ID to instance $INSTANCE_ID as /dev/xvdf..."
aws ec2 attach-volume --volume-id "$VOLUME_ID" --instance-id "$INSTANCE_ID" --device /dev/xvdf

echo "Waiting for volume to be attached..."
aws ec2 wait volume-in-use --volume-ids "$VOLUME_ID"

echo "EBS volume attached successfully."

echo "Instance ID: $INSTANCE_ID"
echo "Private IP: $PRIVATE_IP"
echo "Security Group ID: $SG_ID"

if [ "$PUBLIC" = true ]; then
  PUBLIC_IP=$(aws ec2 describe-instances --instance-ids "$INSTANCE_ID" --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)
  echo "Public IP: $PUBLIC_IP"
fi
