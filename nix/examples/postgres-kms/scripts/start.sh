#!/bin/bash

# No `set -x`: secure-boot signing key material is handled in memory and
# xtrace would echo it to stderr.

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

# shellcheck source=lib/identity.sh
. "$SCRIPT_DIR/lib/identity.sh"

SECURE_BOOT_FLAG=""
DEBUG_FLAG=""
VPC_ID_FLAG=""
SECRET_MANAGER_FLAG=""
IDENTITY_ARN=""
SECRET_MANAGER_INTERACTIVE=""
NON_INTERACTIVE=false
while [[ $# -gt 0 ]]; do
  case $1 in
    --secure-boot)
      SECURE_BOOT_FLAG="--secure-boot"
      shift
      ;;
    --debug)
      DEBUG_FLAG="--debug"
      shift
      ;;
    --vpc-id)
      VPC_ID_FLAG="--vpc-id $2"
      shift; shift
      ;;
    --non-interactive|--yes|-y)
      NON_INTERACTIVE=true
      shift
      ;;
    --secrets-manager)
      SECRET_MANAGER_FLAG="true"
      shift
      # Check if next argument is absent or starts with '--'
      if [[ $# -eq 0 ]] || [[ "$1" == --* ]]; then
        SECRET_MANAGER_INTERACTIVE="true"
      else
        IDENTITY_ARN="$1"
        validate_secret_arn "$IDENTITY_ARN"
        shift
      fi
      ;;
    *)
      echo "Unknown option $1"
      exit 1
      ;;
  esac
done

# Validate that --secrets-manager requires --secure-boot
if [ -n "$SECRET_MANAGER_FLAG" ] && [ -z "$SECURE_BOOT_FLAG" ]; then
  echo "Error: --secrets-manager requires --secure-boot"
  exit 1
fi

ARTIFACTS_DIR="$SCRIPT_DIR/../artifacts"
RESOURCES_FILE="$ARTIFACTS_DIR/resources.json"

mkdir -p "$ARTIFACTS_DIR"
# Keep an existing resources file: it may hold a reusable IDENTITY_ARN
if [ ! -f "$RESOURCES_FILE" ]; then
  echo '{}' > "$RESOURCES_FILE"
fi

# Generate a fresh golden identity and upload it to Secrets Manager.
# Regenerating deliberately rolls PCR7 (the AWS revocation model).
generate_and_upload_keys() {
  echo ""
  echo "No Secret ARN provided. Would you like to generate a new signing identity and upload it to AWS Secrets Manager?"
  if [ "$NON_INTERACTIVE" = true ]; then
    echo "Non-interactive mode: generating and uploading identity."
    CONFIRM="yes"
  else
    read -r -p "Generate and upload identity? (yes/no): " CONFIRM
  fi

  if [[ "$CONFIRM" != "yes" ]]; then
    echo "Identity generation declined. Please provide an existing Secret ARN:"
    echo "  ./scripts/start.sh --secure-boot --secrets-manager arn:aws:secretsmanager:REGION:ACCOUNT:secret:NAME"
    exit 1
  fi

  echo "Generating and uploading secure boot golden identity..."
  IDENTITY_ARN=$(generate_and_upload_identity "nitrotpm-sb-identity") || exit 1
  echo "Identity uploaded (no private key written to disk). ARN: $IDENTITY_ARN"
  update_resource "IDENTITY_ARN" "$IDENTITY_ARN"
}

check_credentials_var() {
  local var_name=$1
  local var_value="${!var_name}"

  if [ -n "$var_value" ]; then
    echo "$var_name is set in environment"
    return 0
  fi

  # Fall back to the matching aws configure key.
  local aws_config_key=""
  case "$var_name" in
    "AWS_ACCESS_KEY_ID")
      aws_config_key="aws_access_key_id"
      ;;
    "AWS_SECRET_ACCESS_KEY")
      aws_config_key="aws_secret_access_key"
      ;;
    "AWS_DEFAULT_REGION")
      aws_config_key="region"
      ;;
    *)
      echo "Error: Unknown AWS credential variable $var_name"
      exit 1
      ;;
  esac

  local aws_value
  aws_value=$(aws configure get "$aws_config_key" 2>/dev/null)

  if [ -n "$aws_value" ]; then
    echo "$var_name obtained from aws configure"
    export "$var_name"="$aws_value"
    return 0
  fi

  echo "Error: $var_name is not set in environment and not available via 'aws configure get $aws_config_key'"
  exit 1
}

echo "Starting deployment process..."

# Display secure boot warning if secure boot mode is enabled without Secrets Manager
if [ -n "$SECURE_BOOT_FLAG" ] && [ -z "$SECRET_MANAGER_FLAG" ]; then
  echo -e "\033[33m⚠️  WARNING: Secure boot builds are NOT reproducible (keys generated at build time)! ⚠️\033[0m"
fi

# Display debug warning if debug mode is enabled
if [ -n "$DEBUG_FLAG" ]; then
  echo -e "\033[31m⚠️  WARNING: Building in DEBUG mode with operator access enabled! ⚠️\033[0m"
fi

echo "Checking AWS credentials..."
check_credentials_var AWS_ACCESS_KEY_ID
check_credentials_var AWS_SECRET_ACCESS_KEY
check_credentials_var AWS_DEFAULT_REGION

# SESSION_TOKEN is optional: IAM users with long-term keys have none
if [ -z "${AWS_SESSION_TOKEN:-}" ]; then
  if aws_value=$(aws configure get aws_session_token 2>/dev/null) && [ -n "$aws_value" ]; then
    export AWS_SESSION_TOKEN="$aws_value"
    echo "AWS_SESSION_TOKEN obtained from aws configure"
  fi
fi

# Final validation: confirm the credential chain actually works
CALLER_IDENTITY=$(aws sts get-caller-identity --output json 2>/dev/null) || {
  echo "Error: AWS credentials are invalid. Please check your configuration."
  exit 1
}
CALLER_ARN=$(echo "$CALLER_IDENTITY" | jq -r '.Arn')

echo "AWS credentials are set and validated."

# Interactive key generation mode: generate identity and upload to Secrets Manager
if [ -n "$SECRET_MANAGER_INTERACTIVE" ]; then
  # Offer to reuse a retained golden identity from a previous deployment
  if [ -f "$RESOURCES_FILE" ]; then
    RETAINED_IDENTITY_ARN=$(jq -r '.IDENTITY_ARN // empty' "$RESOURCES_FILE" 2>/dev/null)
    if [ -n "$RETAINED_IDENTITY_ARN" ]; then
      echo ""
      echo "Found retained secure boot identity from a previous deployment:"
      echo "  Identity: $RETAINED_IDENTITY_ARN"
      if [ "$NON_INTERACTIVE" = true ]; then
        echo "Non-interactive mode: reusing retained identity."
        USE_RETAINED="yes"
      else
        read -r -p "Use this retained identity? (yes/no): " USE_RETAINED
      fi
      if [[ "$USE_RETAINED" == "yes" ]]; then
        IDENTITY_ARN="$RETAINED_IDENTITY_ARN"
        SECRET_MANAGER_INTERACTIVE=""
        echo "Using retained identity from Secrets Manager."
      else
        echo "Generating new identity..."
      fi
    fi
  fi
  # If still in interactive mode (user declined retained identity or none found), generate new one
  if [ -n "$SECRET_MANAGER_INTERACTIVE" ]; then
    generate_and_upload_keys
  fi
fi

# Generate local signing keys when --secure-boot is used without --secrets-manager
if [ -n "$SECURE_BOOT_FLAG" ] && [ -z "$SECRET_MANAGER_FLAG" ]; then
  LOCAL_KEY_DIR="$SCRIPT_DIR/../sb-keys"
  echo ""
  echo -e "\033[33m⚠️  WARNING: Generating local signing keys at: $LOCAL_KEY_DIR\033[0m"
  echo -e "\033[33m   Keys are overwritten on every run — measurements will change each time.\033[0m"
  echo -e "\033[33m   For persistent, reproducible signing use: --secure-boot --secrets-manager\033[0m"
  echo ""

  echo "Generating secure boot key hierarchy (PK, KEK, db + ESL files + UEFI var store)..."
  if ! generate_local_sb_keys "$LOCAL_KEY_DIR" "$SCRIPT_DIR/.."; then
    echo "Error: Failed to generate secure boot key hierarchy"
    rm -rf "$LOCAL_KEY_DIR"
    exit 1
  fi
  echo "Secure boot key hierarchy generated at: $LOCAL_KEY_DIR"
fi

# --secrets-manager: rebuild the reproducible UEFI envelope from the persisted identity
if [ -n "$SECURE_BOOT_FLAG" ] && [ -n "$SECRET_MANAGER_FLAG" ]; then
  echo "Rebuilding UEFI secure boot envelope from persisted identity (ESLs, uefi_data.aws)..."
  if ! rebuild_sb_envelope_from_identity "$SCRIPT_DIR/../sb-keys" "$SCRIPT_DIR/.." "$IDENTITY_ARN"; then
    exit 1
  fi
  echo "UEFI secure boot data generated at: $SCRIPT_DIR/../sb-keys"
fi

echo "Step 1: Creating AMI..."
CREATE_AMI_ARGS="$SECURE_BOOT_FLAG $DEBUG_FLAG"
if [ -n "$SECRET_MANAGER_FLAG" ] && [ -n "$IDENTITY_ARN" ]; then
  CREATE_AMI_ARGS="$CREATE_AMI_ARGS --identity-arn $IDENTITY_ARN"
fi
OUTPUT=$("$SCRIPT_DIR/steps/00_create_ami.sh" $CREATE_AMI_ARGS)
CREATE_AMI_RC=$?

# Scrub local sb-keys/ after the build so key material doesn't linger on disk
if [ -n "$SECURE_BOOT_FLAG" ] && [ -d "$SCRIPT_DIR/../sb-keys" ]; then
  rm -rf "$SCRIPT_DIR/../sb-keys"
  echo "Local sb-keys/ removed after build."
fi

if [ $CREATE_AMI_RC -ne 0 ]; then
  echo "Error: AMI creation failed"
  echo "$OUTPUT"
  exit 1
fi

AMI_ID=$(echo "$OUTPUT" | grep -oP 'ami-[a-z0-9]+')

if [ -z "$AMI_ID" ]; then
  echo "Error: Unable to extract AMI ID from the output"
  echo "$OUTPUT"
  exit 1
fi

update_resource "AMI_ID" "$AMI_ID"
echo "AMI created successfully. AMI ID: $AMI_ID"

echo "Step 2: Setting up IAM role and instance profile..."
ROLE_NAME="TpmAttestationRole"
INSTANCE_PROFILE_NAME="TpmAttestationProfile"

echo "Creating/checking role '$ROLE_NAME' and instance profile '$INSTANCE_PROFILE_NAME'..."
OUTPUT=$("$SCRIPT_DIR/steps/01_create_instance_profile.sh" -r "$ROLE_NAME" -p "$INSTANCE_PROFILE_NAME" $DEBUG_FLAG)

if [ $? -ne 0 ]; then
  echo "Error: IAM role and instance profile setup failed"
  echo "$OUTPUT"
  exit 1
fi

update_resource "ROLE_NAME" "$ROLE_NAME"
update_resource "INSTANCE_PROFILE_NAME" "$INSTANCE_PROFILE_NAME"
echo "IAM role and instance profile setup completed."

echo "Step 3: Creating KMS key..."
INSTANCE_ROLE_ARN=$(aws iam get-role --role-name "$ROLE_NAME" --query 'Role.Arn' --output text)
ADMIN_ROLE_ARN="$CALLER_ARN"
echo "Creating KMS key with instance role '$INSTANCE_ROLE_ARN' and admin role '$ADMIN_ROLE_ARN'..."
# Signed image's tpm_pcr.json (PCR4+PCR7) when secure boot is active, else the unsigned baseline
PCR_DIR=$(resolve_pcr_dir "$SCRIPT_DIR/.." "$SECURE_BOOT_FLAG")
OUTPUT=$("$SCRIPT_DIR/steps/02_create_kms_key.sh" -r "$INSTANCE_ROLE_ARN" -a "$ADMIN_ROLE_ARN" -m "$PCR_DIR")

if [ $? -ne 0 ]; then
  echo "Error: KMS key creation failed"
  echo "$OUTPUT"
  exit 1
fi

KMS_KEY_ID=$(echo "$OUTPUT" | grep -oP 'KMS key created with ID: \K.*')

if [ -z "$KMS_KEY_ID" ]; then
  echo "Error: Unable to extract KMS key ID from the output"
  echo "$OUTPUT"
  exit 1
fi

update_resource "KMS_KEY_ID" "$KMS_KEY_ID"
echo "KMS key created successfully. Key ID: $KMS_KEY_ID"

echo "Step 4: Creating symmetric key and user data..."
KEY_TMPDIR=$(mktemp -d)
chmod 700 "$KEY_TMPDIR"
KEY_FILE="$KEY_TMPDIR/symmetric_key"
cleanup_key_file() { rm -rf "$KEY_TMPDIR"; }
trap cleanup_key_file EXIT

OUTPUT=$("$SCRIPT_DIR/steps/03_create_symmetric_key.sh" -k "$KMS_KEY_ID" --plaintext-key-out "$KEY_FILE")

if [ $? -ne 0 ]; then
  echo "Error: Symmetric key creation failed"
  echo "$OUTPUT"
  exit 1
fi

echo "Symmetric key and user data created successfully."

echo "Step 5a: Creating certificates..."
OUTPUT=$("$SCRIPT_DIR/steps/05a_create_certificates.sh" -r "$ROLE_NAME" --symmetric-key "$KEY_FILE")

if [ $? -ne 0 ]; then
  echo "Error: Certificate creation failed"
  echo "$OUTPUT"
  exit 1
fi

rm -f "$KEY_FILE"

SECRET_ARN=$(echo "$OUTPUT" | grep -oP 'SECRET_ARN: \K.*')

if [ -n "$SECRET_ARN" ]; then
  update_resource "SECRET_ARN" "$SECRET_ARN"
fi

echo "Certificates created successfully."

echo "Step 6: Creating EBS volume..."
AVAILABILITY_ZONE=$(aws ec2 describe-availability-zones --query 'AvailabilityZones[0].ZoneName' --output text 2>/dev/null || echo "${AWS_DEFAULT_REGION}a")

echo "Creating blank EBS volume in availability zone '$AVAILABILITY_ZONE'..."
OUTPUT=$("$SCRIPT_DIR/steps/04_create_ebs_volume.sh" -z "$AVAILABILITY_ZONE")

if [ $? -ne 0 ]; then
  echo "Error: EBS volume creation failed"
  echo "$OUTPUT"
  exit 1
fi

VOLUME_ID=$(echo "$OUTPUT" | grep -oP 'Volume ID: \K.*')

if [ -z "$VOLUME_ID" ]; then
  echo "Error: Unable to extract Volume ID from the output"
  echo "$OUTPUT"
  exit 1
fi

update_resource "VOLUME_ID" "$VOLUME_ID"
echo "EBS volume created successfully. Volume ID: $VOLUME_ID"

echo "Step 7: Launching EC2 instance..."
# Launch with a public IP so PostgreSQL mTLS is reachable from outside the VPC.
OUTPUT=$("$SCRIPT_DIR/steps/05_run_instance.sh" -a "$AMI_ID" -p "$INSTANCE_PROFILE_NAME" -v "$VOLUME_ID" $VPC_ID_FLAG --public $DEBUG_FLAG)

if [ $? -ne 0 ]; then
  echo "Error: EC2 run instance failed"
  echo "$OUTPUT"
  exit 1
fi

INSTANCE_ID=$(echo "$OUTPUT" | grep -oP 'Instance ID: \K.*')
PRIVATE_IP=$(echo "$OUTPUT" | grep -oP 'Private IP: \K.*')
PUBLIC_IP=$(echo "$OUTPUT" | grep -oP 'Public IP: \K.*')
SG_ID=$(echo "$OUTPUT" | grep -oP 'Security Group ID: \K.*')

if [ -z "$INSTANCE_ID" ] || [ -z "$PUBLIC_IP" ] || [ -z "$SG_ID" ]; then
  echo "Error: Unable to extract instance details from the output"
  echo "$OUTPUT"
  exit 1
fi

update_resource "INSTANCE_ID" "$INSTANCE_ID"
update_resource "SECURITY_GROUP_ID" "$SG_ID"
echo "EC2 instance launched successfully."

echo "Deployment process completed successfully."
echo "Summary:"
echo "  - AMI ID: $AMI_ID"
echo "  - IAM Role: $ROLE_NAME"
echo "  - Instance Profile: $INSTANCE_PROFILE_NAME"
echo "  - KMS Key ID: $KMS_KEY_ID"
if [ -n "$IDENTITY_ARN" ]; then
  echo "  - Secret ARN (identity): $IDENTITY_ARN"
fi
if [ -n "${SECRET_ARN:-}" ]; then
  echo "  - Secret ARN (client certs): $SECRET_ARN"
fi
echo "  - EBS Volume ID: $VOLUME_ID"
echo "  - Artifacts: $SCRIPT_DIR/../artifacts/"
echo "  - EC2 Instance ID: $INSTANCE_ID"
echo "  - EC2 Private IP: $PRIVATE_IP"
echo "  - EC2 Public IP: $PUBLIC_IP"
echo "  - Security Group ID: $SG_ID"

echo "Resource IDs have been saved to $RESOURCES_FILE"

print_sg_authorization_notice "$SG_ID"
echo "Once your host is allowlisted, connect over mTLS to: $PUBLIC_IP:5432"
echo "You can also connect via SSM: aws ssm start-session --target $INSTANCE_ID"
