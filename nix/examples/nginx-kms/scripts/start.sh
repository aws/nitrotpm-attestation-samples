#!/bin/bash

# Parse command line arguments
SECURE_BOOT_FLAG=""
DEBUG_FLAG=""
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
    *)
      echo "Unknown option $1"
      exit 1
      ;;
  esac
done


SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
ARTIFACTS_DIR="$SCRIPT_DIR/../artifacts"
RESOURCES_FILE="$ARTIFACTS_DIR/resources.json"

mkdir -p "$ARTIFACTS_DIR"

echo '{}' > "$RESOURCES_FILE"

update_resource() {
  local KEY=$1
  local VALUE=$2
  jq --arg key "$KEY" --arg value "$VALUE" '.[$key] = $value' "$RESOURCES_FILE" > tmp.json && mv tmp.json "$RESOURCES_FILE"
}

check_credentials_var() {
  local var_name=$1
  local var_value="${!var_name}"

  # If environment variable is already set, use it
  if [ -n "$var_value" ]; then
    echo "$var_name is set in environment"
    return 0
  fi

  # Try to get value from aws configure
  local aws_config_key=""
  case "$var_name" in
    "AWS_ACCESS_KEY_ID")
      aws_config_key="aws_access_key_id"
      ;;
    "AWS_SECRET_ACCESS_KEY")
      aws_config_key="aws_secret_access_key"
      ;;
    "AWS_SESSION_TOKEN")
      aws_config_key="aws_session_token"
      ;;
    "AWS_DEFAULT_REGION")
      aws_config_key="region"
      ;;
    *)
      echo "Error: Unknown AWS credential variable $var_name"
      exit 1
      ;;
  esac

  local aws_value=$(aws configure get "$aws_config_key" 2>/dev/null)

  if [ -n "$aws_value" ]; then
    echo "$var_name obtained from aws configure"
    export "$var_name"="$aws_value"
    return 0
  fi

  # Neither environment variable nor aws configure provided a value
  echo "Error: $var_name is not set in environment and not available via 'aws configure get $aws_config_key'"
  exit 1
}

echo "Starting deployment process..."

# Display secure boot warning if secure boot mode is enabled
if [ -n "$SECURE_BOOT_FLAG" ]; then
  echo -e "\033[33m⚠️  WARNING: Secure boot builds are NOT reproducible (keys generated at build time)! ⚠️\033[0m"
fi

# Display debug warning if debug mode is enabled
if [ -n "$DEBUG_FLAG" ]; then
  echo -e "\033[31m⚠️  WARNING: Building in DEBUG mode with operator access enabled! ⚠️\033[0m"
fi

echo "Checking AWS credentials..."
check_credentials_var AWS_ACCESS_KEY_ID
check_credentials_var AWS_SECRET_ACCESS_KEY
check_credentials_var AWS_SESSION_TOKEN
check_credentials_var AWS_DEFAULT_REGION

echo "AWS credentials are set and validated."

# Generate signing keys when --secure-boot is requested
if [ -n "$SECURE_BOOT_FLAG" ]; then
  LOCAL_KEY_DIR="$SCRIPT_DIR/../sb-keys"
  echo ""
  echo -e "\033[33m⚠️  WARNING: Generating local signing keys at: $LOCAL_KEY_DIR\033[0m"
  echo -e "\033[33m   Keys are overwritten on every run — measurements will change each time.\033[0m"
  echo ""

  rm -rf "$LOCAL_KEY_DIR"
  mkdir -p "$LOCAL_KEY_DIR"

  # Generate full secure boot key hierarchy using nix shell for efitools
  echo "Generating secure boot key hierarchy (PK, KEK, db + ESL files + UEFI var store)..."
  nix --extra-experimental-features nix-command --extra-experimental-features flakes shell \
    nixpkgs#openssl nixpkgs#efitools nixpkgs#util-linux --command bash -c "
    cd '$LOCAL_KEY_DIR'

    # Generate GUID
    uuidgen --random > GUID.txt

    # Generate PK (Platform Key)
    openssl req -newkey rsa:4096 -nodes -keyout PK.key -new -x509 -sha256 -days 3650 -subj '/CN=Platform key/' -out PK.crt 2>/dev/null
    cert-to-efi-sig-list -g \"\$(cat GUID.txt)\" PK.crt PK.esl
    sign-efi-sig-list -g \"\$(cat GUID.txt)\" -k PK.key -c PK.crt PK PK.esl PK.auth

    # Generate KEK (Key Exchange Key)
    openssl req -newkey rsa:4096 -nodes -keyout KEK.key -new -x509 -sha256 -days 3650 -subj '/CN=Key Exchange Key/' -out KEK.crt 2>/dev/null
    cert-to-efi-sig-list -g \"\$(cat GUID.txt)\" KEK.crt KEK.esl
    sign-efi-sig-list -g \"\$(cat GUID.txt)\" -k PK.key -c PK.crt KEK KEK.esl KEK.auth

    # Generate db (Signature Database Key)
    openssl req -newkey rsa:4096 -nodes -keyout db.key -new -x509 -sha256 -days 3650 -subj '/CN=Signature Database key/' -out db.crt 2>/dev/null
    cert-to-efi-sig-list -g \"\$(cat GUID.txt)\" db.crt db.esl
    sign-efi-sig-list -g \"\$(cat GUID.txt)\" -k KEK.key -c KEK.crt db db.esl db.auth
  "

  if [ $? -ne 0 ]; then
    echo "Error: Failed to generate secure boot key hierarchy"
    rm -rf "$LOCAL_KEY_DIR"
    exit 1
  fi

  # Generate UEFI variable store (uefi_data.aws)
  echo "Generating UEFI variable store..."
  nix --extra-experimental-features nix-command --extra-experimental-features flakes run .#generate-uefi-vars -- \
    -P "$LOCAL_KEY_DIR/PK.esl" \
    -K "$LOCAL_KEY_DIR/KEK.esl" \
    --db "$LOCAL_KEY_DIR/db.esl" \
    -O "$LOCAL_KEY_DIR/uefi_data.aws"

  if [ $? -ne 0 ]; then
    echo "Error: Failed to generate UEFI variable store"
    rm -rf "$LOCAL_KEY_DIR"
    exit 1
  fi

  chmod 0600 "$LOCAL_KEY_DIR/PK.key" "$LOCAL_KEY_DIR/KEK.key" "$LOCAL_KEY_DIR/db.key"
  echo "Secure boot key hierarchy generated at: $LOCAL_KEY_DIR"
fi

echo "Step 1: Creating AMI..."
# Build the argument list for 00_create_ami.sh
OUTPUT=$("$SCRIPT_DIR/steps/00_create_ami.sh" $SECURE_BOOT_FLAG $DEBUG_FLAG)
CREATE_AMI_RC=$?

# Scrub the local sb-keys/ directory once the AMI build is done. The keys
# are either still in Secrets Manager (--secrets-manager) or were
# ephemerally generated for this run (plain --secure-boot); either way they
# should not linger on the working tree. Signing runs outside the nix
# derivation, and the keys were only used as file-path inputs to the
# external `nix run .#sign-efi-image` invocation, so removing the local
# copies fully reclaims the key material.
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
OUTPUT=$("$SCRIPT_DIR/steps/01_create_instance_profile.sh" -r "$ROLE_NAME" -p "$INSTANCE_PROFILE_NAME")

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
ADMIN_ROLE_ARN=$(aws sts get-caller-identity --query 'Arn' --output text)

echo "Creating KMS key with instance role '$INSTANCE_ROLE_ARN' and admin role '$ADMIN_ROLE_ARN'..."
# Pick the measurements directory: the signed image's tpm_pcr.json (with PCR7)
# when secure boot is active, otherwise the unsigned image's baseline.
PCR_DIR="$SCRIPT_DIR/../result"
if [ -n "$SECURE_BOOT_FLAG" ] && [ -f "$SCRIPT_DIR/../signed-image/tpm_pcr.json" ]; then
  PCR_DIR="$SCRIPT_DIR/../signed-image"
fi
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
OUTPUT=$("$SCRIPT_DIR/steps/03_create_symmetric_key.sh" -k "$KMS_KEY_ID")

if [ $? -ne 0 ]; then
  echo "Error: Symmetric key creation failed"
  echo "$OUTPUT"
  exit 1
fi

echo "Symmetric key and user data created successfully."

echo "Step 5: Launching EC2 instance..."
OUTPUT=$("$SCRIPT_DIR/steps/04_run_instance.sh" -a "$AMI_ID" -p "$INSTANCE_PROFILE_NAME")

if [ $? -ne 0 ]; then
  echo "Error: EC2 run instance failed"
  echo "$OUTPUT"
  exit 1
fi

INSTANCE_ID=$(echo "$OUTPUT" | grep -oP 'Instance ID: \K.*')
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
echo "  - Artifacts: $SCRIPT_DIR/../artifacts/"
echo "  - EC2 Instance ID: $INSTANCE_ID"
echo "  - EC2 Public IP: $PUBLIC_IP"
echo "  - Security Group ID: $SG_ID"

echo "Resource IDs have been saved to $RESOURCES_FILE"

echo "You can access the server at: http://$PUBLIC_IP?ciphertext=<YOUR_CYPHERTEXT>"
