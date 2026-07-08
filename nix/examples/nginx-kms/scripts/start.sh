#!/bin/bash

# Golden-identity helpers (generate_identity_material).
START_SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
# shellcheck source=lib/identity.sh
. "$START_SCRIPT_DIR/lib/identity.sh"

# Validate that a value matches the AWS Secrets Manager ARN format
validate_secret_arn() {
  local arn="$1"
  if [[ "$arn" != arn:aws:secretsmanager:* ]]; then
    echo "Error: '$arn' is not a valid Secrets Manager ARN. Expected format: arn:aws:secretsmanager:<region>:<account>:secret:<name>"
    exit 1
  fi
}

SECURE_BOOT_FLAG=""
DEBUG_FLAG=""
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

# Create a Secrets Manager secret from a file path, typically a process
# substitution so the value streams from a pipe and is never written to a file.
# Prints the new secret's ARN on stdout.
upload_secret() {
  local name="$1" src="$2"
  aws secretsmanager create-secret \
    --name "$name" \
    --secret-string "file://$src" \
    --query 'ARN' --output text
}

# Generate the golden identity and upload it to Secrets Manager as a single
# JSON secret nitrotpm-sb-identity-<ts> = {guid, db_key, db_crt, pk_crt,
# kek_crt}. Persisting the full identity (not just db) keeps every ESL input
# byte-stable, so PCR7 is reproducible across runs; regenerating it
# deliberately rolls PCR7 (the AWS revocation model).
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

  echo "Generating secure boot golden identity (GUID + PK, KEK, db certs)..."

  local TIMESTAMP
  TIMESTAMP=$(date +%s)

  # Generate the identity JSON in memory; db_key stays in IDENTITY_JSON (never on disk), unset after upload.
  local IDENTITY_JSON
  IDENTITY_JSON=$(generate_identity_material)
  if [ $? -ne 0 ] || [ -z "$IDENTITY_JSON" ]; then
    echo "Error: Failed to generate secure boot identity"
    exit 1
  fi

  # Validate completeness before uploading, without writing any field to disk.
  if ! printf '%s' "$IDENTITY_JSON" | jq -e \
      'has("guid") and has("db_key") and has("db_crt") and has("pk_crt") and has("kek_crt")
       and (.guid != "" and .db_key != "" and .db_crt != "" and .pk_crt != "" and .kek_crt != "")' \
      >/dev/null; then
    echo "Error: generated identity material is incomplete"
    unset IDENTITY_JSON
    exit 1
  fi

  echo "Golden identity generated successfully."

  echo "Uploading secure boot identity to AWS Secrets Manager..."
  local IDENTITY_SECRET_NAME="nitrotpm-sb-identity-${TIMESTAMP}"
  IDENTITY_ARN=$(upload_secret "$IDENTITY_SECRET_NAME" <(printf '%s' "$IDENTITY_JSON"))
  if [ $? -ne 0 ] || [ -z "$IDENTITY_ARN" ]; then
    echo "Error: Failed to upload identity to Secrets Manager"
    unset IDENTITY_JSON
    exit 1
  fi
  unset IDENTITY_JSON
  echo "Identity uploaded. ARN: $IDENTITY_ARN"

  update_resource "IDENTITY_ARN" "$IDENTITY_ARN"

  echo "Identity uploaded to AWS Secrets Manager. No private key was written to disk."
}

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
ARTIFACTS_DIR="$SCRIPT_DIR/../artifacts"
RESOURCES_FILE="$ARTIFACTS_DIR/resources.json"

mkdir -p "$ARTIFACTS_DIR"

# Check if resources file already exists with content
if [ -f "$RESOURCES_FILE" ] && [ "$(jq 'length' "$RESOURCES_FILE" 2>/dev/null)" -gt 0 ]; then
  echo ""
  echo "WARNING: A resources file already exists at: $RESOURCES_FILE"
  echo "This may indicate a previous deployment that was not cleaned up."
  echo ""
  if [ "$NON_INTERACTIVE" = true ]; then
    echo "Non-interactive mode: overwriting existing resources file."
    RESPONSE="no"
  else
    read -r -p "Would you like to run cleanup first? (yes/no/abort): " RESPONSE
  fi
  case "$RESPONSE" in
    yes)
      echo "Running cleanup..."
      "$SCRIPT_DIR/clean.sh"
      if [ $? -ne 0 ]; then
        echo "Error: Cleanup failed. Aborting."
        exit 1
      fi
      echo "Cleanup complete. Continuing with new deployment."
      ;;
    no)
      echo "Overwriting existing resources file."
      ;;
    *)
      echo "Aborting deployment."
      exit 0
      ;;
  esac
fi

if [ ! -f "$RESOURCES_FILE" ]; then
    echo '{}' > "$RESOURCES_FILE"
fi

update_resource() {
  local KEY=$1
  local VALUE=$2
  local tmp
  tmp=$(mktemp "${RESOURCES_FILE}.XXXXXX")
  jq --arg key "$KEY" --arg value "$VALUE" '.[$key] = $value' "$RESOURCES_FILE" > "$tmp" && mv "$tmp" "$RESOURCES_FILE" || rm -f "$tmp"
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
check_credentials_var AWS_SESSION_TOKEN
check_credentials_var AWS_DEFAULT_REGION

echo "AWS credentials are set and validated."

# Interactive key generation mode: generate identity and upload to Secrets Manager
if [ -n "$SECRET_MANAGER_INTERACTIVE" ]; then
  # Reuse a retained golden identity from a previous deployment if resources.json
  # records one. The whole identity is a single secret, so a single ARN is all
  # we need — no partial-identity states to reconcile.
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

# For --secrets-manager, rebuild the ESLs and uefi_data.aws from the persisted
# golden identity (db.crt + fixed GUID + PK/KEK certs from the identity bundle).
# Every ESL input is byte-stable across runs, so PCR7 is reproducible.
if [ -n "$SECURE_BOOT_FLAG" ] && [ -n "$SECRET_MANAGER_FLAG" ]; then
  LOCAL_KEY_DIR="$SCRIPT_DIR/../sb-keys"
  rm -rf "$LOCAL_KEY_DIR"
  mkdir -p "$LOCAL_KEY_DIR"

  echo "Rebuilding UEFI secure boot envelope from persisted identity (ESLs, uefi_data.aws)..."

  # Unpack the identity's PUBLIC fields (guid + certs) to disk; db_key stays in the secret, fetched in-memory at signing.
  if [ -z "$IDENTITY_ARN" ]; then
    echo "Error: no secure boot identity (IDENTITY_ARN) available; cannot"
    echo "       rebuild a reproducible envelope."
    rm -rf "$LOCAL_KEY_DIR"
    exit 1
  fi

  IDENTITY_JSON=$(aws secretsmanager get-secret-value --secret-id "$IDENTITY_ARN" --query SecretString --output text)
  if [ $? -ne 0 ]; then
    echo "Error: Failed to retrieve secure boot identity from Secrets Manager"
    rm -rf "$LOCAL_KEY_DIR"
    exit 1
  fi
  echo "$IDENTITY_JSON" | jq -r '.guid'    > "$LOCAL_KEY_DIR/GUID.txt"
  echo "$IDENTITY_JSON" | jq -r '.db_crt'  > "$LOCAL_KEY_DIR/db.crt"
  echo "$IDENTITY_JSON" | jq -r '.pk_crt'  > "$LOCAL_KEY_DIR/PK.crt"
  echo "$IDENTITY_JSON" | jq -r '.kek_crt' > "$LOCAL_KEY_DIR/KEK.crt"
  unset IDENTITY_JSON
  if [ ! -s "$LOCAL_KEY_DIR/GUID.txt" ] || [ ! -s "$LOCAL_KEY_DIR/db.crt" ] \
     || [ ! -s "$LOCAL_KEY_DIR/PK.crt" ] || [ ! -s "$LOCAL_KEY_DIR/KEK.crt" ]; then
    echo "Error: secure boot identity is missing guid/db_crt/pk_crt/kek_crt"
    rm -rf "$LOCAL_KEY_DIR"
    exit 1
  fi

  # Rebuild the ESLs from the fixed GUID + persisted certs (cert-to-efi-sig-list is byte-deterministic).
  nix --extra-experimental-features nix-command --extra-experimental-features flakes shell \
    nixpkgs#efitools --command bash -c "
    cd '$LOCAL_KEY_DIR'
    cert-to-efi-sig-list -g \"\$(cat GUID.txt)\" PK.crt PK.esl
    cert-to-efi-sig-list -g \"\$(cat GUID.txt)\" KEK.crt KEK.esl
    cert-to-efi-sig-list -g \"\$(cat GUID.txt)\" db.crt db.esl
  "

  if [ $? -ne 0 ]; then
    echo "Error: Failed to rebuild UEFI secure boot envelope"
    rm -rf "$LOCAL_KEY_DIR"
    exit 1
  fi

  # Generate UEFI variable store (uefi_data.aws)
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

  echo "UEFI secure boot data generated at: $LOCAL_KEY_DIR"
fi

echo "Step 1: Creating AMI..."
# Build the argument list for 00_create_ami.sh
CREATE_AMI_ARGS="$SECURE_BOOT_FLAG $DEBUG_FLAG"
if [ -n "$SECRET_MANAGER_FLAG" ] && [ -n "$IDENTITY_ARN" ]; then
  # Pass the golden-identity ARN through; sign-efi-image fetches db.key from it
  # in memory at signing time.
  CREATE_AMI_ARGS="$CREATE_AMI_ARGS --identity-arn $IDENTITY_ARN"
fi
OUTPUT=$("$SCRIPT_DIR/steps/00_create_ami.sh" $CREATE_AMI_ARGS)
CREATE_AMI_RC=$?

# Scrub local sb-keys/ after the build: the material is either persisted in
# Secrets Manager or was ephemeral for this run, so it shouldn't linger.
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
if [ -n "$IDENTITY_ARN" ]; then
  echo "  - Secret ARN (identity): $IDENTITY_ARN"
fi
echo "  - Artifacts: $SCRIPT_DIR/../artifacts/"
echo "  - EC2 Instance ID: $INSTANCE_ID"
echo "  - EC2 Public IP: $PUBLIC_IP"
echo "  - Security Group ID: $SG_ID"

echo "Resource IDs have been saved to $RESOURCES_FILE"

echo "You can access the server at: http://$PUBLIC_IP?ciphertext=<YOUR_CYPHERTEXT>"
