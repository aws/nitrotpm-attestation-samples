#!/bin/bash
set -euo pipefail

usage() {
  echo "Usage: $0 -k KMS_KEY_ID | --kms-key-id KMS_KEY_ID"
  echo "  -k, --kms-key-id        Specify the KMS Key ID"
  exit 1
}

while [[ "$#" -gt 0 ]]; do
  case $1 in
    -k|--kms-key-id) KMS_KEY_ID="$2"; shift ;;
    *) usage ;;
  esac
  shift
done

if [ -z "$KMS_KEY_ID" ]; then
  echo "Error: KMS Key ID is required."
  usage
fi

# Create artifacts directory if it doesn't exist
ARTIFACTS_DIR="artifacts"
mkdir -p "$ARTIFACTS_DIR"

# Generate a symmetric key
openssl rand -base64 32 > "$ARTIFACTS_DIR/symmetric_key.bin"
echo "Symmetric key generated."

# Encrypt the symmetric key using KMS
aws kms encrypt \
  --key-id "$KMS_KEY_ID" \
  --plaintext fileb://"$ARTIFACTS_DIR/symmetric_key.bin" \
  --output text \
  --query CiphertextBlob | base64 --decode > "$ARTIFACTS_DIR/encrypted_key.bin"
echo "Symmetric key encrypted with KMS."

# Encode the encrypted key as base64
ENCRYPTED_KEY=$(base64 -w 0 "$ARTIFACTS_DIR/encrypted_key.bin")

# Create the user data JSON
cat << EOF > "$ARTIFACTS_DIR/user_data.json"
{
  "key_id": "${KMS_KEY_ID}",
  "ciphertext": "${ENCRYPTED_KEY}"
}
EOF
echo "User data JSON created in $ARTIFACTS_DIR/user_data.json"
