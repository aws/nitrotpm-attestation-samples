#!/bin/bash
set -euo pipefail

usage() {
  echo "Usage: $0 -k KMS_KEY_ID [--plaintext-key-out FILE]"
  echo "  -k, --kms-key-id        Specify the KMS Key ID"
  echo "  --plaintext-key-out     Write plaintext key to FILE (mode 0600)"
  exit 1
}

PLAINTEXT_KEY_OUT=""

while [[ "$#" -gt 0 ]]; do
  case $1 in
    -k|--kms-key-id) KMS_KEY_ID="$2"; shift ;;
    --plaintext-key-out) PLAINTEXT_KEY_OUT="$2"; shift ;;
    *) usage ;;
  esac
  shift
done

if [ -z "$KMS_KEY_ID" ]; then
  echo "Error: KMS Key ID is required."
  usage
fi

# Create artifacts directory if it doesn't exist
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
ARTIFACTS_DIR="$SCRIPT_DIR/../../artifacts"
mkdir -p "$ARTIFACTS_DIR"

# Generate a symmetric key into a private temp file
KEY_TMPFILE=$(mktemp)
trap 'rm -f "$KEY_TMPFILE"' EXIT
(umask 077; openssl rand -base64 32 > "$KEY_TMPFILE")
echo "Symmetric key generated."

# Encrypt the symmetric key using KMS
aws kms encrypt \
  --key-id "$KMS_KEY_ID" \
  --plaintext fileb://"$KEY_TMPFILE" \
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

# If the caller requested the plaintext key, copy it out with restricted perms
if [ -n "$PLAINTEXT_KEY_OUT" ]; then
  install -m 0600 "$KEY_TMPFILE" "$PLAINTEXT_KEY_OUT"
fi
