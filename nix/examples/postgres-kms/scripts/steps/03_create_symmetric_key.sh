#!/bin/bash
set -euo pipefail

usage() {
  echo "Usage: $0 -k KMS_KEY_ARN [--plaintext-key-out FILE]"
  echo "  -k, --kms-key-arn       Full ARN of the KMS key (not a bare key id)"
  echo "  --plaintext-key-out     Write plaintext key to FILE (mode 0600)"
  exit 1
}

KMS_KEY_ARN=""
PLAINTEXT_KEY_OUT=""

while [[ "$#" -gt 0 ]]; do
  case $1 in
    -k|--kms-key-arn) KMS_KEY_ARN="$2"; shift ;;
    --plaintext-key-out) PLAINTEXT_KEY_OUT="$2"; shift ;;
    *) usage ;;
  esac
  shift
done

if [ -z "$KMS_KEY_ARN" ]; then
  echo "Error: KMS key ARN is required."
  usage
fi

# Must be full ARN: kms-init matches by exact string equality; a bare key id passes here and
# fails every boot.
if [[ "$KMS_KEY_ARN" != arn:aws*:kms:*:key/* ]]; then
  echo "Error: '$KMS_KEY_ARN' is not a full KMS key ARN." >&2
  echo "       Expected arn:aws:kms:<region>:<account>:key/<uuid> — the instance" >&2
  echo "       compares this against the ARN pinned into the image." >&2
  exit 1
fi

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
ARTIFACTS_DIR="$SCRIPT_DIR/../../artifacts"
mkdir -p "$ARTIFACTS_DIR"

KEY_TMPFILE=$(mktemp)
trap 'rm -f "$KEY_TMPFILE"' EXIT
(umask 077; openssl rand -base64 32 > "$KEY_TMPFILE")
echo "Symmetric key generated."

aws kms encrypt \
  --key-id "$KMS_KEY_ARN" \
  --plaintext fileb://"$KEY_TMPFILE" \
  --output text \
  --query CiphertextBlob | base64 --decode > "$ARTIFACTS_DIR/encrypted_key.bin"
echo "Symmetric key encrypted with KMS."

ENCRYPTED_KEY=$(base64 -w 0 "$ARTIFACTS_DIR/encrypted_key.bin")

cat << EOF > "$ARTIFACTS_DIR/user_data.json"
{
  "key_id": "${KMS_KEY_ARN}",
  "ciphertext": "${ENCRYPTED_KEY}"
}
EOF
echo "User data JSON created in $ARTIFACTS_DIR/user_data.json"

if [ -n "$PLAINTEXT_KEY_OUT" ]; then
  install -m 0600 "$KEY_TMPFILE" "$PLAINTEXT_KEY_OUT"
fi
