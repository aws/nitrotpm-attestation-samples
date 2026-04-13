#!/bin/bash
set -euo pipefail

usage() {
  echo "Usage: $0 -k <KMS_KEY_ID> -r <ROLE_NAME>"
  echo "  -k, --kms-key-id    KMS Key ID (used for context/logging)"
  echo "  -r, --role-name     IAM role to grant Secrets Manager read access"
  exit 1
}

while [[ "$#" -gt 0 ]]; do
  case $1 in
    -k|--kms-key-id) KMS_KEY_ID="$2"; shift ;;
    -r|--role-name) ROLE_NAME="$2"; shift ;;
    *) usage ;;
  esac
  shift
done

if [ -z "${KMS_KEY_ID:-}" ] || [ -z "${ROLE_NAME:-}" ]; then
  echo "Error: Both KMS_KEY_ID and ROLE_NAME are required."
  usage
fi

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
ARTIFACTS_DIR="$SCRIPT_DIR/../../artifacts"
SYMMETRIC_KEY="$ARTIFACTS_DIR/symmetric_key.bin"
USER_DATA_FILE="$ARTIFACTS_DIR/user_data.json"

if [ ! -f "$SYMMETRIC_KEY" ]; then
  echo "Error: Symmetric key not found at $SYMMETRIC_KEY"
  exit 1
fi

if [ ! -f "$USER_DATA_FILE" ]; then
  echo "Error: user_data.json not found at $USER_DATA_FILE"
  exit 1
fi

# Create a temporary directory for certificate generation
CERT_TMPDIR=$(mktemp -d)
trap 'rm -rf "$CERT_TMPDIR"' EXIT

echo "Generating certificates..."

# --- Step 1: Generate self-signed CA (RSA 4096, 3650 days) ---
openssl req -x509 -newkey rsa:4096 -nodes \
  -keyout "$CERT_TMPDIR/ca.key" \
  -out "$CERT_TMPDIR/ca.crt" \
  -days 3650 \
  -subj "/CN=postgres-ca"
echo "CA certificate generated."

# --- Step 2: Generate server certificate (RSA 2048, 825 days) signed by CA ---
openssl req -newkey rsa:2048 -nodes \
  -keyout "$CERT_TMPDIR/server.key" \
  -out "$CERT_TMPDIR/server.csr" \
  -subj "/CN=postgres-server"

openssl x509 -req \
  -in "$CERT_TMPDIR/server.csr" \
  -CA "$CERT_TMPDIR/ca.crt" \
  -CAkey "$CERT_TMPDIR/ca.key" \
  -CAcreateserial \
  -out "$CERT_TMPDIR/server.crt" \
  -days 825
echo "Server certificate generated."

# --- Step 3: Generate client certificate (RSA 2048, 825 days) signed by CA ---
openssl req -newkey rsa:2048 -nodes \
  -keyout "$CERT_TMPDIR/client.key" \
  -out "$CERT_TMPDIR/client.csr" \
  -subj "/CN=postgres-client"

openssl x509 -req \
  -in "$CERT_TMPDIR/client.csr" \
  -CA "$CERT_TMPDIR/ca.crt" \
  -CAkey "$CERT_TMPDIR/ca.key" \
  -CAcreateserial \
  -out "$CERT_TMPDIR/client.crt" \
  -days 825
echo "Client certificate generated."

# --- Step 4: Bundle server certs into tarball and encrypt with symmetric key ---
tar -cf "$CERT_TMPDIR/server_bundle.tar" \
  -C "$CERT_TMPDIR" ca.crt server.crt server.key

openssl enc -aes-256-cbc -salt -pbkdf2 \
  -in "$CERT_TMPDIR/server_bundle.tar" \
  -out "$CERT_TMPDIR/encrypted_server_bundle.bin" \
  -pass "file:$SYMMETRIC_KEY"
echo "Server certificate bundle encrypted."

# Copy encrypted bundle to artifacts for reference
cp "$CERT_TMPDIR/encrypted_server_bundle.bin" "$ARTIFACTS_DIR/encrypted_server_bundle.bin"

# --- Step 5: Base64-encode encrypted bundle and add to user_data.json ---
SERVER_CERT_BUNDLE=$(base64 -w 0 "$CERT_TMPDIR/encrypted_server_bundle.bin")

jq --arg bundle "$SERVER_CERT_BUNDLE" '. + {server_cert_bundle: $bundle}' \
  "$USER_DATA_FILE" > "$CERT_TMPDIR/user_data_updated.json"
mv "$CERT_TMPDIR/user_data_updated.json" "$USER_DATA_FILE"
echo "user_data.json updated with server_cert_bundle."

# --- Step 6: Store client bundle in Secrets Manager ---
CA_CERT_B64=$(base64 -w 0 "$CERT_TMPDIR/ca.crt")
CLIENT_CERT_B64=$(base64 -w 0 "$CERT_TMPDIR/client.crt")
CLIENT_KEY_B64=$(base64 -w 0 "$CERT_TMPDIR/client.key")

CLIENT_BUNDLE_JSON=$(jq -n \
  --arg ca_cert "$CA_CERT_B64" \
  --arg client_cert "$CLIENT_CERT_B64" \
  --arg client_key "$CLIENT_KEY_B64" \
  '{ca_cert: $ca_cert, client_cert: $client_cert, client_key: $client_key}')

UNIQUE_SUFFIX=$(date +%s)-$(openssl rand -hex 4)
SECRET_NAME="postgres-kms/client-cert-${UNIQUE_SUFFIX}"

REGION=$(aws configure get region 2>/dev/null || echo "${AWS_DEFAULT_REGION:-us-east-1}")

SECRET_ARN=$(aws secretsmanager create-secret \
  --name "$SECRET_NAME" \
  --secret-string "$CLIENT_BUNDLE_JSON" \
  --region "$REGION" \
  --query 'ARN' \
  --output text)
echo "Client certificate bundle stored in Secrets Manager: $SECRET_ARN"

# --- Step 7: Attach inline IAM policy for Secrets Manager access ---
POLICY_DOCUMENT=$(cat <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "secretsmanager:GetSecretValue",
      "Resource": "$SECRET_ARN"
    }
  ]
}
EOF
)

aws iam put-role-policy \
  --role-name "$ROLE_NAME" \
  --policy-name "SecretsManagerClientCertAccess" \
  --policy-document "$POLICY_DOCUMENT"
echo "IAM inline policy SecretsManagerClientCertAccess attached to role $ROLE_NAME."

# --- Step 8: Record SECRET_ARN in resources.json ---
RESOURCES_FILE="$ARTIFACTS_DIR/resources.json"
if [ -f "$RESOURCES_FILE" ]; then
  jq --arg arn "$SECRET_ARN" '. + {SECRET_ARN: $arn}' "$RESOURCES_FILE" > "$CERT_TMPDIR/resources_updated.json"
  mv "$CERT_TMPDIR/resources_updated.json" "$RESOURCES_FILE"
else
  echo "{\"SECRET_ARN\": \"$SECRET_ARN\"}" > "$RESOURCES_FILE"
fi
echo "SECRET_ARN recorded in resources.json."

echo "Certificate generation completed successfully."
echo "SECRET_ARN: $SECRET_ARN"
