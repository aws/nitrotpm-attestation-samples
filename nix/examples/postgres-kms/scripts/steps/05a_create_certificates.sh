#!/bin/bash
set -euo pipefail

usage() {
  echo "Usage: $0 --symmetric-key <FILE>"
  echo "  --symmetric-key      Path to the plaintext symmetric key file"
  exit 1
}

SYMMETRIC_KEY=""

while [[ "$#" -gt 0 ]]; do
  case $1 in
    -k|--kms-key-id) shift ;; # accepted for backward compat, unused
    --symmetric-key) SYMMETRIC_KEY="$2"; shift ;;
    *) usage ;;
  esac
  shift
done

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
ARTIFACTS_DIR="$SCRIPT_DIR/../../artifacts"
USER_DATA_FILE="$ARTIFACTS_DIR/user_data.json"

# Fall back to the legacy fixed path for backward compatibility
if [ -z "$SYMMETRIC_KEY" ]; then
  SYMMETRIC_KEY="$ARTIFACTS_DIR/symmetric_key.bin"
fi

if [ ! -f "$SYMMETRIC_KEY" ]; then
  echo "Error: Symmetric key not found at $SYMMETRIC_KEY"
  exit 1
fi

if [ ! -f "$USER_DATA_FILE" ]; then
  echo "Error: user_data.json not found at $USER_DATA_FILE"
  exit 1
fi

CERT_TMPDIR=$(mktemp -d)
trap 'rm -rf "$CERT_TMPDIR"' EXIT

echo "Generating certificates..."

openssl req -x509 -newkey rsa:4096 -nodes \
  -keyout "$CERT_TMPDIR/ca.key" \
  -out "$CERT_TMPDIR/ca.crt" \
  -days 3650 \
  -subj "/CN=postgres-ca"
echo "CA certificate generated."

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

tar -cf "$CERT_TMPDIR/server_bundle.tar" \
  -C "$CERT_TMPDIR" ca.crt server.crt server.key

openssl enc -aes-256-cbc -salt -pbkdf2 \
  -in "$CERT_TMPDIR/server_bundle.tar" \
  -out "$CERT_TMPDIR/encrypted_server_bundle.bin" \
  -pass "file:$SYMMETRIC_KEY"
echo "Server certificate bundle encrypted."

cp "$CERT_TMPDIR/encrypted_server_bundle.bin" "$ARTIFACTS_DIR/encrypted_server_bundle.bin"

SERVER_CERT_BUNDLE=$(base64 -w 0 "$CERT_TMPDIR/encrypted_server_bundle.bin")

jq --arg bundle "$SERVER_CERT_BUNDLE" '. + {server_cert_bundle: $bundle}' \
  "$USER_DATA_FILE" > "$CERT_TMPDIR/user_data_updated.json"
mv "$CERT_TMPDIR/user_data_updated.json" "$USER_DATA_FILE"
echo "user_data.json updated with server_cert_bundle."

CA_CERT_B64=$(base64 -w 0 "$CERT_TMPDIR/ca.crt")
CLIENT_CERT_B64=$(base64 -w 0 "$CERT_TMPDIR/client.crt")
CLIENT_KEY_B64=$(base64 -w 0 "$CERT_TMPDIR/client.key")

# Via a file, not argv: --secret-string on the command line leaks the client key through
# /proc/<pid>/cmdline. CERT_TMPDIR is 0700, trap-removed, and already holds client.key.
CLIENT_BUNDLE_FILE="$CERT_TMPDIR/client_bundle.json"
jq -n \
  --arg ca_cert "$CA_CERT_B64" \
  --arg client_cert "$CLIENT_CERT_B64" \
  --arg client_key "$CLIENT_KEY_B64" \
  '{ca_cert: $ca_cert, client_cert: $client_cert, client_key: $client_key}' \
  > "$CLIENT_BUNDLE_FILE"

UNIQUE_SUFFIX=$(date +%s)-$(openssl rand -hex 4)
SECRET_NAME="postgres-kms/client-cert-${UNIQUE_SUFFIX}"

SECRET_ARN=$(aws secretsmanager create-secret \
  --name "$SECRET_NAME" \
  --secret-string "file://$CLIENT_BUNDLE_FILE" \
  --query 'ARN' \
  --output text)
echo "Client certificate bundle stored in Secrets Manager: $SECRET_ARN"

# The instance never reads this secret (its server bundle arrives via user-data);
# only the deployer/e2e client fetches it, so the instance role gets no grant here.

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
