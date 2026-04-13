#!/bin/bash
set -euo pipefail

usage() {
  echo "Usage: $0 -s SERVER_ADDRESS [--key SSH_KEY_FILE]"
  echo "  -s, --server    Specify the server's public IP address"
  echo "      --key       Specify the SSH private key file (optional)"
  exit 1
}

# Parse command line arguments
while [[ "$#" -gt 0 ]]; do
  case $1 in
    -s|--server) SERVER_ADDRESS="$2"; shift ;;
    --key) KEY_FILE="$2"; shift ;;
    *) usage ;;
  esac
  shift
done

if [ -z "${SERVER_ADDRESS:-}" ]; then
  echo "Error: Server address is required."
  usage
fi

SSH_OPTS="-o StrictHostKeyChecking=no -o ConnectTimeout=10"
if [ -n "${KEY_FILE:-}" ]; then
  SSH_OPTS="$SSH_OPTS -i $KEY_FILE"
fi

echo "Testing PostgreSQL connectivity on $SERVER_ADDRESS..."

RESULT=$(ssh $SSH_OPTS root@"$SERVER_ADDRESS" "sudo -u postgres psql -c 'SELECT 1;' -t -A" 2>&1) || {
  echo "Test FAILED: Could not connect to PostgreSQL on $SERVER_ADDRESS"
  echo "Output: $RESULT"
  exit 1
}

if [ "$(echo "$RESULT" | tr -d '[:space:]')" = "1" ]; then
  echo "Test PASSED: PostgreSQL is running and responding on $SERVER_ADDRESS"
else
  echo "Test FAILED: Unexpected response from PostgreSQL"
  echo "Expected: 1"
  echo "Got: $RESULT"
  exit 1
fi
