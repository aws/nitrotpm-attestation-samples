#!/bin/bash
set -uo pipefail

# Fetch IMDSv2 token
TOKEN=$(curl -s -f -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600") || {
  echo "Error: Failed to fetch IMDSv2 token. Is IMDS reachable?" >&2
  exit 1
}

# Discover IAM role name
ROLE=$(curl -s -f -H "X-aws-ec2-metadata-token: $TOKEN" \
  "http://169.254.169.254/latest/meta-data/iam/security-credentials/") || {
  echo "Error: No IAM role attached to this instance." >&2
  exit 1
}

# Fetch credentials
CREDS=$(curl -s -f -H "X-aws-ec2-metadata-token: $TOKEN" \
  "http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE") || {
  echo "Error: Failed to fetch credentials for role '$ROLE'." >&2
  exit 1
}

export AWS_ACCESS_KEY_ID=$(echo "$CREDS" | jq -r .AccessKeyId)
export AWS_SECRET_ACCESS_KEY=$(echo "$CREDS" | jq -r .SecretAccessKey)
export AWS_SESSION_TOKEN=$(echo "$CREDS" | jq -r .Token)

echo "Credentials refreshed for role: $ROLE"
echo "Expiration: $(echo "$CREDS" | jq -r .Expiration)"
