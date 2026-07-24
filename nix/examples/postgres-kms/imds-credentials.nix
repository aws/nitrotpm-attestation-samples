{
  pkgs,
  ...
}:
pkgs.writeScript "imds-credentials.sh" ''
  #!${pkgs.bash}/bin/bash
  set -euo pipefail

  # Fetch IMDSv2 token
  TOKEN=$(${pkgs.curl}/bin/curl -s -f -X PUT "http://169.254.169.254/latest/api/token" \
    -H "X-aws-ec2-metadata-token-ttl-seconds: 21600") || {
    echo "Error: Failed to fetch IMDSv2 token. Is IMDS reachable?" >&2
    exit 1
  }

  # Discover the IAM role name
  ROLE_NAME=$(${pkgs.curl}/bin/curl -s -f \
    -H "X-aws-ec2-metadata-token: $TOKEN" \
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/") || {
    echo "Error: Failed to discover IAM role. Is an IAM role attached to this instance?" >&2
    exit 1
  }

  if [ -z "$ROLE_NAME" ]; then
    echo "Error: No IAM role attached to this instance." >&2
    exit 1
  fi

  # Fetch temporary credentials for the role
  CREDENTIALS=$(${pkgs.curl}/bin/curl -s -f \
    -H "X-aws-ec2-metadata-token: $TOKEN" \
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE_NAME") || {
    echo "Error: Failed to fetch credentials for role '$ROLE_NAME'." >&2
    exit 1
  }

  # Extract credential fields
  AWS_ACCESS_KEY_ID=$(echo "$CREDENTIALS" | ${pkgs.jq}/bin/jq -r .AccessKeyId)
  AWS_SECRET_ACCESS_KEY=$(echo "$CREDENTIALS" | ${pkgs.jq}/bin/jq -r .SecretAccessKey)
  AWS_SESSION_TOKEN=$(echo "$CREDENTIALS" | ${pkgs.jq}/bin/jq -r .Token)

  # Output export statements for eval usage
  echo "export AWS_ACCESS_KEY_ID=$AWS_ACCESS_KEY_ID"
  echo "export AWS_SECRET_ACCESS_KEY=$AWS_SECRET_ACCESS_KEY"
  echo "export AWS_SESSION_TOKEN=$AWS_SESSION_TOKEN"
''
