{ 
  pkgs,
  system,
  nitro-tee,
  ...
}:
pkgs.writeScript "kms-init.sh" ''
  #!${pkgs.bash}/bin/bash
  set -euo pipefail

  # Fetch IMDSv2 token
  TOKEN=$(${pkgs.curl}/bin/curl -sf -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")

  # Fetch user data from EC2 metadata service using IMDSv2
  USER_DATA=$(${pkgs.curl}/bin/curl -sf -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/user-data)

  # Persist user-data so cert-init can read it without IMDS access
  echo "$USER_DATA" > /run/kms-init/user_data.json

  KEY_ID=$(echo "$USER_DATA" | ${pkgs.jq}/bin/jq -re .key_id)
  CIPHERTEXT=$(echo "$USER_DATA" | ${pkgs.jq}/bin/jq -re .ciphertext)

  SYMMETRIC_KEY=$(${nitro-tee.packages.${system}.kms-decrypt-app}/bin/nitro-tpm-kms-decrypt --key-id "$KEY_ID" "$CIPHERTEXT")
  echo "$SYMMETRIC_KEY" > /run/kms-init/symmetric_key
''
