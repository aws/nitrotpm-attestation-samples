{ 
  pkgs,
  system,
  nitro-tee,
  key-group,
  ...
}:
pkgs.writeScript "kms-init.sh" ''
  #!${pkgs.bash}/bin/bash
  set -euo pipefail

  # Fetch IMDSv2 token
  TOKEN=$(${pkgs.curl}/bin/curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")

  # Fetch user data from EC2 metadata service using IMDSv2
  USER_DATA=$(${pkgs.curl}/bin/curl -H "X-aws-ec2-metadata-token: $TOKEN" -s http://169.254.169.254/latest/user-data)

  # Extract KEY_ID and CIPHERTEXT from user data
  KEY_ID=$(echo "$USER_DATA" | ${pkgs.jq}/bin/jq -r .key_id)
  CIPHERTEXT=$(echo "$USER_DATA" | ${pkgs.jq}/bin/jq -r .ciphertext)

  # Decrypt the symmetric key
  SYMMETRIC_KEY=$(${nitro-tee.packages.${system}.kms-decrypt-app}/bin/nitro-tpm-kms-decrypt --key-id "$KEY_ID" "$CIPHERTEXT")

  # Save the symmetric key to a known location
  echo "$SYMMETRIC_KEY" > /run/symmetric_key
  chmod 640 /run/symmetric_key
  chown root:${key-group} /run/symmetric_key
''
