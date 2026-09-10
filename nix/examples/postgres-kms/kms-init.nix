{
  pkgs,
  system,
  nitro-tee,
  kmsKeyArn,
  ...
}:
pkgs.writeScript "kms-init.sh" ''
  #!${pkgs.bash}/bin/bash
  set -euo pipefail

  . ${./kms-verify.sh}

  # KMS key fixed at build time; empty = buildable but unbootable (see kms-verify.sh).
  PINNED_KMS_KEY_ARN='${kmsKeyArn}'

  TOKEN=$(${pkgs.curl}/bin/curl -sf -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
  USER_DATA=$(${pkgs.curl}/bin/curl -sf -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/user-data)

  echo "$USER_DATA" > /run/kms-init/user_data.json

  # Default to "" so an absent key_id reaches kms_verify_pinned_key_id with a clear error, not a bare jq failure.
  KEY_ID=$(echo "$USER_DATA" | ${pkgs.jq}/bin/jq -r '.key_id // ""')
  # Default to "" for the same reason as key_id: -re would abort here under `set -e`, before the
  # base64 guard below could report why.
  CIPHERTEXT=$(echo "$USER_DATA" | ${pkgs.jq}/bin/jq -r '.ciphertext // ""')

  kms_verify_pinned_key_id "$PINNED_KMS_KEY_ARN" "$KEY_ID" \
    || { echo "FATAL: refusing to decrypt against an unpinned or substituted KMS key" >&2; exit 1; }

  # '-' not in base64 alphabet; blocks unmeasured user-data from reaching the decrypt helper as a flag.
  case "$CIPHERTEXT" in
    "" | *[^A-Za-z0-9+/=]* )
      echo "FATAL: ciphertext is not base64; refusing to pass it to the decrypt helper" >&2
      exit 1 ;;
  esac

  # Decrypt against PINNED_KMS_KEY_ARN, not $KEY_ID: the guarantee comes from the measurement.
  SYMMETRIC_KEY=$(${nitro-tee.packages.${system}.kms-decrypt-app}/bin/nitro-tpm-kms-decrypt --key-id "$PINNED_KMS_KEY_ARN" "$CIPHERTEXT")

  # A failed decrypt must not become the LUKS passphrase.
  case "$SYMMETRIC_KEY" in
    "" | *[^A-Za-z0-9+/=]* )
      echo "FATAL: decrypt helper returned no usable key material" >&2
      exit 1 ;;
  esac

  echo "$SYMMETRIC_KEY" > /run/kms-init/symmetric_key
''
