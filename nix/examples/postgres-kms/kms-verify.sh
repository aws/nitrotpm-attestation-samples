# shellcheck shell=bash
# Binds this image to one KMS key ARN. User-data isn't measured, so pinning the ARN into the
# measured store (PCR4) stops an operator launching the genuine AMI against a key they control.
# Fixes *which* key, not *which* ciphertext. Sourced by kms-init.nix + scripts/test_kms_verify.sh.

# kms_verify_pinned_key_id <pinned-arn> <user-data-key-id> -- 0=accept, 1=reject with stderr reason.
# Empty <pinned-arn> = fresh-clone build; must fail closed, never fall back to trusting user-data.
kms_verify_pinned_key_id() {
  local pinned=$1 supplied=$2

  if [ -z "$pinned" ]; then
    echo "kms-verify: this image was built without a pinned KMS key ARN." \
         "Write the ARN into nix/examples/postgres-kms/kms-key-arn.txt and rebuild" \
         "(scripts/steps/02a_create_kms_key.sh does this)." >&2
    return 1
  fi

  if [ -z "$supplied" ]; then
    echo "kms-verify: user-data carries no key_id; expected the pinned key $pinned" >&2
    return 1
  fi

  # Exact equality only: any relaxation widens the attack surface.
  if [ "$supplied" = "$pinned" ]; then
    return 0
  fi

  case "$supplied" in
    arn:*)
      echo "kms-verify: user-data key_id '$supplied' does not match the pinned key" \
           "$pinned -- refusing to decrypt" >&2
      ;;
    *)
      # Bare UUID names no account/region, so it cannot be compared to the pinned ARN.
      echo "kms-verify: user-data key_id '$supplied' is not a full ARN, so it" \
           "does not match the pinned key $pinned. user_data.json must carry" \
           "the complete arn:aws:kms:<region>:<account>:key/<uuid>." >&2
      ;;
  esac
  return 1
}
