#!/bin/bash
#
# Builds the raw image and registers an AMI from it.
#
# When --secure-boot is requested, the unsigned image is built first; the
# signed UKI is then patched into the ESP via sign-efi-image (which runs at
# runtime, so the db.key never enters the nix store); and the AMI is
# registered with the matching UEFI variable store. PCR4+PCR7 are computed
# against the signed image.

set -uo pipefail

SECURE_BOOT=false
DEBUG=false
DB_KEY_ARN=""
while [[ $# -gt 0 ]]; do
  case $1 in
    --secure-boot)
      SECURE_BOOT=true
      shift
      ;;
    --debug)
      DEBUG=true
      shift
      ;;
    --db-key-arn)
      DB_KEY_ARN="$2"
      shift 2
      ;;
    --secret-cert-arn)
      # Accepted but unused here; start.sh does the Secrets Manager retrieval
      # and key staging before invoking this script.
      shift 2
      ;;
    *)
      echo "Unknown option $1"
      exit 1
      ;;
  esac
done

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_DIR="$( cd "$SCRIPT_DIR/../.." &> /dev/null && pwd )"
cd "$PROJECT_DIR"

# Determine the package name (no -secure-boot variants — secure boot is
# applied as a post-build signing step)
PACKAGE_NAME="raw-image"
[ "$DEBUG" = true ] && PACKAGE_NAME="${PACKAGE_NAME}-debug"

# Sanity check: secure boot requires the sb-keys directory
if [ "$SECURE_BOOT" = true ]; then
  if [ ! -d "sb-keys" ]; then
    echo "Error: secure boot requested but sb-keys/ directory is missing."
    echo "       start.sh should populate sb-keys/ with the key hierarchy."
    exit 1
  fi
  # db.key is only staged on disk when NOT fetching it via --db-key-arn.
  REQUIRED_SB_FILES="db.crt PK.esl KEK.esl db.esl"
  [ -z "$DB_KEY_ARN" ] && REQUIRED_SB_FILES="db.key $REQUIRED_SB_FILES"
  for f in $REQUIRED_SB_FILES; do
    if [ ! -f "sb-keys/$f" ]; then
      echo "Error: secure boot requested but sb-keys/$f is missing."
      exit 1
    fi
  done
fi

echo "Running Nix UKI build for package: $PACKAGE_NAME"
nix --extra-experimental-features nix-command --extra-experimental-features flakes \
  build .#"$PACKAGE_NAME"

if [ $? -ne 0 ]; then
  echo "Error: Nix UKI build failed"
  exit 1
fi

echo "Nix UKI build completed successfully."

if [ ! -d "result" ]; then
  echo "Error: 'result' folder not found"
  exit 1
fi

if [ "$SECURE_BOOT" = true ]; then
  # result/ is a read-only nix store symlink, so copy to a writable location
  # first. Signing runs outside the nix derivation, so db.key never enters
  # /nix/store/.
  echo "Signing UKI and patching into ESP..."
  WORK_DIR="$PROJECT_DIR/signed-image"
  rm -rf "$WORK_DIR"
  mkdir -p "$WORK_DIR"
  cp -r result/. "$WORK_DIR/"
  chmod -R u+w "$WORK_DIR"

  # sign-efi-image signs the UKI, patches the ESP, builds the UEFI var store,
  # and prints the full PCR set (PCR4 + PCR7) to stdout, captured into
  # tpm_pcr.json.
  SIGN_ARGS=("$WORK_DIR" "$PROJECT_DIR/sb-keys")
  [ -n "$DB_KEY_ARN" ] && SIGN_ARGS+=(--db-key-arn "$DB_KEY_ARN")
  nix --extra-experimental-features nix-command --extra-experimental-features flakes \
    run .#sign-efi-image -- "${SIGN_ARGS[@]}" \
    > "$WORK_DIR/tpm_pcr.json"

  if [ $? -ne 0 ]; then
    echo "Error: secure boot signing / PCR computation failed"
    exit 1
  fi

  RAW_IMAGE=$(find "$WORK_DIR" -maxdepth 1 -name '*.raw' | head -1)
  if [ ! -f "$RAW_IMAGE" ]; then
    echo "Error: signed raw image not found in $WORK_DIR"
    exit 1
  fi

  echo "Creating UKI AMI from signed image..."
  nix --extra-experimental-features nix-command --extra-experimental-features flakes \
    run .#create-ami -- "$RAW_IMAGE" "$WORK_DIR/uefi_data.aws"
else
  echo "Creating UKI AMI..."
  nix --extra-experimental-features nix-command --extra-experimental-features flakes \
    run .#create-ami -- result/nixos-tee_1.raw
fi

if [ $? -ne 0 ]; then
  echo "Error: UKI AMI creation failed"
  exit 1
fi

echo "UKI AMI created successfully."
