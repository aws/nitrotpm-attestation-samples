#!/bin/bash

# Parse command line arguments
SECURE_BOOT=false
DEBUG=false
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
    *)
      echo "Unknown option $1"
      exit 1
      ;;
  esac
done

# Build the package name based on flags
PACKAGE_NAME="raw-image"
[ "$DEBUG" = true ] && PACKAGE_NAME="${PACKAGE_NAME}-debug"

echo "Running Nix UKI build for package: $PACKAGE_NAME"

nix --extra-experimental-features nix-command --extra-experimental-features flakes build .#$PACKAGE_NAME

if [ $? -ne 0 ]; then
  echo "Error: Nix UKI build failed"
  exit 1
fi

echo "Nix UKI build completed successfully."

if [ ! -d "result" ]; then
  echo "Error: 'result' folder not found"
  exit 1
fi

# If secure boot, generate keys and sign the image
if [ "$SECURE_BOOT" = true ]; then
  echo "Building secure boot key material..."
  nix --extra-experimental-features nix-command --extra-experimental-features flakes build .#secure-boot-keys --out-link sb-keys

  if [ $? -ne 0 ]; then
    echo "Error: Failed to build secure boot keys"
    exit 1
  fi

  DB_KEY="sb-keys/db.key"
  DB_CRT="sb-keys/db.crt"

  if [ ! -f "$DB_KEY" ] || [ ! -f "$DB_CRT" ]; then
    echo "Error: db.key or db.crt not found in secure-boot-keys output"
    exit 1
  fi

  echo "Signing EFI image for secure boot..."
  nix --extra-experimental-features nix-command --extra-experimental-features flakes run .#sign-efi-image -- \
    result/unsigned.efi "$DB_KEY" "$DB_CRT" signed.efi

  if [ $? -ne 0 ]; then
    echo "Error: Secure boot signing failed"
    exit 1
  fi
  echo "Image signed for secure boot."
fi

echo "Creating UKI AMI..."

# Build the AMI creation target name
CREATE_AMI_TARGET="create-ami"
[ "$SECURE_BOOT" = true ] && CREATE_AMI_TARGET="${CREATE_AMI_TARGET}-secure-boot"

nix --extra-experimental-features nix-command --extra-experimental-features flakes run .#$CREATE_AMI_TARGET -- result/nixos-tee_1.raw

if [ $? -ne 0 ]; then
  echo "Error: UKI AMI creation failed"
  exit 1
fi

echo "UKI AMI created successfully."
