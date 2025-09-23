#!/bin/bash

# Parse command line arguments
PACKAGE_NAME="raw-image"
while [[ $# -gt 0 ]]; do
  case $1 in
    --debug)
      PACKAGE_NAME="raw-image-debug"
      shift
      ;;
    *)
      echo "Unknown option $1"
      exit 1
      ;;
  esac
done

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

echo "Creating UKI AMI..."
nix --extra-experimental-features nix-command --extra-experimental-features flakes run .#create-ami -- result/nixos-tee_1.raw

if [ $? -ne 0 ]; then
  echo "Error: UKI AMI creation failed"
  exit 1
fi

echo "UKI AMI created successfully."
