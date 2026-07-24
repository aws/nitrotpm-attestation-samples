{
  pkgs,
  ...
}:
pkgs.writeScript "luks-init.sh" ''
  #!${pkgs.bash}/bin/bash
  set -euo pipefail

  KEY=$(cat /run/kms-init/symmetric_key)

  # The EBS volume is hot-attached after the instance is "running", so the
  # device (xvdf, or nvme1n1 on Nitro) may not exist yet — wait for it.
  DATA_DEV=""
  for _ in $(${pkgs.coreutils}/bin/seq 60); do
    if [ -e /dev/xvdf ]; then
      DATA_DEV=/dev/xvdf
      break
    elif [ -e /dev/nvme1n1 ]; then
      DATA_DEV=/dev/nvme1n1
      break
    fi
    echo "Waiting for data device to be attached..."
    ${pkgs.coreutils}/bin/sleep 2
  done
  if [ -z "$DATA_DEV" ]; then
    echo "Error: No data device found at /dev/xvdf or /dev/nvme1n1 after 120s"
    exit 1
  fi
  echo "Using data device: $DATA_DEV"

  # Check if the device is already LUKS-formatted (first boot vs subsequent boot)
  if ! ${pkgs.cryptsetup}/bin/cryptsetup isLuks "$DATA_DEV"; then
    # First boot: format, open, and create filesystem
    echo "$KEY" | ${pkgs.cryptsetup}/bin/cryptsetup luksFormat "$DATA_DEV" --key-file=-
    echo "$KEY" | ${pkgs.cryptsetup}/bin/cryptsetup luksOpen "$DATA_DEV" data --key-file=-
    ${pkgs.e2fsprogs}/bin/mkfs.ext4 /dev/mapper/data
  else
    # Subsequent boot: just open the existing LUKS volume
    echo "$KEY" | ${pkgs.cryptsetup}/bin/cryptsetup luksOpen "$DATA_DEV" data --key-file=-
  fi
''
