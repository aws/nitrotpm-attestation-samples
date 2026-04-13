{
  pkgs,
  ...
}:
pkgs.writeScript "luks-init.sh" ''
  #!${pkgs.bash}/bin/bash
  set -euo pipefail

  # Read the symmetric key from the KMS init service output
  KEY=$(cat /run/kms-init/symmetric_key)

  # Resolve the data device: on Nitro instances, /dev/xvdf is exposed as an NVMe device.
  # The attach API maps xvdf → /dev/disk/by-id/nvme-Amazon_Elastic_Block_Store_vol*
  # Fall back to /dev/xvdf for non-NVMe instance types.
  if [ -e /dev/xvdf ]; then
    DATA_DEV=/dev/xvdf
  elif [ -e /dev/nvme1n1 ]; then
    DATA_DEV=/dev/nvme1n1
  else
    echo "Error: No data device found at /dev/xvdf or /dev/nvme1n1"
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
