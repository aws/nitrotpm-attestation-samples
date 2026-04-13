{
  pkgs,
  ...
}:
pkgs.writeScript "luks-init.sh" ''
  #!${pkgs.bash}/bin/bash
  set -euo pipefail

  # Read the symmetric key from the KMS init service output
  KEY=$(cat /run/kms-init/symmetric_key)

  # Check if the device is already LUKS-formatted (first boot vs subsequent boot)
  if ! ${pkgs.cryptsetup}/bin/cryptsetup isLuks /dev/xvdf; then
    # First boot: format, open, and create filesystem
    echo "$KEY" | ${pkgs.cryptsetup}/bin/cryptsetup luksFormat /dev/xvdf --key-file=-
    echo "$KEY" | ${pkgs.cryptsetup}/bin/cryptsetup luksOpen /dev/xvdf data --key-file=-
    ${pkgs.e2fsprogs}/bin/mkfs.ext4 /dev/mapper/data
  else
    # Subsequent boot: just open the existing LUKS volume
    echo "$KEY" | ${pkgs.cryptsetup}/bin/cryptsetup luksOpen /dev/xvdf data --key-file=-
  fi
''
