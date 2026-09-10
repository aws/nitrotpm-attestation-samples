{
  pkgs,
  ...
}:
pkgs.writeScript "luks-init.sh" ''
  #!${pkgs.bash}/bin/bash
  set -euo pipefail

  CRYPTSETUP=${pkgs.cryptsetup}/bin/cryptsetup

  LUKS_JQ=${pkgs.jq}/bin/jq
  . ${./luks-verify.sh}

  fail() { echo "FATAL: $*" >&2; exit 1; }

  # Always close on rejection: a stale mapping blocks retries and exposes /dev/mapper/data even when data.mount is blocked.
  close_mapping() { $CRYPTSETUP close data 2>/dev/null || true; }

  KEY=$(cat /run/kms-init/symmetric_key)

  # EBS is hot-attached after "running"; poll until the device appears.
  # /dev/xvdf is the attach-volume BDM name, symlinked by the amazon-ec2-utils udev rules.
  # Never fall back to /dev/nvme1n1: NVMe indices follow enumeration order, so the guess can
  # land on the root disk and luksFormat below destroys it. No symlink = time out, fail closed.
  DATA_DEV=""
  for _ in $(${pkgs.coreutils}/bin/seq 60); do
    if [ -b /dev/xvdf ]; then
      DATA_DEV=/dev/xvdf
      break
    fi
    echo "Waiting for data device to be attached..."
    ${pkgs.coreutils}/bin/sleep 2
  done
  if [ -z "$DATA_DEV" ]; then
    echo "Error: no /dev/xvdf block device after 120s; refusing to guess an NVMe index"
    exit 1
  fi
  echo "Using data device: $DATA_DEV"

  # Zero the 16 MiB LUKS2 metadata region on any post-luksFormat failure so the next boot re-initialises rather than treating a headerless volume as tampered.
  rollback_format() {
    echo "Rolling back partial initialisation of $DATA_DEV" >&2
    close_mapping
    ${pkgs.coreutils}/bin/dd if=/dev/zero of="$DATA_DEV" bs=1M count=16 \
      conv=fsync status=none 2>/dev/null || true
  }

  # A header with wrong parameters is a tamper signal — never silently reformat, that destroys data and hides the evidence.
  if ! $CRYPTSETUP isLuks --type luks2 "$DATA_DEV"; then
    echo "No LUKS2 header found; formatting with authenticated encryption..."
    echo "$KEY" | $CRYPTSETUP luksFormat --type luks2 \
      --cipher "$LUKS_EXPECTED_CIPHER" \
      --key-size "$LUKS_EXPECTED_KEYSIZE" \
      --integrity "$LUKS_EXPECTED_INTEGRITY_ARG" \
      --sector-size "$LUKS_EXPECTED_SECTOR_SIZE" \
      --pbkdf "$LUKS_EXPECTED_PBKDF" \
      --batch-mode \
      "$DATA_DEV" --key-file=- \
      || { rollback_format; fail "luksFormat failed on $DATA_DEV"; }

    echo "$KEY" | $CRYPTSETUP luksOpen --type luks2 "$DATA_DEV" data --key-file=- \
      || { rollback_format; fail "luksOpen failed on the freshly formatted $DATA_DEV"; }

    luks_verify_status "$($CRYPTSETUP status data)" \
      || { rollback_format; fail "freshly formatted volume does not match the pinned format"; }

    ${pkgs.e2fsprogs}/bin/mkfs.ext4 /dev/mapper/data \
      || { rollback_format; fail "mkfs.ext4 failed on /dev/mapper/data"; }
  else
    META=$($CRYPTSETUP luksDump --dump-json-metadata "$DATA_DEV") \
      || fail "cannot read LUKS2 JSON metadata from $DATA_DEV"
    luks_verify_header_json "$META" \
      || fail "refusing to open $DATA_DEV: header was tampered with"

    echo "$KEY" | $CRYPTSETUP luksOpen --type luks2 "$DATA_DEV" data --key-file=-

    # luksOpen success proves only key correctness; verify the active mapping parameters and close (not zero) on mismatch to preserve tamper evidence.
    luks_verify_status "$($CRYPTSETUP status data)" \
      || { close_mapping; fail "active mapping for $DATA_DEV does not match the pinned format"; }
  fi
''
