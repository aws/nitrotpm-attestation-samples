{ config, pkgs, lib, ... }:

# Automated setup of ephemeral instance storage
#
# This module combines all instance storage devices via RAID0 into a single
# encrypted device using an ephemeral encryption key. This guarantees that data
# does not persist across reboots and hence replace root volume operations.

let
  cfg = config.services.instance-storage;

  prepareInstanceStorage = pkgs.writeShellApplication {
    name = "prepare-instance-storage";
    runtimeInputs = with pkgs; [
      coreutils
      cryptsetup
      util-linux
      mdadm
      systemd
    ] ++ lib.optionals (cfg.usage == "root" || cfg.usage == "mount") [
      xfsprogs
    ];
    text = ''
      shopt -s nullglob

      # Discover instance storage devices
      DEVICES=()

      for dev in /sys/class/block/nvme*n*
      do
        if [ -f "$dev/device/model" ]; then
          read -r model < "$dev/device/model"
          if [[ "$model" == *"Amazon EC2 NVMe Instance Storage"* ]]; then
            DEVICES+=("/dev/$(basename "$dev")")
          fi
        fi
      done

      DEVICE_COUNT=''${#DEVICES[@]}

      if [ "$DEVICE_COUNT" -eq 0 ]; then
        echo "No instance storage devices found"

        exit 0
      fi

      echo "Found $DEVICE_COUNT instance storage device(s): ''${DEVICES[*]}"

      # Setup target device (single device or RAID0 array)
      if [ "$DEVICE_COUNT" -eq 1 ]; then
        TARGET_DEVICE="''${DEVICES[0]}"
      else
        TARGET_DEVICE="/dev/md/instance-storage"

        mdadm --stop "$TARGET_DEVICE" 2>/dev/null || true

        for dev in "''${DEVICES[@]}"
        do
          mdadm --zero-superblock "$dev" 2>/dev/null || true
        done

        mdadm --create "$TARGET_DEVICE" \
          --level=0 \
          --raid-devices="$DEVICE_COUNT" \
          --force \
          "''${DEVICES[@]}"

        udevadm wait "$TARGET_DEVICE"

        echo "RAID0 array created: $TARGET_DEVICE"
      fi

      # Encrypt with ephemeral key
      CRYPT_NAME="instance-storage"
      CRYPT_DEVICE="/dev/mapper/$CRYPT_NAME"

      ENCRYPTION_KEY=$(head -c 32 /dev/urandom | base64 -w 0)

      echo -n "$ENCRYPTION_KEY" | base64 -d | cryptsetup luksFormat \
        --type luks2 \
        --key-file - \
        --batch-mode \
        "$TARGET_DEVICE"

      echo -n "$ENCRYPTION_KEY" | base64 -d | cryptsetup open \
        --key-file - \
        "$TARGET_DEVICE" \
        "$CRYPT_NAME"

      unset ENCRYPTION_KEY

      echo "Encrypted device: $CRYPT_DEVICE"

      ${lib.optionalString (cfg.usage == "root" || cfg.usage == "mount") ''
        udevadm wait "$CRYPT_DEVICE"

        mkfs.xfs "$CRYPT_DEVICE"

        echo "Created XFS filesystem on $CRYPT_DEVICE"
      ''}
    '';
  };


in
{
  options.services.instance-storage = {
    enable = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = ''
        Whether to automatically set up ephemeral instance storage.

        Combines all instance storage devices via RAID0 into a single encrypted
        device using an ephemeral encryption key. This guarantees that data does
        not persist across reboots and hence replace root volume operations.
      '';
    };

    usage = lib.mkOption {
      type = lib.types.enum [ "root" "mount" "raw"];
      default = "root";
      description = ''
        How to use the ephemeral instance storage device.
        - "root": Mount instance storage directly as root filesystem.
                  Falls back to tmpfs if no instance storage is available.
        - "mount": Provides additional ephemeral storage space.
                   Creates an XFS filesystem and mounts it at /mnt/instance-storage.
        - "raw": Only sets up the encrypted device at /dev/mapper/instance-storage.
                 For custom setups, create a systemd service that depends on the device.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    boot.swraid.enable = true;
    boot.initrd.kernelModules = [
      "nvme" "nvme_core"
      "dm-crypt" "dm-mod"
    ];
    boot.initrd.availableKernelModules = [
      "aes" "cbc"
    ] ++ lib.optionals (cfg.usage == "root" || cfg.usage == "mount") [
      "xfs"
    ];
    boot.initrd.systemd = {
      storePaths = [
        "${pkgs.cryptsetup}/bin/cryptsetup"
        "${prepareInstanceStorage}"
      ] ++ lib.optionals (cfg.usage == "root" || cfg.usage == "mount") [
        "${pkgs.xfsprogs}/bin/mkfs.xfs"
      ];

      services.instance-storage-prepare = {
        description = "Prepare ephemeral instance storage";
        unitConfig.DefaultDependencies = false;
        after = [ "systemd-modules-load.service" ];
        before = [ "initrd-root-fs.target" ];
        wantedBy = [ "initrd-root-fs.target" ];
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
          ExecStart = "${lib.getExe prepareInstanceStorage}";
        };
      };

      services.instance-storage-root-mount = lib.mkIf (cfg.usage == "root") {
        description = "Mount instance storage as root";
        unitConfig = {
          DefaultDependencies = false;
          ConditionPathExists = "/dev/mapper/instance-storage";
        };
        after = [ "instance-storage-prepare.service" ];
        before = [ "sysroot.mount" ];
        wantedBy = [ "initrd-root-fs.target" ];
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
        };
        script = ''
          mkdir -p /sysroot
          mount -t xfs -o discard,noatime /dev/mapper/instance-storage /sysroot

          echo "Instance storage mounted at /sysroot"
        '';
      };

      # Prevent tmpfs fallback from mounting if instance storage is already mounted
      units."sysroot.mount.d/instance-storage.conf" = lib.mkIf (cfg.usage == "root") {
        text = ''
          [Unit]
          ConditionPathIsMountPoint=!/sysroot
        '';
      };

      mounts = lib.optionals (cfg.usage == "mount") [
        {
          where = "/sysroot/mnt/instance-storage";
          what = "/dev/mapper/instance-storage";
          type = "xfs";
          options = "discard,noatime";
          after = [ "initrd-root-fs.target" ];
          before = [ "initrd-switch-root.target" ];
          wantedBy = [ "initrd-switch-root.target" ];
          unitConfig = {
            DefaultDependencies = false;
          };
        }
      ];
    };
  };
}
