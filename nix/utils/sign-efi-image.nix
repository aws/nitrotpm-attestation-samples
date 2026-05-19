{ pkgs, lib, stdenv, system }:

let
  python-uefivars = pkgs.fetchFromGitHub {
    owner = "awslabs";
    repo = "python-uefivars";
    rev = "main";
    sha256 = "sha256-HzaKFyKMqEADPvydCdD29P9nC7Qwq/UYvgZYCx4oEhw=";
  };

  pythonEnv = pkgs.python3.withPackages (ps: with ps; [ google-crc32c ]);

  nixArch = builtins.head (builtins.split "-" system);
  efiFileName = "BOOT${if nixArch == "aarch64" then "aa64" else "x64"}.EFI";

  script = pkgs.writeShellApplication {
    name = "sign-efi-image";
    runtimeInputs = with pkgs; [
      sbsigntool
      efitools
      mtools
      util-linux
      jq
      pythonEnv
    ];

    text = ''
      set -euo pipefail

      if [ "$#" -lt 2 ]; then
        echo "Usage: sign-efi-image <image-dir> <keys-dir>"
        echo ""
        echo "Signs the unsigned UKI in <image-dir>, builds the UEFI variable"
        echo "store from the secure boot key hierarchy in <keys-dir>, and"
        echo "patches the signed UKI into the raw image's ESP partition."
        echo ""
        echo "Keys are read from file paths (not nix store inputs), so private"
        echo "key material never lands in /nix/store/."
        echo ""
        echo "Arguments:"
        echo "  image-dir  Output of 'nix build .#raw-image' (contains"
        echo "             unsigned.efi, *.raw, repart-output.json)"
        echo "  keys-dir   Directory with db.key, db.crt, PK.esl, KEK.esl,"
        echo "             db.esl"
        echo ""
        echo "Outputs (written to image-dir):"
        echo "  signed.efi      The signed UKI"
        echo "  uefi_data.aws   UEFI variable store for AMI registration"
        exit 1
      fi

      IMAGE_DIR="$1"
      KEYS_DIR="$2"
      EFI_NAME="${efiFileName}"

      if [ ! -d "$IMAGE_DIR" ]; then
        echo "Error: image-dir '$IMAGE_DIR' not found" >&2
        exit 1
      fi

      if [ ! -f "$IMAGE_DIR/unsigned.efi" ]; then
        echo "Error: required file 'unsigned.efi' not found in $IMAGE_DIR" >&2
        exit 1
      fi

      RAW_IMAGE=$(find "$IMAGE_DIR" -maxdepth 1 -name '*.raw' | head -1)
      if [ -z "$RAW_IMAGE" ]; then
        echo "Error: no .raw disk image found in $IMAGE_DIR" >&2
        exit 1
      fi

      if [ ! -f "$IMAGE_DIR/repart-output.json" ]; then
        echo "Error: repart-output.json not found in $IMAGE_DIR" >&2
        exit 1
      fi

      for f in db.key db.crt PK.esl KEK.esl db.esl; do
        if [ ! -f "$KEYS_DIR/$f" ]; then
          echo "Error: required key file '$f' not found in $KEYS_DIR" >&2
          exit 1
        fi
      done

      WORK_DIR=$(mktemp -d)
      trap 'rm -rf "$WORK_DIR"' EXIT INT TERM

      echo "Signing UKI with db.key..."
      sbsign --key "$KEYS_DIR/db.key" \
             --cert "$KEYS_DIR/db.crt" \
             --output "$WORK_DIR/$EFI_NAME" \
             "$IMAGE_DIR/unsigned.efi"

      echo "Verifying signature..."
      sbverify --cert "$KEYS_DIR/db.crt" "$WORK_DIR/$EFI_NAME"

      echo "Generating UEFI variable store..."
      python3 ${python-uefivars}/uefivars \
        -i none \
        -o aws \
        -O "$WORK_DIR/uefi_data.aws" \
        -P "$KEYS_DIR/PK.esl" \
        -K "$KEYS_DIR/KEK.esl" \
        --db "$KEYS_DIR/db.esl"

      # Patch the signed UKI into the ESP partition of the raw image. The
      # caller is expected to have placed a writable copy of the raw image
      # into IMAGE_DIR (the original from result/ is a read-only nix store
      # symlink).
      if [ ! -w "$RAW_IMAGE" ]; then
        echo "Error: raw image '$RAW_IMAGE' is not writable. Copy it to a"
        echo "       writable location before invoking sign-efi-image." >&2
        exit 1
      fi

      echo "Locating ESP partition offset..."
      ESP_OFFSET=$(jq -r '.[] | select(.type == "esp") | .offset' "$IMAGE_DIR/repart-output.json")
      ESP_SIZE=$(jq -r '.[] | select(.type == "esp") | .raw_size' "$IMAGE_DIR/repart-output.json")

      if [ -z "$ESP_OFFSET" ] || [ "$ESP_OFFSET" = "null" ]; then
        echo "Error: could not locate ESP partition offset in repart-output.json" >&2
        exit 1
      fi

      SIGNED_SIZE=$(stat -c '%s' "$WORK_DIR/$EFI_NAME")
      if [ "$SIGNED_SIZE" -gt "$ESP_SIZE" ]; then
        echo "Error: signed UKI ($SIGNED_SIZE bytes) exceeds ESP partition size ($ESP_SIZE bytes)" >&2
        exit 1
      fi

      echo "Patching signed UKI into ESP at offset $ESP_OFFSET..."
      mcopy -D o -i "$RAW_IMAGE@@$ESP_OFFSET" \
        "$WORK_DIR/$EFI_NAME" "::/EFI/BOOT/$EFI_NAME"

      cp "$WORK_DIR/$EFI_NAME" "$IMAGE_DIR/signed.efi"
      cp "$WORK_DIR/uefi_data.aws" "$IMAGE_DIR/uefi_data.aws"

      echo ""
      echo "Done."
      echo "  Patched raw image: $RAW_IMAGE"
      echo "  Signed UKI:        $IMAGE_DIR/signed.efi"
      echo "  UEFI var store:    $IMAGE_DIR/uefi_data.aws"
    '';
  };
in
{
  type = "app";
  program = "${script}/bin/sign-efi-image";
}
