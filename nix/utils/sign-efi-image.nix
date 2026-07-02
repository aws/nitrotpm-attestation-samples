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
      nitrotpm-tools
      pythonEnv
    ];

    text = ''
      set -euo pipefail

      if [ "$#" -lt 2 ]; then
        echo "Usage: sign-efi-image <image-dir> <keys-dir> [> tpm_pcr.json]" >&2
        echo "" >&2
        echo "Signs the unsigned UKI in <image-dir>, builds the UEFI variable" >&2
        echo "store from the secure boot key hierarchy in <keys-dir>, patches" >&2
        echo "the signed UKI into the raw image's ESP partition, and computes" >&2
        echo "the full TPM PCR set (PCR4 + PCR7) for the signed image." >&2
        echo "" >&2
        echo "Keys are read from file paths (not nix store inputs), so private" >&2
        echo "key material never lands in /nix/store/." >&2
        echo "" >&2
        echo "Arguments:" >&2
        echo "  image-dir  Output of 'nix build .#raw-image' (contains" >&2
        echo "             unsigned.efi, *.raw, repart-output.json)" >&2
        echo "  keys-dir   Directory with db.key, db.crt, PK.esl, KEK.esl," >&2
        echo "             db.esl" >&2
        echo "" >&2
        echo "Outputs (written to image-dir):" >&2
        echo "  signed.efi      The signed UKI" >&2
        echo "  uefi_data.aws   UEFI variable store for AMI registration" >&2
        echo "" >&2
        echo "The computed PCR JSON is printed to stdout; redirect it to a" >&2
        echo "file, e.g. 'sign-efi-image <image-dir> <keys-dir> > tpm_pcr.json'." >&2
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

      # Progress goes to stderr so stdout carries only the PCR JSON, which
      # the caller redirects (e.g. '... > tpm_pcr.json').
      # Every intermediate tool has its stdout redirected to stderr so that
      # only the final PCR JSON reaches stdout (the caller redirects it into
      # tpm_pcr.json). Tools like sbverify print "Signature verification OK"
      # on stdout, which would otherwise corrupt the JSON.
      echo "Signing UKI with db.key..." >&2
      sbsign --key "$KEYS_DIR/db.key" \
             --cert "$KEYS_DIR/db.crt" \
             --output "$WORK_DIR/$EFI_NAME" \
             "$IMAGE_DIR/unsigned.efi" >&2

      echo "Verifying signature..." >&2
      sbverify --cert "$KEYS_DIR/db.crt" "$WORK_DIR/$EFI_NAME" >&2

      echo "Generating UEFI variable store..." >&2
      python3 ${python-uefivars}/uefivars \
        -i none \
        -o aws \
        -O "$WORK_DIR/uefi_data.aws" \
        -P "$KEYS_DIR/PK.esl" \
        -K "$KEYS_DIR/KEK.esl" \
        --db "$KEYS_DIR/db.esl" >&2

      # Patch the signed UKI into the ESP partition of the raw image. The
      # caller is expected to have placed a writable copy of the raw image
      # into IMAGE_DIR (the original from result/ is a read-only nix store
      # symlink).
      if [ ! -w "$RAW_IMAGE" ]; then
        echo "Error: raw image '$RAW_IMAGE' is not writable. Copy it to a" >&2
        echo "       writable location before invoking sign-efi-image." >&2
        exit 1
      fi

      echo "Locating ESP partition offset..." >&2
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

      echo "Patching signed UKI into ESP at offset $ESP_OFFSET..." >&2
      mcopy -D o -i "$RAW_IMAGE@@$ESP_OFFSET" \
        "$WORK_DIR/$EFI_NAME" "::/EFI/BOOT/$EFI_NAME" >&2

      cp "$WORK_DIR/$EFI_NAME" "$IMAGE_DIR/signed.efi"
      cp "$WORK_DIR/uefi_data.aws" "$IMAGE_DIR/uefi_data.aws"

      echo "" >&2
      echo "Done." >&2
      echo "  Patched raw image: $RAW_IMAGE" >&2
      echo "  Signed UKI:        $IMAGE_DIR/signed.efi" >&2
      echo "  UEFI var store:    $IMAGE_DIR/uefi_data.aws" >&2

      # Compute the full PCR set (PCR4 + PCR7) against the signed image and
      # print the JSON to stdout so the caller can capture it via redirection.
      echo "Computing TPM PCR values (PCR4 + PCR7)..." >&2
      nitro-tpm-pcr-compute \
        --image "$IMAGE_DIR/signed.efi" \
        --PK "$KEYS_DIR/PK.esl" \
        --KEK "$KEYS_DIR/KEK.esl" \
        --db "$KEYS_DIR/db.esl"
    '';
  };
in
{
  type = "app";
  program = "${script}/bin/sign-efi-image";
}
