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
      awscli2
      nitrotpm-tools
      pythonEnv
    ];

    text = ''
      set -euo pipefail

      usage() {
        echo "Usage: sign-efi-image <image-dir> <keys-dir> [--db-key-arn <ARN>] [> tpm_pcr.json]" >&2
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
        echo "  keys-dir   Directory with db.crt, PK.esl, KEK.esl, db.esl" >&2
        echo "             (and db.key unless --db-key-arn is used)" >&2
        echo "" >&2
        echo "Options:" >&2
        echo "  --db-key-arn <ARN>  Fetch the db signing key (PEM) from AWS" >&2
        echo "             Secrets Manager and stream it straight into sbsign" >&2
        echo "             via an in-memory fd. The private key is never" >&2
        echo "             written to disk; no db.key file is read from" >&2
        echo "             keys-dir. Without this flag, keys-dir/db.key is" >&2
        echo "             used as before." >&2
        echo "" >&2
        echo "Outputs (written to image-dir):" >&2
        echo "  signed.efi      The signed UKI" >&2
        echo "  uefi_data.aws   UEFI variable store for AMI registration" >&2
        echo "" >&2
        echo "The computed PCR JSON is printed to stdout; redirect it to a" >&2
        echo "file, e.g. 'sign-efi-image <image-dir> <keys-dir> > tpm_pcr.json'." >&2
      }

      # Fetch a Secrets Manager secret's plaintext to stdout, for use inside a
      # process substitution (see the signing block below). Fails loudly (and,
      # under set -o pipefail, aborts the caller) if the secret is missing or
      # empty, so an unreadable ARN can't silently feed empty input downstream.
      fetch_secret() {
        local arn="$1" value
        if ! value=$(aws secretsmanager get-secret-value \
              --secret-id "$arn" --query SecretString --output text); then
          echo "Error: failed to retrieve secret from Secrets Manager ($arn)" >&2
          return 1
        fi
        if [ -z "$value" ]; then
          echo "Error: secret from Secrets Manager is empty ($arn)" >&2
          return 1
        fi
        printf '%s' "$value"
      }

      if [ "$#" -lt 2 ]; then
        usage
        exit 1
      fi

      IMAGE_DIR="$1"
      KEYS_DIR="$2"
      shift 2
      EFI_NAME="${efiFileName}"

      # Optional: fetch db.key from Secrets Manager instead of reading a file.
      DB_KEY_ARN=""
      while [ "$#" -gt 0 ]; do
        case "$1" in
          --db-key-arn)
            if [ "$#" -lt 2 ]; then
              echo "Error: --db-key-arn requires an ARN argument" >&2
              exit 1
            fi
            DB_KEY_ARN="$2"
            shift 2
            ;;
          *)
            echo "Error: unknown argument '$1'" >&2
            usage
            exit 1
            ;;
        esac
      done

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

      # db.key is only required as a file when not fetching it from Secrets
      # Manager. db.crt + the ESLs are public and always come from keys-dir.
      REQUIRED_KEY_FILES="db.crt PK.esl KEK.esl db.esl"
      if [ -z "$DB_KEY_ARN" ]; then
        REQUIRED_KEY_FILES="db.key $REQUIRED_KEY_FILES"
      fi
      for f in $REQUIRED_KEY_FILES; do
        if [ ! -f "$KEYS_DIR/$f" ]; then
          echo "Error: required key file '$f' not found in $KEYS_DIR" >&2
          exit 1
        fi
      done

      WORK_DIR=$(mktemp -d)
      trap 'rm -rf "$WORK_DIR"' EXIT INT TERM

      # Every intermediate tool has its stdout redirected to stderr so that
      # only the final PCR JSON reaches stdout (the caller redirects it into
      # tpm_pcr.json). Tools like sbverify print "Signature verification OK"
      # on stdout, which would otherwise corrupt the JSON.
      if [ -n "$DB_KEY_ARN" ]; then
        # Stream the signing key straight from Secrets Manager into sbsign via a
        # process-substitution fd. fetch_secret writes the PEM to the fd's pipe;
        # it is never held in a shell variable or written to a file, so it never
        # touches disk (PR #18 r3513902421). sbsign reads the key through
        # OpenSSL's PEM BIO, which is happy with a non-seekable fd.
        echo "Fetching db signing key from Secrets Manager and signing UKI (no disk)..." >&2
        sbsign --key <(fetch_secret "$DB_KEY_ARN") \
               --cert "$KEYS_DIR/db.crt" \
               --output "$WORK_DIR/$EFI_NAME" \
               "$IMAGE_DIR/unsigned.efi" >&2
      else
        echo "Signing UKI with db.key..." >&2
        sbsign --key "$KEYS_DIR/db.key" \
               --cert "$KEYS_DIR/db.crt" \
               --output "$WORK_DIR/$EFI_NAME" \
               "$IMAGE_DIR/unsigned.efi" >&2
      fi

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

      # Patch the signed UKI into the ESP partition of the raw image (the
      # caller must supply a writable copy — result/ is a read-only symlink).
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
