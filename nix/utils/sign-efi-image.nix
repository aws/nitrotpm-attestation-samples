{ pkgs, lib, stdenv, system }:

let
  script = pkgs.writeShellApplication {
    name = "sign-efi-image";
    runtimeInputs = with pkgs; [
      sbsigntool
    ];

    text = ''
      if [ "$#" -lt 3 ]; then
        echo "Usage: sign-efi-image <unsigned-efi> <db.key> <db.crt> [output-path]"
        echo ""
        echo "Signs an EFI binary with the provided secure boot db key and certificate."
        echo "The key and certificate must be provided as file paths (NOT in the nix store)."
        echo ""
        echo "Arguments:"
        echo "  unsigned-efi  Path to the unsigned EFI binary (e.g. result/unsigned.efi)"
        echo "  db.key        Path to the secure boot signing private key"
        echo "  db.crt        Path to the secure boot signing certificate"
        echo "  output-path   Optional output path (default: signed.efi in current directory)"
        exit 1
      fi

      UNSIGNED_EFI="$1"
      DB_KEY="$2"
      DB_CRT="$3"
      OUTPUT="''${4:-./signed.efi}"

      if [ ! -f "$UNSIGNED_EFI" ]; then
        echo "Error: Unsigned EFI file '$UNSIGNED_EFI' not found"
        exit 1
      fi

      if [ ! -f "$DB_KEY" ]; then
        echo "Error: Signing key '$DB_KEY' not found"
        exit 1
      fi

      if [ ! -f "$DB_CRT" ]; then
        echo "Error: Signing certificate '$DB_CRT' not found"
        exit 1
      fi

      echo "Signing EFI binary..."
      sbsign --key "$DB_KEY" \
             --cert "$DB_CRT" \
             --output "$OUTPUT" \
             "$UNSIGNED_EFI"

      echo "Verifying signature..."
      sbverify --cert "$DB_CRT" "$OUTPUT"

      echo "Done. Signed EFI written to: $OUTPUT"
    '';
  };
in
{
  type = "app";
  program = "${script}/bin/sign-efi-image";
}
