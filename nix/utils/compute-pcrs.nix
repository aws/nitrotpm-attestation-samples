{ pkgs, lib, stdenv, system }:

let
  script = pkgs.writeShellApplication {
    name = "compute-pcrs";
    runtimeInputs = with pkgs; [
      nitrotpm-tools
    ];

    text = ''
      if [ "$#" -lt 1 ]; then
        echo "Usage: compute-pcrs <efi-image> [--PK <PK.esl>] [--KEK <KEK.esl>] [--db <db.esl>] [--dbx <dbx.esl>] [-o <output.json>]"
        echo ""
        echo "Computes TPM PCR values for the given EFI image."
        echo "When secure boot ESL files are provided, PCR7 measurements are included."
        echo ""
        echo "Arguments:"
        echo "  efi-image     Path to the EFI binary (signed or unsigned)"
        echo "  --PK          Path to Platform Key EFI Signature List"
        echo "  --KEK         Path to Key Exchange Key EFI Signature List"
        echo "  --db          Path to Signature Database EFI Signature List"
        echo "  --dbx         Path to Forbidden Signatures EFI Signature List"
        echo "  -o            Output file path (default: stdout)"
        exit 1
      fi

      EFI_IMAGE="$1"
      shift

      if [ ! -f "$EFI_IMAGE" ]; then
        echo "Error: EFI image '$EFI_IMAGE' not found" >&2
        exit 1
      fi

      OUTPUT=""
      PCR_ARGS=()

      while [ $# -gt 0 ]; do
        case "$1" in
          --PK|--KEK|--db|--dbx)
            if [ -z "''${2:-}" ] || [ ! -f "''${2:-}" ]; then
              echo "Error: File for $1 not found: ''${2:-}" >&2
              exit 1
            fi
            PCR_ARGS+=("$1" "$2")
            shift 2
            ;;
          -o)
            OUTPUT="''${2:-}"
            shift 2
            ;;
          *)
            echo "Error: Unknown argument: $1" >&2
            exit 1
            ;;
        esac
      done

      if [ -n "$OUTPUT" ]; then
        nitro-tpm-pcr-compute --image "$EFI_IMAGE" "''${PCR_ARGS[@]}" > "$OUTPUT"
        echo "PCR values written to: $OUTPUT" >&2
      else
        nitro-tpm-pcr-compute --image "$EFI_IMAGE" "''${PCR_ARGS[@]}"
      fi
    '';
  };
in
{
  type = "app";
  program = "${script}/bin/compute-pcrs";
}
