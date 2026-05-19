{
  pkgs,
  lib,
  system,
  nixos-generators,
  tee-pkgs,
  userConfig ? { },
  isDebug ? false,
  ...
}:
let

    tee-config = {
        environment = {
            systemPackages = [
                tee-pkgs.kms-decrypt-app
                pkgs.nitrotpm-tools
                # debugging tools
                pkgs.openssl
                pkgs.tpm2-tools
            ];
        };
    };

    # Determine the correct EFI file name based on architecture
    arch = builtins.head (builtins.split "-" system);
    efiFileName = "BOOT${if arch == "aarch64" then "aa64" else "x64"}.EFI";
    ukiPath = "/EFI/BOOT/${efiFileName}";

    # The image builder produces an unsigned image and exports the unsigned UKI
    # plus a baseline tpm_pcr.json (PCR4 only). Secure boot signing happens at
    # runtime via the sign-efi-image flake app so private keys never enter the
    # nix store. See nix/README.md for the full workflow.
    raw-image = (nixos-generators.nixosGenerate {
        inherit system;
        modules = [
            # generic nixos configuration
            ./configuration.nix
            # tee nixos packages and environment
            tee-config
            # user specific nixos config
            userConfig
            {
                _module.args.ukiPath = ukiPath;
                _module.args.espSize = "${if arch == "aarch64" then "128" else "64"}M";
            }
        ] ++ lib.optionals (!isDebug) [ ./asserts.nix ]
          ++ lib.optionals isDebug [ ./debug.nix ];
        customFormats = {"verity" = ./verity.nix;};
        format = "verity";
    }).overrideAttrs
        (oldAttrs: let
            originalEfiPath = oldAttrs.finalPartitions."00-esp".contents."${ukiPath}".source;
        in {
            postInstall = ''
                # Compute baseline TPM PCR values (PCR4 UKI measurement only).
                # PCR7 is explicitly dropped via `jq 'del(.Measurements.PCR7)'`
                # because it cannot be derived without the secure-boot key
                # hierarchy, which is supplied externally to sign-efi-image /
                # compute-pcrs. The `del` filter is idempotent (succeeds
                # whether or not PCR7 is present in the input).
                ${pkgs.nitrotpm-tools}/bin/nitro-tpm-pcr-compute --image ${originalEfiPath} \
                    | ${pkgs.jq}/bin/jq 'del(.Measurements.PCR7)' > $out/tpm_pcr.json

                # Export the unsigned UKI for downstream signing.
                cp ${originalEfiPath} $out/unsigned.efi
            '';
        });
in pkgs.stdenv.mkDerivation {
    name = "tee-uki";
    buildInputs = [
        raw-image
    ];

    buildCommand = ''
        mkdir -p $out
        cp -r ${raw-image}/* $out/
    '';
}
