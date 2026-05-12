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
                # Compute baseline TPM PCR values (PCR4 UKI measurement)
                ${pkgs.nitrotpm-tools}/bin/nitro-tpm-pcr-compute --image ${originalEfiPath} > $out/tpm_pcr.json

                # Export the unsigned UKI for downstream signing
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
