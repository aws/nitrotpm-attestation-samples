{
  pkgs,
  lib,
  system,
  nixos-generators,
  tee-pkgs,
  userConfig ? { },
  isDebug ? false,
  secureBootData ? null,
  ...
}:
let

    # Sign EFI binary with secure boot keys if secureBootData is provided
    sign-efi = efiPath:
        if secureBootData != null then
            pkgs.runCommand "signed-efi" {
                nativeBuildInputs = [ pkgs.sbsigntool ];
            } ''
                mkdir -p $out

                # Verify required secure boot files exist
                if [ ! -f "${secureBootData}/db.key" ]; then
                    echo "ERROR: Secure boot signing key not found: ${secureBootData}/db.key"
                    exit 1
                fi
                if [ ! -f "${secureBootData}/db.crt" ]; then
                    echo "ERROR: Secure boot certificate not found: ${secureBootData}/db.crt"
                    exit 1
                fi

                # Sign the EFI binary using the signature database (db) key
                sbsign --key ${secureBootData}/db.key \
                       --cert ${secureBootData}/db.crt \
                       --output $out/signed.efi \
                       ${efiPath}
            ''
        else null;

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
            signedEfiDrv = sign-efi originalEfiPath;
            finalEfiPath = if signedEfiDrv != null then "${signedEfiDrv}/signed.efi" else originalEfiPath;
        in {
            finalPartitions = lib.recursiveUpdate oldAttrs.finalPartitions {
                "00-esp".contents = {
                    "${ukiPath}".source = finalEfiPath;
                };
            };

            postInstall = let
                # Build secure boot arguments for PCR7 computation
                secureBootArgs = lib.optionals (secureBootData != null) (
                    lib.optional (builtins.pathExists "${secureBootData}/PK.esl") "--PK ${secureBootData}/PK.esl" ++
                    lib.optional (builtins.pathExists "${secureBootData}/KEK.esl") "--KEK ${secureBootData}/KEK.esl" ++
                    lib.optional (builtins.pathExists "${secureBootData}/db.esl") "--db ${secureBootData}/db.esl" ++
                    lib.optional (builtins.pathExists "${secureBootData}/dbx.esl") "--dbx ${secureBootData}/dbx.esl"
                );
            in ''
                # Compute TPM PCR values including secure boot measurements
                ${pkgs.nitrotpm-tools}/bin/nitro-tpm-pcr-compute --image ${finalEfiPath} ${lib.concatStringsSep " " secureBootArgs} > $out/tpm_pcr.json

                ${lib.optionalString (secureBootData != null) ''
                    # Verify the EFI binary signature for secure boot compliance
                    ${pkgs.sbsigntool}/bin/sbverify --cert ${secureBootData}/db.crt "${finalEfiPath}"
                ''}
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
