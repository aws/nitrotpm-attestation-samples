{
  pkgs,
  lib,
  system,
  craneLib,
  nixos-generators,
  tee-pkgs,
  userConfig ? { },
  isDebug ? false,
  ...
}:
let
    # Reuse cargoArtifacts from tee-pkgs to avoid building dependencies twice
    pcr-compute = craneLib.buildPackage {
        cargoArtifacts = tee-pkgs.kms-decrypt-app.cargoArtifacts;
        pname = "nitro-tpm-pcr-compute";
        version = "0.0.1";
        src = builtins.fetchGit {
            url = "git@github.com:aws/NitroTPM-Tools.git";
            rev = "eab69e7a4ebd0f6d5d41ff80882df6292d3e2b38";
            ref = "main";
        };
        cargoExtraArgs = "--package nitro-tpm-pcr-compute";
        strictDeps = true;
        doCheck = false;

        nativeBuildInputs = [
            pkgs.pkg-config
        ];
        buildInputs = [
            pkgs.tpm2-tss
        ];
    };

    tee-config = {
        environment = {
            systemPackages = [
                tee-pkgs.kms-decrypt-app
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
        (oldAttrs: {
            # Compute PCR4 of TPM based on EFI file
            postInstall = ''
                efi_path=${oldAttrs.finalPartitions."00-esp".contents."/EFI/BOOT/${efiFileName}".source}
                ${pcr-compute}/bin/nitro-tpm-pcr-compute --image $efi_path > $out/tpm_pcr.json
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
