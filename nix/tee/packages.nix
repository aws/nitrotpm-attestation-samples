{
  pkgs,
  craneLib,
  ...
}:
let
    src = builtins.fetchGit {
        url = "https://github.com/aws/NitroTPM-Tools.git";
        rev = "50f0fb58a306ee89c7994183cbce3bf4f3331207";
    };

    cargoArtifacts = craneLib.buildDepsOnly {
        inherit src;
        pname = "nitro-tpm-tools";
        version = "1.0.0";
        strictDeps = true;
        doCheck = false;

        nativeBuildInputs = [
            pkgs.pkg-config
        ];
        buildInputs = [
            pkgs.tpm2-tss
        ];
    };
in {
    # Application for decrypting KMS secrets with a help of attestation document
    kms-decrypt-app = craneLib.buildPackage {
        inherit cargoArtifacts src;
        pname = "kms-decrypt-app";
        version = "1.0.0";

        cargoExtraArgs = "--example nitro-tpm-kms-decrypt";
        strictDeps = true;
        doCheck = false;

        nativeBuildInputs = [
            pkgs.pkg-config
        ];
        buildInputs = [
            pkgs.tpm2-tss
            pkgs.openssl
        ];
    };
}
