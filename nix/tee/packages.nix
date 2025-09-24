{
  pkgs,
  craneLib,
  ...
}:
let
    src = builtins.fetchGit {
        url = "https://github.com/aws/NitroTPM-Tools.git";
        ref = "main";
    };

    cargoArtifacts = craneLib.buildDepsOnly {
        inherit src;
        pname = "nitro-tpm-tools";
        version = "0.0.1";
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
        version = "0.0.1";

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
