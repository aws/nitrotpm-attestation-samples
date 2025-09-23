{
  pkgs,
  craneLib,
  ...
}:
let
    src = builtins.fetchGit {
        url = "ssh://git.amazon.com:2222/pkg/Aws-nitro-tpm-tools";
        rev = "a5ab37290be13785daf15734c36123779ecdc369";
        ref = "mainline";
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
