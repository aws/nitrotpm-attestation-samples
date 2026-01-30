{
  pkgs,
  ...
}:
{
  kms-decrypt-app = pkgs.nitrotpm-tools.overrideAttrs (oldAttrs: {
    pname = "nitrotpm-tools-kms-decrypt";

    buildPhase = ''
      runHook preBuild
      cargo build --release --example nitro-tpm-kms-decrypt
      runHook postBuild
    '';

    installPhase = ''
      runHook preInstall
      mkdir -p $out/bin
      install -D -m755 target/release/examples/nitro-tpm-kms-decrypt $out/bin/
      runHook postInstall
    '';
  });
}
