{ pkgs }:

# Shared python-uefivars tool, pinned once here and reused by both
# generate-uefi-vars.nix (the standalone app) and sign-efi-image.nix (which
# builds the UEFI variable store as part of signing). Keeping a single pinned
# source avoids the two copies drifting apart.
let
  # Pinned to an immutable commit (not a moving branch ref) for reproducibility.
  src = pkgs.fetchFromGitHub {
    owner = "awslabs";
    repo = "python-uefivars";
    rev = "60b9542eb1e8c2a8e874dcc6f46c1713f33829c5";
    sha256 = "sha256-HzaKFyKMqEADPvydCdD29P9nC7Qwq/UYvgZYCx4oEhw=";
  };

  pythonEnv = pkgs.python3.withPackages (ps: with ps; [ google-crc32c ]);
in
{
  runtimeInputs = [ pythonEnv ];

  # A ready-to-run wrapper: `uefivars <args...>` passes straight through to
  # python-uefivars with the "-i none -o aws" input/output modes this repo uses.
  wrapper = pkgs.writeShellScript "uefivars" ''
    ${pythonEnv}/bin/python3 ${src}/uefivars -i none -o aws "$@"
  '';
}
