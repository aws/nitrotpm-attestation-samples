{ pkgs, lib, stdenv, system }:

let
  python-uefivars = pkgs.fetchFromGitHub {
    owner = "awslabs";
    repo = "python-uefivars";
    rev = "main";
    sha256 = "sha256-HzaKFyKMqEADPvydCdD29P9nC7Qwq/UYvgZYCx4oEhw=";
  };

  pythonEnv = pkgs.python3.withPackages (ps: with ps; [ google-crc32c ]);

  script = pkgs.writeShellScript "generate-uefi-vars" ''
    if [ "$#" -lt 4 ]; then
      echo "Usage: generate-uefi-vars -P <PK.esl> -K <KEK.esl> --db <db.esl> -O <output.aws>"
      exit 1
    fi
    ${pythonEnv}/bin/python3 ${python-uefivars}/uefivars -i none -o aws "$@"
  '';
in
{
  type = "app";
  program = "${script}";
}
