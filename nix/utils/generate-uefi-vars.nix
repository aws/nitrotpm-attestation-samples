{ pkgs, lib, stdenv, system }:

let
  uefivars = pkgs.callPackage ./uefivars.nix { };

  script = pkgs.writeShellScript "generate-uefi-vars" ''
    if [ "$#" -lt 4 ]; then
      echo "Usage: generate-uefi-vars -P <PK.esl> -K <KEK.esl> --db <db.esl> -O <output.aws>"
      exit 1
    fi
    ${uefivars.wrapper} "$@"
  '';
in
{
  type = "app";
  program = "${script}";
}
