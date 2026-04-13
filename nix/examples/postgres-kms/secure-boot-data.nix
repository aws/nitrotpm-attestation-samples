{ pkgs, lib, stdenv }:

# WARNING: This secure boot data generation is NOT reproducible!
# Keys are generated at build time, resulting in different measurements for each build.
# In production, use consistent pre-generated key material for reproducible builds.
#
# This module generates a complete secure boot key hierarchy and provides the db key and certificate for EFI binary signing:
# - Platform Key (PK): Root of trust, signs KEK updates
# - Key Exchange Key (KEK): Signs signature database updates
# - Signature Database (db): Contains keys that can sign bootloaders/kernels

let
  python-uefivars = pkgs.fetchFromGitHub {
    owner = "awslabs";
    repo = "python-uefivars";
    rev = "main";
    sha256 = "sha256-HzaKFyKMqEADPvydCdD29P9nC7Qwq/UYvgZYCx4oEhw=";
  };

  pythonEnv = pkgs.python3.withPackages (ps: with ps; [
    google-crc32c
  ]);

  secureBootKeys = pkgs.runCommand "secure-boot-keys" {
    nativeBuildInputs = [
      pkgs.openssl
      pkgs.util-linux
      pkgs.efitools
    ];
  } ''
    mkdir -p $out

    echo "INFO: Generate a GUID"
    uuidgen --random > GUID.txt

    echo "INFO: Create the platform key (PK)"
    openssl req -newkey rsa:4096 -nodes -keyout PK.key -new -x509 -sha256 -days 3650 -subj "/CN=Platform key/" -out PK.crt
    openssl x509 -outform DER -in PK.crt -out PK.cer
    cert-to-efi-sig-list -g "$(< GUID.txt)" PK.crt PK.esl
    sign-efi-sig-list -g "$(< GUID.txt)" -k PK.key -c PK.crt PK PK.esl PK.auth

    echo "INFO: Create the key exchange key (KEK)"
    openssl req -newkey rsa:4096 -nodes -keyout KEK.key -new -x509 -sha256 -days 3650 -subj "/CN=Key Exchange Key/" -out KEK.crt
    openssl x509 -outform DER -in KEK.crt -out KEK.cer
    cert-to-efi-sig-list -g "$(< GUID.txt)" KEK.crt KEK.esl
    sign-efi-sig-list -g "$(< GUID.txt)" -k PK.key -c PK.crt KEK KEK.esl KEK.auth

    echo "INFO: Create the signature database (db)"
    openssl req -newkey rsa:4096 -nodes -keyout db.key -new -x509 -sha256 -days 3650 -subj "/CN=Signature Database key/" -out db.crt
    openssl x509 -outform DER -in db.crt -out db.cer
    cert-to-efi-sig-list -g "$(< GUID.txt)" db.crt db.esl
    sign-efi-sig-list -g "$(< GUID.txt)" -k KEK.key -c KEK.crt db db.esl db.auth

    cp db.key db.crt *.esl $out/
  '';

  uefiVarStore = pkgs.runCommand "uefi-var-store" {
    nativeBuildInputs = [ pythonEnv ];
  } ''
    mkdir -p $out

    python ${python-uefivars}/uefivars -i none -o aws -O "$out/uefi_data.aws" \
        -P ${secureBootKeys}/PK.esl \
        -K ${secureBootKeys}/KEK.esl \
        --db ${secureBootKeys}/db.esl
  '';

in
pkgs.runCommand "secure-boot-data" {} ''
  mkdir -p $out

  cp ${secureBootKeys}/db.key ${secureBootKeys}/db.crt ${secureBootKeys}/*.esl $out/
'' // {
  inherit uefiVarStore;
}
