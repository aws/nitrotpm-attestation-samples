{
  pkgs,
  ...
}:
pkgs.writeScript "cert-init.sh" ''
  #!${pkgs.bash}/bin/bash
  set -euo pipefail

  USER_DATA=$(${pkgs.coreutils}/bin/cat /run/kms-init/user_data.json)
  SERVER_CERT_BUNDLE=$(echo "$USER_DATA" | ${pkgs.jq}/bin/jq -re .server_cert_bundle)

  CERTS_DIR=/run/postgresql-certs

  # Extract only the three expected members so a forged bundle can't inject extra files; perms fixup in cert-init-perms.service.
  echo "$SERVER_CERT_BUNDLE" | ${pkgs.coreutils}/bin/base64 -d \
    | ${pkgs.openssl}/bin/openssl enc -d -aes-256-cbc -pbkdf2 -pass file:/run/kms-init/symmetric_key \
    | ${pkgs.gnutar}/bin/tar xf - -C "$CERTS_DIR/" --no-wildcards ca.crt server.crt server.key

  # Re-emit as canonical PEM: openssl skips leading garbage, so re-parsing strips ELF/PEM-polyglot prefixes and fails closed on non-PEM input.
  reemit() {
    local f="$CERTS_DIR/$1"; shift
    "$@" -in "$f" -out "$f.tmp"
    ${pkgs.coreutils}/bin/mv -f "$f.tmp" "$f"
  }
  reemit ca.crt     ${pkgs.openssl}/bin/openssl x509
  reemit server.crt ${pkgs.openssl}/bin/openssl x509
  reemit server.key ${pkgs.openssl}/bin/openssl pkey
''
