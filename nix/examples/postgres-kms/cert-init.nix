{
  pkgs,
  ...
}:
pkgs.writeScript "cert-init.sh" ''
  #!${pkgs.bash}/bin/bash
  set -euo pipefail

  # kms-init persisted the user-data, so no IMDS access is needed here
  USER_DATA=$(${pkgs.coreutils}/bin/cat /run/kms-init/user_data.json)
  SERVER_CERT_BUNDLE=$(echo "$USER_DATA" | ${pkgs.jq}/bin/jq -re .server_cert_bundle)

  # Base64-decode, decrypt with the symmetric key, and unpack into the certs dir
  echo "$SERVER_CERT_BUNDLE" | ${pkgs.coreutils}/bin/base64 -d \
    | ${pkgs.openssl}/bin/openssl enc -d -aes-256-cbc -pbkdf2 -pass file:/run/kms-init/symmetric_key \
    | ${pkgs.gnutar}/bin/tar xf - -C /run/postgresql-certs/

  # Let the postgres user traverse the dir (via group) and own the cert files
  ${pkgs.coreutils}/bin/chown root:postgres /run/postgresql-certs
  ${pkgs.coreutils}/bin/chown postgres:postgres /run/postgresql-certs/ca.crt /run/postgresql-certs/server.crt /run/postgresql-certs/server.key
  ${pkgs.coreutils}/bin/chmod 0640 /run/postgresql-certs/ca.crt /run/postgresql-certs/server.crt
  ${pkgs.coreutils}/bin/chmod 0600 /run/postgresql-certs/server.key
''
