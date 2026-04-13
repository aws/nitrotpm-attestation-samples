{
  pkgs,
  ...
}:
pkgs.writeScript "cert-init.sh" ''
  #!${pkgs.bash}/bin/bash
  set -euo pipefail

  # Fetch IMDSv2 token
  TOKEN=$(${pkgs.curl}/bin/curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")

  # Fetch user data from EC2 metadata service using IMDSv2
  USER_DATA=$(${pkgs.curl}/bin/curl -H "X-aws-ec2-metadata-token: $TOKEN" -s http://169.254.169.254/latest/user-data)

  # Extract the encrypted server certificate bundle from user data
  SERVER_CERT_BUNDLE=$(echo "$USER_DATA" | ${pkgs.jq}/bin/jq -r .server_cert_bundle)

  # Base64-decode and decrypt the server certificate bundle using the symmetric key
  echo "$SERVER_CERT_BUNDLE" | ${pkgs.coreutils}/bin/base64 -d \
    | ${pkgs.openssl}/bin/openssl enc -d -aes-256-cbc -pbkdf2 -pass file:/run/kms-init/symmetric_key \
    | ${pkgs.gnutar}/bin/tar xf - -C /run/postgresql-certs/

  # Set directory ownership so postgres user can traverse it via group
  ${pkgs.coreutils}/bin/chown root:postgres /run/postgresql-certs

  # Set ownership and permissions on the extracted certificate files
  ${pkgs.coreutils}/bin/chown postgres:postgres /run/postgresql-certs/ca.crt /run/postgresql-certs/server.crt /run/postgresql-certs/server.key
  ${pkgs.coreutils}/bin/chmod 0640 /run/postgresql-certs/ca.crt /run/postgresql-certs/server.crt
  ${pkgs.coreutils}/bin/chmod 0600 /run/postgresql-certs/server.key
''
