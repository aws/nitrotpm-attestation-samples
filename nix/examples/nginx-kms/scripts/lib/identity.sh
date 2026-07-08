#!/bin/bash
#
# Secure boot golden-identity helpers. Functions only, no top-level logic.

# Generate the golden identity in memory and emit it as a single JSON object on
# stdout: {guid, db_key, db_crt, pk_crt, kek_crt}. No private key touches disk:
# PK/KEK keys are discarded via `-keyout /dev/null`, and db.key stays in a shell
# variable. jq assembles the JSON inside the nix shell so the multi-line PEMs
# survive the process boundary.
generate_identity_material() {
  nix --extra-experimental-features nix-command --extra-experimental-features flakes shell \
    nixpkgs#openssl nixpkgs#util-linux nixpkgs#jq --command bash -c '
    set -euo pipefail
    guid=$(uuidgen --random)
    pk_crt=$(openssl req -newkey rsa:4096 -nodes -keyout /dev/null -new -x509 -sha256 -days 3650 -subj "/CN=Platform key/" 2>/dev/null)
    kek_crt=$(openssl req -newkey rsa:4096 -nodes -keyout /dev/null -new -x509 -sha256 -days 3650 -subj "/CN=Key Exchange Key/" 2>/dev/null)
    db_key=$(openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 2>/dev/null)
    db_crt=$(printf "%s" "$db_key" | openssl req -new -x509 -sha256 -days 3650 -subj "/CN=Signature Database key/" -key /dev/stdin 2>/dev/null)
    jq -n --arg guid "$guid" --arg db_key "$db_key" --arg db_crt "$db_crt" \
          --arg pk_crt "$pk_crt" --arg kek_crt "$kek_crt" \
          "{guid: \$guid, db_key: \$db_key, db_crt: \$db_crt, pk_crt: \$pk_crt, kek_crt: \$kek_crt}"
  '
}
