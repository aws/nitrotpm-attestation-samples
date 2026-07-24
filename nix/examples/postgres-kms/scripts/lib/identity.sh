#!/bin/bash
#
# Shared helpers (functions only) sourced by start.sh and e2e-test.sh.
#
# The xtrace-suppression idiom in the secret-handling helpers is inlined on
# purpose: a bash RETURN trap fires when the installing function returns, so a
# shared `suppress_xtrace` helper would re-enable xtrace immediately in the
# caller and leak key material.

# Validate the Secrets Manager ARN format; exits on mismatch.
validate_secret_arn() {
  local arn="$1"
  if [[ "$arn" != arn:aws:secretsmanager:* ]]; then
    echo "Error: '$arn' is not a valid Secrets Manager ARN. Expected format: arn:aws:secretsmanager:<region>:<account>:secret:<name>" >&2
    exit 1
  fi
}

# The SG only permits the VPC CIDR by default; print the authorize command the
# user must run to allowlist their host on 5432. Never edits the SG. Args: <sg_id>.
print_sg_authorization_notice() {
  local sg_id="$1" my_ip
  my_ip=$(curl -s --max-time 10 https://checkip.amazonaws.com | tr -d '[:space:]')
  echo ""
  echo "=== ACTION REQUIRED: authorize your host on the DB security group ==="
  echo "Security Group: ${sg_id:-<unknown>}"
  echo "PostgreSQL listens on the instance's PUBLIC IP:5432, but the SG only"
  echo "allows the VPC CIDR by default. Add the public IP of the host that will"
  echo "connect (mTLS client) before it can reach 5432:"
  echo ""
  if [ -n "$my_ip" ]; then
    echo "  Your public IP: $my_ip  (from https://checkip.amazonaws.com)"
    echo "  aws ec2 authorize-security-group-ingress \\"
    echo "    --group-id ${sg_id:-<SG_ID>} --protocol tcp --port 5432 \\"
    echo "    --cidr ${my_ip}/32"
  else
    echo "  (could not auto-detect your public IP via checkip.amazonaws.com)"
    echo "  aws ec2 authorize-security-group-ingress \\"
    echo "    --group-id ${sg_id:-<SG_ID>} --protocol tcp --port 5432 \\"
    echo "    --cidr <YOUR_PUBLIC_IP>/32"
  fi
  echo "===================================================================="
  echo ""
}

# Atomically persist KEY=VALUE into $RESOURCES_FILE (caller's global).
update_resource() {
  local KEY=$1
  local VALUE=$2
  local tmp
  tmp=$(mktemp "${RESOURCES_FILE}.XXXXXX")
  jq --arg key "$KEY" --arg value "$VALUE" '.[$key] = $value' "$RESOURCES_FILE" > "$tmp" && mv "$tmp" "$RESOURCES_FILE" || rm -f "$tmp"
}

# Echo the dir holding the tpm_pcr.json to bind the KMS key policy to:
# signed-image/ (PCR4+PCR7) when secure boot is active, else result/ (PCR4).
# Args: <project_dir> <secure_boot_flag>.
resolve_pcr_dir() {
  local project_dir="$1" secure_boot_flag="$2"
  if [ -n "$secure_boot_flag" ] && [ -f "$project_dir/signed-image/tpm_pcr.json" ]; then
    echo "$project_dir/signed-image"
  else
    echo "$project_dir/result"
  fi
}

# Generate the golden identity in memory and emit it as JSON on stdout:
# {guid, db_key, db_crt, pk_crt, kek_crt}. No private key touches disk.
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

# Generate an ephemeral secure boot key hierarchy (PK, KEK, db + ESLs) into
# <key_dir> and build the UEFI var store. Non-reproducible: PCR7 changes each
# run. Args: <key_dir> <project_dir>.
generate_local_sb_keys() {
  local key_dir="$1" project_dir="$2"

  rm -rf "$key_dir"
  mkdir -p "$key_dir"

  nix --extra-experimental-features nix-command --extra-experimental-features flakes shell \
    nixpkgs#openssl nixpkgs#efitools nixpkgs#util-linux --command bash -c "
    set -euo pipefail
    cd '$key_dir'

    uuidgen --random > GUID.txt

    openssl req -newkey rsa:4096 -nodes -keyout PK.key -new -x509 -sha256 -days 3650 -subj '/CN=Platform key/' -out PK.crt 2>/dev/null
    cert-to-efi-sig-list -g \"\$(cat GUID.txt)\" PK.crt PK.esl
    sign-efi-sig-list -g \"\$(cat GUID.txt)\" -k PK.key -c PK.crt PK PK.esl PK.auth

    openssl req -newkey rsa:4096 -nodes -keyout KEK.key -new -x509 -sha256 -days 3650 -subj '/CN=Key Exchange Key/' -out KEK.crt 2>/dev/null
    cert-to-efi-sig-list -g \"\$(cat GUID.txt)\" KEK.crt KEK.esl
    sign-efi-sig-list -g \"\$(cat GUID.txt)\" -k PK.key -c PK.crt KEK KEK.esl KEK.auth

    openssl req -newkey rsa:4096 -nodes -keyout db.key -new -x509 -sha256 -days 3650 -subj '/CN=Signature Database key/' -out db.crt 2>/dev/null
    cert-to-efi-sig-list -g \"\$(cat GUID.txt)\" db.crt db.esl
    sign-efi-sig-list -g \"\$(cat GUID.txt)\" -k KEK.key -c KEK.crt db db.esl db.auth
  " || return 1

  ( cd "$project_dir" && \
    nix --extra-experimental-features nix-command --extra-experimental-features flakes run .#generate-uefi-vars -- \
      -P "$key_dir/PK.esl" \
      -K "$key_dir/KEK.esl" \
      --db "$key_dir/db.esl" \
      -O "$key_dir/uefi_data.aws" ) || return 1

  chmod 0600 "$key_dir/PK.key" "$key_dir/KEK.key" "$key_dir/db.key"
}

# Create a Secrets Manager secret from a file path (typically a process
# substitution so the value never hits disk). Prints the ARN. Args: <name> <src-path>.
upload_secret() {
  local name="$1" src="$2"
  aws secretsmanager create-secret \
    --name "$name" \
    --secret-string "file://$src" \
    --query 'ARN' --output text
}

# Generate a fresh golden identity in memory and upload it as a single JSON
# secret. Persisting the full identity keeps every ESL input byte-stable so
# PCR7 is reproducible. Prints the secret ARN. Args: <name_prefix>.
generate_and_upload_identity() {
  # Suppress xtrace: identity_json carries the db private key
  case "$-" in *x*) trap 'set -x; trap - RETURN' RETURN; set +x ;; esac

  local name_prefix="$1"
  local ts identity_json arn
  ts=$(date +%s)

  identity_json=$(generate_identity_material) || identity_json=""
  if [ -z "$identity_json" ]; then
    echo "Error: Failed to generate secure boot identity" >&2
    return 1
  fi

  if ! printf '%s' "$identity_json" | jq -e \
      'has("guid") and has("db_key") and has("db_crt") and has("pk_crt") and has("kek_crt")
       and (.guid != "" and .db_key != "" and .db_crt != "" and .pk_crt != "" and .kek_crt != "")' \
      >/dev/null; then
    echo "Error: generated identity material is incomplete" >&2
    unset identity_json
    return 1
  fi

  arn=$(upload_secret "${name_prefix}-${ts}" <(printf '%s' "$identity_json")) || arn=""
  unset identity_json
  if [ -z "$arn" ]; then
    echo "Error: Failed to upload identity to Secrets Manager" >&2
    return 1
  fi
  printf '%s\n' "$arn"
}

# Rebuild the UEFI secure boot envelope (ESLs + uefi_data.aws) into <key_dir>
# from a persisted golden identity. Only public fields are unpacked to disk;
# db_key is fetched in-memory at signing time. Byte-stable inputs make PCR7
# reproducible. Args: <key_dir> <project_dir> <identity_arn>.
rebuild_sb_envelope_from_identity() {
  # Suppress xtrace: the fetched identity JSON carries the db private key
  case "$-" in *x*) trap 'set -x; trap - RETURN' RETURN; set +x ;; esac

  local key_dir="$1" project_dir="$2" identity_arn="$3"

  if [ -z "$identity_arn" ]; then
    echo "Error: no secure boot identity (IDENTITY_ARN) available; cannot rebuild a reproducible envelope." >&2
    return 1
  fi

  rm -rf "$key_dir"
  mkdir -p "$key_dir"

  local identity_json
  identity_json=$(aws secretsmanager get-secret-value --secret-id "$identity_arn" --query SecretString --output text) || {
    echo "Error: Failed to retrieve secure boot identity from Secrets Manager" >&2
    rm -rf "$key_dir"
    return 1
  }
  printf '%s' "$identity_json" | jq -r '.guid'    > "$key_dir/GUID.txt"
  printf '%s' "$identity_json" | jq -r '.db_crt'  > "$key_dir/db.crt"
  printf '%s' "$identity_json" | jq -r '.pk_crt'  > "$key_dir/PK.crt"
  printf '%s' "$identity_json" | jq -r '.kek_crt' > "$key_dir/KEK.crt"
  unset identity_json
  if [ ! -s "$key_dir/GUID.txt" ] || [ ! -s "$key_dir/db.crt" ] \
     || [ ! -s "$key_dir/PK.crt" ] || [ ! -s "$key_dir/KEK.crt" ]; then
    echo "Error: secure boot identity is missing guid/db_crt/pk_crt/kek_crt" >&2
    rm -rf "$key_dir"
    return 1
  fi

  # cert-to-efi-sig-list is byte-deterministic given the fixed GUID + certs.
  nix --extra-experimental-features nix-command --extra-experimental-features flakes shell \
    nixpkgs#efitools --command bash -c "
    set -euo pipefail
    cd '$key_dir'
    cert-to-efi-sig-list -g \"\$(cat GUID.txt)\" PK.crt PK.esl
    cert-to-efi-sig-list -g \"\$(cat GUID.txt)\" KEK.crt KEK.esl
    cert-to-efi-sig-list -g \"\$(cat GUID.txt)\" db.crt db.esl
  " || { echo "Error: Failed to rebuild ESLs" >&2; rm -rf "$key_dir"; return 1; }

  ( cd "$project_dir" && \
    nix --extra-experimental-features nix-command --extra-experimental-features flakes run .#generate-uefi-vars -- \
      -P "$key_dir/PK.esl" \
      -K "$key_dir/KEK.esl" \
      --db "$key_dir/db.esl" \
      -O "$key_dir/uefi_data.aws" ) || {
    echo "Error: Failed to generate UEFI variable store" >&2
    rm -rf "$key_dir"
    return 1
  }
}
