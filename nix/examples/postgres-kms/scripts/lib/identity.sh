#!/bin/bash
#
# Shared helpers sourced by ceremony stages. Xtrace suppression is inlined (not in a shared helper):
# a RETURN trap fires when the installing function returns, re-enabling xtrace in the caller.

# Resolved from this file's own location; deploy.sh runs in a subshell where $SCRIPT_DIR is absent.
IDENTITY_SCRIPTS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )/.." &> /dev/null && pwd )"

validate_secret_arn() {
  local arn="$1"
  if [[ "$arn" != arn:aws:secretsmanager:* ]]; then
    echo "Error: '$arn' is not a valid Secrets Manager ARN. Expected format: arn:aws:secretsmanager:<region>:<account>:secret:<name>" >&2
    exit 1
  fi
}

# Print the command to allowlist the caller's host on 5432. Never edits the SG. Args: <sg_id>.
print_sg_authorization_notice() {
  local sg_id="$1" my_ip region
  my_ip=$(curl -s --max-time 10 https://checkip.amazonaws.com | tr -d '[:space:]')
  # e2e-test.sh doesn't source aws-creds.sh, so AWS_DEFAULT_REGION can be unset here.
  region="${AWS_REGION:-${AWS_DEFAULT_REGION:-$(aws configure get region 2>/dev/null || true)}}"
  echo ""
  echo "=== ACTION REQUIRED: authorize your host on the DB security group ==="
  echo "Security Group: ${sg_id:-<unknown>}"
  echo "PostgreSQL listens on the instance's PUBLIC IP:5432, but the SG only"
  echo "allows the VPC CIDR by default. Add the public IP of the host that will"
  echo "connect (mTLS client) before it can reach 5432:"
  echo ""
  if [ -n "$my_ip" ]; then
    echo "  Your public IP: $my_ip  (from https://checkip.amazonaws.com)"
    echo "  aws ec2 authorize-security-group-ingress --region ${region:-<REGION>} \\"
    echo "    --group-id ${sg_id:-<SG_ID>} --protocol tcp --port 5432 \\"
    echo "    --cidr ${my_ip}/32"
  else
    echo "  (could not auto-detect your public IP via checkip.amazonaws.com)"
    echo "  aws ec2 authorize-security-group-ingress --region ${region:-<REGION>} \\"
    echo "    --group-id ${sg_id:-<SG_ID>} --protocol tcp --port 5432 \\"
    echo "    --cidr <YOUR_PUBLIC_IP>/32"
  fi
  echo "===================================================================="
  echo ""
}

# CI: allowlist runner's public IP on 5432; idempotent; fails if IP undetectable. Args: <sg_id>.
authorize_my_ip() {
  local sg_id="$1" my_ip err
  if [ -z "$sg_id" ]; then
    echo "Error: authorize_my_ip called without a security group id." >&2
    return 1
  fi
  my_ip=$(curl -s --max-time 10 https://checkip.amazonaws.com | tr -d '[:space:]')
  if [ -z "$my_ip" ]; then
    echo "Error: could not detect public IP via checkip.amazonaws.com; cannot authorize SG $sg_id." >&2
    return 1
  fi
  echo "Authorizing $my_ip/32 on SG $sg_id:5432 (--authorize-my-ip)..."
  if err=$(aws ec2 authorize-security-group-ingress \
        --group-id "$sg_id" --protocol tcp --port 5432 --cidr "$my_ip/32" 2>&1); then
    echo "Authorized $my_ip/32 on $sg_id:5432."
  elif printf '%s' "$err" | grep -q 'InvalidPermission.Duplicate'; then
    echo "$my_ip/32 already authorized on $sg_id:5432."
  else
    echo "Error: failed to authorize $my_ip/32 on $sg_id: $err" >&2
    return 1
  fi
}

update_resource() {
  local KEY=$1
  local VALUE=$2
  local tmp
  tmp=$(mktemp "${RESOURCES_FILE}.XXXXXX")
  # Must return non-zero on a failed write: a silent skip here means clean.sh never learns
  # about the resource and it is orphaned.
  if ! jq --arg key "$KEY" --arg value "$VALUE" '.[$key] = $value' "$RESOURCES_FILE" > "$tmp" \
       || ! mv "$tmp" "$RESOURCES_FILE"; then
    rm -f "$tmp"
    echo "Error: could not record $KEY in $RESOURCES_FILE." >&2
    return 1
  fi
}

# Returns signed-image/ (PCR4+PCR7) when secure boot active, else result/ (PCR4). Args:
# <project_dir> <secure_boot_flag>.
resolve_pcr_dir() {
  local project_dir="$1" secure_boot_flag="$2"
  if [ -n "$secure_boot_flag" ] && [ -f "$project_dir/signed-image/tpm_pcr.json" ]; then
    echo "$project_dir/signed-image"
  else
    echo "$project_dir/result"
  fi
}

# Single launch call-site for deploy.sh and e2e-test.sh.
# vpc_id_flag/debug_flag intentionally unquoted: "--vpc-id X" must split, empty flag must vanish.
# Args: <ami_id> <instance_profile> <volume_id> [vpc_id_flag] [debug_flag].
run_instance_step() {
  local ami_id="$1" instance_profile="$2" volume_id="$3" vpc_id_flag="${4:-}" debug_flag="${5:-}"
  # shellcheck disable=SC2086  # vpc_id_flag/debug_flag intentionally unquoted for word-splitting
  "$IDENTITY_SCRIPTS_DIR/steps/05_run_instance.sh" -a "$ami_id" -p "$instance_profile" -v "$volume_id" $vpc_id_flag $debug_flag
}

# Generate {guid, db_key, db_crt, pk_crt, kek_crt} in memory; no private key touches disk.
generate_identity_material() {
  # shellcheck disable=SC2016  # single-quoted heredoc-style arg: expansions run in the inner bash
  nix --extra-experimental-features nix-command --extra-experimental-features flakes shell \
    nixpkgs#openssl nixpkgs#util-linux nixpkgs#jq --command bash -c '
    set -euo pipefail
    guid=$(uuidgen --random)
    pk_crt=$(openssl req -newkey rsa:4096 -nodes -keyout /dev/null -new -x509 -sha256 -days 3650 -subj "/CN=Platform key/" 2>/dev/null)
    kek_crt=$(openssl req -newkey rsa:4096 -nodes -keyout /dev/null -new -x509 -sha256 -days 3650 -subj "/CN=Key Exchange Key/" 2>/dev/null)
    db_key=$(openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 2>/dev/null)
    db_crt=$(printf "%s" "$db_key" | openssl req -new -x509 -sha256 -days 3650 -subj "/CN=Signature Database key/" -key /dev/stdin 2>/dev/null)
    # db_key via the environment, not --arg: /proc/<pid>/cmdline is world-readable.
    db_key="$db_key" jq -n --arg guid "$guid" --arg db_crt "$db_crt" \
          --arg pk_crt "$pk_crt" --arg kek_crt "$kek_crt" \
          "{guid: \$guid, db_key: \$ENV.db_key, db_crt: \$db_crt, pk_crt: \$pk_crt, kek_crt: \$kek_crt}"
  '
}

# Generate ephemeral SB keys (PK, KEK, db + ESLs) + UEFI var store. Non-reproducible: PCR7
# changes each run. Args: <key_dir> <project_dir>.
generate_local_sb_keys() {
  local key_dir="$1" project_dir="$2"

  rm -rf "$key_dir"
  mkdir -p "$key_dir"

  nix --extra-experimental-features nix-command --extra-experimental-features flakes shell \
    nixpkgs#openssl nixpkgs#efitools nixpkgs#util-linux --command bash -c "
    set -euo pipefail
    umask 077
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

# Deny GetSecretValue to all except Deployer. Must be Deny (not Allow): Secrets Manager grants
# if either policy allows, so an Allow-only resource policy leaves any secretsmanager:GetSecretValue
# holder able to read the signing key and gate Decrypt to rogue PCRs.
# Scoped to GetSecretValue only — blanket Deny breaks DeleteSecret (clean.sh:58-61).
# ArnNotEquals + aws:PrincipalArn: evaluates to the IAM role ARN, not the session ARN. Args:
# <deployer_role_arn>.
build_identity_resource_policy() {
  local deployer="$1"
  cat <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyGetSecretValueExceptDeployer",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "secretsmanager:GetSecretValue",
      "Resource": "*",
      "Condition": {
        "ArnNotEquals": {
          "aws:PrincipalArn": "${deployer}"
        }
      }
    }
  ]
}
EOF
}

# Attach Deployer-only resource policy and verify it landed. create-secret has no atomic attach,
# so verify closes the create→attach window (same pattern as 02b's grant audit). Fails closed.
# Args: <secret_arn> <deployer_role_arn>.
lock_secret_to_deployer() {
  local arn="$1" deployer="${2:-}" policy readback

  if [ -z "$deployer" ]; then
    echo -e "\033[33m⚠️  WARNING: no --deployer-role-arn supplied.\033[0m" >&2
    echo -e "\033[33m   Signing identity $arn has NO resource policy Deny: it is readable by any principal\033[0m" >&2
    echo -e "\033[33m   holding secretsmanager:GetSecretValue. That principal could sign a rogue image\033[0m" >&2
    echo -e "\033[33m   and gate kms:Decrypt to those rogue PCRs — defeating the Deployer≠Custodian split.\033[0m" >&2
    echo -e "\033[33m   To lock the secret: --deployer-role-arn <DEPLOYER_ROLE_ARN>\033[0m" >&2
    return 0
  fi

  policy=$(build_identity_resource_policy "$deployer")
  if ! aws secretsmanager put-resource-policy \
        --secret-id "$arn" \
        --resource-policy "$policy" >/dev/null 2>&1; then
    echo "Error: failed to attach the Deployer-only resource policy to $arn" >&2
    return 1
  fi

  readback=$(aws secretsmanager get-resource-policy --secret-id "$arn" \
    --query 'ResourcePolicy' --output text 2>/dev/null) || readback=""
  if ! printf '%s' "$readback" | jq -e --arg deployer "$deployer" \
      '[.Statement[]
        | select(.Effect == "Deny")
        | select(.Action == "secretsmanager:GetSecretValue")
        | select(.Condition.ArnNotEquals["aws:PrincipalArn"] == $deployer)]
       | length == 1' >/dev/null 2>&1; then
    echo "Error: resource policy on $arn did not read back as expected; failing closed." >&2
    return 1
  fi

  echo "Signing identity $arn locked to $deployer." >&2
}

# Create a Secrets Manager secret from a path (process substitution: value never hits disk).
# Attaches Deployer-only policy when deployer ARN provided. Prints ARN. Args: <name> <src-path>
# [deployer_role_arn].
upload_secret() {
  local name="$1" src="$2" deployer="${3:-}" arn
  arn=$(aws secretsmanager create-secret \
    --name "$name" \
    --secret-string "file://$src" \
    --query 'ARN' --output text) || return 1

  # Destroy the secret if locking fails. It already holds the private signing key, the ARN was
  # never printed, and clean.sh only deletes recorded ARNs — so leaving it orphans a live key.
  if ! lock_secret_to_deployer "$arn" "$deployer"; then
    aws secretsmanager delete-secret --secret-id "$arn" \
      --force-delete-without-recovery >/dev/null 2>&1 \
      || echo "Error: could not delete unlocked secret $arn; delete it manually." >&2
    return 1
  fi
  printf '%s\n' "$arn"
}

# Generate and upload identity as one JSON secret. Full identity stored so ESL inputs stay
# byte-stable across rebuilds (reproducible PCR7). Prints ARN. Args: <name_prefix>
# [deployer_role_arn].
generate_and_upload_identity() {
  # Suppress xtrace: identity_json carries the db private key
  case "$-" in *x*) trap 'set -x; trap - RETURN' RETURN; set +x ;; esac

  local name_prefix="$1" deployer="${2:-}"
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

  arn=$(upload_secret "${name_prefix}-${ts}" <(printf '%s' "$identity_json") "$deployer") || arn=""
  unset identity_json
  if [ -z "$arn" ]; then
    echo "Error: Failed to upload identity to Secrets Manager" >&2
    return 1
  fi
  printf '%s\n' "$arn"
}

# Rebuild ESLs + uefi_data.aws from persisted identity; db_key never hits disk. PCR7
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
