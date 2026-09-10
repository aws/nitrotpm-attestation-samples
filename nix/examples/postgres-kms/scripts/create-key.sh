#!/bin/bash
# Stage 2 of 6 — KEY CUSTODIAN.
# Creates the KMS key: Custodian gets PutKeyPolicy, Provisioner gets Encrypt.
# Key is orphaned until stage 3 pins its ARN into the image.
set -euo pipefail

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

# shellcheck source-path=SCRIPTDIR
# shellcheck source=lib/roles.sh
. "$SCRIPT_DIR/lib/roles.sh"
# shellcheck source-path=SCRIPTDIR
# shellcheck source=lib/aws-creds.sh
. "$SCRIPT_DIR/lib/aws-creds.sh"

usage() {
  echo "Usage: $0 [--custodian-role-arn ARN] [--provisioner-role-arn ARN]" >&2
  echo "  --custodian-role-arn     Assume this role for the work (default: ambient credentials)" >&2
  echo "  --provisioner-role-arn   Principal granted kms:Encrypt in the bootstrap policy" >&2
  echo "                           (default: the Custodian, which reproduces the" >&2
  echo "                           single-identity policy exactly)" >&2
  exit 1
}

CUSTODIAN_ROLE_ARN=""
PROVISIONER_ROLE_ARN=""

while [[ "$#" -gt 0 ]]; do
  case $1 in
    --custodian-role-arn) CUSTODIAN_ROLE_ARN="${2:?--custodian-role-arn requires a value}"; shift ;;
    --provisioner-role-arn) PROVISIONER_ROLE_ARN="${2:?--provisioner-role-arn requires a value}"; shift ;;
    *) usage ;;
  esac
  shift
done

resolve_aws_credentials || exit 1

# The key policy names the Custodian. With no flag the caller IS the Custodian.
CUSTODIAN_PRINCIPAL=$(resolve_policy_principal "$CUSTODIAN_ROLE_ARN")

PROVISIONER_ARGS=()
if [ -n "$PROVISIONER_ROLE_ARN" ]; then
  PROVISIONER_ARGS=(--provisioner-role "$PROVISIONER_ROLE_ARN")
else
  echo -e "\033[33m⚠️  WARNING: single-identity mode — no --provisioner-role-arn supplied.\033[0m" >&2
  echo -e "\033[33m   The Custodian will hold BOTH kms:PutKeyPolicy AND kms:Encrypt.\033[0m" >&2
  echo -e "\033[33m   No Custodian/Provisioner separation is in effect: one party can both\033[0m" >&2
  echo -e "\033[33m   rewrite the key policy (grant-plant) and mint ciphertext (DEK substitution).\033[0m" >&2
  echo -e "\033[33m   To enable separation: --provisioner-role-arn <PROVISIONER_ROLE_ARN>\033[0m" >&2
fi

echo "Stage 2/6 (Custodian): creating the KMS key under the bootstrap policy..." >&2

if ! assume_role_exec "$CUSTODIAN_ROLE_ARN" -- \
      "$SCRIPT_DIR/steps/02a_create_kms_key.sh" \
      -a "$CUSTODIAN_PRINCIPAL" "${PROVISIONER_ARGS[@]+"${PROVISIONER_ARGS[@]}"}"; then
  echo "Error: KMS key creation failed." >&2
  exit 1
fi

echo "WARNING: this key is orphaned until stage 3 pins its ARN into the image." >&2
echo "Next: ./scripts/build.sh --key-id <KMS_KEY_ARN>" >&2
