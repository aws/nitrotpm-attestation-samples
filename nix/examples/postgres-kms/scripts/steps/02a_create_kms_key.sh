#!/bin/bash
# Phase one of two-step KMS provisioning: create the key and emit its ARN.
# build.sh pins that ARN into the image, so the CLI value is the single source of truth.
# Bootstrap policy: Custodian gets PutKeyPolicy, Provisioner gets Encrypt, neither gets
# Decrypt. 02b strips both; Custodian's ListGrants/RevokeGrant let 02b clear any grant.
set -euo pipefail

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

# shellcheck source-path=SCRIPTDIR/../lib
# shellcheck source=../lib/kms.sh
. "$SCRIPT_DIR/../lib/kms.sh"

usage() {
  echo "Usage: $0 -a CUSTODIAN_ROLE [-p PROVISIONER_ROLE]"
  echo "  -a, --admin-role          ARN of the Key Custodian principal"
  echo "  -p, --provisioner-role    ARN of the Provisioner principal (default: the Custodian)"
  exit 1
}

ADMIN_ROLE=""
PROVISIONER_ROLE=""

while [[ "$#" -gt 0 ]]; do
  case $1 in
    -a|--admin-role) ADMIN_ROLE="$2"; shift ;;
    -p|--provisioner-role) PROVISIONER_ROLE="$2"; shift ;;
    *) usage ;;
  esac
  shift
done

if [ -z "$ADMIN_ROLE" ]; then
  echo "Error: Admin role ARN is required."
  usage
fi

if ! ADMIN_PRINCIPAL=$(normalize_admin_principal "$ADMIN_ROLE"); then
  echo "Error: Failed to resolve admin principal '$ADMIN_ROLE'."
  exit 1
fi

PROVISIONER_PRINCIPAL=""
if [ -n "$PROVISIONER_ROLE" ]; then
  if ! PROVISIONER_PRINCIPAL=$(normalize_admin_principal "$PROVISIONER_ROLE"); then
    echo "Error: Failed to resolve provisioner principal '$PROVISIONER_ROLE'." >&2
    exit 1
  fi
fi

# No IAM delegation statement, so --bypass-policy-lockout-safety-check is required (same as the
# final policy).
BOOTSTRAP_POLICY=$(build_bootstrap_policy "$ADMIN_PRINCIPAL" "$PROVISIONER_PRINCIPAL")

POLICY_FILE=$(mktemp -t kms_bootstrap_policy.XXXXXX.json)
trap 'rm -f "$POLICY_FILE"' EXIT
echo "$BOOTSTRAP_POLICY" > "$POLICY_FILE"
echo "Bootstrap KMS policy written to $POLICY_FILE"

echo "Creating KMS key with bootstrap policy (Custodian: PutKeyPolicy; Provisioner: Encrypt; no Decrypt)..."
if ! KEY_OUTPUT=$(kms_call_with_retry "KMS key creation" create-key \
      --description "NitroTPM attestation example key" \
      --bypass-policy-lockout-safety-check \
      --policy file://"$POLICY_FILE"); then
  exit 1
fi

KEY_ARN=$(echo "$KEY_OUTPUT" | jq -r '.KeyMetadata.Arn')
if [ -z "$KEY_ARN" ] || [ "$KEY_ARN" = "null" ]; then
  echo "Error: Could not read KeyMetadata.Arn from the create-key response." >&2
  echo "$KEY_OUTPUT" >&2
  exit 1
fi

echo "KMS key created with ARN: $KEY_ARN"
