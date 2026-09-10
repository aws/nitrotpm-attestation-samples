#!/bin/bash
# Stage 4 of 6 — SECRETS / PKI PROVISIONER.
# Mints and wraps the DEK, issues certs, encrypts the server bundle — all in one
# stage so the plaintext DEK never crosses a stage boundary.
# Provisioner has kms:Encrypt but no kms:PutKeyPolicy; Custodian is the reverse.
# No `set -x`: xtrace would echo the plaintext DEK.
set -euo pipefail

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_DIR="$( cd "$SCRIPT_DIR/.." &> /dev/null && pwd )"

# shellcheck source-path=SCRIPTDIR
# shellcheck source=lib/roles.sh
. "$SCRIPT_DIR/lib/roles.sh"
# shellcheck source-path=SCRIPTDIR
# shellcheck source=lib/aws-creds.sh
. "$SCRIPT_DIR/lib/aws-creds.sh"

usage() {
  echo "Usage: $0 --key-id ARN [--provisioner-role-arn ARN]" >&2
  echo "  --key-id                  KMS key ARN whose bootstrap policy grants Encrypt (required)" >&2
  echo "  --provisioner-role-arn    Assume this role for the work (default: ambient credentials)" >&2
  exit 1
}

KEY_ID=""
PROVISIONER_ROLE_ARN=""

while [[ "$#" -gt 0 ]]; do
  case $1 in
    --key-id) KEY_ID="${2:?--key-id requires a value}"; shift ;;
    --provisioner-role-arn) PROVISIONER_ROLE_ARN="${2:?--provisioner-role-arn requires a value}"; shift ;;
    *) usage ;;
  esac
  shift
done

[ -n "$KEY_ID" ] || { echo "Error: --key-id is required." >&2; usage; }

resolve_aws_credentials || exit 1

# EXIT trap: signal or set -e abort between mktemp and rm would otherwise leave the plaintext
# DEK on disk.
KEY_TMPDIR=$(mktemp -d)
trap 'rm -rf "$KEY_TMPDIR"' EXIT INT TERM
# mktemp -d already yields 0700; this is defence in depth against a permissive umask.
chmod 700 "$KEY_TMPDIR"
KEY_FILE="$KEY_TMPDIR/symmetric_key"

echo "Stage 4/6 (Provisioner): minting and wrapping the DEK..." >&2
if ! assume_role_exec "$PROVISIONER_ROLE_ARN" -- \
      "$SCRIPT_DIR/steps/03_create_symmetric_key.sh" \
      -k "$KEY_ID" --plaintext-key-out "$KEY_FILE" >&2; then
  echo "Error: symmetric key creation failed." >&2
  exit 1
fi

echo "Stage 4/6 (Provisioner): issuing certificates and encrypting the server bundle..." >&2
if ! CERT_OUTPUT=$(assume_role_exec "$PROVISIONER_ROLE_ARN" -- \
      "$SCRIPT_DIR/steps/05a_create_certificates.sh" --symmetric-key "$KEY_FILE"); then
  echo "Error: certificate creation failed." >&2
  echo "$CERT_OUTPUT" >&2
  exit 1
fi

# Destroy the plaintext eagerly; the trap remains as the abort-path guarantee.
rm -f "$KEY_FILE"

SECRET_ARN=$(printf '%s' "$CERT_OUTPUT" | sed -n 's/.*SECRET_ARN: //p' | head -n1)
if [ -z "$SECRET_ARN" ]; then
  echo "Error: could not extract SECRET_ARN from the certificate step output." >&2
  echo "$CERT_OUTPUT" >&2
  exit 1
fi

echo "SECRET_ARN: $SECRET_ARN"

echo "" >&2
echo "Wrapped DEK and encrypted server bundle are in $PROJECT_DIR/artifacts/user_data.json." >&2
echo "The plaintext DEK has been destroyed and never left this stage." >&2
echo "Next (Custodian): ./scripts/finalize-key.sh --key-id $KEY_ID \\" >&2
echo "  --instance-role-arn <INSTANCE_ROLE_ARN> --pcr-dir <PCR_DIR>" >&2
