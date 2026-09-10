#!/bin/bash
# Stage 1 of 6 — PLATFORM OPERATOR.
# Creates the workload instance role and profile. Must run before stage 5: KMS
# validates key-policy principals at put-key-policy time. Cannot live in
# create-key.sh (Custodian would control the principal) or build.sh (Deployer
# would control both the code and the trusted principal).
# Diagnostics → stderr; stdout carries only NAME: VALUE handoff lines.
set -euo pipefail

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

# shellcheck source-path=SCRIPTDIR
# shellcheck source=lib/roles.sh
. "$SCRIPT_DIR/lib/roles.sh"
# shellcheck source-path=SCRIPTDIR
# shellcheck source=lib/aws-creds.sh
. "$SCRIPT_DIR/lib/aws-creds.sh"

usage() {
  echo "Usage: $0 [--operator-role-arn ARN] [-r ROLE_NAME] [-p PROFILE_NAME] [--debug]" >&2
  echo "  --operator-role-arn   Assume this role for the work (default: ambient credentials)" >&2
  echo "  -r, --instance-role   Workload role name (default: TpmAttestationRole)" >&2
  echo "  -p, --instance-profile Workload profile name (default: TpmAttestationProfile)" >&2
  echo "  --debug               Attach the SSM managed policy for operator access" >&2
  exit 1
}

OPERATOR_ROLE_ARN=""
ROLE_NAME="TpmAttestationRole"
INSTANCE_PROFILE_NAME="TpmAttestationProfile"
DEBUG_FLAG=""

while [[ "$#" -gt 0 ]]; do
  case $1 in
    --operator-role-arn) OPERATOR_ROLE_ARN="${2:?--operator-role-arn requires a value}"; shift ;;
    -r|--instance-role) ROLE_NAME="${2:?--instance-role requires a value}"; shift ;;
    -p|--instance-profile) INSTANCE_PROFILE_NAME="${2:?--instance-profile requires a value}"; shift ;;
    --debug) DEBUG_FLAG="--debug" ;;
    *) usage ;;
  esac
  shift
done

resolve_aws_credentials || exit 1

echo "Stage 1/6 (Operator): creating instance role '$ROLE_NAME' and profile '$INSTANCE_PROFILE_NAME'..." >&2

if ! assume_role_exec "$OPERATOR_ROLE_ARN" -- \
      "$SCRIPT_DIR/steps/01_create_instance_profile.sh" \
      -r "$ROLE_NAME" -p "$INSTANCE_PROFILE_NAME" $DEBUG_FLAG >&2; then
  echo "Error: instance role and profile setup failed." >&2
  exit 1
fi

if ! INSTANCE_ROLE_ARN=$(assume_role_exec "$OPERATOR_ROLE_ARN" -- \
      aws iam get-role --role-name "$ROLE_NAME" --query 'Role.Arn' --output text); then
  echo "Error: could not resolve the ARN of '$ROLE_NAME'." >&2
  exit 1
fi

echo "ROLE_NAME: $ROLE_NAME"
echo "INSTANCE_PROFILE_NAME: $INSTANCE_PROFILE_NAME"
echo "INSTANCE_ROLE_ARN: $INSTANCE_ROLE_ARN"

echo "Next: ./scripts/create-key.sh --provisioner-role-arn <PROVISIONER_ARN>" >&2
