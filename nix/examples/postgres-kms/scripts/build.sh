#!/bin/bash
# Stage 3 of 6 — RELEASE/BUILD ENGINEER (Deployer).
# Pins the key ARN, builds, signs and registers the AMI. The Deployer holds no
# kms:PutKeyPolicy: it emits PCRs and stops — the Custodian alone gates the key.
# No `set -x`: xtrace would echo secure-boot key material to stderr.
set -euo pipefail

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_DIR="$( cd "$SCRIPT_DIR/.." &> /dev/null && pwd )"
ARTIFACTS_DIR="$PROJECT_DIR/artifacts"
RESOURCES_FILE="$ARTIFACTS_DIR/resources.json"

# shellcheck source-path=SCRIPTDIR
# shellcheck source=lib/roles.sh
. "$SCRIPT_DIR/lib/roles.sh"
# shellcheck source-path=SCRIPTDIR
# shellcheck source=lib/aws-creds.sh
. "$SCRIPT_DIR/lib/aws-creds.sh"
# shellcheck source-path=SCRIPTDIR
# shellcheck source=lib/identity.sh
. "$SCRIPT_DIR/lib/identity.sh"

usage() {
  echo "Usage: $0 --key-id ARN [--deployer-role-arn ARN] [--secure-boot]" >&2
  echo "          [--secrets-manager [IDENTITY_ARN]] [--debug] [-y]" >&2
  echo "  --key-id                KMS key ARN to pin into the image (required)" >&2
  echo "  --deployer-role-arn     Assume this role for the work (default: ambient credentials)" >&2
  echo "  --secure-boot           Sign the UKI and compute PCR7" >&2
  echo "  --secrets-manager [ARN] Reuse/persist the signing identity in Secrets Manager" >&2
  echo "  --debug                 Build the debug variant (operator access enabled)" >&2
  echo "  -y, --yes               Non-interactive: accept prompts" >&2
  exit 1
}

KEY_ID=""
DEPLOYER_ROLE_ARN=""
SECURE_BOOT_FLAG=""
DEBUG_FLAG=""
SECRET_MANAGER_FLAG=""
SECRET_MANAGER_INTERACTIVE=""
IDENTITY_ARN=""
NON_INTERACTIVE=false

while [[ "$#" -gt 0 ]]; do
  case $1 in
    --key-id) KEY_ID="${2:?--key-id requires a value}"; shift ;;
    --deployer-role-arn) DEPLOYER_ROLE_ARN="${2:?--deployer-role-arn requires a value}"; shift ;;
    --secure-boot) SECURE_BOOT_FLAG="--secure-boot" ;;
    --debug) DEBUG_FLAG="--debug" ;;
    -y|--yes|--non-interactive) NON_INTERACTIVE=true ;;
    --secrets-manager)
      SECRET_MANAGER_FLAG="true"
      if [[ $# -gt 1 ]] && [[ "$2" != -* ]]; then
        IDENTITY_ARN="${2:?--secrets-manager requires a value or no argument}"
        validate_secret_arn "$IDENTITY_ARN"
        shift
      else
        SECRET_MANAGER_INTERACTIVE="true"
      fi
      ;;
    *) usage ;;
  esac
  shift
done

[ -n "$KEY_ID" ] || { echo "Error: --key-id is required." >&2; usage; }
if [ -n "$SECRET_MANAGER_FLAG" ] && [ -z "$SECURE_BOOT_FLAG" ]; then
  echo "Error: --secrets-manager requires --secure-boot." >&2
  exit 1
fi

resolve_aws_credentials || exit 1

mkdir -p "$ARTIFACTS_DIR"
[ -f "$RESOURCES_FILE" ] || echo '{}' > "$RESOURCES_FILE"

if [ -n "$SECURE_BOOT_FLAG" ] && [ -z "$SECRET_MANAGER_FLAG" ]; then
  echo -e "\033[33m⚠️  WARNING: Secure boot builds are NOT reproducible (keys generated at build time)! ⚠️\033[0m" >&2
fi
if [ -n "$DEBUG_FLAG" ]; then
  echo -e "\033[31m⚠️  WARNING: Building in DEBUG mode with operator access enabled! ⚠️\033[0m" >&2
fi

# --- pin the ARN: write, track, verify, fail closed --------------------------
ARN_FILE="$PROJECT_DIR/kms-key-arn.txt"
printf '%s\n' "$KEY_ID" > "$ARN_FILE"
echo "Pinned KMS key ARN into $ARN_FILE" >&2

if ! git -C "$PROJECT_DIR" rev-parse --git-dir >/dev/null 2>&1; then
  echo "Error: '$PROJECT_DIR' is not a git repository, so the pinned ARN cannot be tracked." >&2
  echo "       A git+file:// flake ref only includes tracked paths, so the build would not" >&2
  echo "       see the pin and would produce an unpinned or stale-pinned image." >&2
  exit 1
fi
if ! git -C "$PROJECT_DIR" add "$ARN_FILE"; then
  echo "Error: could not 'git add $ARN_FILE'." >&2
  echo "       A git+file:// flake ref only includes tracked paths, so the build" >&2
  echo "       would not see the pin and the key created in stage 2 is orphaned." >&2
  exit 1
fi
if ! git -C "$PROJECT_DIR" ls-files --error-unmatch "$ARN_FILE" >/dev/null 2>&1; then
  echo "Error: '$ARN_FILE' is still untracked after 'git add'; failing closed." >&2
  exit 1
fi
echo "Pinned ARN file is git-tracked." >&2

# --- secure boot identity ----------------------------------------------------
if [ -n "$SECRET_MANAGER_INTERACTIVE" ]; then
  RETAINED=$(jq -r '.IDENTITY_ARN // empty' "$RESOURCES_FILE" 2>/dev/null || true)
  if [ -n "$RETAINED" ]; then
    echo "Found a retained signing identity: $RETAINED" >&2
    if [ "$NON_INTERACTIVE" = true ]; then
      USE_RETAINED="yes"
      echo "Non-interactive: reusing the retained identity." >&2
    else
      read -r -p "Use this retained identity? (yes/no): " USE_RETAINED
    fi
    if [ "$USE_RETAINED" = "yes" ]; then
      IDENTITY_ARN="$RETAINED"
      SECRET_MANAGER_INTERACTIVE=""
    fi
  fi
fi

if [ -n "$SECRET_MANAGER_INTERACTIVE" ]; then
  if [ "$NON_INTERACTIVE" != true ]; then
    read -r -p "Generate and upload a new signing identity? (yes/no): " CONFIRM
    [ "$CONFIRM" = "yes" ] || { echo "Declined; supply an existing ARN with --secrets-manager <ARN>." >&2; exit 1; }
  fi
  echo "Generating and uploading a secure boot signing identity..." >&2
  IDENTITY_ARN=$(assume_role_exec "$DEPLOYER_ROLE_ARN" -- \
    bash -c ". '$SCRIPT_DIR/lib/identity.sh'; generate_and_upload_identity 'nitrotpm-sb-identity' '$DEPLOYER_ROLE_ARN'") || {
    echo "Error: failed to create the signing identity." >&2
    exit 1
  }
fi

if [ -n "$IDENTITY_ARN" ]; then
  # Reuse path too: a secret from an earlier run predates the resource policy.
  assume_role_exec "$DEPLOYER_ROLE_ARN" -- \
    bash -c ". '$SCRIPT_DIR/lib/identity.sh'; lock_secret_to_deployer '$IDENTITY_ARN' '$DEPLOYER_ROLE_ARN'" || exit 1
fi

# Trap: signing key must not survive a failure or signal between key generation and cleanup.
trap 'rm -rf "$PROJECT_DIR/sb-keys" 2>/dev/null || true' EXIT INT TERM

if [ -n "$SECURE_BOOT_FLAG" ]; then
  if [ -n "$IDENTITY_ARN" ]; then
    echo "Rebuilding the UEFI secure boot envelope from the persisted identity..." >&2
    assume_role_exec "$DEPLOYER_ROLE_ARN" -- \
      bash -c ". '$SCRIPT_DIR/lib/identity.sh'; rebuild_sb_envelope_from_identity '$PROJECT_DIR/sb-keys' '$PROJECT_DIR' '$IDENTITY_ARN'" \
      >&2 || exit 1
  else
    echo -e "\033[33m⚠️  Generating ephemeral signing keys at $PROJECT_DIR/sb-keys\033[0m" >&2
    echo -e "\033[33m   Overwritten every run — measurements change each time.\033[0m" >&2
    generate_local_sb_keys "$PROJECT_DIR/sb-keys" "$PROJECT_DIR" >&2 || {
      echo "Error: failed to generate the secure boot key hierarchy." >&2
      rm -rf "$PROJECT_DIR/sb-keys"
      exit 1
    }
  fi
fi

# --- build, sign, register ---------------------------------------------------
CREATE_AMI_ARGS=()
[ -n "$SECURE_BOOT_FLAG" ] && CREATE_AMI_ARGS+=("$SECURE_BOOT_FLAG")
[ -n "$DEBUG_FLAG" ]       && CREATE_AMI_ARGS+=("$DEBUG_FLAG")
if [ -n "$IDENTITY_ARN" ]; then
  CREATE_AMI_ARGS+=(--identity-arn "$IDENTITY_ARN")
fi
# Not wrapped around the step: 00_create_ami.sh adopts it per-call to avoid burning the 1h STS
# window.
[ -n "$DEPLOYER_ROLE_ARN" ] && CREATE_AMI_ARGS+=(--role-arn "$DEPLOYER_ROLE_ARN")

echo "Stage 3/6 (Deployer): building, signing and registering the AMI..." >&2
set +e
AMI_OUTPUT=$("$SCRIPT_DIR/steps/00_create_ami.sh" "${CREATE_AMI_ARGS[@]+"${CREATE_AMI_ARGS[@]}"}")
AMI_RC=$?
set -e

# The signing key must not outlive the build, whether it succeeded or not.
if [ -n "$SECURE_BOOT_FLAG" ] && [ -d "$PROJECT_DIR/sb-keys" ]; then
  rm -rf "$PROJECT_DIR/sb-keys"
  echo "Removed sb-keys/ after the build." >&2
fi

if [ "$AMI_RC" -ne 0 ]; then
  echo "Error: AMI creation failed." >&2
  echo "$AMI_OUTPUT" >&2
  exit 1
fi

AMI_ID=$(printf '%s' "$AMI_OUTPUT" | grep -oE 'ami-[a-z0-9]+' | tail -n1)
if [ -z "$AMI_ID" ]; then
  echo "Error: could not extract the AMI ID from the build output." >&2
  echo "$AMI_OUTPUT" >&2
  exit 1
fi

PCR_DIR=$(resolve_pcr_dir "$PROJECT_DIR" "$SECURE_BOOT_FLAG")

echo "AMI_ID: $AMI_ID"
echo "PCR_DIR: $PCR_DIR"
if [ -n "$IDENTITY_ARN" ]; then
  echo "IDENTITY_ARN: $IDENTITY_ARN"
fi

echo "" >&2
echo "Stage 3 complete. The Deployer cannot finalize the key policy." >&2
echo "PCR values in $PCR_DIR/tpm_pcr.json (Custodian: confirm these match the AMI):" >&2
jq -r '.Measurements | to_entries | map(select(.key | test("^PCR[0-9]+"))) | .[] | "  \(.key): \(.value)"' \
  "$PCR_DIR/tpm_pcr.json" >&2
echo "Hand these PCRs to the Custodian, who runs stage 5:" >&2
echo "  ./scripts/finalize-key.sh --key-id $KEY_ID \\" >&2
echo "    --instance-role-arn <INSTANCE_ROLE_ARN> --pcr-dir $PCR_DIR" >&2
