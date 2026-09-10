#!/bin/bash
#
# Unit tests for kms-verify.sh — guards the gate that pins the KMS key ARN into the image,
# blocking an operator from launching the genuine AMI against an attacker-controlled key via
# user-data.
# Pure (pinned, supplied) -> verdict tests: bash only, no jq, no AWS.

set -u

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_DIR="$( cd "$SCRIPT_DIR/.." &> /dev/null && pwd )"

# shellcheck source-path=SCRIPTDIR/..
# shellcheck source=kms-verify.sh
. "$PROJECT_DIR/kms-verify.sh"

GREEN="\033[32m"
RED="\033[31m"
RESET="\033[0m"

PASS_COUNT=0
FAIL_COUNT=0

pass() { PASS_COUNT=$((PASS_COUNT + 1)); printf "${GREEN}PASS${RESET} %s\n" "$1"; }
fail() { FAIL_COUNT=$((FAIL_COUNT + 1)); printf "${RED}FAIL${RESET} %s\n" "$1"; }

# Exit-code contract: 0 = accept, 1 = reject.
# Any other status is a harness or environment error, never a valid rejection.
# Treating "reject" as "non-zero" would let a missing function (127) satisfy every rejection
# case vacuously.

assert_accepts() {
  local name=$1 pinned=$2 supplied=$3 err rc
  err=$(kms_verify_pinned_key_id "$pinned" "$supplied" 2>&1); rc=$?
  if [ "$rc" -eq 0 ]; then
    pass "$name"
  else
    fail "$name -- expected accept (0), got $rc: $err"
  fi
}

assert_rejects() {
  local name=$1 pinned=$2 supplied=$3 err rc
  err=$(kms_verify_pinned_key_id "$pinned" "$supplied" 2>&1); rc=$?
  case "$rc" in
    1) pass "$name" ;;
    0) fail "$name -- expected reject (1), but the key was accepted" ;;
    *) fail "$name -- expected reject (1), got status $rc: $err" ;;
  esac
}

# assert_rejects_because: pins the reason, not just the verdict — wrong reason sends operators
# chasing the wrong thing.
assert_rejects_because() {
  local name=$1 pinned=$2 supplied=$3 want=$4 err rc
  err=$(kms_verify_pinned_key_id "$pinned" "$supplied" 2>&1); rc=$?
  if [ "$rc" -ne 1 ]; then
    fail "$name -- expected reject (1), got status $rc: $err"
    return
  fi
  case "$err" in
    *"$want"*) pass "$name" ;;
    *) fail "$name -- rejected, but not because of '$want': $err" ;;
  esac
}

PINNED="arn:aws:kms:us-east-1:123456789012:key/1a2b3c4d-5e6f-4071-8293-a4b5c6d7e8f9"
BARE_UUID="1a2b3c4d-5e6f-4071-8293-a4b5c6d7e8f9"

OTHER_KEY="arn:aws:kms:us-east-1:123456789012:key/99999999-5e6f-4071-8293-a4b5c6d7e8f9"
OTHER_REGION="arn:aws:kms:eu-west-1:123456789012:key/1a2b3c4d-5e6f-4071-8293-a4b5c6d7e8f9"
OTHER_ACCOUNT="arn:aws:kms:us-east-1:999999999999:key/1a2b3c4d-5e6f-4071-8293-a4b5c6d7e8f9"
ALIAS_ARN="arn:aws:kms:us-east-1:123456789012:alias/nitrotpm-example"

assert_accepts "accepts the exact pinned ARN" "$PINNED" "$PINNED"

# Empty kms-key-arn.txt is the default for CI/local builds; must fail closed, not fall back to
# trusting user-data.

assert_rejects_because "rejects an image built with no pinned ARN" \
  "" "$PINNED" "built without a pinned KMS key ARN"

assert_rejects_because "rejects an unpinned image even when user-data is empty too" \
  "" "" "built without a pinned KMS key ARN"

assert_rejects_because "rejects an empty user-data key_id" \
  "$PINNED" "" "no key_id"

# jq renders an absent field as "null" without -e; must never be mistaken for a key identifier.
assert_rejects "rejects the literal string 'null' as a key_id" "$PINNED" "null"

assert_rejects_because "rejects a different key in the same account and region" \
  "$PINNED" "$OTHER_KEY" "does not match the pinned"

assert_rejects "rejects the same key id in a different region" "$PINNED" "$OTHER_REGION"
assert_rejects "rejects the same key id in a different account" "$PINNED" "$OTHER_ACCOUNT"

# UpdateAlias is mutable — accepting an alias would let the operator re-point the trust root
# without touching the image.
assert_rejects "rejects an alias ARN for the pinned key" "$PINNED" "$ALIAS_ARN"

# 03_create_symmetric_key.sh historically wrote a bare UUID; it has no account/region so the
# check always fails.
assert_rejects_because "rejects a bare key UUID and says why" \
  "$PINNED" "$BARE_UUID" "full ARN"

# Comparison must be whole-string — a substring match accepts any ARN that embeds the pinned one.
assert_rejects "rejects a value with the pinned ARN as a prefix" \
  "$PINNED" "${PINNED}-evil"

assert_rejects "rejects a value with the pinned ARN as a suffix" \
  "$PINNED" "evil${PINNED}"

assert_rejects "rejects a truncated prefix of the pinned ARN" \
  "$PINNED" "arn:aws:kms:us-east-1:123456789012:key/1a2b3c4d"

# No normalisation: KMS returns one canonical form; case-folding or trimming widens the trust
# surface for no benefit.
assert_rejects "rejects an ARN differing only in case" \
  "$PINNED" "$(printf '%s' "$PINNED" | tr '[:lower:]' '[:upper:]')"

assert_rejects "rejects an ARN with leading whitespace" "$PINNED" " $PINNED"
assert_rejects "rejects an ARN with a trailing newline" "$PINNED" "$PINNED
"

# Source: must decrypt against the pinned ARN, not user-data — swap is undetectable at runtime
# (canonical in kms-init.nix).
KMS_INIT_NIX="$PROJECT_DIR/kms-init.nix"
DECRYPT_LINE=$(grep -n 'nitro-tpm-kms-decrypt' "$KMS_INIT_NIX" 2>/dev/null)
# shellcheck disable=SC2016  # the literal shell variable name is what we match
# (Hoisted from elif: shellcheck directive on an elif branch triggers SC1123 and silently stops checking the rest of the file.)
PINNED_IN_DECRYPT=$(printf '%s' "$DECRYPT_LINE" | grep -c -- '--key-id "\$PINNED_KMS_KEY_ARN"')

if [ -z "$DECRYPT_LINE" ]; then
  fail "source: no nitro-tpm-kms-decrypt invocation found in kms-init.nix"
elif [ "$PINNED_IN_DECRYPT" -gt 0 ]; then
  pass "source: kms-init.nix decrypts against the pinned ARN"
else
  fail "source: kms-init.nix must pass --key-id \"\$PINNED_KMS_KEY_ARN\" to nitro-tpm-kms-decrypt, got: $DECRYPT_LINE"
fi

printf '\n%d passed, %d failed\n' "$PASS_COUNT" "$FAIL_COUNT"
[ "$FAIL_COUNT" -eq 0 ] || exit 1
