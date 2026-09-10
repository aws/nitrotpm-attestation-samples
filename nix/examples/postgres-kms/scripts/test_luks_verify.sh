#!/bin/bash
#
# Unit tests for luks-verify.sh — guards against operator-forged LUKS2 headers
# (cipher_null-ecb swap, stripped integrity). Pure text->verdict fixtures: bash + jq only.

set -u

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_DIR="$( cd "$SCRIPT_DIR/.." &> /dev/null && pwd )"

# shellcheck source-path=SCRIPTDIR/..
# shellcheck source=luks-verify.sh
. "$PROJECT_DIR/luks-verify.sh"

GREEN="\033[32m"
RED="\033[31m"
RESET="\033[0m"

PASS_COUNT=0
FAIL_COUNT=0

pass() { PASS_COUNT=$((PASS_COUNT + 1)); printf "${GREEN}PASS${RESET} %s\n" "$1"; }
fail() { FAIL_COUNT=$((FAIL_COUNT + 1)); printf "${RED}FAIL${RESET} %s\n" "$1"; }

# Exit-code contract: 0=accept, 1=reject; other codes are harness errors (see test_kms_verify.sh).

assert_accepts() {
  local name=$1 fn=$2 input=$3 err rc
  err=$("$fn" "$input" 2>&1); rc=$?
  if [ "$rc" -eq 0 ]; then
    pass "$name"
  else
    fail "$name -- expected accept (0), got $rc: $err"
  fi
}

assert_rejects() {
  local name=$1 fn=$2 input=$3 err rc
  err=$("$fn" "$input" 2>&1); rc=$?
  case "$rc" in
    1) pass "$name" ;;
    0) fail "$name -- expected reject (1), but input was accepted" ;;
    *) fail "$name -- expected reject (1), got status $rc: $err" ;;
  esac
}

# assert_rejects_because: pins the rejection reason — a check that rejects for the wrong reason
# is undetectable otherwise.
assert_rejects_because() {
  local name=$1 fn=$2 input=$3 want=$4 err rc
  err=$("$fn" "$input" 2>&1); rc=$?
  if [ "$rc" -ne 1 ]; then
    fail "$name -- expected reject (1), got status $rc: $err"
    return
  fi
  case "$err" in
    *"$want"*) pass "$name" ;;
    *) fail "$name -- rejected, but not because of '$want': $err" ;;
  esac
}

# header_json <encryption> <sector_size-as-raw-json> [integrity-type]
# Empty third arg omits integrity entirely, modelling an attacker who strips data authentication.
header_json() {
  local enc=$1 ss=$2 integ=${3:-}
  local base
  # shellcheck disable=SC2016  # $enc is a jq --arg binding, not a shell variable
  base='{
    keyslots: {"0": {
      type: "luks2", key_size: 96,
      kdf: {type: "argon2id", time: 4, memory: 1048576, cpus: 4},
      af: {type: "luks1", stripes: 4000, hash: "sha256"}
    }},
    tokens: {},
    segments: {"0": {
      type: "crypt", offset: "16777216", size: "dynamic", iv_tweak: "0",
      encryption: $enc, sector_size: '"$ss"'
    }},
    digests: {"0": {type: "pbkdf2", keyslots: ["0"], segments: ["0"]}},
    config: {json_size: "12288", keyslots_size: "16744448"}
  }'
  if [ -n "$integ" ]; then
    jq -nc --arg enc "$enc" --arg it "$integ" \
      "$base | .segments[\"0\"].integrity =
         {type: \$it, journal_encryption: \"none\", journal_integrity: \"none\"}"
  else
    jq -nc --arg enc "$enc" "$base"
  fi
}

# status_text <cipher> <keysize-value> [integrity-type]
# Models `cryptsetup status data` output. keysize is COMBINED (512 XTS + 256 HMAC = 768); 2.8.x
# brackets units ("768 [bits]"), <=2.7.5 does not.
status_text() {
  local cipher=$1 keysize=$2 integ=${3:-}
  printf '/dev/mapper/data is active.\n'
  printf '  type:    LUKS2\n'
  printf '  cipher:  %s\n' "$cipher"
  printf '  keysize: %s\n' "$keysize"
  printf '  key location: keyring\n'
  if [ -n "$integ" ]; then
    printf '  integrity: %s\n' "$integ"
    printf '  integrity keysize: 256 [bits]\n'
    printf '  integrity tag size: 32 [bytes] \n'
  fi
  printf '  device:  /dev/nvme1n1\n'
  printf '  sector size:  %s\n' "${4:-4096 [bytes]}"
  printf '  offset:  0 [512-byte units] (0 [bytes])\n'
  printf '  mode:    read/write\n'
}

GOOD_HEADER=$(header_json aes-xts-plain64 4096 'hmac(sha256)')

assert_accepts "header: accepts pinned aes-xts-plain64 + hmac(sha256) @ 4096" \
  luks_verify_header_json "$GOOD_HEADER"

assert_rejects "header: rejects cipher_null-ecb segment (the plant primitive)" \
  luks_verify_header_json "$(header_json cipher_null-ecb 4096 'hmac(sha256)')"

assert_rejects "header: rejects header with data authentication stripped" \
  luks_verify_header_json "$(header_json aes-xts-plain64 4096 '')"

assert_rejects "header: rejects unexpected integrity algorithm" \
  luks_verify_header_json "$(header_json aes-xts-plain64 4096 'hmac(sha1)')"

assert_rejects "header: rejects unexpected sector_size" \
  luks_verify_header_json "$(header_json aes-xts-plain64 512 'hmac(sha256)')"

assert_accepts "header: accepts sector_size rendered as a JSON string" \
  luks_verify_header_json "$(header_json aes-xts-plain64 '"4096"' 'hmac(sha256)')"

assert_rejects "header: rejects more than one segment" \
  luks_verify_header_json "$(jq -c '.segments["1"] = .segments["0"]' <<<"$GOOD_HEADER")"

assert_rejects "header: rejects a segment that is not type crypt" \
  luks_verify_header_json "$(jq -c '.segments["0"].type = "linear"' <<<"$GOOD_HEADER")"

assert_rejects "header: rejects a second keyslot (attacker-added unlock path)" \
  luks_verify_header_json "$(jq -c '.keyslots["1"] = .keyslots["0"]' <<<"$GOOD_HEADER")"

assert_rejects "header: rejects zero keyslots" \
  luks_verify_header_json "$(jq -c '.keyslots = {}' <<<"$GOOD_HEADER")"

assert_rejects "header: rejects a short keyslot key (integrity key dropped)" \
  luks_verify_header_json "$(jq -c '.keyslots["0"].key_size = 64' <<<"$GOOD_HEADER")"

assert_rejects "header: rejects a one-byte keyslot key" \
  luks_verify_header_json "$(jq -c '.keyslots["0"].key_size = 1' <<<"$GOOD_HEADER")"

assert_rejects "header: rejects a keyslot that is not type luks2" \
  luks_verify_header_json "$(jq -c '.keyslots["0"].type = "reencrypt"' <<<"$GOOD_HEADER")"

assert_rejects "header: rejects a downgraded keyslot KDF" \
  luks_verify_header_json "$(jq -c '.keyslots["0"].kdf.type = "pbkdf2"' <<<"$GOOD_HEADER")"

assert_rejects "header: rejects a missing keyslot KDF" \
  luks_verify_header_json "$(jq -c 'del(.keyslots["0"].kdf)' <<<"$GOOD_HEADER")"

assert_rejects "header: rejects a digest bound to a different keyslot" \
  luks_verify_header_json "$(jq -c '.digests["0"].keyslots = ["1"]' <<<"$GOOD_HEADER")"

assert_rejects "header: rejects a digest bound to a different segment" \
  luks_verify_header_json "$(jq -c '.digests["0"].segments = ["1"]' <<<"$GOOD_HEADER")"

assert_rejects "header: rejects a second digest" \
  luks_verify_header_json "$(jq -c '.digests["1"] = .digests["0"]' <<<"$GOOD_HEADER")"

assert_rejects "header: rejects any token (alternative unlock path)" \
  luks_verify_header_json "$(jq -c '.tokens["0"] = {type: "systemd-tpm2"}' <<<"$GOOD_HEADER")"

assert_rejects "header: rejects malformed JSON" \
  luks_verify_header_json "not json at all"

assert_rejects "header: rejects empty input" \
  luks_verify_header_json ""

assert_accepts "status: accepts active mapping with pinned parameters" \
  luks_verify_status "$(status_text aes-xts-plain64 '768 [bits]' 'hmac(sha256)')"

assert_rejects_because "status: rejects cipher_null active mapping" \
  luks_verify_status "$(status_text cipher_null-ecb '768 [bits]' 'hmac(sha256)')" \
  "active cipher"

assert_rejects_because "status: rejects mapping with no integrity layer" \
  luks_verify_status "$(status_text aes-xts-plain64 '512 [bits]' '')" \
  "data authentication is not active"

# 512 is the encryption-only key size; the mapping must report combined 768 — seeing 512 means
# no integrity key.
assert_rejects_because "status: rejects encryption-only keysize (512, integrity key missing)" \
  luks_verify_status "$(status_text aes-xts-plain64 '512 [bits]' 'hmac(sha256)')" \
  "active keysize"

# cryptsetup changed unit format at 2.8.x; key off the number, not the suffix, or a nixpkgs
# bump silently bricks the volume.
assert_accepts "status: accepts keysize rendered as '768 bits' (<= v2.7.5)" \
  luks_verify_status "$(status_text aes-xts-plain64 '768 bits' 'hmac(sha256)')"

assert_accepts "status: accepts keysize rendered as '768 [bits]' (2.8.x)" \
  luks_verify_status "$(status_text aes-xts-plain64 '768 [bits]' 'hmac(sha256)')"

assert_rejects_because "status: rejects wrong keysize in the older 'bits' format" \
  luks_verify_status "$(status_text aes-xts-plain64 '256 bits' 'hmac(sha256)')" \
  "active keysize"

# A substring match reads 768 from "integrity keysize:" and passes; assert_rejects_because
# catches the wrong-reason case.
assert_rejects_because "status: does not confuse 'integrity keysize:' with 'keysize:'" \
  luks_verify_status "$(printf '  cipher:  aes-xts-plain64\n  integrity keysize: 768 [bits]\n  keysize: 256 [bits]\n  integrity: hmac(sha256)\n')" \
  "active keysize"

assert_rejects_because "status: rejects wrong sector size on the active mapping" \
  luks_verify_status "$(status_text aes-xts-plain64 '768 [bits]' 'hmac(sha256)' '512 [bytes]')" \
  "active sector size"

assert_rejects_because "status: rejects a mapping with no sector size reported" \
  luks_verify_status "$(printf '  cipher:  aes-xts-plain64\n  integrity: hmac(sha256)\n  keysize: 768 [bits]\n')" \
  "no sector size"

assert_rejects "status: rejects empty input" \
  luks_verify_status ""

printf '\n%d passed, %d failed\n' "$PASS_COUNT" "$FAIL_COUNT"
[ "$FAIL_COUNT" -eq 0 ] || exit 1
