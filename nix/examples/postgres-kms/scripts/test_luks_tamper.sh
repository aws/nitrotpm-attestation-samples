#!/bin/bash
#
# Integration test: real loopback volumes vs luks-verify.sh, proving fixtures model reality.
# Vols A-D: pinned ACCEPT, no-integrity REJECT, wrong-cipher REJECT, first-boot+rollback sequence.
# Requires: Linux, root, dm-integrity, cryptsetup, jq. Usage: sudo $0 [/path/to/cryptsetup]

set -u

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_DIR="$( cd "$SCRIPT_DIR/.." &> /dev/null && pwd )"

# shellcheck source-path=SCRIPTDIR/..
# shellcheck source=luks-verify.sh
. "$PROJECT_DIR/luks-verify.sh"

CRYPTSETUP="${1:-cryptsetup}"

GREEN="\033[32m"
RED="\033[31m"
RESET="\033[0m"
PASS_COUNT=0
FAIL_COUNT=0
pass() { PASS_COUNT=$((PASS_COUNT + 1)); printf "${GREEN}PASS${RESET} %s\n" "$1"; }
fail() { FAIL_COUNT=$((FAIL_COUNT + 1)); printf "${RED}FAIL${RESET} %s\n" "$1"; }

[ "$(id -u)" -eq 0 ] || { echo "must run as root (losetup + device-mapper)"; exit 1; }
command -v "$CRYPTSETUP" >/dev/null || { echo "cryptsetup not found: $CRYPTSETUP"; exit 1; }

WORK=$(mktemp -d)
KEYFILE="$WORK/key"
LOOPS=""
LOOP_DEV=""
MAP=""

cleanup() {
  [ -n "$MAP" ] && "$CRYPTSETUP" close "$MAP" 2>/dev/null
  for l in $LOOPS; do losetup -d "$l" 2>/dev/null; done
  rm -rf "$WORK"
}
trap cleanup EXIT

head -c 32 /dev/urandom | base64 > "$KEYFILE"

# new_loop sets $LOOP_DEV (not echoed for capture: subshell would lose $LOOPS append, leaking
# loop devices).
new_loop() {
  local img="$WORK/$1.img"
  truncate -s 64M "$img"
  LOOP_DEV=$(losetup --find --show "$img") || return 1
  LOOPS="$LOOPS $LOOP_DEV"
}

echo "cryptsetup: $("$CRYPTSETUP" --version)"
echo

echo "=== Volume A: pinned format ==="
new_loop a || { echo "losetup failed"; exit 1; }
LOOP_A=$LOOP_DEV
"$CRYPTSETUP" luksFormat --type luks2 \
  --cipher "$LUKS_EXPECTED_CIPHER" \
  --key-size "$LUKS_EXPECTED_KEYSIZE" \
  --integrity "$LUKS_EXPECTED_INTEGRITY_ARG" \
  --sector-size "$LUKS_EXPECTED_SECTOR_SIZE" \
  --pbkdf "$LUKS_EXPECTED_PBKDF" \
  --batch-mode "$LOOP_A" --key-file="$KEYFILE" \
  || { echo "luksFormat with the pinned parameters FAILED -- the format itself is wrong"; exit 1; }

META_A=$("$CRYPTSETUP" luksDump --dump-json-metadata "$LOOP_A")
echo "--- real segments[0] ---"
echo "$META_A" | jq -c '.segments["0"]'

if luks_verify_header_json "$META_A"; then
  pass "real pinned header is accepted by luks_verify_header_json"
else
  fail "real pinned header was REJECTED -- fixtures do not match reality"
fi

"$CRYPTSETUP" open --type luks2 "$LOOP_A" tamper_test_a --key-file="$KEYFILE" \
  || { echo "luksOpen failed on volume A"; exit 1; }
MAP=tamper_test_a

STATUS_A=$("$CRYPTSETUP" status "$MAP")
echo "--- real status ---"
echo "$STATUS_A"

if luks_verify_status "$STATUS_A"; then
  pass "real active mapping is accepted by luks_verify_status"
else
  fail "real active mapping was REJECTED -- fixtures do not match reality"
fi

"$CRYPTSETUP" close "$MAP"
MAP=""
echo

echo "=== Volume B: --integrity omitted (authentication stripped) ==="
new_loop b || exit 1
LOOP_B=$LOOP_DEV
"$CRYPTSETUP" luksFormat --type luks2 \
  --cipher "$LUKS_EXPECTED_CIPHER" \
  --key-size "$LUKS_EXPECTED_KEYSIZE" \
  --sector-size "$LUKS_EXPECTED_SECTOR_SIZE" \
  --batch-mode "$LOOP_B" --key-file="$KEYFILE" || exit 1

META_B=$("$CRYPTSETUP" luksDump --dump-json-metadata "$LOOP_B")
echo "--- real segments[0] ---"
echo "$META_B" | jq -c '.segments["0"]'

if luks_verify_header_json "$META_B" 2>/dev/null; then
  fail "header without data authentication was ACCEPTED"
else
  pass "header without data authentication is rejected"
fi
echo

echo "=== Volume C: unexpected cipher, integrity intact ==="
new_loop c || exit 1
LOOP_C=$LOOP_DEV
if "$CRYPTSETUP" luksFormat --type luks2 \
  --cipher aes-cbc-essiv:sha256 --key-size 256 \
  --integrity "$LUKS_EXPECTED_INTEGRITY_ARG" \
  --sector-size "$LUKS_EXPECTED_SECTOR_SIZE" \
  --batch-mode "$LOOP_C" --key-file="$KEYFILE" 2>/dev/null; then
  META_C=$("$CRYPTSETUP" luksDump --dump-json-metadata "$LOOP_C")
  echo "--- real segments[0] ---"
  echo "$META_C" | jq -c '.segments["0"]'
  if luks_verify_header_json "$META_C" 2>/dev/null; then
    fail "header with an unexpected cipher was ACCEPTED"
  else
    pass "header with an unexpected cipher is rejected"
  fi
else
  echo "SKIP: kernel/cryptsetup would not create aes-cbc-essiv:sha256 + integrity"
fi

echo

# Volume D: format+open+mkfs is non-atomic; rollback zeroes LUKS2 metadata so isLuks fails and
# init retries.
echo "=== Volume D: first-boot sequence then rollback ==="
new_loop d || exit 1
LOOP_D=$LOOP_DEV
MKFS=$(command -v mkfs.ext4 || echo /sbin/mkfs.ext4)
DUMPE2FS=$(command -v dumpe2fs || echo /sbin/dumpe2fs)

"$CRYPTSETUP" luksFormat --type luks2 \
  --cipher "$LUKS_EXPECTED_CIPHER" \
  --key-size "$LUKS_EXPECTED_KEYSIZE" \
  --integrity "$LUKS_EXPECTED_INTEGRITY_ARG" \
  --sector-size "$LUKS_EXPECTED_SECTOR_SIZE" \
  --pbkdf "$LUKS_EXPECTED_PBKDF" \
  --batch-mode "$LOOP_D" --key-file="$KEYFILE" || exit 1
"$CRYPTSETUP" open --type luks2 "$LOOP_D" tamper_test_d --key-file="$KEYFILE" || exit 1
MAP=tamper_test_d

if luks_verify_status "$("$CRYPTSETUP" status "$MAP")" >/dev/null 2>&1 \
   && "$MKFS" -q /dev/mapper/"$MAP" 2>/dev/null \
   && "$DUMPE2FS" -h /dev/mapper/"$MAP" >/dev/null 2>&1; then
  pass "first-boot sequence yields a verified mapping with a mountable ext4"
else
  fail "first-boot sequence did not produce a usable filesystem"
fi

"$CRYPTSETUP" close "$MAP"
MAP=""

dd if=/dev/zero of="$LOOP_D" bs=1M count=16 conv=fsync status=none 2>/dev/null
if "$CRYPTSETUP" isLuks --type luks2 "$LOOP_D" 2>/dev/null; then
  fail "rollback left a LUKS2 header behind -- volume would stay stranded"
else
  pass "rollback clears the LUKS2 header so init retries on the next boot"
fi

echo
printf '%d passed, %d failed\n' "$PASS_COUNT" "$FAIL_COUNT"
[ "$FAIL_COUNT" -eq 0 ] || exit 1
