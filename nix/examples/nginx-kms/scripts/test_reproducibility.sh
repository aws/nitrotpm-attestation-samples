#!/bin/bash
#
# Tests the reproducibility of the secure boot signing pipeline.
#
# Validates two invariants by computing PCR7 (UEFI secure boot
# configuration measurement) under different key conditions:
#
#   1. REPRODUCIBLE: Same PK/KEK/db hierarchy → same PCR7 across runs.
#      This is what --secrets-manager (with the same ARN) guarantees.
#
#   2. NON-REPRODUCIBLE: Fresh PK/KEK/db each run → different PCR7
#      values. This is the default --secure-boot behavior.
#
# PCR4 (UKI content hash) is independent of signing keys and remains
# stable across all runs as long as the unsigned UKI is unchanged.
#
# Does NOT call AWS. Exercises only the build/sign/PCR-compute phases
# via the flake apps (sign-efi-image, compute-pcrs).
#
# Usage: ./scripts/test_reproducibility.sh

set -u

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_DIR="$( cd "$SCRIPT_DIR/.." &> /dev/null && pwd )"
TEST_DIR="$PROJECT_DIR/.test-repro"

GREEN="\033[32m"
RED="\033[31m"
YELLOW="\033[33m"
RESET="\033[0m"

PASS_COUNT=0
FAIL_COUNT=0

cleanup() {
  rm -rf "$TEST_DIR"
}
trap cleanup EXIT INT TERM

run_step() {
  local label="$1"
  shift
  echo -e "${YELLOW}>>> $label${RESET}"
  if ! "$@"; then
    echo -e "${RED}!!! Step failed: $label${RESET}"
    return 1
  fi
}

assert_pcr_match() {
  local label="$1" file_a="$2" file_b="$3" pcr="$4"
  local val_a val_b
  val_a=$(jq -r ".Measurements.${pcr} // empty" "$file_a")
  val_b=$(jq -r ".Measurements.${pcr} // empty" "$file_b")
  if [ -z "$val_a" ] || [ -z "$val_b" ]; then
    echo -e "${RED}FAIL${RESET} $label: ${pcr} missing"
    FAIL_COUNT=$((FAIL_COUNT + 1)); return
  fi
  if [ "$val_a" = "$val_b" ]; then
    echo -e "${GREEN}PASS${RESET} $label: ${pcr} matches"
    echo "  value: $val_a"
    PASS_COUNT=$((PASS_COUNT + 1))
  else
    echo -e "${RED}FAIL${RESET} $label: ${pcr} differs"
    echo "  run A: $val_a"
    echo "  run B: $val_b"
    FAIL_COUNT=$((FAIL_COUNT + 1))
  fi
}

assert_pcr_differ() {
  local label="$1" file_a="$2" file_b="$3" pcr="$4"
  local val_a val_b
  val_a=$(jq -r ".Measurements.${pcr} // empty" "$file_a")
  val_b=$(jq -r ".Measurements.${pcr} // empty" "$file_b")
  if [ -z "$val_a" ] || [ -z "$val_b" ]; then
    echo -e "${RED}FAIL${RESET} $label: ${pcr} missing"
    FAIL_COUNT=$((FAIL_COUNT + 1)); return
  fi
  if [ "$val_a" != "$val_b" ]; then
    echo -e "${GREEN}PASS${RESET} $label: ${pcr} differs as expected"
    echo "  run A: $val_a"
    echo "  run B: $val_b"
    PASS_COUNT=$((PASS_COUNT + 1))
  else
    echo -e "${RED}FAIL${RESET} $label: ${pcr} unexpectedly matches"
    echo "  value: $val_a"
    FAIL_COUNT=$((FAIL_COUNT + 1))
  fi
}

# Generates a full secure boot key hierarchy (PK/KEK/db keys + ESLs) into
# the given directory. Mirrors the openssl/efitools sequence used by
# scripts/start.sh.
generate_full_hierarchy() {
  local out_dir="$1"
  mkdir -p "$out_dir"

  nix --extra-experimental-features nix-command --extra-experimental-features flakes shell \
    nixpkgs#openssl nixpkgs#efitools nixpkgs#util-linux --command bash -c "
    cd '$out_dir'
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
  " >/dev/null 2>&1

  chmod 0600 "$out_dir/PK.key" "$out_dir/KEK.key" "$out_dir/db.key"
}

# Prepares an isolated, writable image directory by copying the unsigned
# build output. sign-efi-image patches the raw image's ESP in place, so
# each run needs its own copy.
prepare_image_dir() {
  local out_dir="$1"
  rm -rf "$out_dir"
  mkdir -p "$out_dir"
  cp -r "$PROJECT_DIR/result/." "$out_dir/"
  chmod -R u+w "$out_dir"
}

# Signs the unsigned UKI in <image-dir> with the keys in <keys-dir>, then
# computes PCR4+PCR7 against the signed UKI. Mirrors the sequence used by
# scripts/steps/00_create_ami.sh.
sign_and_compute_pcrs() {
  local image_dir="$1"
  local keys_dir="$2"

  nix --extra-experimental-features nix-command --extra-experimental-features flakes \
    run .#sign-efi-image -- "$image_dir" "$keys_dir" >/dev/null 2>&1

  nix --extra-experimental-features nix-command --extra-experimental-features flakes \
    run .#compute-pcrs -- \
    --image "$image_dir/signed.efi" \
    --PK "$keys_dir/PK.esl" \
    --KEK "$keys_dir/KEK.esl" \
    --db "$keys_dir/db.esl" \
    > "$image_dir/tpm_pcr.json" 2>/dev/null
}

# ------------------------------------------------------------------------

cd "$PROJECT_DIR"

echo "===================================================="
echo " Secure Boot Reproducibility Test"
echo "===================================================="
echo

run_step "Building unsigned UKI (nix, cached on subsequent runs)" \
  nix --extra-experimental-features nix-command --extra-experimental-features flakes \
  build .#raw-image
echo

if [ ! -f "result/unsigned.efi" ]; then
  echo -e "${RED}Error: result/unsigned.efi not produced by build${RESET}"
  exit 1
fi

mkdir -p "$TEST_DIR"

# ==== Test 1: REPRODUCIBILITY (fixed key hierarchy) ====
echo "----------------------------------------------------"
echo " Test 1: Reproducibility with fixed key hierarchy"
echo "         (simulates --secrets-manager with same ARN)"
echo "----------------------------------------------------"

FIXED_KEYS="$TEST_DIR/fixed-keys"
RUN1A="$TEST_DIR/run1a"
RUN1B="$TEST_DIR/run1b"

run_step "Generating fixed key hierarchy"        generate_full_hierarchy "$FIXED_KEYS"
run_step "Run 1A: prepare image dir"             prepare_image_dir "$RUN1A"
run_step "Run 1A: sign + compute PCRs"           sign_and_compute_pcrs "$RUN1A" "$FIXED_KEYS"
run_step "Run 1B: prepare image dir"             prepare_image_dir "$RUN1B"
run_step "Run 1B: sign + compute PCRs"           sign_and_compute_pcrs "$RUN1B" "$FIXED_KEYS"

echo
assert_pcr_match  "PCR4 (UKI hash, key-independent)" \
  "$RUN1A/tpm_pcr.json" "$RUN1B/tpm_pcr.json" "PCR4"
assert_pcr_match  "PCR7 (secure boot config, fixed keys)" \
  "$RUN1A/tpm_pcr.json" "$RUN1B/tpm_pcr.json" "PCR7"
echo

# ==== Test 2: NON-REPRODUCIBILITY (fresh key hierarchy each run) ====
echo "----------------------------------------------------"
echo " Test 2: Non-reproducibility with fresh keys each run"
echo "         (simulates --secure-boot without --secrets-manager)"
echo "----------------------------------------------------"

KEYS2A="$TEST_DIR/keys2a"
KEYS2B="$TEST_DIR/keys2b"
RUN2A="$TEST_DIR/run2a"
RUN2B="$TEST_DIR/run2b"

run_step "Run 2A: generate keys"                 generate_full_hierarchy "$KEYS2A"
run_step "Run 2A: prepare image dir"             prepare_image_dir "$RUN2A"
run_step "Run 2A: sign + compute PCRs"           sign_and_compute_pcrs "$RUN2A" "$KEYS2A"
run_step "Run 2B: generate keys"                 generate_full_hierarchy "$KEYS2B"
run_step "Run 2B: prepare image dir"             prepare_image_dir "$RUN2B"
run_step "Run 2B: sign + compute PCRs"           sign_and_compute_pcrs "$RUN2B" "$KEYS2B"

echo
assert_pcr_match  "PCR4 (UKI hash, unchanged)" \
  "$RUN2A/tpm_pcr.json" "$RUN2B/tpm_pcr.json" "PCR4"
assert_pcr_differ "PCR7 (secure boot config, fresh keys)" \
  "$RUN2A/tpm_pcr.json" "$RUN2B/tpm_pcr.json" "PCR7"
echo

# ==== Summary ====
echo "===================================================="
echo " Summary"
echo "===================================================="
echo -e "${GREEN}Passed: $PASS_COUNT${RESET}"
if [ $FAIL_COUNT -gt 0 ]; then
  echo -e "${RED}Failed: $FAIL_COUNT${RESET}"
  exit 1
else
  echo -e "Failed: 0"
  exit 0
fi
