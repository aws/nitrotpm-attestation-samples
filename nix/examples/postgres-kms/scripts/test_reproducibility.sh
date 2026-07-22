#!/bin/bash
#
# Tests reproducibility of the postgres-kms image builds.
#
#   Test 1 - PCR4 reproducibility: two nix builds from the same locked flake
#            produce identical unsigned UKI measurements.
#   Test 2 - PCR7 reproducibility (identity reuse): same identity, ESLs rebuilt
#            twice -> PCR7 identical. Proves the --secrets-manager path is
#            deterministic.
#   Test 3 - PCR7 is image-independent: same identity, two differently-mutated
#            UKIs -> PCR4 differs, PCR7 identical.
#
# None of these tests call AWS. Usage:
#   ./scripts/test_reproducibility.sh [--debug]

set -u

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_DIR="$( cd "$SCRIPT_DIR/.." &> /dev/null && pwd )"
TEST_DIR="$PROJECT_DIR/.test-repro"

# shellcheck source=lib/identity.sh
. "$SCRIPT_DIR/lib/identity.sh"

GREEN="\033[32m"
RED="\033[31m"
YELLOW="\033[33m"
RESET="\033[0m"

PASS_COUNT=0
FAIL_COUNT=0

DEBUG=false
while [[ $# -gt 0 ]]; do
  case $1 in
    --debug) DEBUG=true; shift ;;
    *) echo "Unknown option $1"; exit 1 ;;
  esac
done

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
    PASS_COUNT=$((PASS_COUNT + 1))
  else
    echo -e "${RED}FAIL${RESET} $label: ${pcr} unexpectedly matches"
    echo "  value: $val_a"
    FAIL_COUNT=$((FAIL_COUNT + 1))
  fi
}

# Generate a one-time identity (PK/KEK/db keys + certs + fixed GUID).
generate_identity() {
  local out_dir="$1"
  mkdir -p "$out_dir"

  nix --extra-experimental-features nix-command --extra-experimental-features flakes shell \
    nixpkgs#openssl nixpkgs#util-linux --command bash -c "
    cd '$out_dir'
    uuidgen --random > GUID.txt
    openssl req -newkey rsa:4096 -nodes -keyout PK.key -new -x509 -sha256 -days 3650 -subj '/CN=Platform key/' -out PK.crt 2>/dev/null
    openssl req -newkey rsa:4096 -nodes -keyout KEK.key -new -x509 -sha256 -days 3650 -subj '/CN=Key Exchange Key/' -out KEK.crt 2>/dev/null
    openssl req -newkey rsa:4096 -nodes -keyout db.key -new -x509 -sha256 -days 3650 -subj '/CN=Signature Database key/' -out db.crt 2>/dev/null
  " >/dev/null 2>&1

  chmod 0600 "$out_dir/PK.key" "$out_dir/KEK.key" "$out_dir/db.key"
}

# Rebuild ESLs from the persisted certs + fixed GUID (the --secrets-manager model).
prepare_keys_from_identity() {
  local dest="$1" identity="$2"
  mkdir -p "$dest"
  cp "$identity/GUID.txt" "$identity/PK.crt" "$identity/KEK.crt" \
     "$identity/db.crt" "$identity/db.key" "$dest/"

  nix --extra-experimental-features nix-command --extra-experimental-features flakes shell \
    nixpkgs#efitools --command bash -c "
    cd '$dest'
    cert-to-efi-sig-list -g \"\$(cat GUID.txt)\" PK.crt PK.esl
    cert-to-efi-sig-list -g \"\$(cat GUID.txt)\" KEK.crt KEK.esl
    cert-to-efi-sig-list -g \"\$(cat GUID.txt)\" db.crt db.esl
  " >/dev/null 2>&1

  chmod 0600 "$dest/db.key"
}

# Copy the unsigned build output into an isolated writable dir.
prepare_image_dir() {
  local src="$1" out_dir="$2"
  rm -rf "$out_dir"
  mkdir -p "$out_dir"
  cp -r "$src/." "$out_dir/"
  chmod -R u+w "$out_dir"
}

# Mutate the unsigned UKI so PCR4 changes between runs.
mutate_uki() {
  local image_dir="$1" marker="$2"
  nix --extra-experimental-features nix-command --extra-experimental-features flakes shell \
    nixpkgs#binutils nixpkgs#coreutils --command bash -c "
    cd '$image_dir'
    off=\$(objdump -h unsigned.efi | awk '\$2==\".linux\"{print \$6}')
    if [ -z \"\$off\" ]; then
      echo 'mutate_uki: .linux section not found in unsigned.efi' >&2
      exit 1
    fi
    printf '%s' '$marker' | dd of=unsigned.efi bs=1 seek=\$((16#\$off)) conv=notrunc status=none
  " >/dev/null
}

# Sign the UKI and capture PCR4+PCR7.
sign_and_compute_pcrs() {
  local image_dir="$1" keys_dir="$2"
  nix --extra-experimental-features nix-command --extra-experimental-features flakes \
    run .#sign-efi-image -- "$image_dir" "$keys_dir" \
    > "$image_dir/tpm_pcr.json" 2>/dev/null
}

# ------------------------------------------------------------------------

cd "$PROJECT_DIR"

NIX="nix --extra-experimental-features nix-command --extra-experimental-features flakes"
PACKAGE="raw-image"
[ "$DEBUG" = true ] && PACKAGE="raw-image-debug"

echo "===================================================="
echo " Postgres-KMS Reproducibility Test"
echo "===================================================="
echo

# ==== Test 1: PCR4 reproducibility (two builds) ====
echo "----------------------------------------------------"
echo " Test 1: PCR4 reproducibility (two nix builds)"
echo "         EXPECT: PCR4 identical"
echo "----------------------------------------------------"

run_step "Build A" $NIX build .#"$PACKAGE" --out-link "$TEST_DIR/result-a"
run_step "Build B (--rebuild)" $NIX build .#"$PACKAGE" --rebuild --out-link "$TEST_DIR/result-b"

PCR_A="$TEST_DIR/result-a/tpm_pcr.json"
PCR_B="$TEST_DIR/result-b/tpm_pcr.json"

echo
assert_pcr_match "PCR4 (unsigned UKI, two builds)" "$PCR_A" "$PCR_B" "PCR4"
echo

# ==== Test 2: PCR7 reproducibility (identity reuse) ====
echo "----------------------------------------------------"
echo " Test 2: PCR7 reproducibility (identity reuse)"
echo "         persisted certs + fixed GUID, ESLs rebuilt"
echo "         EXPECT: PCR4 + PCR7 identical"
echo "----------------------------------------------------"

mkdir -p "$TEST_DIR"
IDENTITY="$TEST_DIR/identity"
run_step "Generating golden identity (once)" generate_identity "$IDENTITY"

KEYS2A="$TEST_DIR/keys2a"
KEYS2B="$TEST_DIR/keys2b"
RUN2A="$TEST_DIR/run2a"
RUN2B="$TEST_DIR/run2b"

run_step "Run 2A: prepare keys (rebuild ESLs from identity)" prepare_keys_from_identity "$KEYS2A" "$IDENTITY"
run_step "Run 2A: prepare image dir" prepare_image_dir "$TEST_DIR/result-a" "$RUN2A"
run_step "Run 2A: sign + compute PCRs" sign_and_compute_pcrs "$RUN2A" "$KEYS2A"
run_step "Run 2B: prepare keys (rebuild ESLs from identity)" prepare_keys_from_identity "$KEYS2B" "$IDENTITY"
run_step "Run 2B: prepare image dir" prepare_image_dir "$TEST_DIR/result-b" "$RUN2B"
run_step "Run 2B: sign + compute PCRs" sign_and_compute_pcrs "$RUN2B" "$KEYS2B"

echo
assert_pcr_match "PCR4 (UKI hash, unchanged)" "$RUN2A/tpm_pcr.json" "$RUN2B/tpm_pcr.json" "PCR4"
assert_pcr_match "PCR7 (secure boot policy, identity reuse)" "$RUN2A/tpm_pcr.json" "$RUN2B/tpm_pcr.json" "PCR7"
echo

# ==== Test 3: PCR7 is image-independent ====
echo "----------------------------------------------------"
echo " Test 3: same identity, DIFFERENT image each run"
echo "         EXPECT: PCR4 differs, PCR7 identical"
echo "----------------------------------------------------"

KEYS3A="$TEST_DIR/keys3a"
KEYS3B="$TEST_DIR/keys3b"
RUN3A="$TEST_DIR/run3a"
RUN3B="$TEST_DIR/run3b"

run_step "Run 3A: prepare keys" prepare_keys_from_identity "$KEYS3A" "$IDENTITY"
run_step "Run 3A: prepare image dir" prepare_image_dir "$TEST_DIR/result-a" "$RUN3A"
run_step "Run 3A: mutate UKI" mutate_uki "$RUN3A" "PCR4-VARIANT-A"
run_step "Run 3A: sign + compute PCRs" sign_and_compute_pcrs "$RUN3A" "$KEYS3A"
run_step "Run 3B: prepare keys" prepare_keys_from_identity "$KEYS3B" "$IDENTITY"
run_step "Run 3B: prepare image dir" prepare_image_dir "$TEST_DIR/result-b" "$RUN3B"
run_step "Run 3B: mutate UKI" mutate_uki "$RUN3B" "PCR4-VARIANT-B"
run_step "Run 3B: sign + compute PCRs" sign_and_compute_pcrs "$RUN3B" "$KEYS3B"

echo
assert_pcr_differ "PCR4 (UKI hash, distinct images)" "$RUN3A/tpm_pcr.json" "$RUN3B/tpm_pcr.json" "PCR4"
assert_pcr_match  "PCR7 (secure boot policy, image-independent)" "$RUN3A/tpm_pcr.json" "$RUN3B/tpm_pcr.json" "PCR7"
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
