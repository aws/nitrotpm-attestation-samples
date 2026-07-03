#!/bin/bash
#
# Tests the reproducibility of the secure boot signing pipeline by computing
# PCR7 (the UEFI secure boot policy measurement) under the two key-reuse
# models --secrets-manager can implement.
#
# PCR7 measures the byte-exact contents of the PK/KEK/db EFI Signature Lists
# (ESLs). Each ESL embeds the owner GUID and the DER-encoded certificate, so
# ANY change to the GUID or to a PK/KEK/db cert changes PCR7.
#
#   Test 1 - CURRENT model (db-only reuse): NOT reproducible.
#     --secrets-manager persists only db.key/db.crt. PK/KEK and the owner
#     GUID are regenerated fresh every run, so PCR7 differs every run. This
#     is the reproducibility gap reported in PR #18 (r3513426905).
#
#   Test 2 - FIXED model (identity reuse): reproducible.
#     The full golden identity is persisted as certs + a fixed GUID
#     (db.key/db.crt + PK.crt/KEK.crt + GUID). The ESLs are rebuilt from
#     those fixed inputs each run. cert-to-efi-sig-list is byte-deterministic
#     given a fixed cert + GUID (the ESL format carries no timestamps), so
#     PCR7 is identical across runs. PK/KEK private keys are never needed
#     (the uefivars '-i none' model consumes ESLs, not .auth files).
#
#   Test 3 - PCR7 is image-independent.
#     Same golden identity, but two DIFFERENT UKIs (the unsigned image is
#     mutated between runs so PCR4 changes). PCR4 must differ and PCR7 must
#     stay identical, proving PCR7 is a pure function of the enrolled key set
#     and never measures the image. The test also breaks if PCR4 fails to
#     change (the mutation was a no-op, so the invariant went untested).
#
# PCR4 (UKI content hash) tracks the image: it is independent of the signing
# keys and stays stable only while the unsigned UKI is unchanged (Tests 1-2),
# and changes when the image changes (Test 3).
#
# Does NOT call AWS. Exercises only the build/sign/PCR-compute phases via the
# flake apps (sign-efi-image computes the PCRs it prints). The key-prep
# helpers mirror the corresponding branches of scripts/start.sh; keep them in
# sync when that logic changes.
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

# Generates a one-time secure boot identity (PK/KEK/db keys + certs + a fixed
# owner GUID) into the given directory. This models the golden identity that
# --secrets-manager generates once and persists. PK.key/KEK.key are produced
# for completeness but are NOT part of the reproducible reuse set.
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

# FIXED model: rebuild the ESL set from the persisted certs + fixed GUID, as
# the fixed --secrets-manager path in start.sh does. No PK/KEK private keys
# and no new GUID are involved, so the ESL bytes -- and thus PCR7 -- are
# identical across runs.
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

# CURRENT model: reuse only db.key/db.crt; regenerate PK/KEK and the owner
# GUID fresh every run (mirrors today's --secrets-manager envelope block).
# The fresh PK/KEK certs and random GUID change the PK/KEK/db ESL bytes, so
# PCR7 differs every run -- the bug this fix addresses.
prepare_keys_db_only() {
  local dest="$1" identity="$2"
  mkdir -p "$dest"
  cp "$identity/db.crt" "$identity/db.key" "$dest/"

  nix --extra-experimental-features nix-command --extra-experimental-features flakes shell \
    nixpkgs#openssl nixpkgs#efitools nixpkgs#util-linux --command bash -c "
    cd '$dest'
    uuidgen --random > GUID.txt

    openssl req -newkey rsa:4096 -nodes -keyout PK.key -new -x509 -sha256 -days 3650 -subj '/CN=Platform key/' -out PK.crt 2>/dev/null
    openssl req -newkey rsa:4096 -nodes -keyout KEK.key -new -x509 -sha256 -days 3650 -subj '/CN=Key Exchange Key/' -out KEK.crt 2>/dev/null

    cert-to-efi-sig-list -g \"\$(cat GUID.txt)\" PK.crt PK.esl
    cert-to-efi-sig-list -g \"\$(cat GUID.txt)\" KEK.crt KEK.esl
    cert-to-efi-sig-list -g \"\$(cat GUID.txt)\" db.crt db.esl
  " >/dev/null 2>&1

  chmod 0600 "$dest/db.key"
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

# Mutates the unsigned UKI in <image-dir> so its Authenticode hash -- and thus
# PCR4 -- changes, simulating a genuinely different application image. It
# overwrites a few bytes inside the .linux (kernel) section IN PLACE: same
# size, same section layout, so the result is still a valid, signable PE, but
# the whole-PE hash differs. <marker> is distinct per run, so two mutated
# images differ deterministically (no reliance on randomness).
#
# PCR7 measures only the PK/KEK/db ESLs, never the image, so this mutation
# must NOT affect PCR7 -- which is exactly what Test 3 asserts.
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

# Signs the unsigned UKI in <image-dir> with the keys in <keys-dir>, then
# computes PCR4+PCR7 against the signed UKI. Mirrors the sequence used by
# scripts/steps/00_create_ami.sh.
sign_and_compute_pcrs() {
  local image_dir="$1"
  local keys_dir="$2"

  # sign-efi-image also computes the PCR set and prints it to stdout;
  # progress goes to stderr, so redirect stdout into tpm_pcr.json.
  nix --extra-experimental-features nix-command --extra-experimental-features flakes \
    run .#sign-efi-image -- "$image_dir" "$keys_dir" \
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

# The golden identity is generated ONCE and reused by both tests, exactly as
# --secrets-manager generates it once and persists it in Secrets Manager.
IDENTITY="$TEST_DIR/identity"
run_step "Generating golden secure boot identity (once)" \
  generate_identity "$IDENTITY"
echo

# ==== Test 1: CURRENT model - db-only reuse is NOT reproducible ====
echo "----------------------------------------------------"
echo " Test 1: db-only reuse (current --secrets-manager)"
echo "         fresh PK/KEK + random GUID each run"
echo "         EXPECT: PCR7 differs (reproducibility gap)"
echo "----------------------------------------------------"

KEYS1A="$TEST_DIR/keys1a"
KEYS1B="$TEST_DIR/keys1b"
RUN1A="$TEST_DIR/run1a"
RUN1B="$TEST_DIR/run1b"

run_step "Run 1A: prepare keys (db reused, PK/KEK/GUID fresh)" prepare_keys_db_only "$KEYS1A" "$IDENTITY"
run_step "Run 1A: prepare image dir"                          prepare_image_dir "$RUN1A"
run_step "Run 1A: sign + compute PCRs"                        sign_and_compute_pcrs "$RUN1A" "$KEYS1A"
run_step "Run 1B: prepare keys (db reused, PK/KEK/GUID fresh)" prepare_keys_db_only "$KEYS1B" "$IDENTITY"
run_step "Run 1B: prepare image dir"                          prepare_image_dir "$RUN1B"
run_step "Run 1B: sign + compute PCRs"                        sign_and_compute_pcrs "$RUN1B" "$KEYS1B"

echo
assert_pcr_match  "PCR4 (UKI hash, key-independent)" \
  "$RUN1A/tpm_pcr.json" "$RUN1B/tpm_pcr.json" "PCR4"
assert_pcr_differ "PCR7 (secure boot policy, db-only reuse)" \
  "$RUN1A/tpm_pcr.json" "$RUN1B/tpm_pcr.json" "PCR7"
echo

# ==== Test 2: FIXED model - identity reuse IS reproducible ====
echo "----------------------------------------------------"
echo " Test 2: identity reuse (fixed --secrets-manager)"
echo "         persisted certs + fixed GUID, ESLs rebuilt"
echo "         EXPECT: PCR7 identical (reproducible)"
echo "----------------------------------------------------"

KEYS2A="$TEST_DIR/keys2a"
KEYS2B="$TEST_DIR/keys2b"
RUN2A="$TEST_DIR/run2a"
RUN2B="$TEST_DIR/run2b"

run_step "Run 2A: prepare keys (rebuild ESLs from identity)" prepare_keys_from_identity "$KEYS2A" "$IDENTITY"
run_step "Run 2A: prepare image dir"                         prepare_image_dir "$RUN2A"
run_step "Run 2A: sign + compute PCRs"                       sign_and_compute_pcrs "$RUN2A" "$KEYS2A"
run_step "Run 2B: prepare keys (rebuild ESLs from identity)" prepare_keys_from_identity "$KEYS2B" "$IDENTITY"
run_step "Run 2B: prepare image dir"                         prepare_image_dir "$RUN2B"
run_step "Run 2B: sign + compute PCRs"                       sign_and_compute_pcrs "$RUN2B" "$KEYS2B"

echo
assert_pcr_match  "PCR4 (UKI hash, unchanged)" \
  "$RUN2A/tpm_pcr.json" "$RUN2B/tpm_pcr.json" "PCR4"
assert_pcr_match  "PCR7 (secure boot policy, identity reuse)" \
  "$RUN2A/tpm_pcr.json" "$RUN2B/tpm_pcr.json" "PCR7"
echo

# ==== Test 3: PCR7 is image-independent (PCR4 changes, PCR7 does not) ====
echo "----------------------------------------------------"
echo " Test 3: same identity, DIFFERENT image each run"
echo "         EXPECT: PCR4 differs, PCR7 identical"
echo "         (PCR7 is a function of the identity only)"
echo "----------------------------------------------------"

KEYS3A="$TEST_DIR/keys3a"
KEYS3B="$TEST_DIR/keys3b"
RUN3A="$TEST_DIR/run3a"
RUN3B="$TEST_DIR/run3b"

# Reuse the SAME golden identity for both runs (as Test 2 does), but sign two
# DIFFERENT UKIs. Each image dir gets its own unsigned.efi mutated with a
# distinct marker, so PCR4 must differ; PCR7 must not, because it never
# measures the image.
run_step "Run 3A: prepare keys (rebuild ESLs from identity)" prepare_keys_from_identity "$KEYS3A" "$IDENTITY"
run_step "Run 3A: prepare image dir"                         prepare_image_dir "$RUN3A"
run_step "Run 3A: mutate UKI (changes PCR4)"                 mutate_uki "$RUN3A" "PCR4-VARIANT-A"
run_step "Run 3A: sign + compute PCRs"                       sign_and_compute_pcrs "$RUN3A" "$KEYS3A"
run_step "Run 3B: prepare keys (rebuild ESLs from identity)" prepare_keys_from_identity "$KEYS3B" "$IDENTITY"
run_step "Run 3B: prepare image dir"                         prepare_image_dir "$RUN3B"
run_step "Run 3B: mutate UKI (changes PCR4)"                 mutate_uki "$RUN3B" "PCR4-VARIANT-B"
run_step "Run 3B: sign + compute PCRs"                       sign_and_compute_pcrs "$RUN3B" "$KEYS3B"

echo
# If PCR4 does NOT differ here the mutation did not take effect, so Test 3
# would prove nothing -- assert_pcr_differ fails and flags that explicitly.
assert_pcr_differ "PCR4 (UKI hash, distinct images)" \
  "$RUN3A/tpm_pcr.json" "$RUN3B/tpm_pcr.json" "PCR4"
assert_pcr_match  "PCR7 (secure boot policy, image-independent)" \
  "$RUN3A/tpm_pcr.json" "$RUN3B/tpm_pcr.json" "PCR7"
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
