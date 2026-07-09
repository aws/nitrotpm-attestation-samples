#!/bin/bash
#
# Tests reproducibility of the secure boot signing pipeline.
#
# PCR7 measures the byte-exact PK/KEK/db EFI Signature Lists (ESLs); each ESL
# embeds the owner GUID and the DER cert, so ANY change to the GUID or a cert
# changes PCR7. PCR4 (UKI content hash) tracks the image, not the keys.
#
#   Test 1 - db-only reuse (the old model): NOT reproducible. PK/KEK + GUID
#            regenerated each run -> PCR7 differs (the gap this fix closes).
#   Test 2 - identity reuse (fixed): reproducible. Full identity persisted, ESLs
#            rebuilt from fixed certs + GUID -> PCR7 identical.
#   Test 3 - PCR7 is image-independent: same identity, two different UKIs ->
#            PCR4 differs, PCR7 identical (also fails if the mutation was a no-op).
#   Test 4 - db.key never touches disk: sign via --identity-arn -> PCR7 equals
#            Test 2 and no db.key file exists. Needs AWS; skipped otherwise.
#   Test 5 - generate_identity_material writes no private key to disk.
#
# Tests 1-3, 5 do NOT call AWS; Test 4 does (throwaway secret, deleted after).
# The key-prep helpers mirror scripts/start.sh; keep them in sync.
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

# Generate a one-time identity (PK/KEK/db keys + certs + fixed GUID) into
# out_dir, modeling what --secrets-manager persists once.
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

# FIXED model: rebuild the ESLs from the persisted certs + fixed GUID (as
# start.sh's --secrets-manager path does). Includes db.key in the keys dir.
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

# NO-DISK model: like prepare_keys_from_identity but WITHOUT db.key on disk
# (public artifacts only); db.key comes via --identity-arn. Used by Test 4.
prepare_keys_no_dbkey() {
  local dest="$1" identity="$2"
  mkdir -p "$dest"
  cp "$identity/GUID.txt" "$identity/PK.crt" "$identity/KEK.crt" \
     "$identity/db.crt" "$dest/"

  nix --extra-experimental-features nix-command --extra-experimental-features flakes shell \
    nixpkgs#efitools --command bash -c "
    cd '$dest'
    cert-to-efi-sig-list -g \"\$(cat GUID.txt)\" PK.crt PK.esl
    cert-to-efi-sig-list -g \"\$(cat GUID.txt)\" KEK.crt KEK.esl
    cert-to-efi-sig-list -g \"\$(cat GUID.txt)\" db.crt db.esl
  " >/dev/null 2>&1
}

# CURRENT model: reuse only db.key/db.crt; regenerate PK/KEK + GUID each run
# (mirrors today's --secrets-manager envelope block) -> PCR7 differs.
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

# Copy the unsigned build output into an isolated writable dir; sign-efi-image
# patches the ESP in place, so each run needs its own copy.
prepare_image_dir() {
  local out_dir="$1"
  rm -rf "$out_dir"
  mkdir -p "$out_dir"
  cp -r "$PROJECT_DIR/result/." "$out_dir/"
  chmod -R u+w "$out_dir"
}

# Mutate the unsigned UKI in <image-dir> so PCR4 changes: overwrite bytes in
# the .linux section IN PLACE (same size/layout -> still a signable PE). The
# distinct <marker> makes two mutated images differ deterministically.
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

# Sign the UKI in <image-dir> with <keys-dir> and capture PCR4+PCR7.
sign_and_compute_pcrs() {
  local image_dir="$1"
  local keys_dir="$2"

  # sign-efi-image prints the PCR JSON to stdout, progress to stderr.
  nix --extra-experimental-features nix-command --extra-experimental-features flakes \
    run .#sign-efi-image -- "$image_dir" "$keys_dir" \
    > "$image_dir/tpm_pcr.json" 2>/dev/null
}

# Sign via the no-disk path: sign-efi-image fetches db_key from Secrets Manager
# (--identity-arn) in memory, so <keys-dir> holds only db.crt + ESLs.
sign_and_compute_pcrs_via_arn() {
  local image_dir="$1" keys_dir="$2" identity_arn="$3"

  nix --extra-experimental-features nix-command --extra-experimental-features flakes \
    run .#sign-efi-image -- "$image_dir" "$keys_dir" --identity-arn "$identity_arn" \
    > "$image_dir/tpm_pcr.json" 2>/dev/null
}

# Fail unless NO db.key file exists anywhere under <dir>.
assert_no_db_key_on_disk() {
  local label="$1" dir="$2"
  local found
  found=$(find "$dir" -name 'db.key' 2>/dev/null)
  if [ -z "$found" ]; then
    echo -e "${GREEN}PASS${RESET} $label: no db.key on disk"
    PASS_COUNT=$((PASS_COUNT + 1))
  else
    echo -e "${RED}FAIL${RESET} $label: db.key written to disk"
    echo "  found: $found"
    FAIL_COUNT=$((FAIL_COUNT + 1))
  fi
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

# Generate the identity ONCE; all tests reuse it.
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

# Same identity, two differently-mutated UKIs: PCR4 must differ, PCR7 must not.
run_step "Run 3A: prepare keys (rebuild ESLs from identity)" prepare_keys_from_identity "$KEYS3A" "$IDENTITY"
run_step "Run 3A: prepare image dir"                         prepare_image_dir "$RUN3A"
run_step "Run 3A: mutate UKI (changes PCR4)"                 mutate_uki "$RUN3A" "PCR4-VARIANT-A"
run_step "Run 3A: sign + compute PCRs"                       sign_and_compute_pcrs "$RUN3A" "$KEYS3A"
run_step "Run 3B: prepare keys (rebuild ESLs from identity)" prepare_keys_from_identity "$KEYS3B" "$IDENTITY"
run_step "Run 3B: prepare image dir"                         prepare_image_dir "$RUN3B"
run_step "Run 3B: mutate UKI (changes PCR4)"                 mutate_uki "$RUN3B" "PCR4-VARIANT-B"
run_step "Run 3B: sign + compute PCRs"                       sign_and_compute_pcrs "$RUN3B" "$KEYS3B"

echo
# If PCR4 does NOT differ, the mutation was a no-op -- assert_pcr_differ fails.
assert_pcr_differ "PCR4 (UKI hash, distinct images)" \
  "$RUN3A/tpm_pcr.json" "$RUN3B/tpm_pcr.json" "PCR4"
assert_pcr_match  "PCR7 (secure boot policy, image-independent)" \
  "$RUN3A/tpm_pcr.json" "$RUN3B/tpm_pcr.json" "PCR7"
echo

# ==== Test 4: db.key never touches disk ====
echo "----------------------------------------------------"
echo " Test 4: sign via --identity-arn (no db.key on disk)"
echo "         EXPECT: signing OK, PCR7 == Test 2, no db.key file"
echo "----------------------------------------------------"

# Resolve a region for Secrets Manager (config -> env -> IMDSv2).
SM_REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-$(aws configure get region 2>/dev/null)}}"
if [ -z "$SM_REGION" ]; then
  IMDS_TOKEN=$(curl -s -X PUT http://169.254.169.254/latest/api/token \
    -H "X-aws-ec2-metadata-token-ttl-seconds: 60" 2>/dev/null)
  SM_REGION=$(curl -s -H "X-aws-ec2-metadata-token: $IMDS_TOKEN" \
    http://169.254.169.254/latest/meta-data/placement/region 2>/dev/null)
fi

if ! command -v aws >/dev/null 2>&1 \
   || [ -z "$SM_REGION" ] \
   || ! aws sts get-caller-identity --region "$SM_REGION" >/dev/null 2>&1; then
  echo -e "${YELLOW}SKIP${RESET} Test 4: AWS credentials / Secrets Manager unavailable"
  echo "  (requires aws CLI, a resolvable region, and valid credentials)"
else
  KEYS4="$TEST_DIR/keys4"
  RUN4="$TEST_DIR/run4"
  # Unique-ish secret name derived from PID + PPID.
  IDENTITY_SECRET_NAME="nitrotpm-sb-test-identity-$$-$PPID"
  IDENTITY_ARN=""

  # Upload a throwaway identity secret (production shape) and delete it on exit.
  cleanup_test4_secret() {
    [ -n "$IDENTITY_ARN" ] && aws secretsmanager delete-secret \
      --secret-id "$IDENTITY_ARN" --force-delete-without-recovery \
      --region "$SM_REGION" >/dev/null 2>&1
  }
  trap 'cleanup_test4_secret; cleanup' EXIT INT TERM

  echo -e "${YELLOW}>>> Run 4: upload throwaway identity to Secrets Manager${RESET}"
  # Assemble the identity JSON and stream it into create-secret (no secret file).
  IDENTITY_ARN=$(jq -n \
      --arg guid   "$(cat "$IDENTITY/GUID.txt")" \
      --rawfile db_key  "$IDENTITY/db.key" \
      --rawfile db_crt  "$IDENTITY/db.crt" \
      --rawfile pk_crt  "$IDENTITY/PK.crt" \
      --rawfile kek_crt "$IDENTITY/KEK.crt" \
      '{guid: $guid, db_key: $db_key, db_crt: $db_crt, pk_crt: $pk_crt, kek_crt: $kek_crt}' \
    | aws secretsmanager create-secret --name "$IDENTITY_SECRET_NAME" \
        --secret-string file:///dev/stdin \
        --query ARN --output text --region "$SM_REGION" 2>/dev/null | tr -d '[:space:]')

  if [ -z "$IDENTITY_ARN" ] || [[ "$IDENTITY_ARN" != arn:aws:secretsmanager:* ]]; then
    echo -e "${RED}FAIL${RESET} Test 4: could not create identity secret"
    FAIL_COUNT=$((FAIL_COUNT + 1))
  else
    run_step "Run 4: prepare keys WITHOUT db.key on disk" prepare_keys_no_dbkey "$KEYS4" "$IDENTITY"
    run_step "Run 4: prepare image dir"                   prepare_image_dir "$RUN4"
    run_step "Run 4: sign via ARN + compute PCRs"         sign_and_compute_pcrs_via_arn "$RUN4" "$KEYS4" "$IDENTITY_ARN"

    echo
    # (a) PCR7 matches the file-based reuse (Test 2): the fd path is byte-identical.
    assert_pcr_match "PCR7 (fd path == file-based identity reuse)" \
      "$RUN4/tpm_pcr.json" "$RUN2A/tpm_pcr.json" "PCR7"
    # (b) db.key was never written anywhere in the tree.
    assert_no_db_key_on_disk "keys dir has no db.key"  "$KEYS4"
    assert_no_db_key_on_disk "image dir has no db.key" "$RUN4"
  fi
fi
echo

# ==== Test 5: identity generation never writes a private key to disk ====
echo "----------------------------------------------------"
echo " Test 5: generate_identity_material (no key on disk)"
echo "         EXPECT: valid db key/cert pair, zero *.key files"
echo "----------------------------------------------------"

# Source the real generator (lib/identity.sh) so we exercise production code.
if [ ! -f "$SCRIPT_DIR/lib/identity.sh" ]; then
  echo -e "${RED}FAIL${RESET} Test 5: scripts/lib/identity.sh not found"
  FAIL_COUNT=$((FAIL_COUNT + 1))
else
  # shellcheck source=lib/identity.sh
  . "$SCRIPT_DIR/lib/identity.sh"

  # Run generation with TMPDIR + HOME pointed at a sandbox, so any stray file lands where we can detect it.
  SANDBOX="$TEST_DIR/gen-sandbox"
  rm -rf "$SANDBOX"; mkdir -p "$SANDBOX"
  GEN_OUT="$TEST_DIR/gen-material.json"

  ( export TMPDIR="$SANDBOX" HOME="$SANDBOX"; generate_identity_material ) > "$GEN_OUT" 2>/dev/null

  # (a) output is complete and the db key/cert are a matching pair.
  GEN_DB_KEY=$(jq -r '.db_key // empty' "$GEN_OUT" 2>/dev/null)
  GEN_DB_CRT=$(jq -r '.db_crt // empty' "$GEN_OUT" 2>/dev/null)
  GEN_GUID=$(jq -r '.guid // empty' "$GEN_OUT" 2>/dev/null)
  if [ -n "$GEN_DB_KEY" ] && [ -n "$GEN_DB_CRT" ] && [ -n "$GEN_GUID" ]; then
    KEY_PUB=$(printf '%s' "$GEN_DB_KEY" | nix --extra-experimental-features nix-command --extra-experimental-features flakes shell nixpkgs#openssl --command bash -c 'openssl pkey -pubout 2>/dev/null | openssl sha256')
    CRT_PUB=$(printf '%s' "$GEN_DB_CRT" | nix --extra-experimental-features nix-command --extra-experimental-features flakes shell nixpkgs#openssl --command bash -c 'openssl x509 -noout -pubkey 2>/dev/null | openssl sha256')
    if [ -n "$KEY_PUB" ] && [ "$KEY_PUB" = "$CRT_PUB" ]; then
      echo -e "${GREEN}PASS${RESET} Test 5: db key/cert form a valid pair (guid $GEN_GUID)"
      PASS_COUNT=$((PASS_COUNT + 1))
    else
      echo -e "${RED}FAIL${RESET} Test 5: db key/cert public keys do not match"
      FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
  else
    echo -e "${RED}FAIL${RESET} Test 5: generation output missing guid/db_key/db_crt"
    FAIL_COUNT=$((FAIL_COUNT + 1))
  fi
  unset GEN_DB_KEY

  # (b) no private key is WRITTEN during generation. A post-hoc file scan misses
  #     keys that were written then rm'd, so trace the openat syscalls instead.
  #     Requires ptrace (yama scope 0); skip (don't fail) when unavailable.
  if [ "$(cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null || echo 0)" = "0" ]; then
    STRACE_LOG="$TEST_DIR/gen-strace.log"
    export -f generate_identity_material
    ( export TMPDIR="$SANDBOX" HOME="$SANDBOX"
      nix --extra-experimental-features nix-command --extra-experimental-features flakes shell \
        nixpkgs#strace --command bash -c \
        "strace -f -y -e trace=openat -o '$STRACE_LOG' bash -c 'generate_identity_material >/dev/null'"
    ) >/dev/null 2>&1 || true
    # Write/create opens, minus the read-only nix store and virtual filesystems;
    # extract the quoted path (strace's 2nd arg) and flag anything key-like.
    WROTE_KEYS=$(grep -E 'O_(WRONLY|RDWR|CREAT)' "$STRACE_LOG" 2>/dev/null \
      | grep -oE ', "[^"]+", O_' | sed -E 's/^, "//; s/", O_$//' \
      | grep -vE '^/(nix|proc|sys|dev|etc)/' \
      | grep -iE '(\.key|private)' | sort -u)
    if [ -z "$WROTE_KEYS" ]; then
      echo -e "${GREEN}PASS${RESET} Test 5: no private-key file opened for writing during generation"
      PASS_COUNT=$((PASS_COUNT + 1))
    else
      echo -e "${RED}FAIL${RESET} Test 5: generation wrote private-key file(s) to disk"
      echo "$WROTE_KEYS" | sed 's/^/  /'
      FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
  else
    echo -e "${YELLOW}SKIP${RESET} Test 5: no-disk syscall assertion (ptrace unavailable)"
  fi
fi
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
