# shellcheck shell=bash
# Pinned data-volume format. LUKS2 header checksums are unkeyed, so an operator can strip
# integrity from segments[0] and luksOpen still succeeds — it only proves the key. Verify the
# header and active mapping before trusting either. Sourced by luks-init.nix + test_luks_verify.sh.

LUKS_EXPECTED_CIPHER="aes-xts-plain64"
# XTS splits the key in half, so 512 => AES-256.
LUKS_EXPECTED_KEYSIZE="512"
LUKS_EXPECTED_INTEGRITY_KEYSIZE="256"

# _ARG: --integrity flag value; _INTEGRITY: how LUKS2 metadata renders it.
# hmac-sha256 over aes-gcm-random: GCM's 96-bit nonce risks collision on write-heavy PGDATA.
# shellcheck disable=SC2034  # consumed by luks-init.nix, which sources this file
LUKS_EXPECTED_INTEGRITY_ARG="hmac-sha256"
LUKS_EXPECTED_INTEGRITY="hmac(sha256)"

# 4096 gives dm-integrity write atomicity and matches PostgreSQL's 8 KiB pages.
LUKS_EXPECTED_SECTOR_SIZE="4096"

# Passed to luksFormat and asserted: prevents a future cryptsetup default mismatch across
# format/open.
# shellcheck disable=SC2034  # consumed by luks-init.nix, which sources this file
LUKS_EXPECTED_PBKDF="argon2id"

# LUKS2 JSON states the combined enc+integrity key in BYTES, not bits.
LUKS_EXPECTED_KEYSLOT_BYTES=$(( (LUKS_EXPECTED_KEYSIZE + LUKS_EXPECTED_INTEGRITY_KEYSIZE) / 8 ))

# Overridable: image injects a store path, tests use $PATH.
: "${LUKS_JQ:=jq}"

# Pure parameter expansion — no sed, avoids GNU/BSD divergence.
_luks_trim() {
  local s=$1
  s=${s#"${s%%[![:space:]]*}"}
  s=${s%"${s##*[![:space:]]}"}
  printf '%s' "$s"
}

# _luks_status_field <status-text> <exact-field-name> -- exact match prevents "integrity
# keysize" satisfying "keysize".
_luks_status_field() {
  local text=$1 want=$2 line key val
  while IFS= read -r line; do
    case "$line" in
      *:*) ;;
      *) continue ;;
    esac
    key=$(_luks_trim "${line%%:*}")
    [ "$key" = "$want" ] || continue
    val=$(_luks_trim "${line#*:}")
    printf '%s\n' "$val"
    return 0
  done <<EOF
$text
EOF
  return 1
}

# luks_verify_header_json <luksDump --dump-json-metadata output> -- runs before luksOpen, needs
# no key.
luks_verify_header_json() {
  local meta=$1 out rc=0

  # cryptsetup may render numbers as strings; coerce before comparing.
  # shellcheck disable=SC2016  # $cipher etc. are jq --arg bindings, not shell vars
  out=$(printf '%s' "$meta" | "$LUKS_JQ" -e \
    --arg cipher "$LUKS_EXPECTED_CIPHER" \
    --arg integrity "$LUKS_EXPECTED_INTEGRITY" \
    --arg sector_size "$LUKS_EXPECTED_SECTOR_SIZE" \
    --arg pbkdf "$LUKS_EXPECTED_PBKDF" \
    --arg keyslot_bytes "$LUKS_EXPECTED_KEYSLOT_BYTES" '
      (.segments | length) == 1
      and .segments["0"].type == "crypt"
      and .segments["0"].encryption == $cipher
      and (.segments["0"].sector_size | tostring) == $sector_size
      and (.segments["0"].integrity.type // "") == $integrity

      # Keyslots, digests and tokens are all alternative ways in, so a segments-only
      # check left slot 0 rewritable with a short key and a second slot appendable.
      and (.keyslots | length) == 1
      and .keyslots["0"].type == "luks2"
      and (.keyslots["0"].key_size | tostring) == $keyslot_bytes
      and .keyslots["0"].kdf.type == $pbkdf
      and (.digests | length) == 1
      and .digests["0"].keyslots == ["0"]
      and .digests["0"].segments == ["0"]
      and ((.tokens // {}) | length) == 0
    ' 2>&1) || rc=$?

  if [ "$rc" -ne 0 ]; then
    echo "luks-verify: header does not match the pinned format" \
         "(cipher=$LUKS_EXPECTED_CIPHER integrity=$LUKS_EXPECTED_INTEGRITY" \
         "sector_size=$LUKS_EXPECTED_SECTOR_SIZE kdf=$LUKS_EXPECTED_PBKDF" \
         "keyslot_key_bytes=$LUKS_EXPECTED_KEYSLOT_BYTES, one keyslot/digest," \
         "no tokens): ${out:-no output}" >&2
    return 1
  fi
  return 0
}

# luks_verify_status <cryptsetup status output> -- authoritative check; luksOpen only proves
# key correctness.
luks_verify_status() {
  local text=$1 cipher keysize integrity sector_size expected_total

  cipher=$(_luks_status_field "$text" cipher) \
    || { echo "luks-verify: no cipher in mapping status" >&2; return 1; }
  if [ "$cipher" != "$LUKS_EXPECTED_CIPHER" ]; then
    echo "luks-verify: active cipher '$cipher' != $LUKS_EXPECTED_CIPHER" >&2
    return 1
  fi

  # Integrity checked before keysize: no-integrity volume reports smaller keysize, masking the
  # real failure.
  integrity=$(_luks_status_field "$text" integrity) \
    || { echo "luks-verify: data authentication is not active on the mapping" >&2; return 1; }
  if [ "$integrity" != "$LUKS_EXPECTED_INTEGRITY" ]; then
    echo "luks-verify: active integrity '$integrity' != $LUKS_EXPECTED_INTEGRITY" >&2
    return 1
  fi

  keysize=$(_luks_status_field "$text" keysize) \
    || { echo "luks-verify: no keysize in mapping status" >&2; return 1; }
  # keysize is the COMBINED key (enc + integrity = 768 bits); compare leading integer only,
  # since cryptsetup 2.8.x changed the units format ("768 bits" -> "768 [bits]").
  expected_total=$((LUKS_EXPECTED_KEYSIZE + LUKS_EXPECTED_INTEGRITY_KEYSIZE))
  if [ "${keysize%%[![:digit:]]*}" != "$expected_total" ]; then
    echo "luks-verify: active keysize '$keysize' != $expected_total bits" \
         "($LUKS_EXPECTED_KEYSIZE encryption + $LUKS_EXPECTED_INTEGRITY_KEYSIZE integrity)" >&2
    return 1
  fi

  # Re-checked here, not just pre-open: a header rewritten between luksDump and luksOpen
  # could otherwise activate at a different size. Leading integer only — units vary.
  sector_size=$(_luks_status_field "$text" "sector size") \
    || { echo "luks-verify: no sector size in mapping status" >&2; return 1; }
  if [ "${sector_size%%[![:digit:]]*}" != "$LUKS_EXPECTED_SECTOR_SIZE" ]; then
    echo "luks-verify: active sector size '$sector_size' != $LUKS_EXPECTED_SECTOR_SIZE" >&2
    return 1
  fi

  return 0
}
