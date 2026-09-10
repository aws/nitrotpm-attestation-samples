#!/bin/bash
#
# Shared helpers for 02a_create_kms_key.sh and 02b_finalize_kms_policy.sh.
# Two-step: ARN must be pinned into the image before build (→ PCR4), but PCR-gated policy needs
# post-build PCRs.

# Assumed-role session ARNs (sts::…:assumed-role/…) are not valid KMS principals; resolve to
# the IAM role ARN.
normalize_admin_principal() {
  local principal="$1"

  if [[ "$principal" =~ ^arn:aws[a-zA-Z-]*:sts::[0-9]{12}:assumed-role/([^/]+)/.+$ ]]; then
    local role_name="${BASH_REMATCH[1]}"
    aws iam get-role --role-name "$role_name" --query 'Role.Arn' --output text
    return
  fi

  echo "$principal"
}

# Emit bootstrap key policy. Custodian gets policy control + grant audit; Provisioner gets
# Encrypt only.
# Split prevents any single party from rewriting the policy AND minting ciphertext during the
# bootstrap window.
# Collapses to a single statement when provisioner is absent or matches custodian, so the
# zero-config
# path is byte-identical to the pre-split policy. Args: <custodian_principal>
# [provisioner_principal].
build_bootstrap_policy() {
  local custodian="$1" provisioner="${2:-}"

  if [ -z "$provisioner" ] || [ "$provisioner" = "$custodian" ]; then
    cat <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "Allow provisioning to wrap the DEK, install the final key policy, and audit grants",
      "Effect": "Allow",
      "Principal": {
        "AWS": "${custodian}"
      },
      "Action": [
        "kms:PutKeyPolicy",
        "kms:Encrypt",
        "kms:ScheduleKeyDeletion",
        "kms:ListGrants",
        "kms:RevokeGrant"
      ],
      "Resource": "*"
    }
  ]
}
EOF
    return
  fi

  cat <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "Custodian installs the final key policy and audits grants",
      "Effect": "Allow",
      "Principal": {
        "AWS": "${custodian}"
      },
      "Action": [
        "kms:PutKeyPolicy",
        "kms:ScheduleKeyDeletion",
        "kms:ListGrants",
        "kms:RevokeGrant"
      ],
      "Resource": "*"
    },
    {
      "Sid": "Provisioner wraps the DEK during the bootstrap window only",
      "Effect": "Allow",
      "Principal": {
        "AWS": "${provisioner}"
      },
      "Action": [
        "kms:Encrypt"
      ],
      "Resource": "*"
    }
  ]
}
EOF
}

# Convert tpm_pcr.json to "kms:RecipientAttestation:NitroTPMPCR<n>": "<sha384>" pairs.
# required-pcrs is mandatory: accepting whatever's in the file made a weak gate
# indistinguishable from success.
# Args: <measurements-file> <required-pcrs, space-separated e.g. "PCR4 PCR7">.
extract_pcr_values() {
  local measurements_file="$1" required_pcrs="${2:-}"

  if [ ! -f "$measurements_file" ]; then
    echo "Error: Measurements file '$measurements_file' does not exist." >&2
    return 1
  fi

  if [ -z "$required_pcrs" ]; then
    echo "Error: extract_pcr_values requires an explicit list of PCRs to enforce." >&2
    return 1
  fi

  if ! jq empty "$measurements_file" 2>/dev/null; then
    echo "Error: Invalid JSON in measurements file '$measurements_file'." >&2
    return 1
  fi
  if ! jq -e '.Measurements' "$measurements_file" >/dev/null 2>&1; then
    echo "Error: No 'Measurements' object found in '$measurements_file'." >&2
    return 1
  fi

  # Fail closed before building the condition block: a missing PCR is a weaker gate.
  local pcr
  for pcr in $required_pcrs; do
    if ! jq -e --arg p "$pcr" \
        '.Measurements[$p] | type == "string" and test("^[0-9a-fA-F]{96}$")' \
        "$measurements_file" >/dev/null 2>&1; then
      echo "Error: required $pcr is missing or not a SHA384 hex value in '$measurements_file'." >&2
      echo "       Refusing to install a key policy that does not gate on $pcr." >&2
      echo "       Present: $(jq -r '.Measurements | keys | join(", ")' "$measurements_file" 2>/dev/null)" >&2
      return 1
    fi
  done

  # Inline `if ! pcr_output=$(...)` because `set -e` is active: a bare assignment suppresses
  # errexit.
  local pcr_output
  if ! pcr_output=$(jq -r '
    .Measurements
    | to_entries
    | map(select(.key | test("^PCR([0-9]|1[0-9]|2[0-3])$")) | select(.value | type == "string" and test("^[0-9a-fA-F]{96}$")))
    | if length == 0 then
        error("No valid PCR entries found. PCR keys must be PCR0-PCR23 with SHA384 hash values (96 hex characters).")
      else
        map("\"kms:RecipientAttestation:NitroTPM" + .key + "\": \"" + .value + "\"")
        | join(", ")
      end
  ' "$measurements_file" 2>&1); then
    if echo "$pcr_output" | grep -q "No valid PCR entries found"; then
      echo "Error: $pcr_output" >&2
    else
      echo "Error: Failed to process PCR values from '$measurements_file'. Invalid PCR format detected." >&2
      echo "Expected: PCR keys (PCR0-PCR23) with SHA384 hash values (96 hex characters)." >&2
    fi
    return 1
  fi

  if [ -z "$pcr_output" ]; then
    echo "Error: No valid PCR values extracted from '$measurements_file'." >&2
    return 1
  fi

  echo "$pcr_output"
  return 0
}

# Emit final PCR-gated policy. Encrypt + PutKeyPolicy removed forever; Decrypt requires attestation.
# jq -n so a malformed PCR condition fails here rather than silently installing a broken policy.
# Args: <admin-principal> <instance-role-arn> <pcr-condition-object>.
build_final_policy() {
  local admin="$1" instance_role="$2" pcr_condition="$3"

  jq -n --arg admin "$admin" --arg role "$instance_role" --argjson pcrs "$pcr_condition" '{
    Version: "2012-10-17",
    Statement: [
      { Sid: "Allow provisioning to schedule key deletion and keep grants auditable",
        Effect: "Allow",
        Principal: {AWS: $admin},
        Action: ["kms:ScheduleKeyDeletion","kms:ListGrants","kms:RevokeGrant","kms:GetKeyPolicy"],
        Resource: "*" },
      { Sid: "Allow decryption for the Instance role",
        Effect: "Allow",
        Principal: {AWS: $role},
        Action: ["kms:Decrypt"],
        Resource: "*",
        Condition: {StringEqualsIgnoreCase: $pcrs} },
      { Sid: "Deny grant creation to everyone; grants bypass the PCR condition",
        Effect: "Deny",
        Principal: "*",
        Action: "kms:CreateGrant",
        Resource: "*" }
    ]}'
}

# Check security properties of the live policy. Diffing the stored document doesn't work: KMS
# re-serializes it (whitespace, "*" → {"AWS":"*"}), so normalization is indistinguishable from
# a racing PutKeyPolicy. Checks: only the instance role may Decrypt, under exactly these PCRs;
# CreateGrant Denied to all; no Allow of any action outside the final policy's set.
# Prints one line per fault; empty = policy is ours.
# Args: <policy-json> <instance-role-arn> <pcr-condition-object>.
kms_policy_faults() {
  local policy="$1" instance_role="$2" pcr_condition="$3"

  printf '%s' "$policy" | jq -r \
    --arg role "$instance_role" --argjson pcrs "$pcr_condition" '
    def as_list: if type == "array" then . else [.] end;
    def actions: [.Action // [] | as_list | .[] | ascii_downcase];
    # KMS expands wildcards, so prefix-match: kms:Decr* grants Decrypt but equals nothing.
    def covers($want): actions | any(. as $a
      | $a == "*" or $a == "kms:*" or $a == $want
      or (($a | endswith("*")) and ($want | startswith($a[0:-1]))));
    def principals: [ if (.Principal | type) == "string" then .Principal
                      else (.Principal.AWS // empty) | as_list | .[] end ];

    # Lowercased; keep in step with build_final_policy.
    [ "kms:decrypt", "kms:schedulekeydeletion", "kms:listgrants", "kms:revokegrant",
      "kms:getkeypolicy" ] as $permitted
    | [ .Statement[] | select(.Effect == "Allow") ] as $allow
    # Inverted shapes populate no .Action/.Principal, so every check below reads them as empty
    # and silently passes them. Fail closed instead: an Allow with NotAction can grant Decrypt.
    | [ $allow[] | select(has("NotAction") or has("NotPrincipal") or has("NotResource")) ] as $unaudited
    | [ $allow[] | select(covers("kms:decrypt")) ] as $decrypt
    | [ .Statement[] | select(.Effect == "Deny")
        | select(covers("kms:creategrant")) ] as $deny
    | [ ( if ($unaudited | length) > 0 then
            "Allow statement(s) use NotAction/NotPrincipal/NotResource and cannot be audited: \($unaudited | map(.Sid // "unnamed") | join(", "))"
          else empty end ),
        if ($decrypt | length) != 1 then
          "kms:Decrypt is granted by \($decrypt | length) Allow statement(s), expected exactly 1"
        else
          ( if ($decrypt[0] | principals) != [$role] then
              "kms:Decrypt principal is [\($decrypt[0] | principals | join(", "))], expected [\($role)]"
            else empty end ),
          ( if (($decrypt[0].Condition // {}).StringEqualsIgnoreCase // {}) != $pcrs then
              "kms:Decrypt is not gated on exactly the PCR values just measured"
            else empty end )
        end,
        # Allowlist, not denylist: ReEncryptFrom is Decrypt-equivalent without being named
        # Decrypt, and a denylist misses whatever KMS ships next. Exact match, so wildcards fault.
        ( ( [ $allow[] | actions[] ] - $permitted ) as $extra
          | if ($extra | length) > 0 then
              "Allow statement(s) grant action(s) outside the final policy: \($extra | unique | join(", "))"
            else empty end ),
        ( if ([$deny[] | principals] | flatten | any(. == "*")) then empty
          else "kms:CreateGrant is not denied to all principals" end )
      ] | .[]'
}

# Retry only IAM-propagation "invalid principals" errors (newly-created role not yet visible to
# KMS); all others fail immediately. Args: <what-for-messages> <aws-kms-args...>.
kms_call_with_retry() {
  local what=$1
  shift
  local max_attempts=30
  local attempt=1
  local sleep_interval=2
  local output="" exit_code

  while [ $attempt -le $max_attempts ]; do
    set +e
    output=$(aws kms "$@" 2>&1)
    exit_code=$?
    set -e

    if echo "$output" | grep -q "An error occurred"; then
      if echo "$output" | grep -q "invalid principals"; then
        sleep $sleep_interval
        attempt=$((attempt + 1))
        continue
      fi

      echo "Error: $what failed with a non-retryable error: $output" >&2
      return 1
    fi

    if [ $exit_code -ne 0 ]; then
      echo "Error: $what failed: $output" >&2
      return 1
    fi

    echo "$output"
    return 0
  done

  echo "Error: $what did not succeed after $max_attempts attempts" >&2
  echo "Last output: $output" >&2
  return 1
}
