#!/bin/bash

usage() {
  echo "Usage: $0 -r INSTANCE_ROLE -a ADMIN_ROLE [-m MEASUREMENTS] | --instance-role INSTANCE_ROLE --admin-role ADMIN_ROLE [--measurements MEASUREMENTS]"
  echo "  -r, --instance-role        Specify the ARN of the instance role"
  echo "  -a, --admin-role          Specify the ARN of the admin role"
  echo "  -m, --measurements        Specify the folder containing tpm_pcr.json (default: result)"
  exit 1
}

MEASUREMENTS="result"

while [[ "$#" -gt 0 ]]; do
  case $1 in
    -r|--instance-role) INSTANCE_ROLE="$2"; shift ;;
    -a|--admin-role) ADMIN_ROLE="$2"; shift ;;
    -m|--measurements) MEASUREMENTS="$2"; shift ;;
    *) usage ;;
  esac
  shift
done

if [ -z "$INSTANCE_ROLE" ] || [ -z "$ADMIN_ROLE" ]; then
  echo "Error: Instance role ARN and admin role ARN are required."
  usage
fi

if [ ! -d "$MEASUREMENTS" ]; then
  echo "Error: Measurements folder '$MEASUREMENTS' does not exist."
  exit 1
fi

extract_pcr_values() {
  local measurements_file="$1"

  # Validate input file exists
  if [ ! -f "$measurements_file" ]; then
    echo "Error: Measurements file '$measurements_file' does not exist." >&2
    return 1
  fi

  # Validate that the file is a valid JSON which contains the Measurements object
  if ! jq empty "$measurements_file" 2>/dev/null; then
    echo "Error: Invalid JSON in measurements file '$measurements_file'." >&2
    return 1
  fi
  if ! jq -e '.Measurements' "$measurements_file" >/dev/null 2>&1; then
    echo "Error: No 'Measurements' object found in '$measurements_file'." >&2
    return 1
  fi

  # Extract and validate PCR values with comprehensive checks
  local pcr_output
  pcr_output=$(jq -r '
    .Measurements
    | to_entries
    | map(select(.key | test("^PCR([0-9]|1[0-9]|2[0-3])$")) | select(.value | type == "string" and test("^[0-9a-fA-F]{96}$")))
    | if length == 0 then
        error("No valid PCR entries found. PCR keys must be PCR0-PCR23 with SHA384 hash values (96 hex characters).")
      else
        map("\"kms:RecipientAttestation:NitroTPM" + .key + "\": \"" + .value + "\"")
        | join(", ")
      end
  ' "$measurements_file" 2>&1)

  if [ $? -ne 0 ]; then
    if echo "$pcr_output" | grep -q "No valid PCR entries found"; then
      echo "Error: $pcr_output" >&2
    else
      echo "Error: Failed to process PCR values from '$measurements_file'. Invalid PCR format detected." >&2
      echo "Expected: PCR keys (PCR0-PCR23) with SHA384 hash values (96 hex characters)." >&2
    fi
    return 1
  fi

  # Validate we got some output
  if [ -z "$pcr_output" ]; then
    echo "Error: No valid PCR values extracted from '$measurements_file'." >&2
    return 1
  fi

  echo "$pcr_output"
  return 0
}

# Retry logic for KMS key creation to handle IAM role propagation delays
create_kms_key_with_retry() {
  local policy_file=$1
  local max_attempts=30
  local attempt=1
  local sleep_interval=2

  while [ $attempt -le $max_attempts ]; do
    local key_output=$(aws kms create-key \
      --description "NitroTPM attestation example key" \
      --policy file://"$policy_file" 2>&1)
    local exit_code=$?

    # Check if output contains error information (AWS CLI can return 0 even with errors)
    if echo "$key_output" | grep -q "An error occurred"; then
      # Check if the error is due to invalid principals (IAM propagation issue)
      if echo "$key_output" | grep -q "invalid principals"; then
        sleep $sleep_interval
        attempt=$((attempt + 1))
        continue
      fi

      # For any other error, fail immediately
      echo "Error: AWS command failed with non-retryable error: $key_output"
      return 1
    fi

    # If exit code is non-zero and no clear error pattern, treat as error
    if [ $exit_code -ne 0 ]; then
      echo "Error: AWS command failed: $key_output"
      return 1
    fi

    echo "$key_output"
    return 0
  done

  echo "Error: Failed to create KMS key after $max_attempts attempts"
  echo "Last output: $key_output"
  return 1
}

PCR_VALUES=$(extract_pcr_values "$MEASUREMENTS/tpm_pcr.json")
if [ $? -ne 0 ]; then
  echo "Error: Failed to extract PCR values from measurements file."
  exit 1
fi

if [ -z "$PCR_VALUES" ]; then
  echo "Error: No PCR values were extracted."
  exit 1
fi

KEY_POLICY=$(cat <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "Allow access for Key Administrators",
      "Effect": "Allow",
      "Principal": {
        "AWS": "${ADMIN_ROLE}"
      },
      "Action": "kms:*",
      "Resource": "*"
    },
    {
      "Sid": "Allow decryption for the Instance role",
      "Effect": "Allow",
      "Principal": {
        "AWS": "${INSTANCE_ROLE}"
      },
      "Action": [
        "kms:Decrypt"
      ],
      "Resource": "*",
      "Condition": {
        "StringEqualsIgnoreCase": {
${PCR_VALUES}
        }
      }
    }
  ]
}
EOF
)

KEY_POLICY_FILE=$(mktemp -t kms_policy.XXXXXX.json)
echo "$KEY_POLICY" > "$KEY_POLICY_FILE"
echo "KMS policy written to $KEY_POLICY_FILE"

echo "Creating KMS key..."
KEY_OUTPUT=$(create_kms_key_with_retry "$KEY_POLICY_FILE")
if [ $? -ne 0 ]; then
  echo "Error: Failed to create KMS key: $KEY_OUTPUT"
  exit 1
fi

echo "AWS KMS command completed. Processing output..."
KEY_ID=$(echo "$KEY_OUTPUT" | jq -r '.KeyMetadata.KeyId')
echo "KMS key created with ID: $KEY_ID"

# Clean up temporary policy file
rm -f "$KEY_POLICY_FILE"
