#!/bin/bash
#
# Credential resolution for ceremony stages. Exported (not SDK default chain): assume_role_exec
# runs in a subshell with explicit env vars, so region must be in the environment, not only
# ~/.aws/config.

# Resolve var from env or 'aws configure get'. Returns 1 if neither yields a value. Args:
# <var_name> <aws_config_key>.
_resolve_one() {
  local var_name="$1" config_key="$2" current value
  current="${!var_name:-}"
  if [ -n "$current" ]; then
    return 0
  fi

  value=$(aws configure get "$config_key" 2>/dev/null) || value=""
  if [ -n "$value" ]; then
    # shellcheck disable=SC2163  # indirect export is the point of this helper
    export "$var_name=$value"
    echo "$var_name resolved from 'aws configure get $config_key'." >&2
    return 0
  fi

  return 1
}

# Export required AWS creds; session token is optional. Returns 1 on first unresolvable variable.
resolve_aws_credentials() {
  local pairs=(
    "AWS_ACCESS_KEY_ID aws_access_key_id"
    "AWS_SECRET_ACCESS_KEY aws_secret_access_key"
    "AWS_DEFAULT_REGION region"
  )
  local pair var key

  for pair in "${pairs[@]}"; do
    read -r var key <<<"$pair"
    if ! _resolve_one "$var" "$key"; then
      echo "Error: $var is not set and not available via 'aws configure get $key'." >&2
      return 1
    fi
  done

  # Optional: only present for temporary credentials.
  _resolve_one AWS_SESSION_TOKEN aws_session_token || true
  return 0
}
