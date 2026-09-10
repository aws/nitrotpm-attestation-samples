#!/bin/bash
#
# Per-stage credential scoping. Empty role ARN is a passthrough: both the zero-config path
# (no flags → run as caller) and the real-ceremony path (Custodian's shell already holds the
# right creds).
# All diagnostics go to stderr: eight call sites parse step-script stdout with sed, so a
# stray line breaks the parse.

# Run a command under <role_arn>'s creds, or ambient creds when ARN is empty. Args: <role_arn>
# [--] <cmd> [args...].
assume_role_exec() {
  local role_arn="${1:-}"
  shift || true
  [ "${1:-}" = "--" ] && shift

  if [ $# -eq 0 ]; then
    echo "Error: assume_role_exec called without a command." >&2
    return 2
  fi

  if [ -z "$role_arn" ]; then
    "$@"
    return
  fi

  local creds
  if ! creds=$(aws sts assume-role \
        --role-arn "$role_arn" \
        --role-session-name "nitrotpm-$$" \
        --query 'Credentials.[AccessKeyId,SecretAccessKey,SessionToken]' \
        --output text 2>&1); then
    echo "Error: could not assume '$role_arn': $creds" >&2
    return 1
  fi

  echo "Assumed role: $role_arn" >&2

  # Subshell: credentials die with the command, caller's ambient creds untouched.
  (
    AWS_ACCESS_KEY_ID=$(printf '%s' "$creds" | cut -f1)
    AWS_SECRET_ACCESS_KEY=$(printf '%s' "$creds" | cut -f2)
    AWS_SESSION_TOKEN=$(printf '%s' "$creds" | cut -f3)
    export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
    "$@"
  )
}

# Returns the explicit ARN, or caller's identity when ARN is empty (zero-config). Args:
# <role_arn_or_empty>.
resolve_policy_principal() {
  local arn="${1:-}"
  if [ -n "$arn" ]; then
    printf '%s\n' "$arn"
  else
    aws sts get-caller-identity --query 'Arn' --output text
  fi
}
