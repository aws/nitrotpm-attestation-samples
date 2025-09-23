#!/bin/bash

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

usage() {
  echo "Usage: $0 -s SERVER_ADDRESS -m MESSAGE | --server SERVER_ADDRESS --message MESSAGE"
  echo "  -s, --server        Specify the server's public IP address or domain name"
  echo "  -m, --message       Specify the message to encrypt and send"
  exit 1
}

# Parse command line arguments
while [[ "$#" -gt 0 ]]; do
  case $1 in
    -s|--server) SERVER_ADDRESS="$2"; shift ;;
    -m|--message) MESSAGE="$2"; shift ;;
    *) usage ;;
  esac
  shift
done

# Check if the server address and message are provided
if [ -z "$SERVER_ADDRESS" ] || [ -z "$MESSAGE" ]; then
  echo "Error: Both server address and message are required."
  usage
fi

# Function to url encode a string
urlencode() {
  local STRING="${1}"
  local STRLEN=${#STRING}
  local ENCODED=""
  local POS C O

  for (( POS=0 ; POS<STRLEN ; POS++ )); do
    C=${STRING:$POS:1}
    case "$C" in
      [-_.~a-zA-Z0-9] ) O="${C}" ;;
      * )               printf -v O '%%%02x' "'$C"
    esac
    ENCODED+="${O}"
  done
  echo "${ENCODED}"
}

ARTIFACTS_DIR="$SCRIPT_DIR/../artifacts"

# Check if the artifacts directory exists
if [ ! -d "$ARTIFACTS_DIR" ]; then
  echo "Error: Artifacts directory '$ARTIFACTS_DIR' not found."
  exit 1
fi

# Read the symmetric key from the artifacts directory
SYMMETRIC_KEY=$(base64 -d "$ARTIFACTS_DIR/symmetric_key.bin" | xxd -p -c 32 | tr -d '\n')
if [ -z "$SYMMETRIC_KEY" ]; then
  echo "Error: Could not read symmetric key from $ARTIFACTS_DIR/symmetric_key.bin"
  exit 1
fi

IV=$(openssl rand -hex 16)
ENCRYPTED=$(echo -n "$MESSAGE" | openssl enc -aes-256-cbc -K "$SYMMETRIC_KEY" -iv "$IV" -base64 -A)
CIPHERTEXT="${IV}${ENCRYPTED}"
echo "CIPHERTEXT: $CIPHERTEXT"

ENCODED_CIPHERTEXT=$(urlencode "$CIPHERTEXT")
echo "ENCODED_CIPHERTEXT: $ENCODED_CIPHERTEXT"

# Send the request to the server
echo "Sending request to http://$SERVER_ADDRESS?ciphertext=$ENCODED_CIPHERTEXT"
RESPONSE=$(curl -s "http://$SERVER_ADDRESS?ciphertext=$ENCODED_CIPHERTEXT")

if [ "$RESPONSE" == "$MESSAGE" ]; then
  echo "Test passed: The server successfully decrypted the message."
  echo "Original message: $MESSAGE"
  echo "Server response:  $RESPONSE"
else
  echo "Test failed: The server's response does not match the original message."
  echo "Original message: $MESSAGE"
  echo "Server response:  $RESPONSE"
fi
