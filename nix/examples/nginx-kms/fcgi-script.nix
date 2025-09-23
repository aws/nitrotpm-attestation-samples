{ 
  pkgs,
  system,
  ...
}:
pkgs.writeScript "decrypt-wrapper.sh" ''
  #!${pkgs.bash}/bin/bash

  # Output error with status code
  error_response() {
    local status_code=$1
    local error_message=$2
    echo "Status: $status_code"
    echo "Content-type: text/plain"
    echo ""
    echo "$error_message"
    exit 0
  }

  # URL decode using Python
  urldecode() {
    ${pkgs.python3}/bin/python3 -c "import sys, urllib.parse as ul; print(ul.unquote_plus(sys.argv[1]))" "$1"
  }

  # Parse query string
  IFS='&' read -ra PARAMS <<< "$QUERY_STRING"
  for param in "''${PARAMS[@]}"; do
    IFS='=' read -r key value <<< "$param"
    if [ "$key" = "ciphertext" ]; then
      CIPHERTEXT=$(urldecode "$value")
    fi
  done

  # Check if ciphertext is provided
  if [ -z "$CIPHERTEXT" ]; then
    error_response 400 "Error: ciphertext parameter is required."
  fi

  # Read the symmetric key
  SYMMETRIC_KEY=$(cat /run/symmetric_key | ${pkgs.coreutils}/bin/base64 -d | ${pkgs.xxd}/bin/xxd -p -c 32 | tr -d '\n')

  # Extract IV (first 32 characters, as it's in hex format) and the rest is the actual ciphertext
  IV=''${CIPHERTEXT:0:32}
  ACTUAL_CIPHERTEXT=''${CIPHERTEXT:32}

  # Decrypt the ciphertext using the symmetric key and IV
  PLAINTEXT=$(echo "$ACTUAL_CIPHERTEXT" | ${pkgs.openssl}/bin/openssl enc -d -aes-256-cbc -base64 -K "$SYMMETRIC_KEY" -iv "$IV" -A)
  DECRYPT_EXIT_CODE=$?

  # If decryption failed, return an error status
  if [ $DECRYPT_EXIT_CODE -ne 0 ]; then
    error_response 500 "Error: Decryption failed. Exit code: $DECRYPT_EXIT_CODE"
  fi

  # If everything is OK, return the result
  echo "Content-type: text/plain"
  echo ""
  echo "$PLAINTEXT"
''
