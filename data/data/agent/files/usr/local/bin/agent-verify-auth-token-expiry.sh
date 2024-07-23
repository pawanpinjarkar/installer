#!/bin/bash

set -e

# shellcheck disable=SC1091
source "issue_status.sh"

status_issue="65_token"

# Function to check token expiry
check_token_expiry() {
  # Convert the expiry time to seconds since epoch
  expiry_epoch=$(date -d "$AGENT_AUTH_TOKEN_EXPIRY" +%s)

  # Get the current time in seconds since epoch
  current_epoch=$(date +%s)

  # Compare the current time with the expiry time
  if [ "$current_epoch" -gt "$expiry_epoch" ]; then
    printf '\\e{lightred}Auth token is expired. Re-run 'add-nodes' command to create new image files(ISO/PXE files.\\e{reset}'| set_issue "${status_issue}"
    exit 1
  else
    printf '\\e{lightgreen}The token is still valid.'| set_issue "${status_issue}"
  fi
}

# Continuous loop to check the token expiry
while true; do
  check_token_expiry
  sleep 5
done