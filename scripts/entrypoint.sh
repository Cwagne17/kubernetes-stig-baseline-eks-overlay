#!/bin/bash
set -e

# Default values
PROFILE_PATH="/opt/profile"
OUTPUT_DIR="/opt/output"
INPUTS_FILE="/opt/profile/inputs.yml"
WAIVERS_FILE="/opt/profile/waivers.yml"

# Build cinc-auditor command arguments
ARGS=("exec" "${PROFILE_PATH}")
[ -n "${TARGET}" ] && ARGS+=("-t" "${TARGET}")
[ -f "${INPUTS_FILE}" ] && ARGS+=("--input-file" "${INPUTS_FILE}")
[ -f "${WAIVERS_FILE}" ] && ARGS+=("--waiver-file" "${WAIVERS_FILE}")
ARGS+=("--reporter" "progress-bar" "json:${OUTPUT_DIR}/results.json")
[ $# -gt 0 ] && ARGS+=("$@")

# Print the command for debugging
echo "Executing: cinc-auditor ${ARGS[*]}"
echo "---"

# Execute the command
cinc-auditor "${ARGS[@]}"
