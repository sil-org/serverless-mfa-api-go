#!/usr/bin/env bash
set -uo pipefail

usage() {
    cat <<EOF
Usage: $(basename "$0") --profile <aws-profile> --table <table-name> --key-id <api-key-id> <input-file>

Puts the API key item in <input-file> (as produced by fetch_key.sh) into
--table, then verifies the upload by getting the item whose value matches
--key-id and comparing it against <input-file>.
EOF
}

PROFILE=""
TABLE=""
KEY_ID=""
INPUT_FILE=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --profile) PROFILE="$2"; shift 2 ;;
        --table) TABLE="$2"; shift 2 ;;
        --key-id) KEY_ID="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        -*) echo "Unknown option: $1" >&2; usage; exit 1 ;;
        *) INPUT_FILE="$1"; shift ;;
    esac
done

if [[ -z "$PROFILE" || -z "$TABLE" || -z "$KEY_ID" || -z "$INPUT_FILE" ]]; then
    echo "Missing required argument(s)" >&2
    usage
    exit 1
fi

if [[ ! -f "$INPUT_FILE" ]]; then
    echo "Input file not found: $INPUT_FILE" >&2
    exit 1
fi

echo "Importing item to $TABLE..."
if ! aws dynamodb put-item \
  --profile "$PROFILE" \
  --table-name "$TABLE" \
  --item "$(cat "$INPUT_FILE")"; then
    echo "Put item failed"
    exit 3
fi

echo "Verifying import..."
workdir=$(mktemp -d)
trap 'rm -rf "$workdir"' EXIT

if ! aws dynamodb get-item \
  --profile "$PROFILE" \
  --table-name "$TABLE" \
  --key "{\"value\": {\"S\": \"$KEY_ID\"}}" \
  | jq '.Item' > "$workdir/target_key.json"; then
    echo "AWS DynamoDB get-item failed"
    exit 4
fi

if ! jq --exit-status 'if . == null then false else true end' "$workdir/target_key.json" > /dev/null; then
    echo "Verification failed: Item not found in target table"
    exit 4
fi

if diff --brief <(jq --sort-keys . "$INPUT_FILE") <(jq --sort-keys . "$workdir/target_key.json") > /dev/null; then
    echo "Verification successful: Source and target items match"
else
    echo "Verification failed: Source and target items do not match"
    exit 5
fi

echo "Import complete!"
