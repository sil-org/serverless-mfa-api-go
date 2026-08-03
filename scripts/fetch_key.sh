#!/usr/bin/env bash
set -uo pipefail

usage() {
    cat <<EOF
Usage: $(basename "$0") --profile <aws-profile> --table <table-name> --key-id <api-key-id> [--output <file>]

Scans the source API key table for the item whose value matches --key-id
and writes it to --output, or to stdout if --output is omitted.
EOF
}

PROFILE=""
TABLE=""
KEY_ID=""
OUTPUT="/dev/stdout"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --profile) PROFILE="$2"; shift 2 ;;
        --table) TABLE="$2"; shift 2 ;;
        --key-id) KEY_ID="$2"; shift 2 ;;
        --output) OUTPUT="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown option: $1" >&2; usage; exit 1 ;;
    esac
done

if [[ -z "$PROFILE" || -z "$TABLE" || -z "$KEY_ID" ]]; then
    echo "Missing required argument(s)" >&2
    usage
    exit 1
fi

echo "Extracting data from $TABLE..." >&2
if ! result=$(aws dynamodb scan \
  --profile "$PROFILE" \
  --table-name "$TABLE" \
  --filter-expression "#key = :v" \
  --expression-attribute-names '{"#key":"value"}' \
  --expression-attribute-values "{\":v\":{\"S\":\"$KEY_ID\"}}" \
  | jq '.Items[0]'); then
    echo "AWS DynamoDB scan failed" >&2
    exit 1
fi

if [[ "$result" == "null" ]]; then
    echo "No item found in source table for the given API key ID" >&2
    exit 2
fi

printf '%s\n' "$result" > "$OUTPUT"
