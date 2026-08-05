#!/usr/bin/env bash
set -uo pipefail

usage() {
    cat <<EOF
Usage: $(basename "$0") --profile <aws-profile> --table <table-name> --key-id <api-key-id> [--output <file>]

Scans the source credential table for items whose apiKey matches --key-id and
writes the resulting JSON array of items to --output, or to stdout if
--output is omitted.
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
if ! items=$(aws dynamodb scan \
  --profile "$PROFILE" \
  --table-name "$TABLE" \
  --filter-expression "#key = :v" \
  --expression-attribute-names '{"#key":"apiKey"}' \
  --expression-attribute-values "{\":v\":{\"S\":\"$KEY_ID\"}}" \
  | jq .Items); then
    echo "AWS DynamoDB scan failed" >&2
    exit 1
fi

count=$(jq length <<< "$items")
echo "Fetched $count item(s) from $TABLE" >&2

printf '%s\n' "$items" > "$OUTPUT"
