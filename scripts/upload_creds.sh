#!/usr/bin/env bash
set -uo pipefail

usage() {
    cat <<EOF
Usage: $(basename "$0") --profile <aws-profile> --table <table-name> --key-id <api-key-id> <input-file>

Uploads the credential items in <input-file> (a JSON array, as produced by
fetch_creds.sh) to --table in batches of 25, then verifies the upload by
scanning --table for items whose apiKey matches --key-id and comparing
them against <input-file>.
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

workdir=$(mktemp -d)
trap 'rm -rf "$workdir"' EXIT

input_count=$(jq length "$INPUT_FILE")
echo "Read $input_count item(s) from $INPUT_FILE"

# 1. Transform the raw items into DynamoDB Batch Write format chunked by 25 items
echo "Formatting and chunking items..."
if ! jq -c --arg table "$TABLE" '
  def chunk(n):
    def _chunk: if length <= n then . else .[0:n], (.[n:] | _chunk) end;
    _chunk;

  map({PutRequest: {Item: .}}) | chunk(25) | {($table): .}
' "$INPUT_FILE" > "$workdir/batched_payloads.ndjson"; then
    echo "Formatting failed"
    exit 2
fi

batch_count=$(wc -l < "$workdir/batched_payloads.ndjson")
echo "Split into $batch_count batch(es)"

# 2. Loop through each 25-item chunk and write to the target table
echo "Importing items to $TABLE..."
uploaded_count=0
batch_num=0
while read -r payload; do
    batch_num=$((batch_num + 1))
    if ! aws dynamodb batch-write-item \
      --profile "$PROFILE" \
      --request-items "$payload" > /dev/null; then
        echo "Batch write failed"
        exit 3
    fi
    batch_size=$(jq --arg table "$TABLE" '.[$table] | length' <<< "$payload")
    uploaded_count=$((uploaded_count + batch_size))
    echo "Uploaded batch $batch_num/$batch_count ($batch_size item(s))..."
done < "$workdir/batched_payloads.ndjson"

echo "Uploaded $uploaded_count item(s) total"
echo "Import complete, comparing results..."

# 3. Verify the upload
if ! aws dynamodb scan \
  --profile "$PROFILE" \
  --table-name "$TABLE" \
  --filter-expression "#key = :v" \
  --expression-attribute-names '{"#key":"apiKey"}' \
  --expression-attribute-values "{\":v\":{\"S\":\"$KEY_ID\"}}" \
  | jq .Items > "$workdir/target_items.json"; then
    echo "AWS DynamoDB scan of target table failed"
    exit 4
fi

target_count=$(jq length "$workdir/target_items.json")
echo "Found $target_count item(s) in $TABLE matching --key-id"

jq --sort-keys 'walk(if type == "array" then sort else . end)' "$INPUT_FILE" > "$workdir/sorted_input_items.json"
jq --sort-keys 'walk(if type == "array" then sort else . end)' "$workdir/target_items.json" > "$workdir/sorted_target_items.json"

if ! diff --brief "$workdir/sorted_input_items.json" "$workdir/sorted_target_items.json" > /dev/null; then
    echo "Data mismatch between source and target tables"
    exit 5
fi

echo "Import complete and verified successfully! ($target_count/$input_count item(s) match)"
