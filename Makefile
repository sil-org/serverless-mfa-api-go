demo: proxy ui app dbinit
	./local_data.sh

proxy:
	docker compose up -d proxy

ui:
	docker compose up -d ui

app:
	docker compose kill app
	docker compose rm -f app
	docker compose up -d app

test: clean db
	docker compose run --rm app go test ./...

db:
	docker compose up -d dynamo

dbinit: db wait createwebauthntable createapikeytable createtotptable

wait:
	sleep 5

createwebauthntable:
	AWS_ENDPOINT=http://localhost:8000 AWS_DEFAULT_REGION=local AWS_ACCESS_KEY_ID=abc123 AWS_SECRET_ACCESS_KEY=abc123 AWS_PAGER="" aws dynamodb create-table \
		--table-name WebAuthn \
		--billing-mode PAY_PER_REQUEST \
		--attribute-definitions AttributeName=uuid,AttributeType=S \
		--key-schema AttributeName=uuid,KeyType=HASH

createtotptable:
	AWS_ENDPOINT=http://localhost:8000 AWS_DEFAULT_REGION=local AWS_ACCESS_KEY_ID=abc123 AWS_SECRET_ACCESS_KEY=abc123 AWS_PAGER="" aws dynamodb create-table \
		--table-name Totp \
		--billing-mode PAY_PER_REQUEST \
		--attribute-definitions AttributeName=uuid,AttributeType=S \
		--key-schema AttributeName=uuid,KeyType=HASH

# create ApiKey table with test key = EC7C2E16-5028-432F-8AF2-A79A64CF3BC1, secret = 1ED18444-7238-410B-A536-D6C15A3C
createapikeytable:
	AWS_ENDPOINT=http://localhost:8000 AWS_DEFAULT_REGION=local AWS_ACCESS_KEY_ID=abc123 AWS_SECRET_ACCESS_KEY=abc123 AWS_PAGER="" aws dynamodb create-table \
		--table-name ApiKey \
		--billing-mode PAY_PER_REQUEST \
		--attribute-definitions AttributeName=value,AttributeType=S \
		--key-schema AttributeName=value,KeyType=HASH
	sleep 3
	AWS_ENDPOINT=http://localhost:8000 AWS_DEFAULT_REGION=local AWS_ACCESS_KEY_ID=abc123 AWS_SECRET_ACCESS_KEY=abc123 aws dynamodb put-item \
		--table-name ApiKey \
		--item '{"value": {"S": "EC7C2E16-5028-432F-8AF2-A79A64CF3BC1"},"hashedApiSecret": {"S": "$$2y$$10$$HtvmT/nnfofEhoFNmtk/9OfP4DDJvjzSa5dVhtOKolwb8hc6gJ9LK"},"activatedAt": {"N": "1590518082000"},"createdAt": {"N": "1590518082000"},"email": {"S": "example-user@example.com"}}'

showapikeys:
	aws dynamodb scan \
		--table-name ApiKey \
		--endpoint-url http://localhost:8000 \
		--region localhost

showwebauth:
	aws dynamodb scan \
		--table-name WebAuthn \
		--endpoint-url http://localhost:8000 \
		--region localhost

clean:
	docker compose kill
	docker compose rm -f
