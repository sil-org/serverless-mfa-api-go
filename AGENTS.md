# AGENTS.md

This file provides guidance to coding agents working in this repository.

## What this is

A Go backend providing shared TOTP and WebAuthn/Passkey MFA services for multiple consuming applications, authenticated via a per-tenant API key + secret pair (the secret also doubles as the encryption key for stored credentials — losing it means losing all credentials protected by it). It ships as two entry points sharing the same core package and router:

- `server/` — standalone binary using `net/http` (for local dev / non-Lambda deployment)
- `lambda/` — AWS Lambda handler (via `aws-lambda-go`), deployed through AWS CDK (`cdk/`, a separate Go module) with Terraform-provisioned prerequisites (`terraform/`)

The full HTTP API is documented in `openapi.yaml` and summarized in `README.md`.

## Commands

```bash
make test           # tears down/rebuilds Docker Compose env, runs `go test ./...` in the app container
make demo           # starts proxy+ui+app+dbinit, for manual testing through the demo-ui over HTTPS via Traefik
make db             # start just the local DynamoDB container
make dbinit         # start DynamoDB + create the WebAuthn/Totp/ApiKey tables + seed a test API key
make clean          # kill and remove all compose containers
```

To run a single test or use your IDE's test runner, start DynamoDB and the tables with `make dbinit`, then run tests with `AWS_ENDPOINT=http://localhost:8000 AWS_DEFAULT_REGION=localhost AWS_ACCESS_KEY_ID=abc123 AWS_SECRET_ACCESS_KEY=abc123 go test ./...` (see `fixtures_test.go` / `suite_test.go` for how tests get their AWS/env config). CI runs tests via `docker compose run app go test ./...`.

Local HTTP API is available on `localhost:8161` once `make demo` (or `app`+`db`) is running. `make dbinit` seeds an API key/secret pair documented in the Makefile and README (`createapikeytable` target) for manual testing.

Lint/vuln-check (matches CI): `golangci-lint run` (config in `.golangci.yaml`) and `go tool govulncheck ./...`.

To exercise the Lambda build path locally: `air -c .air-cdk.toml` (requires CDK + SAM CLI installed; runs `sam local start-api` on port 8160, rebuilding on change). Manual Lambda build for deploy: `./build.sh` (builds `bootstrap` with `-tags lambda.norpc`, then `cdk synth`).

## Architecture

### Core package + two entry points

The root package `mfa` (module `github.com/sil-org/serverless-mfa-api-go`) holds all business logic: API key management (`apikey.go`), TOTP (`totp.go`), WebAuthn registration/login (`webauthn.go`, `webauthnuser.go`), and DynamoDB access (`storage.go`). `router/router.go` builds a single `http.ServeMux` (Go 1.22+ method+pattern routing) wrapping every route in `authenticationMiddleware` (`router/middleware.go`), which calls `mfa.AuthenticateRequest`. Both `server/main.go` and `lambda/main.go` do the same three things — load `EnvConfig` via `envconfig`, call `mfa.NewApp`, mount `router.NewMux(app)` — and differ only in how they serve HTTP (`http.ListenAndServe` vs. a hand-rolled `lambdaResponseWriter` that adapts `events.APIGatewayProxyRequest`/`Response`).

### Authentication and per-tenant encryption

Every request (except `GET /status`) must carry `x-mfa-apikey` / `x-mfa-apisecret` headers. `AuthenticateRequest` (`auth.go`) loads the matching `ApiKey` from DynamoDB, verifies the secret against `HashedSecret` (bcrypt), then dispatches based on the first URL path segment (`webauthn` → loads/creates a `WebauthnUser`, `totp` → returns the `ApiKey` itself, `api-key` → returns the `ApiKey`). The API secret is also used to derive an AES key (see `apikey.go`'s `EncryptData`/`DecryptData`, and the legacy `EncryptLegacy`/`DecryptLegacy` pair used for old U2F fields) — all TOTP secrets and WebAuthn credential blobs are encrypted at rest with the caller's own secret, never a service-wide key. `ApiKey.ReEncrypt*` methods support key rotation (`POST /api-key/rotate`, marked experimental) by decrypting under the old key and re-encrypting under the new one across both the TOTP and WebAuthn tables.

### Storage

`storage.go`'s `Storage` type wraps a raw `dynamodb.Client` with generic `Store`/`Load`/`Delete`/`ScanAll`/`ScanApiKey` methods operating on struct tags (`dynamodbav`) via `attributevalue`. There are three tables, one per concern (`ApiKeyTable`, `TotpTable`, `WebauthnTable`), named via env vars in `EnvConfig` (`config.go`). Scans auto-paginate via `LastEvaluatedKey`. There is no ORM/model layer beyond this — domain types (`ApiKey`, `TOTP`, `WebauthnUser`) call `Storage` methods directly on themselves (e.g. `ApiKey.Load()`/`Save()`).

### WebAuthn user model

`WebauthnUser` (`webauthnuser.go`) stores both legacy U2F fields (`EncryptedAppId`/`EncryptedKeyHandle`/`EncryptedPublicKey`, decrypted with `DecryptLegacy`) and modern WebAuthn fields (`EncryptedCredentials`, `EncryptedSessionData`, decrypted with `DecryptData`) on the same record, keyed by the caller-supplied `x-mfa-UserUUID`. A special credential ID (`LegacyU2FCredID = "u2f"`) marks the at-most-one synthesized credential representing old U2F registrations, letting old and new auth methods coexist per user. `WebauthnMeta` (in `webauthn.go`) carries per-request Relying Party info (RPID/RPOrigin/RPDisplayName) from headers rather than from `EnvConfig`, since this API is intentionally shared across multiple consuming applications/domains.

### Testing conventions

Tests use `testify/suite`; `MfaSuite` (`suite_test.go`) resets the local DynamoDB tables before each test via `initDb`. `fixtures_test.go` provides shared fixture builders (`getDBConfig`, `getTestWebauthnUsers`) for seeding multiple API keys and WebAuthn users with credentials in one call. Tests require the Docker Compose DynamoDB instance running on `localhost:8010` — there is no mocking of DynamoDB.

### CI/CD

`.github/workflows/test-deploy-publish.yml`: `tests` (docker compose `go test ./...`) and `lint` (`golangci-lint` + `govulncheck`) run on every push; on `main` or a version tag, `deploy` builds the Lambda binary and runs `cdk deploy` per AWS region (`us-east-1`, `us-west-2`), and `build-and-publish` builds/pushes a Docker image to `ghcr.io`. The `cdk/` directory is its own Go module (separate `go.mod`) and is excluded from triggering CI via `paths-ignore` only for `terraform/**`, not for `cdk/`.
