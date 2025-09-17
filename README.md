# A Serverless MFA API with support for TOTP and WebAuthn

This project provides a semi-generic backend API for supporting Time-based One Time Passcode (TOTP) and WebAuthn 
Passkey registration and authentication. It is intended to be run in a manner as to be shared between multiple consuming
applications. It uses an API key and secret to authenticate requests, and further uses that secret as the encryption 
key. Loss of the API secret would mean loss of all credentials stored.

This application can be run in two ways:
1. As a standalone server using the builtin webserver available in the `server/` folder
2. As an AWS Lambda function using the `lambda/` implementation. This implementation can also use 
[AWS CDK](https://aws.amazon.com/cdk/) to help automate build/deployment. It should also be 
noted that the `lambda` format depends on some resources already existing in AWS. There is a `lambda/terraform/`
folder with the Terraform configurations needed to provision them. 

# API definition

The full definition of the API is found in the openapi.yaml file. A brief summary follows.

## The APIKey API

### Create APIKey

`POST /api-key`

### Activate APIKey

`POST /api-key/activate`

### Rotate APIKey (experimental)

This endpoint has not yet been proven in production use. Proceed at your own risk.

`POST /api-key/rotate`

## The TOTP API

### Required Headers
1. `x-mfa-apikey` - The API Key
2. `x-mfa-apisecret` - The API Key Secret

### Create TOTP Passcode

`POST /totp`

### Delete TOTP Passcode

`DELETE /totp/{uuid}`

### Validate TOTP Passcode

`POST /totp/{uuid}/validate`

Coming soon.

## The Webauthn API
Yes, as you'll see below this API makes heavy use of custom headers for things that seem like they could go into 
the request body. We chose to use headers though so that what is sent in the body can be handed off directly
to the WebAuthn library and fit the structures it was expecting without causing any conflicts, etc.

### Required Headers
1. `x-mfa-apikey` - The API Key
2. `x-mfa-apisecret` - The API Key Secret
3. `x-mfa-RPDisplayName` - The Relying Party Display Name, ex: `ACME Inc.`
4. `x-mfa-RPID` - The Relying Party ID, ex: `domain.com` (should only be the top level domain, no subdomain, protocol, 
or path)
5. `x-mfa-RPOrigin` - The browser Origin for the request, ex: `https://sub.domain.com` (include appropriate subdomain 
and protocol, no path or port)
6. `x-mfa-UserUUID` - The UUID for the user attempting to register or authenticate with WebAuthn. This has nothing
to do with WebAuthn, but is the primary key for finding the right records in DynamoDB
7. `x-mfa-Username` - The user's username of your service
8. `x-mfa-UserDisplayName` - The user's display name

### Optional headers

1. `x-mfa-Usericon` - 
2. `x-mfa-Rpicon` -

### Begin Registration
`POST /webauthn/register`

### Finish Registration
`PUT /webauthn/register`

### Begin Login
`POST /webauthn/login`

### Finish Login
`PUT /webauthn/login`

### Delete Webauthn "User"
`DELETE /webauthn/user`

### Delete one of the user's Webauthn credentials
`DELETE /webauthn/credential`

# Development

## Unit tests

To run unit tests, simply run "make test". It will spin up a Docker Compose environment and run the tests using
Docker containers for the API and for DynamoDB.

## Manual testing

Unit tests can be run individually, either on the command line or through your IDE. It is also possible to 
test the server and Lambda implementations locally.

### Server

#### HTTP

If HTTPS is not needed, simply start the `app` container and exercise the API using localhost and the Docker port
defined in docker-compose.yml (currently 8161).

#### HTTPS

To use a "demo UI" that can interact with the API using HTTPS, use Traefik proxy, which is defined in the Docker
Compose environment. Traefik is a proxy that creates a Let's Encrypt certificate and routes traffic to the local
container via a registered DNS record. To configure this, define the following variables in `local.env`:

- DNS_PROVIDER=cloudflare
- CLOUDFLARE_DNS_API_TOKEN=<insert a valid Cloudflare token that has DNS write permission on the domain defined below>
- LETS_ENCRYPT_EMAIL=<insert your actual email address here>
- LETS_ENCRYPT_CA=production
- TLD=<your DNS domain>
- SANS=mfa-ui.<your domain>,mfa-app.<your domain>
- BACKEND1_URL=http://ui:80
- FRONTEND1_DOMAIN=mfa-ui.<your domain>
- BACKEND2_URL=http://app:8080
- FRONTEND2_DOMAIN=mfa-app.<your domain>

Create DNS A records (without Cloudflare proxy enabled) for the values defined in `FRONTEND1_DOMAIN` and 
`FRONTEND2_DOMAIN` pointing to 127.0.0.1 and wait for DNS propagation. Once all of the above configuration is in place,
run `make demo`. The first time will take several minutes for all the initialization. You can watch Docker logs on the 
proxy container to keep tabs on the progress.

### Lambda

To exercise the API as it would be used in AWS Lambda, run this command: `air -c .air-cdk.toml`. This will run a
file watcher that will rebuild the app code and the CDK stack, then run `sam local start-api` using the generated
Cloudformation template. This will listen on port 8160. Any code changes will trigger a rebuild and SAM will restart
using the new code.

Implementation notes:

- SAM uses Docker internally, which would make it complicated to run with Docker Compose.
- You will need to install CDK and SAM on your computer for this to work.
- It can use the DynamoDB container in Docker Compose, which can be started using `make dbinit`.
- The `make dbinit` command creates an APIKey (key: `EC7C2E16-5028-432F-8AF2-A79A64CF3BC1` 
secret: `1ED18444-7238-410B-A536-D6C15A3C`)
- Some unit tests will delete the APIKey created by `make dbinit`.
