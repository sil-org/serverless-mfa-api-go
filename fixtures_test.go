package mfa

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/go-webauthn/webauthn/webauthn"
)

type baseTestConfig struct {
	AwsConfig      aws.Config
	EnvConfig      EnvConfig
	Storage        *Storage
	WebAuthnClient *webauthn.WebAuthn
}

func getDBConfig(ms *MfaSuite) baseTestConfig {
	awsConfig := testAwsConfig()
	envCfg := testEnvConfig(awsConfig)
	localStorage, err := NewStorage(awsConfig)
	ms.NoError(err, "failed creating local storage for test")

	web, err := webauthn.New(&webauthn.Config{
		RPDisplayName: "TestRPName",   // Display Name for your site
		RPID:          "111.11.11.11", // Generally the FQDN for your site
		Debug:         true,
		RPOrigins:     []string{testRpOrigin},
	})

	ms.NoError(err, "failed creating new webAuthnClient for test")

	return baseTestConfig{
		AwsConfig:      awsConfig,
		EnvConfig:      envCfg,
		Storage:        localStorage,
		WebAuthnClient: web,
	}
}

func getTestWebauthnUsers(ms *MfaSuite, config baseTestConfig) []WebauthnUser {
	cred10 := webauthn.Credential{ID: []byte("C10")}
	cred20 := webauthn.Credential{ID: []byte("C20")}
	cred21 := webauthn.Credential{ID: []byte("C21")}

	// Make new, unique webauthn users with their own api keys
	apiKey0 := ApiKey{
		Key:         "1034567890123456",
		Secret:      "E086600E-3DBF-4C23-A0DA-9C55D448",
		Store:       config.Storage,
		ActivatedAt: 1,
	}
	must(apiKey0.Hash())

	apiKey1 := apiKey0
	apiKey1.Key = "1134567890123456"
	apiKey1.Secret = "E186600E-3DBF-4C23-A0DA-9C55D448"
	must(apiKey1.Hash())

	apiKey2 := apiKey0
	apiKey2.Key = "1234567890123456"
	apiKey2.Secret = "E286600E-3DBF-4C23-A0DA-9C55D448"
	must(apiKey2.Hash())

	testUser0 := WebauthnUser{
		ID:             apiKey0.Secret,
		Name:           "Nancy_NoCredential",
		DisplayName:    "Nancy NoCredential",
		Store:          config.Storage,
		WebAuthnClient: config.WebAuthnClient,
		ApiKey:         apiKey0,
		ApiKeyValue:    apiKey0.Key,
	}

	testUser1 := testUser0
	testUser1.ID = apiKey1.Secret
	testUser1.Name = "Oscar_OneCredential"
	testUser1.DisplayName = "Oscar OneCredential"
	testUser1.ApiKey = apiKey1
	testUser1.ApiKeyValue = apiKey1.Key
	testUser1.Credentials = []webauthn.Credential{cred10}

	testUser2 := testUser0
	testUser2.ID = apiKey2.Secret
	testUser2.Name = "Tony_TwoCredentials"
	testUser2.DisplayName = "Tony TwoCredentials"
	testUser2.ApiKey = apiKey2
	testUser2.ApiKeyValue = apiKey2.Key
	testUser2.Credentials = []webauthn.Credential{cred20, cred21}

	users := []WebauthnUser{testUser0, testUser1, testUser2}
	for i := range users {
		ms.NoError(users[i].encryptAndStoreCredentials(), "failed saving initial test user")
	}

	params := &dynamodb.ScanInput{
		TableName: aws.String(config.EnvConfig.WebauthnTable),
	}

	ctx := context.Background()
	results, err := config.Storage.client.Scan(ctx, params)
	ms.NoError(err, "failed to scan storage for new user entries")
	ms.Equal(int32(3), results.Count, "Count:3", "initial data wasn't saved properly")

	return users
}

func mustEncryptLegacy(key ApiKey, plaintext string) string {
	ciphertext, err := key.EncryptLegacy(plaintext)
	must(err)
	return ciphertext
}
