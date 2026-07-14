package mfa

import (
	"context"
	"log/slog"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
)

var envConfig EnvConfig

// EnvConfig holds environment specific configurations and is populated on init
type EnvConfig struct {
	ApiKeyTable   string `required:"true" split_words:"true"`
	TotpTable     string `required:"true" split_words:"true"`
	WebauthnTable string `required:"true" split_words:"true"`

	AwsEndpoint      string `default:"" split_words:"true"`
	AwsDefaultRegion string `default:"" split_words:"true"`

	AWSConfig aws.Config `json:"-"`

	Environment string
	SentryDSN   string `split_words:"true"`
}

func (e *EnvConfig) InitAWS() {
	cfg, err := config.LoadDefaultConfig(
		context.Background(),
		config.WithRegion(e.AwsDefaultRegion),
		config.WithBaseEndpoint(e.AwsEndpoint),
	)
	if err != nil {
		panic("InitAWS failed at LoadDefaultConfig: " + err.Error())
	}
	e.AWSConfig = cfg
}

func SetConfig(c EnvConfig) {
	envConfig = c
	slog.Info("config loaded",
		"api_key_table", envConfig.ApiKeyTable,
		"environment", envConfig.Environment,
		"aws_default_region", envConfig.AwsDefaultRegion,
		"aws_endpoint", envConfig.AwsEndpoint,
		"totp_table", envConfig.TotpTable,
		"webauthn_table", envConfig.WebauthnTable,
	)
}

func Fatal(msg string, err error) {
	slog.Error(msg, "error", err)
	os.Exit(1)
}
