package mfa

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

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

func (e *EnvConfig) String() string {
	b, err := json.Marshal(e)
	if err != nil {
		return fmt.Sprintf("error stringifying envConfig: %s", err)
	}
	return string(b)
}

func SetConfig(c EnvConfig) {
	envConfig = c
	log.Println("config:", envConfig.String())
}
