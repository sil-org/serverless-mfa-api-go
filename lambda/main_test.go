package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"testing"

	"github.com/aws/aws-lambda-go/lambdacontext"
	"github.com/getsentry/sentry-go"
	"github.com/stretchr/testify/require"
)

func Test_sentryInit(t *testing.T) {
	sentryInit()
}

func Test_captureServerError(t *testing.T) {
	assert := require.New(t)

	transport := &sentry.MockTransport{}
	assert.NoError(sentry.Init(sentry.ClientOptions{Dsn: "https://public@sentry.example.com/1", Transport: transport}))

	slog.New(errorLog).Error("failed to create a new TOTP", "handler", "CreateTOTP", "error", errors.New("failed to store TOTP"))

	ctx := lambdacontext.NewContext(context.Background(), &lambdacontext.LambdaContext{AwsRequestID: "request-id"})
	r := &http.Request{Pattern: "POST /totp", URL: &url.URL{Path: "/totp"}}
	captureServerError(ctx, r, []byte(`{"error":"Internal server error"}`))

	assert.Len(transport.Events(), 1)
	event := transport.Events()[0]
	assert.Equal("failed to create a new TOTP", event.Message)
	assert.Equal("failed to store TOTP", event.Extra["error"])
	assert.Equal("POST /totp", event.Tags["route"])
	assert.Equal("request-id", event.Tags["aws_request_id"])
	assert.Nil(event.Request, "the request headers include the API secret")
}
