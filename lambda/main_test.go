package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"testing"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambdacontext"
	"github.com/getsentry/sentry-go"
	"github.com/stretchr/testify/require"

	mfa "github.com/sil-org/serverless-mfa-api-go"
)

func Test_sentryInit(t *testing.T) {
	sentryInit()
}

func Test_captureServerError(t *testing.T) {
	assert := require.New(t)

	transport := &sentry.MockTransport{}
	assert.NoError(sentry.Init(sentry.ClientOptions{Dsn: "https://public@sentry.example.com/1", Transport: transport}))

	recorder := &errorRecorder{Handler: slog.NewJSONHandler(io.Discard, nil)}
	slog.New(recorder).Error("failed to create a new TOTP", "handler", "CreateTOTP", "error", errors.New("failed to store TOTP"))

	ctx := lambdacontext.NewContext(context.Background(), &lambdacontext.LambdaContext{AwsRequestID: "request-id"})
	r := &http.Request{Pattern: "POST /totp", URL: &url.URL{Path: "/totp"}, Header: http.Header{}}
	r.Header.Set(mfa.HeaderAPIKey, "api-key")
	r.Header.Set(mfa.HeaderAPISecret, "api-secret")
	r.Header.Set("x-mfa-UserUUID", "user-uuid")
	captureServerError(ctx, r, []byte(`{"error":"Internal server error"}`), recorder.last.Load())

	assert.Len(transport.Events(), 1)
	event := transport.Events()[0]
	assert.Equal("failed to create a new TOTP", event.Message)
	assert.Equal("failed to store TOTP", event.Extra["error"])
	assert.Equal("POST /totp", event.Tags["route"])
	assert.Equal("request-id", event.Tags["aws_request_id"])
	assert.NotNil(event.Request)
	assert.Equal("user-uuid", event.Request.Headers["X-Mfa-Useruuid"])
	assert.NotContains(event.Request.Headers, "X-Mfa-Apisecret", "the API secret must not be sent to Sentry")
	assert.NotContains(event.Request.Headers, "X-Mfa-Apikey", "the API key must not be sent to Sentry")
}

func Test_newHandler(t *testing.T) {
	assert := require.New(t)

	recorder := &errorRecorder{Handler: slog.NewJSONHandler(io.Discard, nil)}
	slog.New(recorder).Error("error from an earlier request")

	response, err := newHandler(recorder)(context.Background(), events.APIGatewayProxyRequest{HTTPMethod: http.MethodGet, Path: "/status"})
	assert.NoError(err)
	assert.Equal(http.StatusNoContent, response.StatusCode)
	assert.Nil(recorder.last.Load(), "each request must start without the previous request's error")
}
