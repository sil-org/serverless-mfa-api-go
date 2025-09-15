package main

import (
	"context"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/kelseyhightower/envconfig"

	mfa "github.com/silinternational/serverless-mfa-api-go"
	"github.com/silinternational/serverless-mfa-api-go/router"
)

var envConfig mfa.EnvConfig

func init() {
	log.SetOutput(os.Stdout)

	err := envconfig.Process("", &envConfig)
	if err != nil {
		log.Fatalf("error loading env vars: %s", err)
	}
	envConfig.InitAWS()
}

func main() {
	log.SetOutput(os.Stdout)

	err := envconfig.Process("", &envConfig)
	if err != nil {
		log.Fatalf("error loading env vars: %s", err)
	}
	envConfig.InitAWS()
	mfa.SetConfig(envConfig)

	lambda.Start(handler)
}

func credentialToDelete(req events.APIGatewayProxyRequest) (string, bool) {
	if strings.ToLower(req.HTTPMethod) != `delete` {
		return "", false
	}

	path := req.Path
	if !strings.HasPrefix(path, "/webauthn/credential/") {
		return "", false
	}

	parts := strings.Split(path, `/`)
	if len(parts) != 4 {
		return "", false
	}

	credID := parts[3]
	return credID, true
}

func handler(ctx context.Context, req events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	r := httpRequestFromProxyRequest(ctx, req)
	w := newLambdaResponseWriter()

	app := mfa.NewApp(envConfig)
	mux := router.NewMux(app)

	mux.ServeHTTP(w, r)

	headers := map[string]string{}
	for k, v := range w.Header() {
		headers[k] = v[0]
	}

	return events.APIGatewayProxyResponse{
		StatusCode: w.Status,
		Headers:    headers,
		Body:       string(w.Body),
	}, nil
}

func httpRequestFromProxyRequest(ctx context.Context, req events.APIGatewayProxyRequest) *http.Request {
	headers := http.Header{}
	for k, v := range req.Headers {
		headers.Set(k, v)
	}
	requestURL, _ := url.Parse(req.Path)
	r := &http.Request{
		Method:        req.HTTPMethod,
		ProtoMinor:    0,
		Header:        headers,
		Body:          io.NopCloser(strings.NewReader(req.Body)),
		ContentLength: int64(len(req.Body)),
		RemoteAddr:    req.RequestContext.Identity.SourceIP,
		RequestURI:    req.Path,
		URL:           requestURL,
	}

	return r.WithContext(ctx)
}
