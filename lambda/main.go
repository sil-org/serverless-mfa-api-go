package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-lambda-go/lambdacontext"
	"github.com/getsentry/sentry-go"
	"github.com/kelseyhightower/envconfig"

	mfa "github.com/sil-org/serverless-mfa-api-go"
	"github.com/sil-org/serverless-mfa-api-go/router"
)

var envConfig mfa.EnvConfig

var errorLog = &errorRecorder{Handler: slog.NewJSONHandler(os.Stdout, nil)}

func main() {
	slog.SetDefault(slog.New(errorLog))

	err := envconfig.Process("", &envConfig)
	if err != nil {
		mfa.Fatal("error loading env vars", err)
	}
	envConfig.InitAWS()
	mfa.SetConfig(envConfig)

	sentryInit()

	lambda.Start(handler)
}

func handler(ctx context.Context, req events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	// Lambda reuses the process between invocations, so drop any record left by the previous one
	errorLog.last.Store(nil)

	r := httpRequestFromProxyRequest(ctx, req)
	w := newLambdaResponseWriter()

	app := mfa.NewApp(envConfig)
	mux := router.NewMux(app)

	mux.ServeHTTP(w, r)

	headers := map[string]string{}
	for k, v := range w.Header() {
		headers[k] = v[0]
	}

	if w.Status == http.StatusInternalServerError && envConfig.SentryDSN != "" {
		captureServerError(ctx, r, w.Body)
		sentry.Flush(2 * time.Second)
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

func sentryInit() {
	if envConfig.SentryDSN == "" {
		return
	}

	if err := sentry.Init(sentry.ClientOptions{
		Dsn:         envConfig.SentryDSN,
		EnableLogs:  true,
		Environment: envConfig.Environment,
	}); err != nil {
		slog.Error(fmt.Sprintf("Sentry initialization failed: %v", err))
	}
}

// captureServerError does not attach the request (scope.SetRequest) because its headers include the API secret.
func captureServerError(ctx context.Context, r *http.Request, body []byte) {
	sentry.WithScope(func(scope *sentry.Scope) {
		scope.SetLevel(sentry.LevelError)
		scope.SetTag("route", r.Pattern)
		if lc, ok := lambdacontext.FromContext(ctx); ok {
			scope.SetTag("aws_request_id", lc.AwsRequestID)
		}

		message := string(body)
		if record := errorLog.last.Load(); record != nil {
			message = record.Message
			record.Attrs(func(attr slog.Attr) bool {
				scope.SetExtra(attr.Key, attr.Value.String())
				return true
			})
		}
		sentry.CaptureMessage(message)
	})
}

// errorRecorder keeps the latest error-level log record, which holds the real cause behind a generic 500 response.
type errorRecorder struct {
	slog.Handler
	last atomic.Pointer[slog.Record]
}

func (e *errorRecorder) Handle(ctx context.Context, record slog.Record) error {
	if record.Level >= slog.LevelError {
		clone := record.Clone()
		e.last.Store(&clone)
	}
	return e.Handler.Handle(ctx, record)
}
