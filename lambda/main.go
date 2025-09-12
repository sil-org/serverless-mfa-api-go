package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/gorilla/mux"
	"github.com/kelseyhightower/envconfig"

	mfa "github.com/silinternational/serverless-mfa-api-go"
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

func addDeleteCredentialParamForMux(r *http.Request, key, value string) *http.Request {
	vars := map[string]string{key: value}
	return mux.SetURLVars(r, vars)
}

func handler(ctx context.Context, req events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	r := httpRequestFromProxyRequest(ctx, req)

	app := mfa.NewApp(envConfig)

	if !strings.HasPrefix(r.URL.Path, "/api-key") {
		user, err := mfa.AuthenticateRequest(r)
		if err != nil {
			return clientError(http.StatusUnauthorized, fmt.Sprintf("unable to authenticate request: %s", err))
		}
		newCtx := context.WithValue(r.Context(), mfa.UserContextKey, user)
		r = r.WithContext(newCtx)
	}

	// Use custom lambda http.ResponseWriter
	w := newLambdaResponseWriter()

	// This (delete /webauthn/credential/abc123) expects a path param that is
	//   the id that was previously returned as
	//   the key_handle_hash from the FinishRegistration call.
	// Alternatively, if the id param indicates that a legacy U2F key should be removed
	//   (e.g. by matching the string "u2f")
	//   then that user is saved with all of its legacy u2f fields blanked out.
	if credIdToDelete, ok := credentialToDelete(req); ok {
		// add the id to the context in order for mux to retrieve it
		r = addDeleteCredentialParamForMux(r, mfa.IDParam, credIdToDelete)
		app.DeleteCredential(w, r)
		// Routes other than /webauthn/delete/credential/abc213
	} else {
		route := strings.ToLower(fmt.Sprintf("%s %s", req.HTTPMethod, req.Path))

		switch route {
		case "post /api-key":
			app.CreateApiKey(w, r)
		case "post /api-key/activate":
			app.ActivateApiKey(w, r)
		case "post /api-key/rotate":
			app.RotateApiKey(w, r)
		case "post /totp":
			app.CreateTOTP(w, r)
		case "post /webauthn/login":
			app.BeginLogin(w, r)
		case "put /webauthn/login":
			app.FinishLogin(w, r)
		case "post /webauthn/register":
			app.BeginRegistration(w, r)
		case "put /webauthn/register":
			app.FinishRegistration(w, r)
		case "delete /webauthn/user":
			app.DeleteUser(w, r)
		default:
			return clientError(http.StatusNotFound, fmt.Sprintf("The requested route is not supported: %s", route))
		}
	}
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

// clientError helper for send responses relating to client errors.
func clientError(status int, body string) (events.APIGatewayProxyResponse, error) {
	type cError struct {
		Error string
	}

	js, _ := json.Marshal(cError{Error: body})

	return events.APIGatewayProxyResponse{
		StatusCode: status,
		Body:       string(js),
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
