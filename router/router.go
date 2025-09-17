package router

import (
	"net/http"

	mfa "github.com/silinternational/serverless-mfa-api-go"
)

// NewMux forms a new ServeMux router, see https://pkg.go.dev/net/http#ServeMux.
func NewMux(app *mfa.App) *http.ServeMux {
	mux := http.NewServeMux()

	for pattern, handler := range getRoutes(app) {
		mux.Handle(pattern, authenticationMiddleware(handler))
	}
	return mux
}

// getRoutes returns a list of routes for the server
func getRoutes(app *mfa.App) map[string]http.HandlerFunc {
	return map[string]http.HandlerFunc{
		"POST /api-key/activate":                             app.ActivateApiKey,
		"POST /api-key/rotate":                               app.RotateApiKey,
		"POST /api-key":                                      app.CreateApiKey,
		"POST /totp":                                         app.CreateTOTP,
		"DELETE /totp/{" + mfa.UUIDParam + "}":               app.DeleteTOTP,
		"POST /totp/{" + mfa.UUIDParam + "}/validate":        app.ValidateTOTP,
		"POST /webauthn/register":                            app.BeginRegistration,
		"PUT /webauthn/register":                             app.FinishRegistration,
		"POST /webauthn/login":                               app.BeginLogin,
		"PUT /webauthn/login":                                app.FinishLogin,
		"DELETE /webauthn/user":                              app.DeleteUser,
		"DELETE /webauthn/credential/{" + mfa.IDParam + "}/": app.DeleteCredential,
	}
}
