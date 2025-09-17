package router

import (
	"net/http"

	mfa "github.com/silinternational/serverless-mfa-api-go"
)

// NewMux forms a new ServeMux router, see https://pkg.go.dev/net/http#ServeMux.
func NewMux(app *mfa.App) *http.ServeMux {
	mux := http.NewServeMux()

	for _, r := range getRoutes(app) {
		mux.Handle(r.Pattern, authenticationMiddleware(r.HandlerFunc))
	}
	return mux
}

// route is used to pass information about a particular route.
type route struct {
	Pattern     string
	HandlerFunc http.HandlerFunc
}

// getRoutes returns a list of routes for the server
func getRoutes(app *mfa.App) []route {
	return []route{
		{
			Pattern:     "POST /api-key/activate",
			HandlerFunc: app.ActivateApiKey,
		},
		{
			Pattern:     "POST /api-key/rotate",
			HandlerFunc: app.RotateApiKey,
		},
		{
			Pattern:     "POST /api-key",
			HandlerFunc: app.CreateApiKey,
		},
		{
			Pattern:     "POST /totp",
			HandlerFunc: app.CreateTOTP,
		},
		{
			Pattern:     "DELETE /totp/{" + mfa.UUIDParam + "}",
			HandlerFunc: app.DeleteTOTP,
		},
		{
			Pattern:     "POST /webauthn/register",
			HandlerFunc: app.BeginRegistration,
		},
		{
			Pattern:     "PUT /webauthn/register",
			HandlerFunc: app.FinishRegistration,
		},
		{
			Pattern:     "POST /webauthn/login",
			HandlerFunc: app.BeginLogin,
		},
		{
			Pattern:     "PUT /webauthn/login",
			HandlerFunc: app.FinishLogin,
		},
		{
			Pattern:     "DELETE /webauthn/user",
			HandlerFunc: app.DeleteUser,
		},
		{ // This expects a path param that is the id that was previously returned
			// as the key_handle_hash from the FinishRegistration call.
			// Alternatively, if the id param indicates that a legacy U2F key should be removed
			//	 (e.g. by matching the string "u2f")
			//   then that user is saved with all of its legacy u2f fields blanked out.
			Pattern:     "DELETE /webauthn/credential/{" + mfa.IDParam + "}/",
			HandlerFunc: app.DeleteCredential,
		},
	}
}
