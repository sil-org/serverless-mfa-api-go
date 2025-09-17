package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/gorilla/mux"
	"github.com/kelseyhightower/envconfig"

	mfa "github.com/silinternational/serverless-mfa-api-go"
)

var envConfig mfa.EnvConfig

func main() {
	log.SetOutput(os.Stdout)
	log.Println("Server starting...")

	err := envconfig.Process("", &envConfig)
	if err != nil {
		log.Fatalf("error loading env vars: %s", err)
	}
	envConfig.InitAWS()
	mfa.SetConfig(envConfig)

	// ListenAndServe starts an HTTP server with a given address and
	// handler defined in NewRouter.
	log.Println("Starting service on port 8080")
	router := newRouter(mfa.NewApp(envConfig))
	log.Fatal(http.ListenAndServe(":8080", router))
}

// route is used to pass information about a particular route.
type route struct {
	Name        string
	Method      string
	Pattern     string
	HandlerFunc http.HandlerFunc
}

// getRoutes returns a list of routes for the server
func getRoutes(app *mfa.App) []route {
	return []route{
		{
			Name:        "ActivateApiKey",
			Method:      "POST",
			Pattern:     "/api-key/activate",
			HandlerFunc: app.ActivateApiKey,
		},
		{
			Name:        "RotateApiKey",
			Method:      "POST",
			Pattern:     "/api-key/rotate",
			HandlerFunc: app.RotateApiKey,
		},
		{
			Name:        "CreateApiKey",
			Method:      "POST",
			Pattern:     "/api-key",
			HandlerFunc: app.CreateApiKey,
		},
		{
			Name:        "FinishRegistration",
			Method:      "PUT",
			Pattern:     "/webauthn/register",
			HandlerFunc: app.FinishRegistration,
		},
		{
			Name:        "BeginLogin",
			Method:      "POST",
			Pattern:     "/webauthn/login",
			HandlerFunc: app.BeginLogin,
		},
		{
			Name:        "FinishLogin",
			Method:      "PUT",
			Pattern:     "/webauthn/login",
			HandlerFunc: app.FinishLogin,
		},
		{
			Name:        "DeleteUser",
			Method:      "DELETE",
			Pattern:     "/webauthn/user",
			HandlerFunc: app.DeleteUser,
		},
		{ // This expects a path param that is the id that was previously returned
			// as the key_handle_hash from the FinishRegistration call.
			// Alternatively, if the id param indicates that a legacy U2F key should be removed
			//	 (e.g. by matching the string "u2f")
			//   then that user is saved with all of its legacy u2f fields blanked out.
			Name:        "DeleteCredential",
			Method:      "DELETE",
			Pattern:     fmt.Sprintf("/webauthn/credential/{%s}", mfa.IDParam),
			HandlerFunc: app.DeleteCredential,
		},
		{
			Name:        "CreateTOTP",
			Method:      "POST",
			Pattern:     "/totp",
			HandlerFunc: app.CreateTOTP,
		},
	}
}

// newRouter forms a new mux router, see https://github.com/gorilla/mux.
func newRouter(app *mfa.App) *mux.Router {
	// Create a basic router.
	router := mux.NewRouter().StrictSlash(true)

	// authenticate request based on api key and secret in headers
	// also adds user to context
	router.Use(authenticationMiddleware)

	// Assign the handlers to run when endpoints are called.
	for _, route := range getRoutes(app) {
		router.Methods(route.Method).Path(route.Pattern).Name(route.Name).Handler(route.HandlerFunc)
	}

	router.NotFoundHandler = router.NewRoute().HandlerFunc(notFound).GetHandler()
	return router
}

func notFound(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(http.StatusNotFound)

	notFound := map[string]string{
		"Method":     r.Method,
		"URL":        r.URL.String(),
		"RequestURI": r.RequestURI,
	}
	if err := json.NewEncoder(w).Encode(notFound); err != nil {
		log.Printf("ERROR could not marshal not found message to JSON: %s", err)
	}
}
