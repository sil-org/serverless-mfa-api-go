package router

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	mfa "github.com/silinternational/serverless-mfa-api-go"
)

// authenticationMiddleware gets API key information from request headers and validates the key/signature
// Then it uses api meta information provided in headers to configure a webauthn client and fetch the
// user from storage and attach to context.
func authenticationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api-key") {
			next.ServeHTTP(w, r)
			return
		}

		user, err := mfa.AuthenticateRequest(r)
		if err != nil {
			http.Error(w, fmt.Sprintf("unable to authenticate request: %s", err), http.StatusUnauthorized)
			return
		}

		// Add user into context for further use
		ctx := context.WithValue(r.Context(), mfa.UserContextKey, user)

		// Call the next handler, which can be another middleware in the chain, or the final handler.
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
