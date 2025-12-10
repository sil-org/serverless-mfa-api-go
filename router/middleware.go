package router

import (
	"context"
	"log"
	"net/http"

	mfa "github.com/sil-org/serverless-mfa-api-go"
)

// authenticationMiddleware gets API key information from request headers and validates the key/signature.
// If the key is active and valid an authenticated user (e.g. Webauthn user and client) is added to the request
// context.
func authenticationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, err := mfa.AuthenticateRequest(r)
		if err != nil {
			log.Printf("unable to authenticate request: %s", err)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Add user into context for further use
		ctx := context.WithValue(r.Context(), mfa.UserContextKey, user)

		// Call the next handler, which can be another middleware in the chain, or the final handler.
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
