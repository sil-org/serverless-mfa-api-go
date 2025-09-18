package mfa

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
)

const (
	IDParam   = "id"
	UUIDParam = "uuid"
)

// simpleError is a custom error type that can be JSON-encoded for API responses
type simpleError struct {
	Error string `json:"error"`
}

// newSimpleError creates a new simpleError from the given error
func newSimpleError(err error) simpleError {
	return simpleError{Error: err.Error()}
}

// jsonResponse encodes a body as JSON and writes it to the response. It sets the response Content-Type header to
// "application/json".
func jsonResponse(w http.ResponseWriter, body interface{}, status int) {
	var data interface{}
	switch b := body.(type) {
	case error:
		data = newSimpleError(b)
	default:
		data = body
	}

	var jBody []byte
	var err error
	if data != nil {
		jBody, err = json.Marshal(data)
		if err != nil {

			// SonarQube flagged this as vulnerable to injection attacks. Rather than exhaustively search for places
			// where user input is inserted into the error message, I'll just sanitize it as recommended.
			sanitizedError := strings.ReplaceAll(strings.ReplaceAll(err.Error(), "\n", "_"), "\r", "_")

			log.Printf("failed to marshal response body to json: %s", sanitizedError)
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("failed to marshal response body to json"))
			return
		}
	}

	w.Header().Set("content-type", "application/json")
	w.WriteHeader(status)
	_, err = w.Write(jBody)
	if err != nil {
		log.Printf("failed to write response in jsonResponse: %s\n", err)
	}
}
