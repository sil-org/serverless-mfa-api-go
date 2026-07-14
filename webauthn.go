package mfa

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

const failedToGetUser = "failed to get user"

// WebauthnMeta holds metadata about the calling service for use in WebAuthn responses.
// Since this service/api is consumed by multiple sources this information cannot
// be stored in the envConfig
type WebauthnMeta struct {
	RPDisplayName   string `json:"RPDisplayName"` // Display Name for your site
	RPID            string `json:"RPID"`          // Generally the FQDN for your site
	RPOrigin        string `json:"RPOrigin"`      // The origin URL for WebAuthn requests
	RPIcon          string `json:"RPIcon"`        // Optional icon URL for your site
	UserUUID        string `json:"UserUUID"`
	Username        string `json:"Username"`
	UserDisplayName string `json:"UserDisplayName"`
	UserIcon        string `json:"UserIcon"`
}

// beginRegistrationResponse adds uuid to response for consumers that depend on this api to generate the uuid
type beginRegistrationResponse struct {
	UUID string `json:"uuid"`
	protocol.CredentialCreation
}

// finishRegistrationResponse contains the response data for the FinishRegistration endpoint
type finishRegistrationResponse struct {
	KeyHandleHash string `json:"key_handle_hash"`
}

// finishLoginResponse contains the response data for the FinishLogin endpoint
type finishLoginResponse struct {
	KeyHandleHash string `json:"key_handle_hash"`
}

// BeginRegistration processes the first half of the Webauthn Registration flow. It is the handler for the
// "POST /webauthn/register" endpoint, initiated by the client when creation of a new passkey is requested.
func (a *App) BeginRegistration(w http.ResponseWriter, r *http.Request) {
	const beginRegistration = "BeginRegistration"

	user, err := getWebauthnUser(r)
	if err != nil {
		slog.Error(failedToGetUser, "handler", beginRegistration, "error", err)
		jsonResponse(w, internalServerError, http.StatusInternalServerError)
		return
	}

	// If user.id is empty, treat as new user/registration
	if user.ID == "" {
		user.ID = NewUUID()
	}

	options, err := user.BeginRegistration()
	if err != nil {
		slog.Error("failed to begin registration", "handler", beginRegistration, "error", err)
		jsonResponse(w, invalidRequest, http.StatusBadRequest)
		return
	}

	response := beginRegistrationResponse{
		user.ID,
		*options,
	}

	jsonResponse(w, response, http.StatusOK)
}

// FinishRegistration processes the last half of the Webauthn Registration flow. It is the handler for the
// "PUT /webauthn/register" endpoint, initiated by the client with information encrypted by the new private key.
func (a *App) FinishRegistration(w http.ResponseWriter, r *http.Request) {
	const finishRegistration = "FinishRegistration"

	user, err := getWebauthnUser(r)
	if err != nil {
		slog.Error(failedToGetUser, "handler", finishRegistration, "error", err)
		jsonResponse(w, internalServerError, http.StatusInternalServerError)
		return
	}

	keyHandleHash, err := user.FinishRegistration(r)
	if err != nil {
		slog.Error("failed to finish registration", "handler", finishRegistration, "error", err)
		jsonResponse(w, invalidRequest, http.StatusBadRequest)
		return
	}

	response := finishRegistrationResponse{
		KeyHandleHash: keyHandleHash,
	}

	jsonResponse(w, response, http.StatusOK) // Handle next steps
}

// BeginLogin processes the first half of the Webauthn Authentication flow. It is the handler for the
// "POST /webauthn/login" endpoint, initiated by the client at the beginning of a login request.
func (a *App) BeginLogin(w http.ResponseWriter, r *http.Request) {
	const beginLogin = "BeginLogin"

	user, err := getWebauthnUser(r)
	if err != nil {
		slog.Error(failedToGetUser, "handler", beginLogin, "error", err)
		jsonResponse(w, internalServerError, http.StatusInternalServerError)
		return
	}

	options, err := user.BeginLogin()
	if err != nil {
		slog.Error("error beginning user login", "handler", beginLogin, "error", err)
		jsonResponse(w, invalidRequest, http.StatusBadRequest)
		return
	}

	jsonResponse(w, options, http.StatusOK)
}

// FinishLogin processes the second half of the Webauthn Authentication flow. It is the handler for the
// "PUT /webauthn/login" endpoint, initiated by the client with login data signed with the private key.
func (a *App) FinishLogin(w http.ResponseWriter, r *http.Request) {
	const finishLogin = "FinishLogin"

	user, err := getWebauthnUser(r)
	if err != nil {
		slog.Error(failedToGetUser, "handler", finishLogin, "error", err)
		jsonResponse(w, internalServerError, http.StatusInternalServerError)
		return
	}

	credential, err := user.FinishLogin(r)
	if err != nil {
		// SonarQube flagged this as vulnerable to injection attacks. Rather than exhaustively search for places
		// where user input is inserted into the error message, I'll just sanitize it as recommended.
		sanitizedError := strings.ReplaceAll(strings.ReplaceAll(err.Error(), "\n", "_"), "\r", "_")
		slog.Error("failed to finish user login", "handler", finishLogin, "error", sanitizedError)

		jsonResponse(w, invalidRequest, http.StatusBadRequest)
		return
	}

	resp := finishLoginResponse{
		KeyHandleHash: hashAndEncodeKeyHandle(credential.ID),
	}

	jsonResponse(w, resp, http.StatusOK)
}

// DeleteUser is the handler for the "DELETE /webauthn/user" endpoint. It removes a user and any stored passkeys owned
// by the user.
func (a *App) DeleteUser(w http.ResponseWriter, r *http.Request) {
	const deleteUser = "DeleteUser"

	user, err := getWebauthnUser(r)
	if err != nil {
		slog.Error(failedToGetUser, "handler", deleteUser, "error", err)
		jsonResponse(w, internalServerError, http.StatusInternalServerError)
		return
	}

	if err := user.Delete(); err != nil {
		slog.Error("error deleting user", "handler", deleteUser, "error", err)
		jsonResponse(w, internalServerError, http.StatusInternalServerError)
		return
	}

	jsonResponse(w, nil, http.StatusNoContent)
}

// DeleteCredential is the handler for the "DELETE /webauthn/credential/{credID}" endpoint. It removes a single
// passkey identified by "credID", which is the key_handle_hash returned by the FinishRegistration endpoint, or "u2f"
// if it is a legacy U2F credential, in which case that user is saved with all of its legacy u2f fields blanked out.
func (a *App) DeleteCredential(w http.ResponseWriter, r *http.Request) {
	const deleteCredential = "DeleteCredential"

	user, err := getWebauthnUser(r)
	if err != nil {
		slog.Error(failedToGetUser, "handler", deleteCredential, "error", err)
		jsonResponse(w, internalServerError, http.StatusInternalServerError)
		return
	}

	credID := r.PathValue(IDParam)
	if credID == "" {
		err := fmt.Errorf("%s path parameter not provided to DeleteCredential, path: %s", IDParam, r.URL.Path)
		slog.Error("invalid request", "handler", deleteCredential, "error", err)
		jsonResponse(w, invalidRequest, http.StatusBadRequest)
		return
	}

	status, err := user.DeleteCredential(credID)
	if err != nil {
		slog.Error("error deleting user credential", "status", status, "error", err)
	}

	switch status {
	case http.StatusNoContent:
		jsonResponse(w, nil, status)
	case http.StatusNotFound:
		jsonResponse(w, "Not found", status)
	case http.StatusInternalServerError:
		jsonResponse(w, internalServerError, status)
	default:
		slog.Error("unexpected status code", "status", status)
		jsonResponse(w, internalServerError, http.StatusInternalServerError)
	}
}

// fixStringEncoding converts a string from standard Base64 to Base64-URL
func fixStringEncoding(content string) string {
	content = strings.ReplaceAll(content, "+", "-")
	content = strings.ReplaceAll(content, "/", "_")
	content = strings.ReplaceAll(content, "=", "")
	return content
}

// fixEncoding converts a string from standard Base64 to Base64-URL as an io.Reader
func fixEncoding(content []byte) io.Reader {
	allStr := string(content)
	return bytes.NewReader([]byte(fixStringEncoding(allStr)))
}

// getWebAuthnFromApiMeta creates a new WebAuthn object from the metadata provided in a web request. Typically used in
// the API authentication phase, early in the handler or in a middleware.
func getWebAuthnFromApiMeta(meta WebauthnMeta) (*webauthn.WebAuthn, error) {
	web, err := webauthn.New(&webauthn.Config{
		RPDisplayName: meta.RPDisplayName,      // Display Name for your site
		RPID:          meta.RPID,               // Generally the FQDN for your site
		RPOrigins:     []string{meta.RPOrigin}, // The origin URL for WebAuthn requests
		Debug:         true,
	})
	if err != nil {
		slog.Error("failed to get new webauthn", "error", err)
	}

	return web, nil
}

// getWebauthnMetaFromRequest creates an WebauthnMeta object from request headers, including basic validation checks. Used during
// API authentication.
func getWebauthnMetaFromRequest(r *http.Request) (WebauthnMeta, error) {
	meta := WebauthnMeta{
		RPDisplayName:   r.Header.Get("x-mfa-RPDisplayName"),
		RPID:            r.Header.Get("x-mfa-RPID"),
		RPOrigin:        r.Header.Get("x-mfa-RPOrigin"),
		RPIcon:          r.Header.Get("x-mfa-RPIcon"),
		UserUUID:        r.Header.Get("x-mfa-UserUUID"),
		Username:        r.Header.Get("x-mfa-Username"),
		UserDisplayName: r.Header.Get("x-mfa-UserDisplayName"),
		UserIcon:        r.Header.Get("x-mfa-UserIcon"),
	}

	// check that required fields are provided
	if meta.RPDisplayName == "" {
		msg := "missing required header: x-mfa-RPDisplayName"
		return WebauthnMeta{}, errors.New(msg)
	}
	if meta.RPID == "" {
		msg := "missing required header: x-mfa-RPID"
		return WebauthnMeta{}, errors.New(msg)
	}
	if meta.Username == "" {
		msg := "missing required header: x-mfa-Username"
		return WebauthnMeta{}, errors.New(msg)
	}
	if meta.UserDisplayName == "" {
		msg := "missing required header: x-mfa-UserDisplayName"
		return WebauthnMeta{}, errors.New(msg)
	}

	return meta, nil
}

// getWebauthnUser returns the authenticated WebauthnUser from the request context. The authentication middleware or
// early handler processing inserts the authenticated user into the context for retrieval by this function.
func getWebauthnUser(r *http.Request) (WebauthnUser, error) {
	user, ok := r.Context().Value(UserContextKey).(WebauthnUser)
	if !ok {
		return WebauthnUser{}, fmt.Errorf("unable to get user from request context")
	}

	return user, nil
}

func authWebauthnUser(r *http.Request, storage *Storage, apiKey ApiKey) (User, error) {
	apiMeta, err := getWebauthnMetaFromRequest(r)
	if err != nil {
		slog.Error("unable to retrieve API meta information from request", "error", err)
		return nil, fmt.Errorf("unable to retrieve API meta information from request: %w", err)
	}

	webAuthnClient, err := getWebAuthnFromApiMeta(apiMeta)
	if err != nil {
		return nil, fmt.Errorf("unable to create webauthn client from api meta config: %w", err)
	}

	user := NewWebauthnUser(apiMeta, storage, apiKey, webAuthnClient)

	// If this user exists (api key value is not empty), make sure the calling API Key owns the user and is allowed to operate on it
	if user.ApiKeyValue != "" && user.ApiKeyValue != apiKey.Key {
		slog.Error("api key tried to access user that does not belong to that api key", "apiKey", apiKey.Key, "userID", user.ID)
		return nil, fmt.Errorf("user does not exist")
	}

	return user, nil
}
