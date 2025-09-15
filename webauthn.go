package mfa

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	uuid "github.com/satori/go.uuid"
)

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
	CredentialID  string `json:"credentialId"` // DEPRECATED, use KeyHandleHash instead
	KeyHandleHash string `json:"key_handle_hash"`
}

// BeginRegistration processes the first half of the Webauthn Registration flow. It is the handler for the
// "POST /webauthn/register" endpoint, initiated by the client when creation of a new passkey is requested.
func (a *App) BeginRegistration(w http.ResponseWriter, r *http.Request) {
	user, err := getWebauthnUser(r)
	if err != nil {
		jsonResponse(w, err, http.StatusBadRequest)
		return
	}

	// If user.id is empty, treat as new user/registration
	if user.ID == "" {
		user.ID = uuid.NewV4().String()
	}

	options, err := user.BeginRegistration()
	if err != nil {
		jsonResponse(w, fmt.Sprintf("failed to begin registration: %s", err), http.StatusBadRequest)
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
	user, err := getWebauthnUser(r)
	if err != nil {
		jsonResponse(w, err, http.StatusBadRequest)
		return
	}

	keyHandleHash, err := user.FinishRegistration(r)
	if err != nil {
		jsonResponse(w, err, http.StatusBadRequest)
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
	user, err := getWebauthnUser(r)
	if err != nil {
		jsonResponse(w, err, http.StatusBadRequest)
		log.Printf("error getting user from context: %s\n", err)
		return
	}

	options, err := user.BeginLogin()
	if err != nil {
		jsonResponse(w, err, http.StatusBadRequest)
		log.Printf("error beginning user login: %s\n", err)
		return
	}

	jsonResponse(w, options, http.StatusOK)
}

// FinishLogin processes the second half of the Webauthn Authentication flow. It is the handler for the
// "PUT /webauthn/login" endpoint, initiated by the client with login data signed with the private key.
func (a *App) FinishLogin(w http.ResponseWriter, r *http.Request) {
	user, err := getWebauthnUser(r)
	if err != nil {
		jsonResponse(w, err, http.StatusBadRequest)
		log.Printf("error getting user from context: %s\n", err)
		return
	}

	credential, err := user.FinishLogin(r)
	if err != nil {
		jsonResponse(w, err, http.StatusBadRequest)
		log.Printf("error finishing user login	: %s\n", err)
		return
	}

	resp := finishLoginResponse{
		CredentialID:  string(credential.ID),
		KeyHandleHash: hashAndEncodeKeyHandle(credential.ID),
	}

	jsonResponse(w, resp, http.StatusOK)
}

// DeleteUser is the handler for the "DELETE /webauthn/user" endpoint. It removes a user and any stored passkeys owned
// by the user.
func (a *App) DeleteUser(w http.ResponseWriter, r *http.Request) {
	user, err := getWebauthnUser(r)
	if err != nil {
		jsonResponse(w, err, http.StatusBadRequest)
		log.Printf("error getting user from context: %s\n", err)
		return
	}

	if err := user.Delete(); err != nil {
		jsonResponse(w, err, http.StatusInternalServerError)
		log.Printf("error deleting user: %s", err)
		return
	}

	jsonResponse(w, nil, http.StatusNoContent)
}

// DeleteCredential is the handler for the "DELETE /webauthn/credential/{credID}" endpoint. It removes a single
// passkey identified by "credID", which is the key_handle_hash returned by the FinishRegistration endpoint, or "u2f"
// if it is a legacy U2F credential.
func (a *App) DeleteCredential(w http.ResponseWriter, r *http.Request) {
	user, err := getWebauthnUser(r)
	if err != nil {
		jsonResponse(w, err, http.StatusBadRequest)
		log.Printf("error getting user from context: %s\n", err)
		return
	}

	credID := r.PathValue(IDParam)
	if credID == "" {
		err := fmt.Errorf("%s path parameter not provided to DeleteCredential, path: %s", IDParam, r.URL.Path)
		jsonResponse(w, err, http.StatusBadRequest)
		log.Printf("%s\n", err)
		return
	}

	status, err := user.DeleteCredential(credID)
	if err != nil {
		log.Printf("error deleting user credential: %s", err)
	}

	jsonResponse(w, err, status)
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
		fmt.Println(err)
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
		log.Printf("unable to retrieve API meta information from request: %s", err)
		return nil, fmt.Errorf("unable to retrieve API meta information from request: %w", err)
	}

	webAuthnClient, err := getWebAuthnFromApiMeta(apiMeta)
	if err != nil {
		return nil, fmt.Errorf("unable to create webauthn client from api meta config: %w", err)
	}

	user := NewWebauthnUser(apiMeta, storage, apiKey, webAuthnClient)

	// If this user exists (api key value is not empty), make sure the calling API Key owns the user and is allowed to operate on it
	if user.ApiKeyValue != "" && user.ApiKeyValue != apiKey.Key {
		log.Printf("api key %s tried to access user %s but that user does not belong to that api key", apiKey.Key, user.ID)
		return nil, fmt.Errorf("user does not exist")
	}

	return user, nil
}
