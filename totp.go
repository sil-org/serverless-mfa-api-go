package mfa

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"image/png"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/pquerna/otp/totp"
)

// TOTPTablePK is the primary key in the TOTP DynamoDB table
const TOTPTablePK = "uuid"

const (
	notFound            = "TOTP not found"
	internalServerError = "Internal server error"
)

// TOTP contains data to represent a Time-based One-Time Passcode (token). The ID and encrypted fields are persisted in
// DynamoDB. The others are non-encrypted and are short-lived.
type TOTP struct {
	// UUID is the unique ID and primary key for the passcode.
	UUID string `dynamodbav:"uuid" json:"uuid"`

	// ApiKey is the ID of the API Key used to create and access this passcode.
	ApiKey string `dynamodbav:"apiKey" json:"apiKey"`

	// EncryptedTotpKey is the encrypted form of the key of the passcode.
	EncryptedTotpKey string `dynamodbav:"encryptedTotpKey" json:"encryptedTotpKey"`

	// Key is the passcode secret key.
	Key string `dynamodbav:"-" json:"-"`

	// ImageURL is a base64-encoded image in data URL format like "data:image/png;base64,iVBORw0KGgo...". The image
	// is a QR code that contains the OTPAuthURL, which the user scans to store the shared secret key and metadata in
	// their authenticator app.
	ImageURL string `dynamodbav:"-" json:"-"`

	// OTPAuthURL is a otpauth URI like "otpauth://totp/idp:john_doe?secret=G5KFM3LNJ5NWQP3O&issuer=idp" that contains
	// the passcode secret key. It may also contain metadata like issuer, algorithm, and number of digits.
	OTPAuthURL string `dynamodbav:"-" json:"-"`
}

// debugString is used by the debugger to show useful TOTP information in watched variables
func (t TOTP) debugString() string {
	return fmt.Sprintf("UUID: %s, Key: %s, ApiKey: %s", t.UUID, t.Key, t.ApiKey)
}

// CreateTOTPRequestBody defines the JSON request body for the CreateTOTP endpoint
type CreateTOTPRequestBody struct {
	Issuer string `json:"issuer"`
	Name   string `json:"label"`
}

// CreateTOTPResponseBody defines the JSON response body for the CreateTOTP endpoint
type CreateTOTPResponseBody struct {
	UUID       string `json:"uuid"`
	TOTPKey    string `json:"totpKey"`
	OTPAuthURL string `json:"otpAuthUrl"`
	ImageURL   string `json:"imageUrl"`
}

// ValidateTOTPRequestBody defines the JSON request body for the ValidateTOTP endpoint
type ValidateTOTPRequestBody struct {
	Code string `json:"code"`
}

// CreateTOTP is the http handler to create a new TOTP passcode.
func (a *App) CreateTOTP(w http.ResponseWriter, r *http.Request) {
	requestBody, err := parseCreateTOTPRequestBody(r.Body)
	if err != nil {
		log.Println("Invalid CreateTOTP request body:", err)
		jsonResponse(w, "Invalid request", http.StatusBadRequest)
		return
	}

	apiKey, err := getAPIKey(r)
	if err != nil {
		log.Printf("CreateTOTP API key error: %v", err)
		jsonResponse(w, internalServerError, http.StatusInternalServerError)
		return
	}

	t, err := newTOTP(a.db, apiKey, requestBody.Issuer, requestBody.Name)
	if err != nil {
		jsonResponse(w, fmt.Errorf("failed to create a new TOTP: %w", err), http.StatusInternalServerError)
		return
	}

	responseBody := CreateTOTPResponseBody{
		UUID:       t.UUID,
		TOTPKey:    t.Key,
		OTPAuthURL: t.OTPAuthURL,
		ImageURL:   t.ImageURL,
	}
	jsonResponse(w, responseBody, http.StatusOK)
}

// parseCreateTOTPRequestBody parses and validates the CreateTOTP request body
func parseCreateTOTPRequestBody(body io.ReadCloser) (*CreateTOTPRequestBody, error) {
	if body == nil {
		return nil, fmt.Errorf("empty request body")
	}

	requestBody := &CreateTOTPRequestBody{}
	err := json.NewDecoder(body).Decode(&requestBody)
	if err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	if requestBody.Issuer == "" {
		return nil, errors.New("issuer is required")
	}

	if requestBody.Name == "" {
		requestBody.Name = "SecretKey"
	}

	return requestBody, nil
}

// newTOTP creates a new TOTP passcode
func newTOTP(db *Storage, apiKey ApiKey, issuer, name string) (TOTP, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: name,

		// This is an increase from our existing Node.js implementation, which uses a 10-byte secret.
		SecretSize: 20,
	})
	if err != nil {
		return TOTP{}, fmt.Errorf("generate failure: %w", err)
	}

	cipherText, err := apiKey.EncryptLegacy(key.Secret())
	if err != nil {
		return TOTP{}, fmt.Errorf("encrypt failure: %w", err)
	}

	image, err := key.Image(164, 164)
	if err != nil {
		return TOTP{}, fmt.Errorf("image failure: %w", err)
	}

	var buf bytes.Buffer
	err = png.Encode(&buf, image)
	if err != nil {
		return TOTP{}, fmt.Errorf("encode failure: %w", err)
	}

	imageDataURL := "data:image/png;base64," + base64.StdEncoding.EncodeToString(buf.Bytes())

	t := TOTP{
		UUID:             NewUUID(),
		ApiKey:           apiKey.Key,
		EncryptedTotpKey: cipherText,
		Key:              key.Secret(),
		ImageURL:         imageDataURL,
		OTPAuthURL:       key.URL(),
	}

	err = db.Store(envConfig.TotpTable, t)
	if err != nil {
		return TOTP{}, fmt.Errorf("failed to store TOTP: %w", err)
	}
	return t, nil
}

// DeleteTOTP is the http handler to delete a passcode.
func (a *App) DeleteTOTP(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue(UUIDParam)

	key, err := getAPIKey(r)
	if err != nil {
		log.Printf("DeleteTOTP API key error: %v", err)
		jsonResponse(w, internalServerError, http.StatusInternalServerError)
		return
	}

	var t TOTP
	err = a.db.Load(envConfig.TotpTable, TOTPTablePK, id, &t)
	if err != nil {
		if strings.Contains(err.Error(), "does not exist") {
			jsonResponse(w, notFound, http.StatusNotFound)
		} else {
			log.Printf("error loading TOTP: %s", err)
			jsonResponse(w, internalServerError, http.StatusInternalServerError)
		}
		return
	}

	if key.Key != t.ApiKey {
		jsonResponse(w, notFound, http.StatusNotFound)
		return
	}

	err = a.db.Delete(envConfig.TotpTable, TOTPTablePK, id)
	if err != nil {
		log.Printf("Failed to delete TOTP: %s", err)
		jsonResponse(w, "Failed to delete TOTP", http.StatusInternalServerError)
		return
	}

	jsonResponse(w, nil, http.StatusNoContent)
}

// ValidateTOTP is the http handler to validate a passcode.
func (a *App) ValidateTOTP(w http.ResponseWriter, r *http.Request) {
	requestBody, err := parseValidateTOTPRequestBody(r.Body)
	if err != nil {
		log.Printf("Invalid ValidateTOTP request body: %s", err)
		jsonResponse(w, "Invalid request", http.StatusBadRequest)
		return
	}

	id := r.PathValue(UUIDParam)

	key, err := getAPIKey(r)
	if err != nil {
		log.Printf("ValidateTOTP API key error: %v", err)
		jsonResponse(w, internalServerError, http.StatusInternalServerError)
		return
	}

	var t TOTP
	err = a.db.Load(envConfig.TotpTable, TOTPTablePK, id, &t)
	if err != nil {
		if strings.Contains(err.Error(), "does not exist") {
			jsonResponse(w, notFound, http.StatusNotFound)
		} else {
			log.Printf("error loading TOTP: %s", err)
			jsonResponse(w, internalServerError, http.StatusInternalServerError)
		}
		return
	}

	if key.Key != t.ApiKey {
		jsonResponse(w, notFound, http.StatusNotFound)
		return
	}

	secret, err := key.DecryptLegacy(t.EncryptedTotpKey)
	if err != nil {
		log.Printf("failed to decrypt TOTP key: %s", err)
		jsonResponse(w, internalServerError, http.StatusInternalServerError)
		return
	}
	t.Key = secret

	valid := totp.Validate(requestBody.Code, t.Key)
	if !valid {
		jsonResponse(w, "Invalid", http.StatusUnauthorized)
		return
	}

	jsonResponse(w, "Valid", http.StatusOK)
}

// parseValidateTOTPRequestBody parses and validates the ValidateTOTP request body
func parseValidateTOTPRequestBody(body io.ReadCloser) (*ValidateTOTPRequestBody, error) {
	if body == nil {
		return nil, fmt.Errorf("empty request body")
	}

	requestBody := &ValidateTOTPRequestBody{}
	err := json.NewDecoder(body).Decode(&requestBody)
	if err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	if requestBody.Code == "" {
		return nil, errors.New("code is required")
	}

	return requestBody, nil
}

// authTOTP is a just a placeholder for TOTP. It takes the verified API Key and returns it as an authenticated User
// for later use.
func authTOTP(apiKey ApiKey) (User, error) {
	return apiKey, nil
}

// getAPIKey returns the authenticated API Key from the request context. The authentication middleware or
// early handler processing inserts the key into the context for retrieval by this function.
func getAPIKey(r *http.Request) (ApiKey, error) {
	key, ok := r.Context().Value(UserContextKey).(ApiKey)
	if !ok {
		return ApiKey{}, fmt.Errorf("unable to get API key from request context")
	}

	return key, nil
}
