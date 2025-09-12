package mfa

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"image/png"
	"io"
	"net/http"

	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"
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

// CreateTOTP is the http handler to create a new TOTP passcode.
func (a *App) CreateTOTP(w http.ResponseWriter, r *http.Request) {
	requestBody, err := parseCreateTOTPRequestBody(r.Body)
	if err != nil {
		jsonResponse(w, err, http.StatusBadRequest)
		return
	}

	apiKey, err := getAPIKey(r)
	if err != nil {
		jsonResponse(w, fmt.Errorf("API Key not found in request context: %w", err), http.StatusInternalServerError)
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
func parseCreateTOTPRequestBody(body io.ReadCloser) (requestBody *CreateTOTPRequestBody, err error) {
	if body == nil {
		return nil, fmt.Errorf("empty request body")
	}

	err = json.NewDecoder(body).Decode(&requestBody)
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
		UUID:             uuid.New().String(),
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
