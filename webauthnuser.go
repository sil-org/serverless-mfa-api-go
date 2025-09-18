package mfa

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"

	"github.com/fxamacker/cbor/v2"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	"github.com/go-webauthn/webauthn/webauthn"
)

// UserContextKey is the context key that points to the authenticated user
const UserContextKey = "user"

// WebAuthnTablePK is the primary key in the WebAuthn DynamoDB table
const WebAuthnTablePK = "uuid"

// LegacyU2FCredID is a special case credential ID for legacy U2F support. At most one credential for each user may
// have this in its ID field.
const LegacyU2FCredID = "u2f"

// WebauthnUser holds user data from DynamoDB, in both encrypted and unencrypted form. It also holds a Webauthn client
// and Webauthn API data.
type WebauthnUser struct {
	// Shared fields between U2F and WebAuthn
	ID          string   `dynamodbav:"uuid" json:"uuid"`
	ApiKeyValue string   `dynamodbav:"apiKey" json:"apiKey"`
	ApiKey      ApiKey   `dynamodbav:"-" json:"-"`
	Store       *Storage `dynamodbav:"-" json:"-"`

	// U2F fields
	AppId              string `dynamodbav:"-" json:"-"`
	EncryptedAppId     string `dynamodbav:"encryptedAppId" json:"encryptedAppId,omitempty"`
	KeyHandle          string `dynamodbav:"-" json:"-"`
	EncryptedKeyHandle string `dynamodbav:"encryptedKeyHandle" json:"encryptedKeyHandle,omitempty"`
	PublicKey          string `dynamodbav:"-" json:"-"`
	EncryptedPublicKey string `dynamodbav:"encryptedPublicKey" json:"encryptedPublicKey,omitempty"`

	// WebAuthn fields
	SessionData          webauthn.SessionData `dynamodbav:"-" json:"-"`
	EncryptedSessionData []byte               `dynamodbav:"EncryptedSessionData" json:"EncryptedSessionData,omitempty"`

	// These can be multiple Yubikeys or other WebAuthn entries
	Credentials          []webauthn.Credential `dynamodbav:"-" json:"-"`
	EncryptedCredentials []byte                `dynamodbav:"EncryptedCredentials" json:"EncryptedCredentials,omitempty"`

	WebAuthnClient *webauthn.WebAuthn `dynamodbav:"-" json:"-"`
	Name           string             `dynamodbav:"-" json:"-"`
	DisplayName    string             `dynamodbav:"-" json:"-"`
	Icon           string             `dynamodbav:"-" json:"-"`
}

// NewWebauthnUser creates a new WebauthnUser from API input data, a storage client and a Webauthn client.
func NewWebauthnUser(apiConfig WebauthnMeta, storage *Storage, apiKey ApiKey, webAuthnClient *webauthn.WebAuthn) WebauthnUser {
	u := WebauthnUser{
		ID:             apiConfig.UserUUID,
		Name:           apiConfig.Username,
		DisplayName:    apiConfig.UserDisplayName,
		Icon:           apiConfig.UserIcon,
		Store:          storage,
		WebAuthnClient: webAuthnClient,
		ApiKey:         apiKey,
		ApiKeyValue:    apiKey.Key,
	}

	if u.ID == "" {
		return u
	}

	err := u.Load()
	if err != nil {
		log.Printf("failed to load user: %s", err)
	}
	return u
}

// RemoveU2F clears U2F fields in the user struct. To be used when a user has requested removal of their legacy U2F key.
// Should be followed by a database store operation.
func (u *WebauthnUser) RemoveU2F() {
	u.AppId = ""
	u.EncryptedAppId = ""
	u.KeyHandle = ""
	u.EncryptedKeyHandle = ""
	u.PublicKey = ""
	u.EncryptedPublicKey = ""
}

// unsetSessionData clears the encrypted session data from a user and stores the updated record in the database.
func (u *WebauthnUser) unsetSessionData() error {
	u.EncryptedSessionData = nil
	return u.Store.Store(envConfig.WebauthnTable, u)
}

// saveSessionData encrypts the user's session data and updates the database record.
// CAUTION: user data is refreshed from the database by this function. Any unsaved data will be lost.
func (u *WebauthnUser) saveSessionData(sessionData webauthn.SessionData) error {
	// load to be sure working with latest data, but we may not have created the record yet (BeginRegistration)
	_ = u.Load()

	js, err := json.Marshal(sessionData)
	if err != nil {
		log.Printf("error marshaling session data to json. Session data: %+v, Error: %s", sessionData, err)
		return err
	}

	enc, err := u.ApiKey.EncryptData(js)
	if err != nil {
		return err
	}

	u.EncryptedSessionData = enc
	return u.Store.Store(envConfig.WebauthnTable, u)
}

// saveNewCredential appends a new credential to the user's credential list, encrypts the list, and updates the
// database record.
// CAUTION: user data is refreshed from the database by this function. Any unsaved data will be lost.
func (u *WebauthnUser) saveNewCredential(credential webauthn.Credential) error {
	// load to be sure working with latest data
	err := u.Load()
	if err != nil {
		return err
	}

	// check existing credentials to make sure this one doesn't already exist
	for _, c := range u.Credentials {
		if string(c.ID) == string(credential.ID) {
			return fmt.Errorf("a credential with this ID already exists")
		}
	}

	// append new credential to existing
	u.Credentials = append(u.Credentials, credential)

	// encrypt credentials for storage
	return u.encryptAndStoreCredentials()
}

// DeleteCredential expects a hashed-encoded credential id. It finds a matching credential for that user and saves the
// user without that credential included. Alternatively, if the given credential id indicates that a legacy U2F key
// should be removed (i.e. by matching the string "u2f") then that user is saved with all of its legacy u2f fields
// blanked out.
// CAUTION: user data is refreshed from the database by this function. Any unsaved data will be lost.
func (u *WebauthnUser) DeleteCredential(credIDHash string) (int, error) {
	// load to be sure working with the latest data
	err := u.Load()
	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf("error in DeleteCredential: %w", err)
	}

	if credIDHash == LegacyU2FCredID {
		u.RemoveU2F()
		if err := u.Store.Store(envConfig.WebauthnTable, u); err != nil {
			return http.StatusInternalServerError, fmt.Errorf("error in DeleteCredential deleting legacy u2f: %w", err)
		}
		return http.StatusNoContent, nil
	}

	if len(u.Credentials) == 0 {
		err := fmt.Errorf("error in DeleteCredential: no webauthn credentials available")
		return http.StatusNotFound, err
	}

	var remainingCreds []webauthn.Credential

	// remove the requested credential from among the user's current webauthn credentials
	for _, c := range u.Credentials {
		if hashAndEncodeKeyHandle(c.ID) == credIDHash {
			continue
		}
		remainingCreds = append(remainingCreds, c)
	}

	if len(remainingCreds) == len(u.Credentials) {
		err := fmt.Errorf("error in DeleteCredential. Credential not found with id: %s", credIDHash)
		return http.StatusNotFound, err
	}

	u.Credentials = remainingCreds

	if err := u.encryptAndStoreCredentials(); err != nil {
		return http.StatusInternalServerError, fmt.Errorf("error in DeleteCredential storing remaining credentials: %w", err)
	}
	return http.StatusNoContent, nil
}

// encryptAndStoreCredentials encrypts the user's credential list and updates the database record
func (u *WebauthnUser) encryptAndStoreCredentials() error {
	if len(u.Credentials) == 0 {
		u.EncryptedCredentials = nil
	} else {
		js, err := json.Marshal(u.Credentials)
		if err != nil {
			return err
		}

		enc, err := u.ApiKey.EncryptData(js)
		if err != nil {
			return err
		}
		u.EncryptedCredentials = enc
	}
	return u.Store.Store(envConfig.WebauthnTable, u)
}

// Load refreshes a user object from the database record and decrypts the session data and credential list
func (u *WebauthnUser) Load() error {
	err := u.Store.Load(envConfig.WebauthnTable, WebAuthnTablePK, u.ID, u)
	if err != nil {
		return fmt.Errorf("failed to load user: %w", err)
	}

	// decrypt SessionStorage if available
	if len(u.EncryptedSessionData) > 0 {
		plain, err := u.ApiKey.DecryptData(u.EncryptedSessionData)
		if err != nil {
			return fmt.Errorf("failed to decrypt encrypted session data: %w", err)
		}

		// unmarshal decrypted session data into SessionData
		var sd webauthn.SessionData
		err = json.Unmarshal(plain, &sd)
		if err != nil {
			log.Printf("failed to unmarshal encrypted session data, will discard and continue. error: %s", err)
		}

		u.SessionData = sd
	}

	// decrypt Credentials if available
	if len(u.EncryptedCredentials) > 0 {
		dec, err := u.ApiKey.DecryptData(u.EncryptedCredentials)
		if err != nil {
			return fmt.Errorf("failed to decrypt encrypted credential data: %w", err)
		}

		// unmarshal decrypted session data into Credentials
		var creds []webauthn.Credential
		err = json.Unmarshal(dec, &creds)
		if err != nil {
			return fmt.Errorf("failed to unmarshal credential data: %w", err)
		}
		u.Credentials = creds
	}

	appid, err := u.ApiKey.DecryptLegacy(u.EncryptedAppId)
	if err != nil {
		return fmt.Errorf("failed to decrypt app id: %w", err)
	}
	u.AppId = appid

	publicKey, err := u.ApiKey.DecryptLegacy(u.EncryptedPublicKey)
	if err != nil {
		return fmt.Errorf("failed to decrypt public key: %w", err)
	}
	u.PublicKey = publicKey

	keyHandle, err := u.ApiKey.DecryptLegacy(u.EncryptedKeyHandle)
	if err != nil {
		return fmt.Errorf("failed to decrypt key handle: %w", err)
	}
	u.KeyHandle = keyHandle

	return nil
}

// Delete removes the user from the database
func (u *WebauthnUser) Delete() error {
	return u.Store.Delete(envConfig.WebauthnTable, WebAuthnTablePK, u.ID)
}

// BeginRegistration processes the first half of the Webauthn Registration flow for the user and returns the
// CredentialCreation data to pass back to the client. User session data is saved in the database.
func (u *WebauthnUser) BeginRegistration() (*protocol.CredentialCreation, error) {
	if u.WebAuthnClient == nil {
		return nil, fmt.Errorf("webauthnUser, %s, missing WebAuthClient in BeginRegistration", u.Name)
	}

	rrk := false
	authSelection := protocol.AuthenticatorSelection{
		RequireResidentKey: &rrk,
		UserVerification:   protocol.VerificationDiscouraged,
	}

	options, sessionData, err := u.WebAuthnClient.BeginRegistration(u, webauthn.WithAuthenticatorSelection(authSelection))
	if err != nil {
		return &protocol.CredentialCreation{}, fmt.Errorf("failed to begin registration: %w", err)
	}

	err = u.saveSessionData(*sessionData)
	if err != nil {
		return &protocol.CredentialCreation{}, fmt.Errorf("failed to save session data: %w", err)
	}

	return options, nil
}

// FinishRegistration processes the last half of the Webauthn Registration flow for the user and returns the
// key_handle_hash to pass back to the client. The client should store this value for later use. User session data is
// cleared from the database.
func (u *WebauthnUser) FinishRegistration(r *http.Request) (string, error) {
	if r.Body == nil {
		return "", fmt.Errorf("request Body may not be nil in FinishRegistration")
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		return "", fmt.Errorf("failed to get api config from request: %w", err)
	}

	br := fixEncoding(body)
	parsedResponse, err := protocol.ParseCredentialCreationResponseBody(br)
	if err != nil {
		logProtocolError("unable to parse body", err)
		return "", fmt.Errorf("unable to parse credential creation response body: %w", err)
	}

	credential, err := u.WebAuthnClient.CreateCredential(u, u.SessionData, parsedResponse)
	if err != nil {
		logProtocolError("unable to create credential", err)
		return "", fmt.Errorf("unable to create credential: %w", err)
	}

	err = u.saveNewCredential(*credential)
	if err != nil {
		return "", fmt.Errorf("unable to save new credential`: %w", err)
	}

	keyHandleHash := hashAndEncodeKeyHandle(credential.ID)

	return keyHandleHash, u.unsetSessionData()
}

// BeginLogin processes the first half of the Webauthn Authentication flow for the user and returns the
// CredentialAssertion data to pass back to the client. User session data is saved in the database.
func (u *WebauthnUser) BeginLogin() (*protocol.CredentialAssertion, error) {
	extensions := protocol.AuthenticationExtensions{}
	if u.AppId != "" {
		extensions["appid"] = u.AppId
	}

	options, sessionData, err := u.WebAuthnClient.BeginLogin(u, webauthn.WithAssertionExtensions(extensions), webauthn.WithUserVerification(protocol.VerificationDiscouraged))
	if err != nil {
		return &protocol.CredentialAssertion{}, err
	}

	err = u.saveSessionData(*sessionData)
	if err != nil {
		log.Printf("error saving session data: %s", err)
		return nil, err
	}

	return options, nil
}

// FinishLogin processes the last half of the Webauthn Authentication flow for the user and returns the
// Credential data to pass back to the client. User session data is untouched by this function.
func (u *WebauthnUser) FinishLogin(r *http.Request) (*webauthn.Credential, error) {
	if r.Body == nil {
		return nil, fmt.Errorf("request Body may not be nil in FinishLogin")
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("failed to read request body: %s", err)
		return &webauthn.Credential{}, fmt.Errorf("failed to read request body: %w", err)
	}

	br := fixEncoding(body)
	parsedResponse, err := protocol.ParseCredentialRequestResponseBody(br)
	if err != nil {
		logProtocolError(fmt.Sprintf("failed to parse credential request response body: %s", body), err)
		return &webauthn.Credential{}, fmt.Errorf("failed to parse credential request response body: %w", err)
	}

	// If user has registered U2F creds, check if RPIDHash is actually hash of AppId
	// if so, replace authenticator data RPIDHash with a hash of the RPID for validation
	if u.AppId != "" {
		appIdHash := sha256.Sum256([]byte(u.AppId))
		rpIdHash := sha256.Sum256([]byte(u.WebAuthnClient.Config.RPID))

		if fmt.Sprintf("%x", parsedResponse.Response.AuthenticatorData.RPIDHash) == fmt.Sprintf("%x", appIdHash) {
			parsedResponse.Response.AuthenticatorData.RPIDHash = rpIdHash[:]
		}
	}

	credential, err := u.WebAuthnClient.ValidateLogin(u, u.SessionData, parsedResponse)
	if err != nil {
		logProtocolError("failed to validate login", err)
		return &webauthn.Credential{}, fmt.Errorf("failed to validate login: %w", err)
	}

	return credential, nil
}

// WebAuthnID returns the user's ID according to the Relying Party
func (u *WebauthnUser) WebAuthnID() []byte {
	return []byte(u.ID)
}

// WebAuthnName returns the user's name according to the Relying Party
func (u *WebauthnUser) WebAuthnName() string {
	return u.Name
}

// WebAuthnDisplayName returns the display name of the user
func (u *WebauthnUser) WebAuthnDisplayName() string {
	return u.DisplayName
}

// WebAuthnIcon returns the user's icon URL
func (u *WebauthnUser) WebAuthnIcon() string {
	return u.Icon
}

// WebAuthnCredentials returns an array of credentials (passkeys) plus a U2F credential if present
func (u *WebauthnUser) WebAuthnCredentials() []webauthn.Credential {
	if u.EncryptedKeyHandle == "" || u.EncryptedPublicKey == "" {
		// no U2F credential found
		return u.Credentials
	}

	decodedCredId, err := base64.RawURLEncoding.DecodeString(u.KeyHandle)
	if err != nil {
		log.Println("error decoding credential id:", err)
		return nil
	}

	decodedPubKey, err := base64.RawURLEncoding.DecodeString(u.PublicKey)
	if err != nil {
		log.Println("error decoding public key:", err)
		return nil
	}

	// U2F key is concatenation of 0x4 + Xcoord + Ycoord
	// documentation / example at https://docs.yubico.com/yesdk/users-manual/application-piv/attestation.html
	coordLen := (len(decodedPubKey) - 1) / 2
	xCoord := decodedPubKey[1 : coordLen+1]
	yCoord := decodedPubKey[1+coordLen:]

	ec2PublicKey := webauthncose.EC2PublicKeyData{
		XCoord: xCoord,
		YCoord: yCoord,
		PublicKeyData: webauthncose.PublicKeyData{
			Algorithm: int64(webauthncose.AlgES256),
			KeyType:   int64(webauthncose.EllipticKey),
		},
	}

	// Get the CBOR-encoded representation of the OKPPublicKeyData
	cborEncodedKey, err := cbor.Marshal(ec2PublicKey)
	if err != nil {
		log.Printf("error marshalling key to cbor: %s", err)
		return nil
	}

	return append(u.Credentials, webauthn.Credential{
		ID:              decodedCredId,
		PublicKey:       cborEncodedKey,
		AttestationType: string(protocol.PublicKeyCredentialType),
	})
}

// hashAndEncodeKeyHandle returns the Base64 URL-encoded SHA256 hash of a byte slice to provide a hash of a key
// handle to the client.
func hashAndEncodeKeyHandle(id []byte) string {
	hash := sha256.Sum256(id)
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

// logProtocolError logs an error and includes additional detail if the given error is an Error from
// go-webauthn/webauthn/protocol
func logProtocolError(msg string, err error) {
	var protocolError *protocol.Error
	if errors.As(err, &protocolError) {
		log.Printf("%s, ProtocolError: %s, DevInfo: %s", msg, protocolError.Details, protocolError.DevInfo)
	} else {
		log.Printf("%s, Error: %s", msg, err)
	}
}
