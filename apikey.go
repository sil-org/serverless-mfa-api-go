package mfa

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// ApiKeyTablePK is the primary key in the ApiKey DynamoDB table
const ApiKeyTablePK = "value"

// key rotation request parameters
const (
	paramNewKeyId     = "newKeyId"
	paramNewKeySecret = "newKeySecret"
	paramOldKeyId     = "oldKeyId"
	paramOldKeySecret = "oldKeySecret"
)

// ApiKey holds API key data from DynamoDB
type ApiKey struct {
	Key          string   `dynamodbav:"value" json:"value"`
	Secret       string   `dynamodbav:"-" json:"-"`
	HashedSecret string   `dynamodbav:"hashedApiSecret" json:"hashedApiSecret"`
	Email        string   `dynamodbav:"email" json:"email"`
	CreatedAt    int      `dynamodbav:"createdAt" json:"createdAt"`
	ActivatedAt  int      `dynamodbav:"activatedAt" json:"activatedAt"`
	Store        *Storage `dynamodbav:"-" json:"-"`
}

// Load refreshes an ApiKey from the database record
func (k *ApiKey) Load() error {
	return k.Store.Load(envConfig.ApiKeyTable, ApiKeyTablePK, k.Key, k)
}

// Save an ApiKey to the database
func (k *ApiKey) Save() error {
	return k.Store.Store(envConfig.ApiKeyTable, k)
}

// Hash generates a bcrypt hash from the Secret field and stores it in HashedSecret
func (k *ApiKey) Hash() error {
	if k.Secret == "" {
		return errors.New("empty secret cannot be hashed")
	}

	hashedSecret, err := bcrypt.GenerateFromPassword([]byte(k.Secret), bcrypt.DefaultCost)
	k.HashedSecret = string(hashedSecret)
	return err
}

// IsCorrect returns true if and only if the key is active and the given string is a match for HashedSecret
func (k *ApiKey) IsCorrect(given string) error {
	if k.ActivatedAt == 0 {
		return fmt.Errorf("key is not active: %s", k.Key)
	}

	if given == "" {
		return errors.New("secret to compare cannot be empty")
	}

	if k.HashedSecret == "" {
		return errors.New("cannot compare with empty hashed secret")
	}

	err := bcrypt.CompareHashAndPassword([]byte(k.HashedSecret), []byte(given))
	if err != nil {
		return err
	}

	return nil
}

// EncryptData uses the Secret to AES encrypt an arbitrary data block. It does not encrypt the key itself.
func (k *ApiKey) EncryptData(plaintext []byte) ([]byte, error) {
	block, err := newCipherBlock(k.Secret)
	if err != nil {
		return nil, err
	}

	// byte array to hold encrypted content
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))

	// The IV needs to be unique, but not secure. Therefore, it's common to
	// include it at the beginning of the ciphertext.
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return []byte{}, err
	}

	// use CTR to encrypt plaintext
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	return ciphertext, nil
}

// DecryptData uses the Secret to AES decrypt an arbitrary data block. It does not decrypt the key itself.
func (k *ApiKey) DecryptData(ciphertext []byte) ([]byte, error) {
	block, err := newCipherBlock(k.Secret)
	if err != nil {
		return nil, err
	}

	// plaintext must be as long as ciphertext minus the length of the IV, which is the same as the AES block size
	plaintext := make([]byte, len(ciphertext)-aes.BlockSize)

	// the IV (initialization vector) is the first BlockSize bytes in the encrypted content
	iv := ciphertext[:aes.BlockSize]

	// use CTR to decrypt content, which starts BlockSize bytes into the ciphertext
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(plaintext, ciphertext[aes.BlockSize:])

	return plaintext, nil
}

// EncryptLegacy uses the Secret to AES encrypt an arbitrary data block. This is intended only for legacy data such
// as U2F keys. The returned data is the Base64-encoded IV and the Base64-encoded cipher text separated by a colon.
func (k *ApiKey) EncryptLegacy(plaintext string) (string, error) {
	block, err := newCipherBlock(k.Secret)
	if err != nil {
		return "", err
	}

	iv := make([]byte, aes.BlockSize)
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return "", fmt.Errorf("failed to create random data for initialization vector: %w", err)
	}

	ciphertext := make([]byte, len(plaintext))
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(ciphertext, []byte(plaintext))

	ivBase64 := base64.StdEncoding.EncodeToString(iv)
	cipherBase64 := base64.StdEncoding.EncodeToString(ciphertext)
	return ivBase64 + ":" + cipherBase64, nil
}

// DecryptLegacy uses the Secret to AES decrypt an arbitrary data block. This is intended only for legacy data such
// as U2F keys.
func (k *ApiKey) DecryptLegacy(ciphertext string) (string, error) {
	if ciphertext == "" {
		return "", nil
	}

	block, err := newCipherBlock(k.Secret)
	if err != nil {
		return "", err
	}

	// data was encrypted, then base64 encoded, then joined with a :, need to split
	// on :, then decode first part as iv and second as encrypted content
	parts := strings.Split(ciphertext, ":")
	if len(parts) != 2 {
		return "", fmt.Errorf("ciphertext does not look like legacy data")
	}

	iv, err := base64.StdEncoding.DecodeString(parts[0])
	if err != nil {
		fmt.Printf("failed to decode iv: %s\n", err)
		return "", err
	}

	decodedCipher, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		fmt.Printf("failed to decode ciphertext: %s\n", err)
		return "", err
	}

	// plaintext will hold decrypted content, it must be at least as long
	// as ciphertext or decryption process will panic
	plaintext := make([]byte, len(decodedCipher))

	// use CTR to decrypt content
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(plaintext, decodedCipher)

	return string(plaintext), nil
}

// Activate an ApiKey. Creates a random string for the key secret and updates the Secret, HashedSecret, and
// ActivatedAt fields.
func (k *ApiKey) Activate() error {
	if k.ActivatedAt != 0 {
		return errors.New("key already activated")
	}

	random := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, random); err != nil {
		return fmt.Errorf("failed to create random secret: %w", err)
	}

	k.Secret = base64.StdEncoding.EncodeToString(random)
	hashedSecret, err := bcrypt.GenerateFromPassword([]byte(k.Secret), 10)
	if err != nil {
		return fmt.Errorf("failed to hash secret: %w", err)
	}

	k.HashedSecret = string(hashedSecret)
	k.ActivatedAt = int(time.Now().UTC().Unix() * 1000)
	return nil
}

// ReEncryptTOTPs loads each TOTP record that was encrypted using the old key, re-encrypts it using the new
// key, and writes the updated data back to the database.
func (k *ApiKey) ReEncryptTOTPs(storage *Storage, oldKey ApiKey) (complete, incomplete int, err error) {
	var records []TOTP
	err = storage.ScanApiKey(envConfig.TotpTable, oldKey.Key, &records)
	if err != nil {
		err = fmt.Errorf("failed to query %s table for key %s: %w", envConfig.TotpTable, oldKey.Key, err)
		return
	}

	incomplete = len(records)
	for _, r := range records {
		err = k.ReEncryptLegacy(oldKey, &r.EncryptedTotpKey)
		if err != nil {
			err = fmt.Errorf("failed to re-encrypt TOTP %v: %w", r.UUID, err)
			return
		}

		r.ApiKey = k.Key

		err = storage.Store(envConfig.TotpTable, &r)
		if err != nil {
			err = fmt.Errorf("failed to store TOTP %v: %w", r.UUID, err)
			return
		}
		complete++
		incomplete--
	}
	return
}

// ReEncryptWebAuthnUsers loads each WebAuthn record that was encrypted using the old key, re-encrypts it using the new
// key, and writes the updated data back to the database.
func (k *ApiKey) ReEncryptWebAuthnUsers(storage *Storage, oldKey ApiKey) (complete, incomplete int, err error) {
	var users []WebauthnUser
	err = storage.ScanApiKey(envConfig.WebauthnTable, oldKey.Key, &users)
	if err != nil {
		err = fmt.Errorf("failed to query %s table for key %s: %w", envConfig.WebauthnTable, oldKey.Key, err)
		return
	}

	incomplete = len(users)
	for _, user := range users {
		user.ApiKey = oldKey
		err = k.ReEncryptWebAuthnUser(storage, user)
		if err != nil {
			err = fmt.Errorf("failed to re-encrypt Webauthn %v: %w", user.ID, err)
			return
		}
		complete++
		incomplete--
	}
	return
}

// ReEncryptWebAuthnUser re-encrypts a WebAuthnUser using the new key, and writes the updated data back to the database.
func (k *ApiKey) ReEncryptWebAuthnUser(storage *Storage, user WebauthnUser) error {
	oldKey := user.ApiKey
	err := k.ReEncrypt(oldKey, &user.EncryptedSessionData)
	if err != nil {
		return err
	}

	err = k.ReEncrypt(oldKey, &user.EncryptedCredentials)
	if err != nil {
		return err
	}

	for _, p := range []*string{&user.EncryptedPublicKey, &user.EncryptedKeyHandle, &user.EncryptedAppId} {
		err = k.ReEncryptLegacy(oldKey, p)
		if err != nil {
			return err
		}
	}

	user.ApiKey = *k
	user.ApiKeyValue = k.Key

	err = storage.Store(envConfig.WebauthnTable, &user)
	if err != nil {
		return err
	}
	return nil
}

// ReEncrypt decrypts a data block with an old key, then encrypts the resulting plaintext with a new key
func (k *ApiKey) ReEncrypt(oldKey ApiKey, v *[]byte) error {
	if v == nil || *v == nil {
		return nil
	}

	plaintext, err := oldKey.DecryptData(*v)
	if err != nil {
		return fmt.Errorf("failed to decrypt data: %w", err)
	}

	newCiphertext, err := k.EncryptData(plaintext)
	if err != nil {
		return fmt.Errorf("failed to encrypt data: %w", err)
	}

	*v = newCiphertext
	return nil
}

// ReEncryptLegacy decrypts a data block with an old key, then encrypts the resulting plaintext with a new key. This
// uses a legacy ciphertext format that is stored as Base64 strings.
func (k *ApiKey) ReEncryptLegacy(oldKey ApiKey, v *string) error {
	if v == nil || *v == "" {
		return nil
	}

	plaintext, err := oldKey.DecryptLegacy(*v)
	if err != nil {
		return fmt.Errorf("failed to decrypt data: %w", err)
	}

	newCiphertext, err := k.EncryptLegacy(plaintext)
	if err != nil {
		return fmt.Errorf("failed to encrypt data: %w", err)
	}

	*v = newCiphertext
	return nil
}

// ActivateApiKey is the handler for the POST /api-key/activate endpoint. It creates the key secret and updates the
// database record.
func (a *App) ActivateApiKey(w http.ResponseWriter, r *http.Request) {
	var requestBody struct {
		ApiKeyValue string `json:"apiKeyValue"`
		Email       string `json:"email"`
	}

	err := json.NewDecoder(r.Body).Decode(&requestBody)
	if err != nil {
		jsonResponse(w, fmt.Errorf("invalid request: %s", err), http.StatusBadRequest)
		return
	}

	if requestBody.ApiKeyValue == "" {
		jsonResponse(w, fmt.Errorf("apiKeyValue is required"), http.StatusBadRequest)
		return
	}

	if requestBody.Email == "" {
		jsonResponse(w, fmt.Errorf("email is required"), http.StatusBadRequest)
		return
	}

	newKey := ApiKey{Key: requestBody.ApiKeyValue, Store: a.db}
	err = newKey.Load()
	if err != nil {
		jsonResponse(w, fmt.Errorf("key not found: %s", err), http.StatusNotFound)
		return
	}

	err = newKey.Activate()
	if err != nil {
		jsonResponse(w, fmt.Errorf("failed to activate key: %s", err), http.StatusBadRequest)
		return
	}

	err = newKey.Save()
	if err != nil {
		jsonResponse(w, fmt.Errorf("failed to save key: %s", err), http.StatusInternalServerError)
		return
	}

	jsonResponse(w, map[string]string{"apiSecret": newKey.Secret}, http.StatusOK)
}

// CreateApiKey is the handler for the POST /api-key endpoint. It creates a new API Key and saves it to the database.
func (a *App) CreateApiKey(w http.ResponseWriter, r *http.Request) {
	var requestBody struct {
		Email string `json:"email"`
	}

	err := json.NewDecoder(r.Body).Decode(&requestBody)
	if err != nil {
		jsonResponse(w, fmt.Errorf("invalid request: %s", err), http.StatusBadRequest)
		return
	}

	if requestBody.Email == "" {
		jsonResponse(w, fmt.Errorf("email is required"), http.StatusBadRequest)
		return
	}

	key, err := NewApiKey(requestBody.Email)
	if err != nil {
		jsonResponse(w, fmt.Errorf("failed to create a random key: %s", err), http.StatusInternalServerError)
		return
	}

	key.Store = a.db
	err = key.Save()
	if err != nil {
		jsonResponse(w, fmt.Errorf("failed to save key: %s", err), http.StatusInternalServerError)
		return
	}

	jsonResponse(w, nil, http.StatusNoContent)
}

// RotateApiKey generates a new secret for an existing key. All data in other tables that is encrypted by the key will
// be re-encrypted using the new secret.
func (a *App) RotateApiKey(w http.ResponseWriter, r *http.Request) {
	requestBody, err := parseRotateKeyRequestBody(r.Body)
	if err != nil {
		jsonResponse(w, fmt.Errorf("invalid request: %s", err), http.StatusBadRequest)
		return
	}

	oldKey := ApiKey{Key: requestBody[paramOldKeyId], Store: a.GetDB()}
	err = oldKey.loadAndCheck(requestBody[paramOldKeySecret])
	if err != nil {
		jsonResponse(w, fmt.Errorf("old key is not valid: %s", err), http.StatusNotFound)
		return
	}

	newKey := ApiKey{Key: requestBody[paramNewKeyId], Store: a.GetDB()}
	err = newKey.loadAndCheck(requestBody[paramNewKeySecret])
	if err != nil {
		jsonResponse(w, fmt.Errorf("new key is not valid: %s", err), http.StatusNotFound)
		return
	}

	totpComplete, totpIncomplete, err := newKey.ReEncryptTOTPs(a.GetDB(), oldKey)
	if err != nil {
		jsonResponse(w, fmt.Errorf("failed to re-encrypt TOTP data: %s", err), http.StatusInternalServerError)
		return
	}

	webauthnComplete, webauthnIncomplete, err := newKey.ReEncryptWebAuthnUsers(a.GetDB(), oldKey)
	if err != nil {
		jsonResponse(w, fmt.Errorf("failed to re-encrypt WebAuthn data: %s", err), http.StatusInternalServerError)
		return
	}

	responseBody := map[string]int{
		"totpComplete":       totpComplete,
		"totpIncomplete":     totpIncomplete,
		"webauthnComplete":   webauthnComplete,
		"webauthnIncomplete": webauthnIncomplete,
	}

	jsonResponse(w, responseBody, http.StatusOK)
}

func parseRotateKeyRequestBody(body io.Reader) (map[string]string, error) {
	var requestBody map[string]string
	err := json.NewDecoder(body).Decode(&requestBody)
	if err != nil {
		return nil, fmt.Errorf("invalid request in RotateApiKey: %s", err)
	}

	fields := []string{paramNewKeyId, paramNewKeySecret, paramOldKeyId, paramOldKeySecret}
	for _, field := range fields {
		if _, ok := requestBody[field]; !ok {
			return nil, fmt.Errorf("%s is required", field)
		}
	}
	return requestBody, nil
}

func (k *ApiKey) loadAndCheck(secret string) error {
	err := k.Load()
	if err != nil {
		return fmt.Errorf("failed to load key: %s", err)
	}

	err = k.IsCorrect(secret)
	if err != nil {
		return fmt.Errorf("key is not valid: %s", err)
	}
	k.Secret = secret
	return nil
}

// NewApiKey creates a new key with a random value
func NewApiKey(email string) (ApiKey, error) {
	random := make([]byte, 20)
	if _, err := io.ReadFull(rand.Reader, random); err != nil {
		return ApiKey{}, err
	}

	key := ApiKey{
		Key:       hex.EncodeToString(random),
		Email:     email,
		CreatedAt: int(time.Now().UTC().Unix() * 1000),
	}
	return key, nil
}

// newCipherBlock creates a new cipher.Block from a base64-encoded AES key. If the string is not valid base64 data, it
// will be interpreted as binary data.
func newCipherBlock(key string) (cipher.Block, error) {
	var sec []byte
	var err error
	sec, err = base64.StdEncoding.DecodeString(key)
	if err != nil {
		sec = []byte(key)
	}

	block, err := aes.NewCipher(sec)
	if err != nil {
		return nil, fmt.Errorf("failed to create new cipher: %w", err)
	}
	return block, nil
}

// debugString is used by the debugger to show useful ApiKey information in watched variables
func (k *ApiKey) debugString() string {
	return fmt.Sprintf("key: %s, secret: %s", k.Key, k.Secret)
}
