package mfa

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func TestApiKey_IsCorrect(t *testing.T) {
	const hashedSecret = "$2y$10$Y.FlUK8q//DfybgFzNG2lONaJwvEFxHnCRo/r60BZbITDT6rOUhGa"

	tests := []struct {
		name         string
		HashedSecret string
		ActivatedAt  int
		Given        string
		wantErr      bool
	}{
		{
			name:         "valid secret",
			HashedSecret: hashedSecret,
			ActivatedAt:  1744896576000,
			Given:        "abc123",
			wantErr:      false,
		},
		{
			name:         "invalid secret",
			HashedSecret: hashedSecret,
			ActivatedAt:  1744896576000,
			Given:        "123abc",
			wantErr:      true,
		},
		{
			name:         "inactive",
			HashedSecret: hashedSecret,
			ActivatedAt:  0,
			Given:        "abc123",
			wantErr:      true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := &ApiKey{
				HashedSecret: tt.HashedSecret,
				ActivatedAt:  tt.ActivatedAt,
			}
			err := k.IsCorrect(tt.Given)
			if (err != nil) != tt.wantErr {
				t.Errorf("IsCorrect() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

// TestApiKey_Hash - test that hashed secret can be verified
func TestApiKey_Hash(t *testing.T) {
	tests := []struct {
		name    string
		Secret  string
		wantErr bool
	}{
		{
			name:    "matching hash",
			Secret:  "abc123",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := &ApiKey{
				Secret:      tt.Secret,
				ActivatedAt: 1744896576000,
			}
			err := k.Hash()
			if (err != nil) != tt.wantErr {
				t.Errorf("Hash() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if len(k.HashedSecret) == 0 {
				t.Error("hashed secret is empty after call to hash")
				return
			}
			err = k.IsCorrect(tt.Secret)
			if err != nil {
				t.Errorf("hashed password not valid after hashing??? error: %s", err)
				return
			}
		})
	}
}

func TestApiKey_EncryptDecrypt(t *testing.T) {
	tests := []struct {
		name      string
		secret    string
		plaintext []byte
		wantErr   bool
	}{
		{
			name:      "test encrypt/decrypt",
			secret:    "ED86600E-3DBF-4C23-A0DA-9C55D448",
			plaintext: []byte("this is a plaintext string to be encrypted"),
			wantErr:   false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k1 := &ApiKey{
				Secret: tt.secret,
			}
			k2 := &ApiKey{
				Secret: tt.secret,
			}

			encrypted, err := k1.EncryptData(tt.plaintext)
			if (err != nil) != tt.wantErr {
				t.Errorf("EncryptData() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			decrypted, err := k2.DecryptData(encrypted)
			if (err != nil) != tt.wantErr {
				t.Errorf("DecryptData() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !bytes.Equal(tt.plaintext, decrypted) {
				t.Errorf("results from decypt do not match expected. Got: %s, wanted: %s", decrypted, tt.plaintext)
				return
			}
		})
	}
}

func (ms *MfaSuite) TestApiKeyEncryptDecryptLegacy() {
	plaintext := "this is a plaintext string to be encrypted"
	key := &ApiKey{Secret: "ED86600E-3DBF-4C23-A0DA-9C55D448"}

	encrypted, err := key.EncryptLegacy(plaintext)
	ms.NoError(err)
	decrypted, err := key.DecryptLegacy(encrypted)
	ms.NoError(err)
	ms.Equal(plaintext, decrypted)
}

func (ms *MfaSuite) TestApiKeyActivate() {
	notActive := ApiKey{
		Key:       "0000000000000000000000000000000000000000",
		Email:     exampleEmail,
		CreatedAt: 1744788331000,
	}
	active := notActive
	active.ActivatedAt = 1744788394000

	tests := []struct {
		name    string
		key     ApiKey
		wantErr bool
	}{
		{
			name:    "not active",
			key:     notActive,
			wantErr: false,
		},
		{
			name:    "already activated",
			key:     active,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		ms.Run(tt.name, func() {
			key := tt.key
			err := key.Activate()
			if tt.wantErr {
				ms.Error(err)
				return
			}

			ms.NoError(err)
			ms.Regexp(regexp.MustCompile("^[A-Za-z0-9+/]{43}=$"), key.Secret, "Secret isn't correct")
			ms.NoError(bcrypt.CompareHashAndPassword([]byte(key.HashedSecret), []byte(key.Secret)),
				"HashedSecret isn't correct")
			ms.WithinDuration(time.Now(), time.Unix(int64(key.ActivatedAt/1000), 0), time.Minute,
				"ActivatedAt isn't set to the current time")

			// ensure no other fields were changed
			ms.Equal(tt.key.Key, key.Key)
			ms.Equal(tt.key.Email, key.Email)
			ms.Equal(tt.key.CreatedAt, key.CreatedAt)
		})
	}
}

func (ms *MfaSuite) TestActivateApiKey() {
	awsConfig := testAwsConfig()
	testEnvConfig(awsConfig)
	localStorage, err := NewStorage(awsConfig)
	must(err)

	key1 := ApiKey{Key: "key1", Email: "1" + exampleEmail, CreatedAt: 1744799133000}
	must(localStorage.Store(envConfig.ApiKeyTable, &key1))
	key2 := ApiKey{Key: "key2", Email: "2" + exampleEmail, CreatedAt: 1744799133000, ActivatedAt: 1744799134000}
	must(localStorage.Store(envConfig.ApiKeyTable, &key2))
	key3 := ApiKey{Key: "key3", Email: "3" + exampleEmail, CreatedAt: 1744799133000}
	must(localStorage.Store(envConfig.ApiKeyTable, &key3))

	tests := []struct {
		name       string
		body       map[string]string
		wantStatus int
		wantError  error
	}{
		{
			name: "not previously activated",
			body: map[string]string{
				"email":       key1.Email,
				"apiKeyValue": key1.Key,
			},
			wantStatus: http.StatusOK,
		},
		{
			name: "already activated",
			body: map[string]string{
				"email":       key2.Email,
				"apiKeyValue": key2.Key,
			},
			wantStatus: http.StatusBadRequest,
			wantError:  ErrKeyAlreadyActivated,
		},
		{
			name: "missing email",
			body: map[string]string{
				"apiKeyValue": key3.Key,
			},
			wantStatus: http.StatusBadRequest,
			wantError:  errors.New("email is required"),
		},
		{
			name: "missing apiKeyValue",
			body: map[string]string{
				"email": exampleEmail,
			},
			wantStatus: http.StatusBadRequest,
			wantError:  errors.New("apiKeyValue is required"),
		},
		{
			name: "key not found",
			body: map[string]string{
				"email":       exampleEmail,
				"apiKeyValue": "not a key",
			},
			wantStatus: http.StatusNotFound,
			wantError:  errors.New("API Key not found"),
		},
	}
	for _, tt := range tests {
		ms.Run(tt.name, func() {
			res := &lambdaResponseWriter{Headers: http.Header{}}
			req := requestWithUser(tt.body, ApiKey{Store: localStorage})
			ms.app.ActivateApiKey(res, req)

			if tt.wantStatus != http.StatusOK {
				ms.Equal(tt.wantStatus, res.Status, fmt.Sprintf("ActivateApiKey response: %s", res.Body))
				var se simpleError
				ms.decodeBody(res.Body, &se)
				ms.ErrorIs(se, tt.wantError)
				return
			}

			ms.Equal(http.StatusOK, res.Status, fmt.Sprintf("ActivateApiKey response: %s", res.Body))

			var response struct {
				Email       string    `json:"email"`
				ApiKeyValue string    `json:"apiKeyValue"`
				ApiSecret   string    `json:"apiSecret"`
				ActivatedAt time.Time `json:"activatedAt"`
				CreatedAt   time.Time `json:"createdAt"`
			}
			ms.NoError(json.Unmarshal(res.Body, &response))
			ms.Regexp("^[A-Za-z0-9+/]{43}=$", response.ApiSecret, "apiSecret isn't correct")
			ms.Equal(tt.body["email"], response.Email, "email isn't correct")
			ms.Equal(tt.body["apiKeyValue"], response.ApiKeyValue, "apiKeyValue isn't correct")
			ms.Equal(time.Date(2025, 4, 16, 10, 25, 33, 0, time.UTC), response.CreatedAt, "createdAt isn't correct")
			ms.WithinDuration(time.Now().UTC(), response.ActivatedAt, time.Minute, "activatedAt isn't correct")
		})
	}
}

func (ms *MfaSuite) TestCreateApiKey() {
	awsConfig := testAwsConfig()
	testEnvConfig(awsConfig)
	localStorage, err := NewStorage(awsConfig)
	must(err)

	tests := []struct {
		name       string
		body       any
		wantStatus int
		wantError  error
	}{
		{
			name: "success",
			body: map[string]interface{}{
				"email": exampleEmail,
			},
			wantStatus: http.StatusOK,
		},
		{
			name:       "missing email",
			body:       map[string]interface{}{},
			wantStatus: http.StatusBadRequest,
			wantError:  errors.New("email is required"),
		},
	}
	for _, tt := range tests {
		ms.Run(tt.name, func() {
			res := &lambdaResponseWriter{Headers: http.Header{}}
			req := requestWithUser(tt.body, ApiKey{Store: localStorage})
			ms.app.CreateApiKey(res, req)

			if tt.wantError != nil {
				ms.Equal(tt.wantStatus, res.Status, fmt.Sprintf("CreateApiKey response: %s", res.Body))
				var se simpleError
				ms.decodeBody(res.Body, &se)
				ms.ErrorIs(se, tt.wantError)
				return
			}

			ms.Equal(tt.wantStatus, res.Status, fmt.Sprintf("CreateApiKey response: %s", res.Body))

			var response struct {
				Email       string    `json:"email"`
				APIKeyValue string    `json:"apiKeyValue"`
				CreatedAt   time.Time `json:"createdAt"`
			}
			ms.NoError(json.Unmarshal(res.Body, &response))
			ms.Equal(exampleEmail, response.Email)
			ms.Regexp("^[0-9a-z]{40}$", response.APIKeyValue)
			ms.WithinDuration(time.Now().UTC(), response.CreatedAt, time.Minute)
		})
	}
}

func (ms *MfaSuite) TestAppRotateApiKey() {
	users := getTestWebauthnUsers(ms, getDBConfig(ms))

	db := ms.app.GetDB()
	config := ms.app.GetConfig()

	user := users[0]
	key := user.ApiKey
	must(db.Store(config.ApiKeyTable, key))

	const numberOfTOTPs = 100
	totpList := make([]TOTP, numberOfTOTPs)
	for i := range totpList {
		totpList[i] = ms.newTOTP(key)
	}

	newKey := newTestKey()
	must(db.Store(config.ApiKeyTable, newKey))

	tests := []struct {
		name       string
		body       any
		key        ApiKey
		wantStatus int
		wantError  string
	}{
		{
			name: "missing key",
			body: map[string]interface{}{
				paramNewKeyId:     newKey.Key,
				paramNewKeySecret: newKey.Secret,
			},
			wantStatus: http.StatusUnauthorized,
			wantError:  "Unauthorized",
		},
		{
			name: "missing newKeyId",
			body: map[string]interface{}{
				paramNewKeySecret: newKey.Secret,
			},
			key:        key,
			wantStatus: http.StatusBadRequest,
			wantError:  "newKeyId is required",
		},
		{
			name: "missing newKeySecret",
			body: map[string]interface{}{
				paramNewKeyId: newKey.Key,
			},
			key:        key,
			wantStatus: http.StatusBadRequest,
			wantError:  "newKeySecret is required",
		},
		{
			name: "good",
			body: map[string]interface{}{
				paramNewKeyId:     newKey.Key,
				paramNewKeySecret: newKey.Secret,
			},
			key:        key,
			wantStatus: http.StatusOK,
		},
	}
	for _, tt := range tests {
		ms.Run(tt.name, func() {
			jsonBody, err := json.Marshal(tt.body)
			must(err)
			b := io.NopCloser(bytes.NewReader(jsonBody))
			request, _ := http.NewRequest(http.MethodPost, "/api-key/rotate", b)
			request.Header.Set(HeaderAPIKey, tt.key.Key)
			request.Header.Set(HeaderAPISecret, tt.key.Secret)

			ctxWithUser := context.WithValue(request.Context(), UserContextKey, tt.key)
			ctxWithDeadline, cancel := context.WithTimeout(ctxWithUser, time.Second)
			defer cancel()
			request = request.WithContext(ctxWithDeadline)

			res := httptest.NewRecorder()
			Router(ms.app).ServeHTTP(res, request)
			ms.Equal(tt.wantStatus, res.Code, "incorrect http status, body: %s", res.Body.String())

			if tt.wantError != "" {
				ms.Contains(res.Body.String(), tt.wantError)
				return
			}

			var response BatchStats
			ms.decodeBody(res.Body.Bytes(), &response)
			ms.Greater(response.TOTP.Complete, 0, "none of the TOTPs were re-encrypted")
			ms.Less(response.TOTP.Complete, numberOfTOTPs, "test didn't cancel before completion")
			ms.Equalf(numberOfTOTPs, response.TOTP.Complete+response.TOTP.Incomplete,
				"total of TOTP.Complete (%d) and TOTP.Incomplete (%d) should equal the total number of TOTPs (%d)",
				response.TOTP.Complete, response.TOTP.Incomplete, numberOfTOTPs)
			ms.Equal(1, response.Webauthn.Complete)

			foundOne := false
			for i := range totpList {
				totpFromDB := TOTP{UUID: totpList[i].UUID, ApiKey: newKey.Key}
				must(db.Load(config.TotpTable, "uuid", totpList[i].UUID, &totpFromDB))
				if newKey.Key == totpFromDB.ApiKey {
					foundOne = true
				}
			}
			ms.True(foundOne, "did not find a TOTP with the new key")

			dbUser := WebauthnUser{ID: user.ID, Store: db, ApiKey: newKey}
			must(dbUser.Load())
			ms.Equal(newKey.Key, dbUser.ApiKey.Key)
		})
	}
}

func (ms *MfaSuite) TestNewApiKey() {
	got, err := NewApiKey(exampleEmail)
	ms.NoError(err)
	ms.Equal(exampleEmail, got.Email, "Email isn't correct")
	ms.Regexp(regexp.MustCompile("^[a-f0-9]{40}$"), got.Key, "Key isn't correct")
	ms.WithinDuration(time.Now(), time.Unix(int64(got.CreatedAt)/1000, 0), time.Minute,
		"CreatedAt isn't set to the current time")
}

func (ms *MfaSuite) TestNewCipherBlock() {
	random := make([]byte, 32)
	_, err := io.ReadFull(rand.Reader, random)
	ms.NoError(err)

	tests := []struct {
		name    string
		key     string
		wantErr bool
	}{
		{
			name:    "key too short",
			key:     "0123456789012345678901234567890",
			wantErr: true,
		},
		{
			name:    "key too long",
			key:     "012345678901234567890123456789012",
			wantErr: true,
		},
		{
			name: "raw",
			key:  string(random),
		},
		{
			name: "base64",
			key:  base64.StdEncoding.EncodeToString(random),
		},
	}
	for _, tt := range tests {
		ms.Run(tt.name, func() {
			got, err := newCipherBlock(tt.key)
			if tt.wantErr {
				ms.Error(err)
				return
			}

			ms.NoError(err)
			ms.Equal(aes.BlockSize, got.BlockSize())
		})
	}
}

func (ms *MfaSuite) TestApiKey_ReEncryptTOTPs() {
	awsConfig := testAwsConfig()
	testEnvConfig(awsConfig)
	storage, err := NewStorage(awsConfig)
	must(err)

	oldKey, err := NewApiKey("old_key@example.com")
	must(err)
	must(oldKey.Activate())
	must(ms.app.GetDB().Store(ms.app.GetConfig().ApiKeyTable, oldKey))

	newKey, err := NewApiKey("new_key@example.com")
	must(err)
	must(newKey.Activate())
	must(ms.app.GetDB().Store(ms.app.GetConfig().ApiKeyTable, newKey))

	_ = ms.newTOTP(oldKey)

	stats, err := newKey.ReEncryptTOTPs(ms.T().Context(), storage, oldKey)
	ms.NoError(err)
	ms.Equal(1, stats.Complete)
	ms.Equal(0, stats.Incomplete)
}

func (ms *MfaSuite) TestReEncryptWebAuthnUsers() {
	awsConfig := testAwsConfig()
	testEnvConfig(awsConfig)
	storage, err := NewStorage(awsConfig)
	must(err)

	baseConfigs := getDBConfig(ms)
	users := getTestWebauthnUsers(ms, baseConfigs)

	newKey := newTestKey()
	must(ms.app.GetDB().Store(ms.app.GetConfig().ApiKeyTable, newKey))

	stats, err := newKey.ReEncryptWebAuthnUsers(ms.T().Context(), storage, users[0].ApiKey)
	ms.NoError(err)
	ms.Equal(0, stats.Incomplete)
	ms.Equal(1, stats.Complete)

	// verify only users[0] is affected because each test user belongs to a different key
	for i, user := range users {
		dbUser := user
		must(dbUser.Load())
		if i == 0 {
			ms.NotEqual(user, dbUser)
		} else {
			ms.Equal(user, dbUser)
		}
	}
}

func (ms *MfaSuite) TestReEncryptWebAuthnUser() {
	awsConfig := testAwsConfig()
	testEnvConfig(awsConfig)
	storage, err := NewStorage(awsConfig)
	must(err)

	baseConfigs := getDBConfig(ms)
	users := getTestWebauthnUsers(ms, baseConfigs)

	tests := []struct {
		name string
		user WebauthnUser
	}{
		{
			name: "rotate U2F user",
			user: users[0],
		},
		{
			name: "rotate WebAuthn user",
			user: users[1],
		},
	}
	for _, tt := range tests {
		ms.Run(tt.name, func() {
			newKey := newTestKey()
			must(ms.app.GetDB().Store(ms.app.GetConfig().ApiKeyTable, newKey))
			ms.NotEqual(newKey.Secret, tt.user.ApiKey.Secret)

			err = newKey.ReEncryptWebAuthnUser(ms.T().Context(), storage, tt.user)
			ms.NoError(err)

			dbUser := WebauthnUser{ID: tt.user.ID, ApiKey: newKey, Store: storage}
			must(dbUser.Load())

			// check U2F data
			ms.DifferentOrEmptyString(tt.user.EncryptedAppId, dbUser.EncryptedAppId)
			ms.DifferentOrEmptyString(tt.user.EncryptedKeyHandle, dbUser.EncryptedKeyHandle)
			ms.DifferentOrEmptyString(tt.user.EncryptedPublicKey, dbUser.EncryptedPublicKey)
			ms.Equal(tt.user.AppId, dbUser.AppId)
			ms.Equal(tt.user.KeyHandle, dbUser.KeyHandle)
			ms.Equal(tt.user.PublicKey, dbUser.PublicKey)

			// check WebAuthn data
			ms.DifferentOrNilByteSlice(tt.user.EncryptedCredentials, dbUser.EncryptedCredentials)
			ms.DifferentOrNilByteSlice(tt.user.EncryptedSessionData, dbUser.EncryptedSessionData)
			ms.Equal(tt.user.Credentials, dbUser.Credentials)
			ms.Equal(tt.user.SessionData, dbUser.SessionData)
		})
	}
}

func (ms *MfaSuite) DifferentOrEmptyString(a, b string) {
	if a == "" && b == "" {
		return
	}
	ms.NotEqual(a, b)
}

func (ms *MfaSuite) DifferentOrNilByteSlice(a, b []byte) {
	if a == nil && b == nil {
		return
	}
	ms.NotEqual(a, b)
}

func (ms *MfaSuite) TestApiKeyReEncrypt() {
	oldKey := ApiKey{}
	must(oldKey.Activate())
	newKey := ApiKey{}
	must(newKey.Activate())

	plaintext := []byte("this is a secret message")
	ciphertext, err := oldKey.EncryptData(plaintext)
	ms.NoError(err)

	// keep a copy of the ciphertext before it changes
	oldCiphertext := ciphertext
	err = newKey.ReEncrypt(oldKey, &ciphertext)
	ms.NoError(err)

	// verify it actually changed
	ms.NotEqual(oldCiphertext, ciphertext)
	ms.Equal(len(oldCiphertext), len(ciphertext))

	// decrypt and compare with the original plaintext
	after, err := newKey.DecryptData(ciphertext)
	ms.NoError(err)
	ms.Equal(plaintext, after)
}

func (ms *MfaSuite) TestApiKeyReEncryptLegacy() {
	oldKey := ApiKey{}
	must(oldKey.Activate())
	newKey := ApiKey{}
	must(newKey.Activate())

	plaintext := "this is a secret message"
	ciphertext, err := oldKey.EncryptLegacy(plaintext)
	ms.NoError(err)

	// decrypt and compare with the original plaintext
	a, err := oldKey.DecryptLegacy(ciphertext)
	ms.NoError(err)
	ms.Equal(plaintext, a)

	// convert to string and retain a copy for comparison
	newCiphertext := ciphertext
	err = newKey.ReEncryptLegacy(oldKey, &newCiphertext)
	ms.NoError(err)

	// verify it actually changed
	ms.False(newCiphertext == ciphertext)

	// decrypt and compare with the original plaintext
	after, err := newKey.DecryptLegacy(newCiphertext)
	ms.NoError(err)
	ms.Equal(plaintext, after)
}

func newTestKey() ApiKey {
	apiKey, err := NewApiKey("user@example.com")
	must(err)
	must(apiKey.Activate())
	return apiKey
}
