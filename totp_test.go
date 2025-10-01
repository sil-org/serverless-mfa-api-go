package mfa

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"time"

	"github.com/pquerna/otp/totp"
)

func (ms *MfaSuite) TestAppCreateTOTP() {
	ctxWithAPIKey := context.WithValue(context.Background(), UserContextKey, newTestKey())
	reqWithAPIKey := (&http.Request{}).WithContext(ctxWithAPIKey)

	validBody := io.NopCloser(strings.NewReader(`{"issuer":"idp","label":"label"}`))
	validRequest := (&http.Request{Body: validBody}).WithContext(ctxWithAPIKey)

	tests := []struct {
		name       string
		request    *http.Request
		wantStatus int
	}{
		{
			name:       "bad request body",
			request:    reqWithAPIKey,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "valid request",
			request:    validRequest,
			wantStatus: http.StatusOK,
		},
	}
	for _, tt := range tests {
		ms.Run(tt.name, func() {
			response := httptest.NewRecorder()
			ms.app.CreateTOTP(response, tt.request)
			ms.Equalf(tt.wantStatus, response.Code, "incorrect http status, response body: %s", response.Body.String())

			if tt.wantStatus == http.StatusOK {
				var responseBody CreateTOTPResponseBody
				ms.NoError(json.Unmarshal(response.Body.Bytes(), &responseBody))
				ms.NotEmpty(responseBody.TOTPKey, "TOTPKey is empty")
				ms.NotEmpty(responseBody.OTPAuthURL, "OTPAuthURL is empty")
				ms.NotEmpty(responseBody.ImageURL, "ImageURL is empty")
				ms.NotEmpty(responseBody.UUID, "UUID is empty")
			}
		})
	}
}

func (ms *MfaSuite) TestParseCreateTOTPRequestBody() {
	tests := []struct {
		name    string
		body    string
		want    *CreateTOTPRequestBody
		wantErr string
	}{
		{
			name:    "empty issuer",
			body:    `{"issuer":"","label":"john_doe@example.com"}`,
			want:    nil,
			wantErr: "issuer is required",
		},
		{
			name: "empty label",
			body: `{"issuer":"idp","label":""}`,
			want: &CreateTOTPRequestBody{
				Issuer: "idp",
				Name:   "SecretKey",
			},
		},
		{
			name: "fully specified",
			body: `{"issuer":"idp","label":"label"}`,
			want: &CreateTOTPRequestBody{
				Issuer: "idp",
				Name:   "label",
			},
		},
	}
	for _, tt := range tests {
		ms.Run(tt.name, func() {
			got, err := parseCreateTOTPRequestBody(io.NopCloser(strings.NewReader(tt.body)))
			if tt.wantErr != "" {
				ms.Error(err)
				ms.Equal(tt.wantErr, err.Error())
				return
			}

			ms.NoError(err)
			ms.Equal(tt.want, got)
		})
	}
}

func (ms *MfaSuite) TestNewTOTP() {
	apiKey := newTestKey()

	got, err := newTOTP(ms.app.GetDB(), apiKey, "issuer", "label")
	ms.NoError(err)
	ms.Equal(apiKey.Key, got.ApiKey, "ApiKey isn't correct")
	ms.Regexp("^[a-zA-Z0-9]{32}$", got.Key, "Key length is not correct. Check SecretSize in totp.GenerateOpts.")
	ms.Regexp("^data:image/png;base64,[a-zA-Z0-9/+=]+$", got.ImageURL, "ImageURL isn't correct")

	wantOTPAuthURL := "otpauth://totp/issuer:label?algorithm=SHA1&digits=6&issuer=issuer&period=30&secret=" + got.Key
	ms.Equal(wantOTPAuthURL, got.OTPAuthURL, "OTPAuthURL isn't correct")

	plainText, err := apiKey.DecryptLegacy(got.EncryptedTotpKey)
	ms.NoError(err)
	ms.Equal(got.Key, plainText, "EncryptedTotpKey isn't correct")
}

func (ms *MfaSuite) TestAppDeleteTOTP() {
	key := newTestKey()
	otherKey := newTestKey()
	testTOTP := ms.newTOTP(key)

	ctxWithAPIKey := context.WithValue(context.Background(), UserContextKey, key)
	ctxWithOtherAPIKey := context.WithValue(context.Background(), UserContextKey, otherKey)

	mux := &http.ServeMux{}
	mux.HandleFunc("DELETE /totp/{"+UUIDParam+"}", ms.app.DeleteTOTP)

	tests := []struct {
		name       string
		request    *http.Request
		wantStatus int
	}{
		{
			name:       "wrong UUID",
			request:    ms.newRequest(ctxWithAPIKey, http.MethodDelete, "/totp/"+NewUUID(), ""),
			wantStatus: http.StatusNotFound,
		},
		{
			name:       "correct UUID, wrong key",
			request:    ms.newRequest(ctxWithOtherAPIKey, http.MethodDelete, "/totp/"+testTOTP.UUID, ""),
			wantStatus: http.StatusNotFound,
		},
		{
			name:       "correct UUID, correct key",
			request:    ms.newRequest(ctxWithAPIKey, http.MethodDelete, "/totp/"+testTOTP.UUID, ""),
			wantStatus: http.StatusNoContent,
		},
	}
	for _, tt := range tests {
		ms.Run(tt.name, func() {
			response := httptest.NewRecorder()
			mux.ServeHTTP(response, tt.request)

			ms.Equalf(tt.wantStatus, response.Code, "incorrect http status, response body: %s", response.Body.String())
		})
	}
}

func (ms *MfaSuite) TestAppValidateTOTP() {
	key := newTestKey()
	otherKey := newTestKey()
	testTOTP, err := newTOTP(ms.app.db, key, "issuer", "name")
	ms.NoError(err)

	ctxWithAPIKey := context.WithValue(context.Background(), UserContextKey, key)
	ctxWithOtherAPIKey := context.WithValue(context.Background(), UserContextKey, otherKey)

	now := time.Now()
	code, err := totp.GenerateCode(testTOTP.Key, now)
	ms.NoError(err)

	mux := &http.ServeMux{}
	mux.HandleFunc("POST /totp/{"+UUIDParam+"}/validate", ms.app.ValidateTOTP)

	tests := []struct {
		name       string
		request    *http.Request
		wantStatus int
	}{
		{
			name: "wrong UUID",
			request: ms.newRequest(ctxWithAPIKey, http.MethodPost,
				"/totp/"+NewUUID()+"/validate", `{"code":"`+code+`"}`),
			wantStatus: http.StatusNotFound,
		},
		{
			name: "correct UUID, wrong key",
			request: ms.newRequest(ctxWithOtherAPIKey, http.MethodPost,
				"/totp/"+testTOTP.UUID+"/validate", `{"code":"`+code+`"}`),
			wantStatus: http.StatusNotFound,
		},
		{
			name: "correct UUID, correct key, wrong code",
			request: ms.newRequest(ctxWithAPIKey, http.MethodPost,
				"/totp/"+testTOTP.UUID+"/validate", `{"code":"000000"}`),
			wantStatus: http.StatusUnauthorized,
		},
		{
			name: "correct UUID, correct key, correct code",
			request: ms.newRequest(ctxWithAPIKey, http.MethodPost,
				"/totp/"+testTOTP.UUID+"/validate", `{"code":"`+code+`"}`),
			wantStatus: http.StatusOK,
		},
	}
	for _, tt := range tests {
		ms.Run(tt.name, func() {
			response := httptest.NewRecorder()
			mux.ServeHTTP(response, tt.request)

			ms.Equalf(tt.wantStatus, response.Code, "incorrect http status, response body: %s", response.Body.String())
		})
	}
}

func (ms *MfaSuite) TestParseValidateTOTPRequestBody() {
	tests := []struct {
		name    string
		body    io.ReadCloser
		want    *ValidateTOTPRequestBody
		wantErr string
	}{
		{
			name:    "no body",
			body:    nil,
			want:    nil,
			wantErr: "empty request body",
		},
		{
			name:    "empty",
			body:    io.NopCloser(strings.NewReader("")),
			want:    nil,
			wantErr: "invalid request: EOF",
		},
		{
			name:    "missing code",
			body:    io.NopCloser(strings.NewReader("{}")),
			want:    nil,
			wantErr: "code is required",
		},
		{
			name: "correct",
			body: io.NopCloser(strings.NewReader(`{"code":"000000"}`)),
			want: &ValidateTOTPRequestBody{
				Code: "000000",
			},
		},
	}
	for _, tt := range tests {
		ms.Run(tt.name, func() {
			got, err := parseValidateTOTPRequestBody(tt.body)
			if tt.wantErr != "" {
				ms.Error(err)
				ms.Equal(tt.wantErr, err.Error())
				return
			}

			ms.NoError(err)
			ms.Equal(tt.want, got)
		})
	}
}

func (ms *MfaSuite) newRequest(ctx context.Context, method, path, body string) *http.Request {
	r := &http.Request{
		Method: method,
		URL:    &url.URL{Path: path},
	}
	if body != "" {
		r.Body = io.NopCloser(strings.NewReader(body))
	}
	return r.WithContext(ctx)
}

func (ms *MfaSuite) newTOTP(key ApiKey) TOTP {
	t := TOTP{
		UUID:             NewUUID(),
		ApiKey:           key.Key,
		EncryptedTotpKey: mustEncryptLegacy(key, "plain text TOTP key"),
	}
	must(ms.app.db.Store(ms.app.GetConfig().TotpTable, t))
	return t
}
