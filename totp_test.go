package mfa

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
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
			ms.Equalf(tt.wantStatus, response.Code, "incorrect http status, body %s", response.Body.String())

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
