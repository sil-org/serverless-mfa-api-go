package main

import (
	"testing"

	"github.com/aws/aws-lambda-go/events"
	"github.com/stretchr/testify/require"
)

func TestCredentialToDelete(t *testing.T) {
	assert := require.New(t)

	tests := []struct {
		name   string
		method string
		path   string
		wantId string
		wantOk bool
	}{
		{
			name:   "method not delete",
			method: "PUT",
			path:   "/webauthn/credential/abc123",
			wantId: "",
			wantOk: false,
		},
		{
			name:   "path not /webauthn ...",
			method: "DELETE",
			path:   "/badstuff/credential/abc123",
			wantId: "",
			wantOk: false,
		},
		{
			name:   "path not /webauthn/credential ...",
			method: "DELETE",
			path:   "/webauthn/badstuff/abc123",
			wantId: "",
			wantOk: false,
		},
		{
			name:   "path too few parts",
			method: "DELETE",
			path:   "/webauthn/credential",
			wantId: "",
			wantOk: false,
		},
		{
			name:   "all good",
			method: "DELETE",
			path:   "/webauthn/credential/abc123",
			wantId: "abc123",
			wantOk: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := events.APIGatewayProxyRequest{
				HTTPMethod: tt.method,
				Path:       tt.path,
			}
			gotId, gotOk := credentialToDelete(req)
			assert.Equal(tt.wantOk, gotOk, "test %s: incorrect bool", tt.name)
			assert.Equal(tt.wantId, gotId, "test %s: incorrect credential ID", tt.name)
		})
	}
}
