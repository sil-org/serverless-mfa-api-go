package mfa

import (
	"context"
	"net/http"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

func (ms *MfaSuite) Test_User_DeleteCredential() {
	baseConfigs := getDBConfig(ms)

	users := getTestWebauthnUsers(ms, baseConfigs)
	testUser0, testUser1, testUser2 := users[0], users[1], users[2]

	dbParams := &dynamodb.ScanInput{
		TableName: aws.String(baseConfigs.EnvConfig.WebauthnTable),
	}

	tests := []struct {
		name            string
		user            WebauthnUser
		credID          string
		wantErrContains string
		wantStatus      int
		wantCredIDs     [][]byte
		dontWantCredID  []byte
		verifyFn        func(*dynamodb.ScanOutput)
	}{
		{
			name:            "no webauthn credentials",
			user:            testUser0,
			credID:          "noMatchingCredID",
			wantStatus:      http.StatusNotFound,
			wantErrContains: "no webauthn credentials available",
			verifyFn: func(results *dynamodb.ScanOutput) {
				// all three test users should remain
				ms.Len(results.Items, 3)
			},
		},
		{
			name:            "one credential but bad credential ID",
			user:            testUser1,
			credID:          "badCredID",
			wantErrContains: "Credential not found with id: badCredID",
			wantCredIDs:     [][]byte{testUser1.Credentials[0].ID},
			wantStatus:      http.StatusNotFound,
		},
		{
			name:           "one credential gets deleted",
			user:           testUser1,
			credID:         hashAndEncodeKeyHandle(testUser1.Credentials[0].ID),
			wantStatus:     http.StatusNoContent,
			dontWantCredID: testUser1.Credentials[0].ID,
		},
		{
			name:           "two credentials and one is deleted",
			user:           testUser2,
			credID:         hashAndEncodeKeyHandle(testUser2.Credentials[0].ID),
			wantStatus:     http.StatusNoContent,
			wantCredIDs:    [][]byte{testUser2.Credentials[1].ID},
			dontWantCredID: testUser2.Credentials[0].ID,
			verifyFn: func(results *dynamodb.ScanOutput) {
				ms.Equal(int32(3), results.Count)
				want := []string{testUser0.ID, testUser1.ID, testUser2.ID}
				got := make([]string, len(want))
				for i := range want {
					got[i] = results.Items[i]["uuid"].(*types.AttributeValueMemberS).Value
				}
				ms.ElementsMatch(got, want)
			},
		},
	}
	for _, tt := range tests {
		ms.T().Run(tt.name, func(t *testing.T) {
			status, err := tt.user.DeleteCredential(tt.credID)

			ms.Equal(tt.wantStatus, status, "incorrect http status")

			if tt.wantErrContains != "" {
				ms.Error(err, "expected an error but didn't get one")
				ms.Contains(err.Error(), tt.wantErrContains, "incorrect error")
			} else {
				ms.NoError(err, "unexpected error")
			}

			ctx := context.Background()
			results, err := baseConfigs.Storage.client.Scan(ctx, dbParams)
			ms.NoError(err, "failed to scan storage for results")

			if tt.verifyFn != nil {
				tt.verifyFn(results)
			}

			gotUser := WebauthnUser{
				ID:     tt.user.ID,
				ApiKey: tt.user.ApiKey,
				Store:  baseConfigs.Storage,
			}
			must(gotUser.Load())

			ms.Len(gotUser.Credentials, len(tt.wantCredIDs), "incorrect remaining credential ids")

			for i, w := range tt.wantCredIDs {
				ms.Equal(string(w), string(gotUser.Credentials[i].ID), "incorrect credential id")
			}

			if len(tt.dontWantCredID) == 0 {
				return
			}

			for _, g := range gotUser.Credentials {
				ms.NotEqual(string(tt.dontWantCredID), string(g.ID), "unexpected credential id")
			}
		})
	}
}
