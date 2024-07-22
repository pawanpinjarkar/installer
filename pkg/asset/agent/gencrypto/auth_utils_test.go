package gencrypto

import (
	"testing"
	"time"

	"github.com/go-openapi/strfmt"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"github.com/openshift/installer/pkg/asset/agent/workflow"
)

func TestParseExpirationFromToken(t *testing.T) {
	cases := []struct {
		name, errorMessage, token  string
		workflowType               workflow.AgentWorkflowType
		expiration                 int
		expirationUnit             time.Duration
		expectedErr, overrideToken bool
	}{
		{
			name:           "valid-unexpired-JWT-token",
			workflowType:   workflow.AgentWorkflowTypeAddNodes,
			expiration:     1,
			expirationUnit: time.Second,
		},
		{
			name:          "invalid-JWT-token",
			workflowType:  workflow.AgentWorkflowTypeInstall,
			overrideToken: true,
			token:         getOverriddenToken(workflow.AgentWorkflowTypeInstall),
			expectedErr:   true,
			errorMessage:  "token contains an invalid number of segments",
		},
		{
			name:          "JWT-token-with-no-exp-claim",
			workflowType:  workflow.AgentWorkflowTypeAddNodes,
			overrideToken: true,
			token:         getOverriddenToken(workflow.AgentWorkflowTypeAddNodes),
			expectedErr:   true,
			errorMessage:  "token missing 'exp' claim",
		},
		{
			name:           "expired-JWT-token",
			workflowType:   workflow.AgentWorkflowTypeAddNodes,
			expiration:     1,
			expirationUnit: time.Microsecond,
			expectedErr:    true,
			errorMessage:   "Auth token is expired. Re-run 'add-nodes' command to create new image files(ISO/PXE files)",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			infraEnvID := string(strfmt.UUID(uuid.New().String()))

			_, privKey, err := KeyPairPEM()
			assert.NoError(t, err)

			if !tc.overrideToken {
				tc.token, err = LocalJWTForKey(infraEnvID, privKey, tc.workflowType, tc.expiration, tc.expirationUnit)
				assert.NoError(t, err)
			}

			err = ParseExpirationFromToken(tc.token, tc.workflowType)
			if tc.expectedErr {
				assert.EqualError(t, err, tc.errorMessage)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func getOverriddenToken(workflowType workflow.AgentWorkflowType) string {
	if workflowType == workflow.AgentWorkflowTypeInstall {
		return "some-token"
	}
	infraEnvID := string(strfmt.UUID(uuid.New().String()))
	_, privKey, _ := KeyPairPEM() //nolint:errcheck
	noExpClaimToken := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		string(InfraEnvKey): infraEnvID,
	})
	priv, _ := jwt.ParseECPrivateKeyFromPEM([]byte(privKey)) //nolint:errcheck
	token, _ := noExpClaimToken.SignedString(priv)           //nolint:errcheck
	return token
}
