package gencrypto

import (
	"time"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
	"github.com/golang-jwt/jwt/v4"
	"github.com/pkg/errors"

	"github.com/openshift/installer/pkg/asset/agent/workflow"
)

// UserAuthHeaderWriter sets the JWT authorization token.
func UserAuthHeaderWriter(token string) runtime.ClientAuthInfoWriter {
	return runtime.ClientAuthInfoWriterFunc(func(r runtime.ClientRequest, _ strfmt.Registry) error {
		return r.SetHeaderParam("Authorization", token)
	})
}

// ParseExpirationFromToken checks if the token is expired or not.
func ParseExpirationFromToken(tokenString string, workflowType workflow.AgentWorkflowType) error {
	token, _, err := new(jwt.Parser).ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return err
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return errors.Errorf("malformed token claims in url")
	}
	// Add exp claim only for add nodes workflow
	if workflowType == workflow.AgentWorkflowTypeAddNodes {
		exp, ok := claims["exp"].(float64)
		if !ok {
			return errors.Errorf("token missing 'exp' claim")
		}
		expTime := time.Unix(int64(exp), 0)
		expiresAt := strfmt.DateTime(expTime)

		expiryTime := time.Time(expiresAt)
		if expiryTime.Before(time.Now()) {
			return errors.Errorf("Auth token is expired. Re-run 'add-nodes' command to create new image files(ISO/PXE files)")
		}
	}
	return nil
}
