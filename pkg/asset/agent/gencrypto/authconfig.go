package gencrypto

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/openshift/installer/pkg/asset"
	"github.com/openshift/installer/pkg/asset/agent/common"
	"github.com/openshift/installer/pkg/asset/agent/joiner"
	"github.com/openshift/installer/pkg/asset/agent/workflow"
)

const expiration = 48
const expirationUnit = time.Hour

var (
	authTokenSecretNamespace = "kube-system"
	authTokenSecretName      = "agent-auth-token" //nolint:gosec // no sensitive info
	authTokenSecretDataKey   = "agentAuthToken"
)

// AuthConfig is an asset that generates ECDSA public/private keys, JWT token.
type AuthConfig struct {
	PublicKey, AgentAuthToken string
}

var _ asset.Asset = (*AuthConfig)(nil)

// LocalJWTKeyType suggests the key type to be used for the token.
type LocalJWTKeyType string

const (
	// InfraEnvKey is used to generate token using infra env id.
	InfraEnvKey LocalJWTKeyType = "infra_env_id"
)

var _ asset.Asset = (*AuthConfig)(nil)

// Dependencies returns the assets on which the AuthConfig asset depends.
func (a *AuthConfig) Dependencies() []asset.Asset {
	return []asset.Asset{
		&common.InfraEnvID{},
		&workflow.AgentWorkflow{},
		&joiner.AddNodesConfig{},
	}
}

// Generate generates the auth config for agent installer APIs.
func (a *AuthConfig) Generate(_ context.Context, dependencies asset.Parents) error {
	infraEnvID := &common.InfraEnvID{}
	agentWorkflow := &workflow.AgentWorkflow{}
	dependencies.Get(infraEnvID, agentWorkflow)

	publicKey, privateKey, err := KeyPairPEM()
	if err != nil {
		return err
	}
	// Encode to Base64 (Standard encoding)
	encodedPubKeyPEM := base64.StdEncoding.EncodeToString([]byte(publicKey))

	a.PublicKey = encodedPubKeyPEM

	newAgentAuthToken, err := LocalJWTForKey(infraEnvID.ID, privateKey, agentWorkflow.Workflow, expiration, expirationUnit)
	if err != nil {
		return err
	}
	a.AgentAuthToken = newAgentAuthToken

	switch agentWorkflow.Workflow {
	case workflow.AgentWorkflowTypeInstall:
		// Auth tokens do not expire

	case workflow.AgentWorkflowTypeAddNodes:
		addNodesConfig := &joiner.AddNodesConfig{}
		dependencies.Get(addNodesConfig)

		err = a.createAuthTokenSecret(addNodesConfig.Params.Kubeconfig)
		if err != nil {
			return err
		}

	default:
		return fmt.Errorf("AgentWorkflowType value not supported: %s", agentWorkflow.Workflow)
	}
	return nil
}

// Name returns the human-friendly name of the asset.
func (*AuthConfig) Name() string {
	return "Agent Installer API Auth Config"
}

// KeyPairPEM returns the public, private keys in PEM format.
func KeyPairPEM() (string, string, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", err
	}

	// encode private key to PEM string
	privBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return "", "", err
	}

	block := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privBytes,
	}

	var privKeyPEM bytes.Buffer
	err = pem.Encode(&privKeyPEM, block)
	if err != nil {
		return "", "", err
	}

	// encode public key to PEM string
	pubBytes, err := x509.MarshalPKIXPublicKey(priv.Public())
	if err != nil {
		return "", "", err
	}

	block = &pem.Block{
		Type:  "EC PUBLIC KEY",
		Bytes: pubBytes,
	}

	var pubKeyPEM bytes.Buffer
	err = pem.Encode(&pubKeyPEM, block)
	if err != nil {
		return "", "", err
	}

	return pubKeyPEM.String(), privKeyPEM.String(), nil
}

// LocalJWTForKey returns a JWT token based on the private key.
func LocalJWTForKey(id, privateKkeyPem string, agentWorkflow workflow.AgentWorkflowType, expiration int, expirationUnit time.Duration) (string, error) {
	priv, err := jwt.ParseECPrivateKeyFromPEM([]byte(privateKkeyPem))
	if err != nil {
		return "", err
	}

	var token *jwt.Token
	switch agentWorkflow {
	case workflow.AgentWorkflowTypeInstall:
		token = jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
			string(InfraEnvKey): id,
		})
	case workflow.AgentWorkflowTypeAddNodes:
		token = jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
			string(InfraEnvKey): id,
			"exp":               time.Now().UTC().Add(time.Duration(expiration) * expirationUnit).Unix(),
		})

	default:
		return "", fmt.Errorf("AgentWorkflowType value not supported: %s", agentWorkflow)
	}

	tokenString, err := token.SignedString(priv)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func (a *AuthConfig) createAuthTokenSecret(kubeconfigPath string) error {
	client, err := initK8sClient(kubeconfigPath)
	if err != nil {
		return err
	}

	authToken, err := a.getOrCreateAuthTokenFromSecret(client)
	if err != nil {
		return err
	}
	if authToken != "" {
		// Update the token in asset store with the retrieved token from the cluster
		a.AgentAuthToken = authToken
	}
	return nil
}

func initK8sClient(kubeconfig string) (*kubernetes.Clientset, error) {
	var err error
	var config *rest.Config
	if kubeconfig != "" {
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
	} else {
		config, err = rest.InClusterConfig()
	}
	if err != nil {
		return nil, err
	}

	k8sclientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	return k8sclientset, err
}

func (a *AuthConfig) getOrCreateAuthTokenFromSecret(k8sclientset kubernetes.Interface) (string, error) {
	// check if secret exists
	retrievedSecret, err := k8sclientset.CoreV1().Secrets(authTokenSecretNamespace).Get(context.Background(), authTokenSecretName, metav1.GetOptions{})

	// if the secret does not exist
	if err != nil {
		if errors.IsNotFound(err) {
			// Create the secret with the new JWT token having an exp claim of 48 hours
			// i.e. the token will be valid for next 48 hours
			err = createSecret(k8sclientset, a.AgentAuthToken)
			if err != nil {
				return "", err
			}
			return "", nil
		}
		// Other errors while trying to get the secret
		return "", fmt.Errorf("failed to get required auth token secret from the cluster: %w. Re-run 'add-nodes' command to create new image files(ISO/PXE files)", err)
	}

	// the secret does exist
	var authToken string

	updatedAtStr := retrievedSecret.Annotations["updatedAt"]
	updatedAt, err := time.Parse(time.RFC3339, updatedAtStr)
	if err != nil {
		return "", err
	}
	// if the secret with JWT token is older than 24 hours
	// update the secret with a new JWT token with an exp claim of 48 hours
	// i.e. the token will be valid for next 48 hours
	if time.Since(updatedAt) > 24*expirationUnit {
		err = updateSecret(k8sclientset, retrievedSecret, a.AgentAuthToken)
		if err != nil {
			return "", err
		}
		logrus.Debug("auth token secret regenerated and updated in the cluster")
	} else {
		logrus.Debug("auth token secret is still valid")
		authToken, err = getSecret(retrievedSecret)
		if err != nil {
			return "", err
		}
	}

	return authToken, err
}

func createSecret(k8sclientset kubernetes.Interface, newAgentAuthToken string) error {
	createdAt := time.Now().UTC()
	expiresAt := createdAt.Add(time.Duration(expiration) * expirationUnit)
	// Create a Secret
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: authTokenSecretName,
			Annotations: map[string]string{
				"createdAt": createdAt.Format(time.RFC3339),
				"expiresAt": expiresAt.Format(time.RFC3339),
				"updatedAt": createdAt.Format(time.RFC3339), // Initially set to same as createdAt
			},
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			authTokenSecretDataKey: []byte(newAgentAuthToken),
		},
	}
	_, err := k8sclientset.CoreV1().Secrets(authTokenSecretNamespace).Create(context.Background(), secret, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("failed to create auth token secret: %w", err)
	}

	return nil
}

func updateSecret(k8sclientset kubernetes.Interface, retrievedSecret *corev1.Secret, newAgentAuthToken string) error {
	retrievedSecret.Data[authTokenSecretDataKey] = []byte(newAgentAuthToken)

	updatedAt := time.Now().UTC()
	expiresAt := updatedAt.Add(expiration * expirationUnit)
	retrievedSecret.Annotations["updatedAt"] = updatedAt.Format(time.RFC3339)
	retrievedSecret.Annotations["expiresAt"] = expiresAt.Format(time.RFC3339)

	_, err := k8sclientset.CoreV1().Secrets(authTokenSecretNamespace).Update(context.TODO(), retrievedSecret, metav1.UpdateOptions{})
	if err != nil {
		logrus.Fatal(err)
	}
	return nil
}

// GetAuthTokenFromCluster returns a token string stored as the secret from the cluster.
func GetAuthTokenFromCluster(ctx context.Context, kubeconfigPath string) (string, error) {
	client, err := initK8sClient(kubeconfigPath)
	if err != nil {
		return "", err
	}

	retrievedSecret, err := client.CoreV1().Secrets(authTokenSecretNamespace).Get(ctx, authTokenSecretName, metav1.GetOptions{})
	if err != nil {
		return "", err
	}
	authToken, err := getSecret(retrievedSecret)
	if err != nil {
		return "", err
	}
	return authToken, err
}

func getSecret(retrievedSecret *corev1.Secret) (string, error) {
	// Check if the secret data contains the expected key
	existingAgentAuthToken, exists := retrievedSecret.Data[authTokenSecretDataKey]
	if !exists {
		logrus.Fatalf("auth token secret %s does not contain the key %s. Re-run 'add-nodes' command to create new image files(ISO/PXE files)", authTokenSecretName, authTokenSecretDataKey)
	}

	// Check if secret is set to empty string in the cluster
	if len(existingAgentAuthToken) == 0 {
		logrus.Fatalf("auth token secret %s found to be empty. Re-run 'add-nodes' command to create new image files(ISO/PXE files)", authTokenSecretName)
	}
	return string(existingAgentAuthToken), nil
}
