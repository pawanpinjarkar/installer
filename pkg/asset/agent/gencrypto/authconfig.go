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

var (
	authTokenSecretNamespace = "kube-system"
	authTokenSecretName      = "agent-auth-token" //nolint:gosec // no sensitive info
	authTokenSecretDataKey   = "agentAuthToken"
)

// AuthConfig is an asset that generates ECDSA public/private keys, JWT token.
type AuthConfig struct {
	PublicKey, AgentAuthToken string
	Client                    kubernetes.Interface
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

	publicKey, privateKey, err := keyPairPEM()
	if err != nil {
		return err
	}
	// Encode to Base64 (Standard encoding)
	encodedPubKeyPEM := base64.StdEncoding.EncodeToString([]byte(publicKey))

	a.PublicKey = encodedPubKeyPEM

	newAgentAuthToken, err := localJWTForKey(infraEnvID.ID, privateKey)
	if err != nil {
		return err
	}
	// set newly generated token
	a.AgentAuthToken = newAgentAuthToken

	switch agentWorkflow.Workflow {
	case workflow.AgentWorkflowTypeInstall:
		// do nothing

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
	logrus.Debugf("Using agent auth token: %s\n", a.AgentAuthToken)

	return nil
}

// Name returns the human-friendly name of the asset.
func (*AuthConfig) Name() string {
	return "Agent Installer API Auth Config"
}

func keyPairPEM() (string, string, error) {
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

func localJWTForKey(id string, privateKkeyPem string) (string, error) {
	priv, err := jwt.ParseECPrivateKeyFromPEM([]byte(privateKkeyPem))
	if err != nil {
		return "", err
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		string(InfraEnvKey): id,
	})

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
		// Update the token with the retrieved token from the cluster
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
	retrievedSecret, err := k8sclientset.CoreV1().Secrets(authTokenSecretNamespace).Get(context.Background(), authTokenSecretName, metav1.GetOptions{})

	// if the secret does not exist
	if err != nil {
		if errors.IsNotFound(err) {
			// Secret does not exist, create the secret and set it with the new agent auth token
			err = createSecret(k8sclientset, a.AgentAuthToken)
			if err != nil {
				return "", err
			}
			return "", nil
		}
		// Other errors while trying to get the secret
		return "", fmt.Errorf("failed to get required auth token secret from the cluster: %w", err)
	}

	authToken, err := getSecret(retrievedSecret)
	if err != nil {
		return "", err
	}
	return authToken, err
}

func createSecret(k8sclientset kubernetes.Interface, newAgentAuthToken string) error {
	// Encode the token in base64
	encodedToken := base64.StdEncoding.EncodeToString([]byte(newAgentAuthToken))

	// Create a Secret
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: authTokenSecretName,
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			authTokenSecretDataKey: []byte(encodedToken),
		},
	}
	_, err := k8sclientset.CoreV1().Secrets(authTokenSecretNamespace).Create(context.Background(), secret, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("failed to create Secret: %w", err)
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
	retrievedEncodedToken, exists := retrievedSecret.Data[authTokenSecretDataKey]
	if !exists {
		return "", fmt.Errorf("auth token secret does not contain the key %s", authTokenSecretDataKey)
	}

	// Decode the token from the Secret
	existingAgentAuthToken, err := base64.StdEncoding.DecodeString(string(retrievedEncodedToken))
	if err != nil {
		return "", fmt.Errorf("failed to decode the auth token secret token from the cluster: %w", err)
	}

	// Check if secret is set to empty string in the cluster
	if len(existingAgentAuthToken) == 0 {
		return "", fmt.Errorf("required auth token secret in the cluster found empty")
	}
	return string(existingAgentAuthToken), nil
}
