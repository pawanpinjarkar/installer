package nodejoiner

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/yaml"

	agentpkg "github.com/openshift/installer/pkg/agent"
	"github.com/openshift/installer/pkg/asset/agent/workflow"
	"github.com/openshift/installer/pkg/types"
	cryptossh "golang.org/x/crypto/ssh"
)

// NewMonitorAddNodesCommand creates a new command for monitor add nodes.
func NewMonitorAddNodesCommand(directory, kubeconfigPath string, ips []string) error {
	err := saveParams(directory, kubeconfigPath)
	if err != nil {
		return err
	}
	k8sclientset, err := initk8sClient(kubeconfigPath)
	if err != nil {
		return err
	}
	sshKey, err := retrieveSSHKeyFromInstallConfigData(k8sclientset)
	if err != nil {
		return err
	}

	// Parse the SSH key
	signer, err := cryptossh.ParsePrivateKey([]byte(sshKey))
	if err != nil {
		logrus.Fatalf("Failed to parse SSH key: %v", err)
		return err
	}

	clientConfig := &cryptossh.ClientConfig{
		User: "core",
		Auth: []cryptossh.AuthMethod{
			cryptossh.PublicKeys(signer),
		},
		HostKeyCallback: cryptossh.InsecureIgnoreHostKey(),
	}

	host := ips[0]
	port := 22
	address := net.JoinHostPort(host, strconv.Itoa(port))

	// Retry logic to connect to the SSH server
	var client *cryptossh.Client
	for {
		client, err = cryptossh.Dial("tcp", address, clientConfig)
		if err == nil {
			break
		}
		logrus.Fatalf("failed to connect to %s: %v. Retrying in 30 seconds..", address, err)

		time.Sleep(30 * time.Second)
	}
	defer client.Close()

	// Create a session
	session, err := client.NewSession()
	if err != nil {
		logrus.Fatalf("Failed to create SSH session: %v", err)
	}
	defer session.Close()

	// Prepare a buffer to capture the command output
	var stdoutBuf bytes.Buffer
	session.Stdout = &stdoutBuf

	// this needs to be run only if its a day2 node
	command := "sudo pwd"
	if err := session.Run(command); err != nil {
		logrus.Fatalf("Failed to run command: %v", err)
	}

	// Parse the file contents
	fileContent := stdoutBuf.String()
	lines := strings.Split(fileContent, "\n")
	var authToken string
	for _, line := range lines {
		if strings.HasPrefix(line, "AGENT_AUTH_TOKEN=") {
			authToken = strings.TrimPrefix(line, "AGENT_AUTH_TOKEN=")
			break
		}
	}

	logrus.Info(authToken)

	cluster, err := agentpkg.NewCluster(context.Background(), "", ips[0], kubeconfigPath, sshKey, authToken, workflow.AgentWorkflowTypeAddNodes)
	if err != nil {
		logrus.Exit(1)
	}

	if err != nil {
		return err
	}

	return agentpkg.MonitorAddNodes(cluster, ips[0])
}

// InitClients initiates a client.
func initk8sClient(kubeconfig string) (*kubernetes.Clientset, error) {
	var config *rest.Config
	var err error
	if kubeconfig != "" {
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)

		if err != nil {
			return nil, err
		}
	}

	k8sclientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	return k8sclientset, err
}

func retrieveSSHKeyFromInstallConfigData(k8sclientset *kubernetes.Clientset) (string, error) {
	clusterConfig, err := k8sclientset.CoreV1().ConfigMaps("kube-system").Get(context.Background(), "cluster-config-v1", metav1.GetOptions{})
	if err != nil {
		if errors.IsNotFound(err) {
			return "", err
		}
		return "", err
	}
	data, ok := clusterConfig.Data["install-config"]
	if !ok {
		return "", fmt.Errorf("cannot find install-config data")
	}

	installConfig := types.InstallConfig{}
	if err = yaml.Unmarshal([]byte(data), &installConfig); err != nil {
		return "", err
	}

	SSHKey := installConfig.SSHKey
	logrus.Info("********SSHKey: ", SSHKey)

	return SSHKey, nil
}
