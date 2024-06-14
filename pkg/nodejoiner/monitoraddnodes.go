package nodejoiner

import (
	"context"
	"fmt"

	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	agentpkg "github.com/openshift/installer/pkg/agent"
	"github.com/openshift/installer/pkg/asset/agent/workflow"
	"github.com/openshift/installer/pkg/types"
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
	retrieveSSHKeyFromInstallConfigData(k8sclientset)

	var token string
	cluster, err := agentpkg.NewCluster(context.Background(), "", ips[0], kubeconfigPath, "", token, workflow.AgentWorkflowTypeAddNodes)
	if err != nil {
		// TODO exit code enumerate
		logrus.Exit(1)
	}

	if err != nil {
		return err
	}

	return agentpkg.MonitorAddNodes(cluster, ips[0])
}

// InitClients initiaties a client.
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
			return "", nil
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
	logrus.Info("****** SSHKey=", SSHKey)

	return SSHKey, nil
}
