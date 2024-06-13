package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	terminal "golang.org/x/term"

	"github.com/openshift/installer/cmd/openshift-install/command"
	"github.com/openshift/installer/pkg/gather/ssh"
	"github.com/openshift/installer/pkg/nodejoiner"
	cyrptossh "golang.org/x/crypto/ssh"
)

func main() {
	nodesAddCmd := &cobra.Command{
		Use:   "add-nodes",
		Short: "Generates an ISO that could be used to boot the configured nodes to let them join an existing cluster",
		RunE: func(cmd *cobra.Command, args []string) error {
			kubeConfig, err := cmd.Flags().GetString("kubeconfig")
			if err != nil {
				return err
			}
			dir, err := cmd.Flags().GetString("dir")
			if err != nil {
				return err
			}
			return nodejoiner.NewAddNodesCommand(dir, kubeConfig, "public-sshkey")
		},
	}

	nodesMonitorCmd := &cobra.Command{
		Use:   "monitor-add-nodes",
		Short: "Monitors the configured nodes while they are joining an existing cluster",
		RunE: func(cmd *cobra.Command, args []string) error {
			dir, err := cmd.Flags().GetString("dir")
			if err != nil {
				return err
			}

			assetDir := cmd.Flags().Lookup("dir").Value.String()
			logrus.Debugf("asset directory: %s", assetDir)
			if len(assetDir) == 0 {
				logrus.Fatal("No cluster installation directory found")
			}
			// instead of getting the authToken from assetStore, ssh into the node and get the
			// token from ephermal nodes's /usr/local/share/assisted-service/assisted-service.env.template
			// authToken, err := agentpkg.FindAuthTokenFromAssetStore(assetDir)
			// if err != nil {
			// 	logrus.Fatal(err)
			// }

			kubeConfig, err := cmd.Flags().GetString("kubeconfig")
			if err != nil {
				return err
			}

			ips := args
			logrus.Infof("Monitoring IPs: %v", ips)
			if len(ips) == 0 {
				logrus.Fatal("At least one IP address must be specified")
			}
			sshPrivateKeys, err := cmd.Flags().GetStringArray("key")
			if err != nil {
				return err
			}
			if len(sshPrivateKeys) == 0 {
				logrus.Fatal("Need path to ssh private key") // it won't be needed if we happen to read the default path?
			}

			// Retry logic to connect to the SSH Server
			var client *cyrptossh.Client
			port := 22
			for {
				client, err = ssh.NewClient("core", net.JoinHostPort(ips[0], strconv.Itoa(port)), sshPrivateKeys)
				if err == nil {
					break
				}
				log.Printf("Failed to dial: %v. Retrying in 5 seconds...", err)
				time.Sleep(5 * time.Second)
			}
			defer client.Close()

			// for now, assumed only one ip is passed to monitor command.
			// client, err := ssh.NewClient("core", net.JoinHostPort(ips[0], strconv.Itoa(port)), sshPrivateKeys)
			// if err != nil {
			// 	if errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.ETIMEDOUT) {
			// 		logrus.Fatal("failed to connect to the machine: %w", err)
			// 	}
			// 	logrus.Fatal("failed to create SSH client: %w", err)
			// }

			// Create a session
			session, err := client.NewSession()
			if err != nil {
				logrus.Fatalf("Failed to create SSH session: %v", err)
			}
			defer session.Close()

			// Prepare a buffer to capture the command output
			var stdoutBuf bytes.Buffer
			session.Stdout = &stdoutBuf

			command := "sudo cat /usr/local/share/assisted-service/assisted-service.env"
			// output, err := session.Output(command)
			// if err != nil {
			// 	logrus.Fatalf("Failed to run command: %v", err)
			// }
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

			// Print the file content
			logrus.Info(authToken)

			sshKey := ""
			return nodejoiner.NewMonitorAddNodesCommand(dir, kubeConfig, sshKey, authToken, ips)
		},
	}

	rootCmd := &cobra.Command{
		Use:              "node-joiner",
		PersistentPreRun: runRootCmd,
	}
	var sshKeys []string
	rootCmd.PersistentFlags().String("kubeconfig", "", "Path to the kubeconfig file.")
	rootCmd.PersistentFlags().StringArrayVar(&sshKeys, "key", []string{}, "Path to SSH private keys that should be used for authentication. If no key was provided, SSH private keys from user's environment will be used")
	rootCmd.PersistentFlags().String("dir", ".", "assets directory")
	rootCmd.PersistentFlags().String("log-level", "info", "log level (e.g. \"debug | info | warn | error\")")

	rootCmd.AddCommand(nodesAddCmd)
	rootCmd.AddCommand(nodesMonitorCmd)
	if err := rootCmd.Execute(); err != nil {
		logrus.Fatal(err)
	}
}

func runRootCmd(cmd *cobra.Command, args []string) {
	logrus.SetOutput(io.Discard)
	logrus.SetLevel(logrus.TraceLevel)

	logLevel, err := cmd.Flags().GetString("log-level")
	if err != nil {
		logrus.Fatal(err)
	}

	level, err := logrus.ParseLevel(logLevel)
	if err != nil {
		level = logrus.InfoLevel
	}

	logrus.AddHook(command.NewFileHookWithNewlineTruncate(os.Stderr, level, &logrus.TextFormatter{
		// Setting ForceColors is necessary because logrus.TextFormatter determines
		// whether or not to enable colors by looking at the output of the logger.
		// In this case, the output is io.Discard, which is not a terminal.
		// Overriding it here allows the same check to be done, but against the
		// hook's output instead of the logger's output.
		ForceColors:            terminal.IsTerminal(int(os.Stderr.Fd())),
		DisableLevelTruncation: true,
		DisableTimestamp:       false,
		FullTimestamp:          true,
		DisableQuote:           true,
	}))

	if err != nil {
		logrus.Fatal(fmt.Errorf("invalid log-level: %w", err))
	}
}
