package main

import (
	"fmt"
	"os"

	"github.com/cverna/coreos-agent-tools/pkg/config"
	"github.com/cverna/coreos-agent-tools/pkg/jenkins"
	"github.com/spf13/cobra"
)

var jenkinsClient *jenkins.Client

var jenkinsCmd = &cobra.Command{
	Use:   "jenkins",
	Short: "Manage Jenkins jobs, builds, and queue",
	Long:  `Jenkins CLI for managing jobs, builds, and queue.`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		// Run parent's PersistentPreRun first
		if parent := cmd.Parent(); parent != nil && parent.PersistentPreRun != nil {
			parent.PersistentPreRun(parent, args)
		}

		// Initialize Jenkins client
		cfg, err := config.GetJenkinsConfig()
		if err != nil {
			fmt.Fprintln(os.Stderr, "Error:", err)
			return err
		}

		jenkinsClient = jenkins.NewClient(cfg.URL, cfg.User, cfg.Token, logger)
		return nil
	},
}

// Jobs subcommand group
var jenkinsJobsCmd = &cobra.Command{
	Use:   "jobs",
	Short: "Manage Jenkins jobs",
	Long:  `List, inspect, trigger, and manage Jenkins jobs.`,
}

// Builds subcommand group
var jenkinsBuildsCmd = &cobra.Command{
	Use:   "builds",
	Short: "Manage Jenkins builds",
	Long:  `List builds, view logs, and manage build artifacts.`,
}

// Queue subcommand group
var jenkinsQueueCmd = &cobra.Command{
	Use:   "queue",
	Short: "Manage Jenkins build queue",
	Long:  `View and manage the Jenkins build queue.`,
}

func init() {
	// Add jenkins command to root
	rootCmd.AddCommand(jenkinsCmd)

	// Add subcommand groups to jenkins
	jenkinsCmd.AddCommand(jenkinsJobsCmd)
	jenkinsCmd.AddCommand(jenkinsBuildsCmd)
	jenkinsCmd.AddCommand(jenkinsQueueCmd)
}
