package main

import (
	"fmt"

	"github.com/cverna/coreos-agent-tools/pkg/config"
	"github.com/cverna/coreos-agent-tools/pkg/jira"
	"github.com/spf13/cobra"
)

var (
	cveStatus     string
	cveCreateLink bool
)

var cveCmd = &cobra.Command{
	Use:   "cve",
	Short: "Process RHCOS CVEs",
	Long:  `Process RHCOS CVEs from Jira, match with RHEL issues, and optionally create issue links.`,
}

var cveProcessCmd = &cobra.Command{
	Use:   "process",
	Short: "Process RHCOS CVEs and match with RHEL issues",
	Long: `Process RHCOS CVEs from Jira, match them with corresponding RHEL vulnerability issues,
and optionally create issue links between them.

The command queries OCPBUGS project for RHCOS CVE issues and the RHEL project for matching
vulnerability issues. It matches issues by CVE ID and RHEL version.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Get Jira config
		cfg, err := config.GetJiraConfig()
		if err != nil {
			printError(err)
			return err
		}

		// Create Jira client and processor
		client := jira.NewClient(cfg.BaseURL, cfg.APIToken, logger)
		processor := jira.NewCVEProcessor(client, logger)

		// Process CVEs
		result, err := processor.ProcessCVEs(cveStatus, cveCreateLink)
		if err != nil {
			printError(err)
			return err
		}

		// Check for processing error
		if result.Error != "" {
			printError(fmt.Errorf("%s", result.Error))
			return fmt.Errorf("%s", result.Error)
		}

		return printJSON(result)
	},
}

func init() {
	// Add cve command to root
	rootCmd.AddCommand(cveCmd)

	// Add process subcommand
	cveProcessCmd.Flags().StringVar(&cveStatus, "status", "all", "Filter CVEs by status (all, closed, open)")
	cveProcessCmd.Flags().BoolVar(&cveCreateLink, "link", false, "Create issue links between RHCOS and RHEL issues")
	cveProcessCmd.SilenceUsage = true
	cveCmd.AddCommand(cveProcessCmd)
}
