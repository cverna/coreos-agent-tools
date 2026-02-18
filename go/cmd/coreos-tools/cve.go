package main

import (
	"fmt"
	"strings"

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

func printPrettyResult(result *jira.CVEProcessingResult) {
	fmt.Println()
	fmt.Println(strings.Repeat("=", 80))
	fmt.Println("RHCOS CVE Processing Results")
	fmt.Println(strings.Repeat("=", 80))
	fmt.Printf("Status Filter: %s\n", result.StatusFilter)
	fmt.Printf("Total CVEs: %d\n", result.TotalCVEs)
	fmt.Printf("Total Issues: %d\n", result.TotalIssues)
	fmt.Printf("Closed: %d\n", result.ClosedCount)
	fmt.Printf("Open: %d\n", result.OpenCount)
	fmt.Println(strings.Repeat("=", 80))
	fmt.Println()

	if len(result.ClosedCVEData) > 0 {
		fmt.Printf("\nClosed CVEs (%d):\n", len(result.ClosedCVEData))
		fmt.Println(strings.Repeat("-", 80))
		for _, item := range result.ClosedCVEData {
			printCVEItem(item)
		}
	}

	if len(result.OpenCVEData) > 0 {
		fmt.Printf("\nOpen CVEs (%d):\n", len(result.OpenCVEData))
		fmt.Println(strings.Repeat("-", 80))
		for _, item := range result.OpenCVEData {
			printCVEItem(item)
		}
	}
}

func printCVEItem(item jira.CVEData) {
	fmt.Printf("  CVE ID: %s\n", item.CVEID)
	fmt.Printf("  Summary: %s\n", item.Summary)
	fmt.Printf("  RHCOS Issue: %s\n", item.RHCOSLink)
	fmt.Printf("  RHEL Version: %s\n", item.RHELVersion)
	fmt.Printf("  RHEL Issue: %s\n", item.RHELLink)
	fmt.Printf("  Status: %s\n", item.Status)
	fmt.Printf("  Fixed in Build: %s\n", item.FixedInBuild)
	fmt.Printf("  Due Date: %s\n", item.DueDate)
	fmt.Printf("  Resolution: %s\n", item.Resolution)
	fmt.Println()
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
