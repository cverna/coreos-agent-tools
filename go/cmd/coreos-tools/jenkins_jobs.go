package main

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

var (
	jobsListFolder string
	jobsListFilter string
	buildParams    []string
)

// jobs list
var jobsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all jobs",
	Long:  `List all Jenkins jobs, optionally filtered by folder or name.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		jobs, err := jenkinsClient.ListJobs(jobsListFolder, jobsListFilter)
		if err != nil {
			printError(err)
			return err
		}
		return printJSON(jobs)
	},
}

// jobs info
var jobsInfoCmd = &cobra.Command{
	Use:   "info <job-name>",
	Short: "Get detailed job information",
	Long:  `Get detailed information about a specific Jenkins job.`,
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		jobName := args[0]
		info, err := jenkinsClient.GetJobInfo(jobName)
		if err != nil {
			printError(err)
			return err
		}
		return printJSON(info)
	},
}

// jobs build
var jobsBuildCmd = &cobra.Command{
	Use:   "build <job-name>",
	Short: "Trigger a new build",
	Long:  `Trigger a new build for a Jenkins job, optionally with parameters.`,
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		jobName := args[0]

		// Parse build parameters
		params := make(map[string]string)
		for _, p := range buildParams {
			parts := strings.SplitN(p, "=", 2)
			if len(parts) == 2 {
				params[parts[0]] = parts[1]
			} else {
				return fmt.Errorf("invalid parameter format: %s (expected KEY=VALUE)", p)
			}
		}

		err := jenkinsClient.TriggerBuild(jobName, params)
		if err != nil {
			printError(err)
			return err
		}

		result := map[string]interface{}{
			"status":  "triggered",
			"job":     jobName,
			"message": fmt.Sprintf("Build triggered for job '%s'", jobName),
		}
		if len(params) > 0 {
			result["parameters"] = params
		}
		return printJSON(result)
	},
}

// jobs abort
var jobsAbortCmd = &cobra.Command{
	Use:   "abort <job-name> <build-number>",
	Short: "Abort a running build",
	Long:  `Abort a running build for a Jenkins job.`,
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		jobName := args[0]
		var buildNumber int
		if _, err := fmt.Sscanf(args[1], "%d", &buildNumber); err != nil {
			return fmt.Errorf("invalid build number: %s", args[1])
		}

		err := jenkinsClient.AbortBuild(jobName, buildNumber)
		if err != nil {
			printError(err)
			return err
		}

		result := map[string]interface{}{
			"status":       "aborted",
			"job":          jobName,
			"build_number": buildNumber,
			"message":      fmt.Sprintf("Build #%d aborted for job '%s'", buildNumber, jobName),
		}
		return printJSON(result)
	},
}

// jobs running
var jobsRunningFilter string

var jobsRunningCmd = &cobra.Command{
	Use:   "running",
	Short: "List currently running jobs",
	Long:  `List all jobs currently running on Jenkins executors.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		running, err := jenkinsClient.GetRunningBuilds(jobsRunningFilter)
		if err != nil {
			printError(err)
			return err
		}
		return printJSON(running)
	},
}

func init() {
	// jobs list flags
	jobsListCmd.Flags().StringVar(&jobsListFolder, "folder", "", "List jobs within a folder")
	jobsListCmd.Flags().StringVar(&jobsListFilter, "filter", "", "Filter jobs by name (case-insensitive)")

	// jobs build flags
	jobsBuildCmd.Flags().StringArrayVarP(&buildParams, "param", "p", nil, "Build parameter (KEY=VALUE), can be specified multiple times")

	// jobs running flags
	jobsRunningCmd.Flags().StringVar(&jobsRunningFilter, "job", "", "Filter by job name")

	// Add commands to jobs group
	jenkinsJobsCmd.AddCommand(jobsListCmd)
	jenkinsJobsCmd.AddCommand(jobsInfoCmd)
	jenkinsJobsCmd.AddCommand(jobsBuildCmd)
	jenkinsJobsCmd.AddCommand(jobsAbortCmd)
	jenkinsJobsCmd.AddCommand(jobsRunningCmd)

	// Suppress usage on errors
	jobsListCmd.SilenceUsage = true
	jobsInfoCmd.SilenceUsage = true
	jobsBuildCmd.SilenceUsage = true
	jobsAbortCmd.SilenceUsage = true
	jobsRunningCmd.SilenceUsage = true
}
