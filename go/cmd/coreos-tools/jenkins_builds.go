package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	buildsListLimit  int
	buildsListStatus string
	buildsListDays   int
	buildLogOutput   string
)

// builds list
var buildsListCmd = &cobra.Command{
	Use:   "list <job-name>",
	Short: "List builds for a job",
	Long:  `List recent builds for a Jenkins job.`,
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		jobName := args[0]

		// If status filter is for failures, use the specialized method
		if buildsListStatus == "FAILURE" || buildsListStatus == "ABORTED" {
			builds, err := jenkinsClient.GetFailedBuilds(jobName, buildsListLimit, buildsListDays)
			if err != nil {
				printError(err)
				return err
			}
			return printJSON(builds)
		}

		builds, err := jenkinsClient.ListBuilds(jobName, buildsListLimit)
		if err != nil {
			printError(err)
			return err
		}

		// Apply status filter if specified
		if buildsListStatus != "" {
			var filtered []interface{}
			for _, b := range builds {
				if b.Result == buildsListStatus {
					filtered = append(filtered, b)
				}
			}
			return printJSON(filtered)
		}

		return printJSON(builds)
	},
}

// builds info
var buildsInfoCmd = &cobra.Command{
	Use:   "info <job-name> <build-number>",
	Short: "Get detailed build information",
	Long:  `Get detailed information about a specific build.`,
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		jobName := args[0]
		var buildNumber int
		if _, err := fmt.Sscanf(args[1], "%d", &buildNumber); err != nil {
			return fmt.Errorf("invalid build number: %s", args[1])
		}

		info, err := jenkinsClient.GetBuildInfo(jobName, buildNumber)
		if err != nil {
			printError(err)
			return err
		}
		return printJSON(info)
	},
}

// builds log
var buildsLogCmd = &cobra.Command{
	Use:   "log <job-name> <build-number>",
	Short: "Get build console log",
	Long:  `Get the console log output for a specific build.`,
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		jobName := args[0]
		var buildNumber int
		if _, err := fmt.Sscanf(args[1], "%d", &buildNumber); err != nil {
			return fmt.Errorf("invalid build number: %s", args[1])
		}

		log, err := jenkinsClient.GetBuildLog(jobName, buildNumber)
		if err != nil {
			printError(err)
			return err
		}

		// If output file specified, write to file
		if buildLogOutput != "" {
			if err := os.WriteFile(buildLogOutput, []byte(log), 0644); err != nil {
				return fmt.Errorf("failed to write log to file: %w", err)
			}
			result := map[string]interface{}{
				"status":  "saved",
				"file":    buildLogOutput,
				"size":    len(log),
				"message": fmt.Sprintf("Log saved to %s", buildLogOutput),
			}
			return printJSON(result)
		}

		// Output as JSON with the log content
		result := map[string]interface{}{
			"job":          jobName,
			"build_number": buildNumber,
			"log":          log,
		}
		return printJSON(result)
	},
}

// builds artifacts
var buildsArtifactsCmd = &cobra.Command{
	Use:   "artifacts <job-name> <build-number>",
	Short: "List build artifacts",
	Long:  `List artifacts produced by a specific build.`,
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		jobName := args[0]
		var buildNumber int
		if _, err := fmt.Sscanf(args[1], "%d", &buildNumber); err != nil {
			return fmt.Errorf("invalid build number: %s", args[1])
		}

		artifacts, err := jenkinsClient.GetBuildArtifacts(jobName, buildNumber)
		if err != nil {
			printError(err)
			return err
		}

		// Add download URLs to artifacts
		type artifactWithURL struct {
			FileName     string `json:"fileName"`
			RelativePath string `json:"relativePath"`
			DisplayPath  string `json:"displayPath,omitempty"`
			DownloadURL  string `json:"downloadUrl"`
		}

		info, _ := jenkinsClient.GetBuildInfo(jobName, buildNumber)
		var result []artifactWithURL
		for _, a := range artifacts {
			url := ""
			if info != nil {
				url = info.URL + "artifact/" + a.RelativePath
			}
			result = append(result, artifactWithURL{
				FileName:     a.FileName,
				RelativePath: a.RelativePath,
				DisplayPath:  a.DisplayPath,
				DownloadURL:  url,
			})
		}

		return printJSON(result)
	},
}

func init() {
	// builds list flags
	buildsListCmd.Flags().IntVarP(&buildsListLimit, "last", "n", 10, "Number of builds to show")
	buildsListCmd.Flags().StringVar(&buildsListStatus, "status", "", "Filter by build status (SUCCESS, FAILURE, ABORTED, UNSTABLE)")
	buildsListCmd.Flags().IntVarP(&buildsListDays, "days", "d", 0, "Only show builds from the last N days")

	// builds log flags
	buildsLogCmd.Flags().StringVarP(&buildLogOutput, "output", "o", "", "Save log to file instead of stdout")

	// Add commands to builds group
	jenkinsBuildsCmd.AddCommand(buildsListCmd)
	jenkinsBuildsCmd.AddCommand(buildsInfoCmd)
	jenkinsBuildsCmd.AddCommand(buildsLogCmd)
	jenkinsBuildsCmd.AddCommand(buildsArtifactsCmd)

	// Suppress usage on errors
	buildsListCmd.SilenceUsage = true
	buildsInfoCmd.SilenceUsage = true
	buildsLogCmd.SilenceUsage = true
	buildsArtifactsCmd.SilenceUsage = true
}
