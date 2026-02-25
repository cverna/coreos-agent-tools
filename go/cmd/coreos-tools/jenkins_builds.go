package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	buildsListLimit      int
	buildsListFetchLimit int
	buildsListStatus     string
	buildsListDays       int
	buildsListStream     string
	buildLogOutput       string
	artifactsDownload    string
	artifactsOutput      string
)

// builds list
var buildsListCmd = &cobra.Command{
	Use:   "list <job-name>",
	Short: "List builds for a job",
	Long:  `List recent builds for a Jenkins job.`,
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		jobName := args[0]

		// Determine fetch limit (use flag value, or default to limit * 10)
		fetchLimit := buildsListFetchLimit
		if fetchLimit == 0 {
			fetchLimit = buildsListLimit * 10
		}

		// If status filter is for failures, use the specialized method
		if buildsListStatus == "FAILURE" || buildsListStatus == "ABORTED" {
			builds, err := jenkinsClient.GetFailedBuilds(jobName, buildsListLimit, buildsListDays, buildsListStream, fetchLimit)
			if err != nil {
				printError(err)
				return err
			}
			return printJSON(builds)
		}

		builds, err := jenkinsClient.ListBuilds(jobName, fetchLimit)
		if err != nil {
			printError(err)
			return err
		}

		// Apply filters
		var filtered []interface{}
		for _, b := range builds {
			// Apply status filter if specified
			if buildsListStatus != "" && b.Result != buildsListStatus {
				continue
			}
			// Apply stream filter if specified
			if buildsListStream != "" && b.Stream != buildsListStream {
				continue
			}
			filtered = append(filtered, b)
			// Stop if we have enough results
			if len(filtered) >= buildsListLimit {
				break
			}
		}

		// If no filters were applied, return original builds (up to limit)
		if buildsListStatus == "" && buildsListStream == "" {
			return printJSON(builds)
		}

		return printJSON(filtered)
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
	Short: "List or download build artifacts",
	Long:  `List artifacts produced by a specific build, or download a specific artifact.`,
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		jobName := args[0]
		var buildNumber int
		if _, err := fmt.Sscanf(args[1], "%d", &buildNumber); err != nil {
			return fmt.Errorf("invalid build number: %s", args[1])
		}

		// Validate: --output requires --download
		if artifactsOutput != "" && artifactsDownload == "" {
			return fmt.Errorf("--output requires --download")
		}

		artifacts, err := jenkinsClient.GetBuildArtifacts(jobName, buildNumber)
		if err != nil {
			printError(err)
			return err
		}

		// Get build info for URLs
		info, err := jenkinsClient.GetBuildInfo(jobName, buildNumber)
		if err != nil {
			printError(err)
			return err
		}

		// If --download is specified, download the artifact
		if artifactsDownload != "" {
			// Find artifact by exact filename match
			var found *struct {
				FileName     string
				RelativePath string
			}
			for _, a := range artifacts {
				if a.FileName == artifactsDownload {
					found = &struct {
						FileName     string
						RelativePath string
					}{a.FileName, a.RelativePath}
					break
				}
			}
			if found == nil {
				return fmt.Errorf("artifact not found: %s", artifactsDownload)
			}

			// Build download URL
			downloadURL := info.URL + "artifact/" + found.RelativePath

			// Determine output path
			outputPath := artifactsOutput
			if outputPath == "" {
				outputPath = found.FileName
			}

			// Download
			size, err := jenkinsClient.DownloadArtifact(downloadURL, outputPath)
			if err != nil {
				printError(err)
				return err
			}

			return printJSON(map[string]interface{}{
				"status": "downloaded",
				"file":   outputPath,
				"size":   size,
			})
		}

		// Default: list artifacts with URLs
		type artifactWithURL struct {
			FileName     string `json:"fileName"`
			RelativePath string `json:"relativePath"`
			DisplayPath  string `json:"displayPath,omitempty"`
			DownloadURL  string `json:"downloadUrl"`
		}

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

// builds kola-failures
var buildsKolaFailuresCmd = &cobra.Command{
	Use:   "kola-failures <job-name> <build-number>",
	Short: "Summarize kola test failures from build logs",
	Long:  `Extract and summarize kola test failures from a build's console log.`,
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		jobName := args[0]
		var buildNumber int
		if _, err := fmt.Sscanf(args[1], "%d", &buildNumber); err != nil {
			return fmt.Errorf("invalid build number: %s", args[1])
		}

		summary, err := jenkinsClient.GetKolaFailures(jobName, buildNumber)
		if err != nil {
			printError(err)
			return err
		}

		return printJSON(summary)
	},
}

func init() {
	// builds list flags
	buildsListCmd.Flags().IntVarP(&buildsListLimit, "last", "n", 10, "Number of builds to show")
	buildsListCmd.Flags().IntVar(&buildsListFetchLimit, "fetch-limit", 0, "Number of builds to fetch before filtering (default: 10x --last)")
	buildsListCmd.Flags().StringVar(&buildsListStatus, "status", "", "Filter by build status (SUCCESS, FAILURE, ABORTED, UNSTABLE)")
	buildsListCmd.Flags().IntVarP(&buildsListDays, "days", "d", 0, "Only show builds from the last N days")
	buildsListCmd.Flags().StringVar(&buildsListStream, "stream", "", "Filter by stream name (e.g., rhel-9.6, 4.17-9.4)")

	// builds log flags
	buildsLogCmd.Flags().StringVarP(&buildLogOutput, "output", "o", "", "Save log to file instead of stdout")

	// builds artifacts flags
	buildsArtifactsCmd.Flags().StringVar(&artifactsDownload, "download", "", "Download artifact by filename")
	buildsArtifactsCmd.Flags().StringVarP(&artifactsOutput, "output", "o", "", "Output file path (default: artifact filename)")

	// Add commands to builds group
	jenkinsBuildsCmd.AddCommand(buildsListCmd)
	jenkinsBuildsCmd.AddCommand(buildsInfoCmd)
	jenkinsBuildsCmd.AddCommand(buildsLogCmd)
	jenkinsBuildsCmd.AddCommand(buildsArtifactsCmd)
	jenkinsBuildsCmd.AddCommand(buildsKolaFailuresCmd)

	// Suppress usage on errors
	buildsListCmd.SilenceUsage = true
	buildsInfoCmd.SilenceUsage = true
	buildsLogCmd.SilenceUsage = true
	buildsArtifactsCmd.SilenceUsage = true
	buildsKolaFailuresCmd.SilenceUsage = true
}
